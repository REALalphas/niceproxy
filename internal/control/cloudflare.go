package control

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"niceproxy/internal/cloudflare"
)

const cfSettingsName = "cloudflare.settings"

type cloudflareSettings struct {
	ClientID string   `json:"clientId"`
	Scopes   []string `json:"scopes"`
}

// ConfigureCloudflare loads public client settings. OAuth tokens remain inside
// the provider manager; the control API never serializes them.
func (a *App) ConfigureCloudflare(options cloudflare.Options) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cfMu.Lock()
	defer a.cfMu.Unlock()
	a.cfDefaultRedirect = options.RedirectURL
	if a.config.PanelDomain != "" {
		options.RedirectURL = "https://" + a.config.PanelDomain + "/api/cloudflare/callback"
	}
	a.cfOptions = options
	a.cfCallbackHost.Store("")
	a.cfHTTPSCallback.Store(false)
	if validateCloudflareRedirect(options.RedirectURL) == nil {
		u, _ := url.Parse(options.RedirectURL)
		a.cfCallbackHost.Store(u.Host)
		a.cfHTTPSCallback.Store(u.Scheme == "https")
	}
	body, err := a.db.Integration(cfSettingsName)
	if err != nil {
		a.cfInitError = "Не удалось прочитать настройки Cloudflare из хранилища."
		return err
	}
	if len(body) > 0 {
		var settings cloudflareSettings
		if err := json.Unmarshal(body, &settings); err != nil {
			a.cfInitError = "Сохранённые настройки Cloudflare повреждены. Настройте OAuth-приложение заново."
			return fmt.Errorf("invalid Cloudflare settings")
		}
		options.ClientID = settings.ClientID
		options.Scopes = settings.Scopes
	}
	a.cf, err = cloudflare.New(options, a.db)
	if err != nil {
		a.cfInitError = "Не удалось загрузить подключение Cloudflare. Проверьте настройки приложения и сохранённый ключ шифрования."
	}
	return err
}

func (a *App) syncCloudflareRedirect(domain string) error {
	a.cfMu.Lock()
	defer a.cfMu.Unlock()
	redirect := a.cfDefaultRedirect
	if domain != "" {
		redirect = "https://" + domain + "/api/cloudflare/callback"
	}
	if redirect != "" {
		if err := validateCloudflareRedirect(redirect); err != nil {
			return err
		}
	}
	a.cfOptions.RedirectURL = redirect
	if parsed, err := url.Parse(redirect); err == nil && parsed != nil {
		a.cfCallbackHost.Store(parsed.Host)
		a.cfHTTPSCallback.Store(parsed.Scheme == "https")
	}
	if a.cf == nil {
		if a.cfOptions.ClientID != "" && len(a.cfOptions.Scopes) > 0 {
			manager, err := cloudflare.New(a.cfOptions, a.db)
			if err != nil {
				a.cfInitError = "Не удалось восстановить Cloudflare после смены домена: " + err.Error()
				return err
			}
			a.cf = manager
		}
		return nil
	}
	if err := a.cf.SetRedirectURL(redirect); err != nil {
		a.cfInitError = "Callback URL не синхронизирован с доменом панели: " + err.Error()
		return err
	}
	a.cfInitError = ""
	return nil
}

func (a *App) cloudflareStatus() cloudflare.Status {
	status := cloudflare.Status{ClientID: a.cfOptions.ClientID, RedirectURL: a.cfOptions.RedirectURL, LoopbackRedirectURL: a.cfOptions.LoopbackRedirectURL, Scopes: []string{}}
	if a.cf != nil {
		status = a.cf.Status()
	}
	if status.Scopes == nil {
		status.Scopes = []string{}
	}
	if a.cfInitError != "" {
		status.Error = a.cfInitError
	}
	return status
}

func (a *App) cloudflareAPI(w http.ResponseWriter, r *http.Request) {
	a.cfMu.Lock()
	defer a.cfMu.Unlock()
	if r.URL.Path == "/api/cloudflare" && r.Method == "GET" {
		write(w, 200, a.cloudflareStatus())
		return
	}
	if r.URL.Path == "/api/cloudflare/settings" && r.Method == "POST" {
		var settings cloudflareSettings
		if err := decode(w, r, &settings); err != nil {
			fail(w, 400, err.Error())
			return
		}
		settings.ClientID = strings.TrimSpace(settings.ClientID)
		if settings.ClientID == "" || len(settings.ClientID) > 256 || strings.ContainsAny(settings.ClientID, " \t\r\n") || len(settings.Scopes) < 1 || len(settings.Scopes) > 32 {
			fail(w, 400, "Укажите публичный Client ID и разрешённые OAuth scope ID.")
			return
		}
		unique := map[string]bool{}
		for i, scope := range settings.Scopes {
			scope = strings.TrimSpace(scope)
			if scope == "" || len(scope) > 128 || strings.ContainsAny(scope, " \t\r\n,:/\\") {
				fail(w, 400, "Каждый OAuth scope ID должен быть отдельной строкой без пробелов.")
				return
			}
			if unique[scope] {
				fail(w, 400, "OAuth scope ID не должны повторяться.")
				return
			}
			unique[scope] = true
			settings.Scopes[i] = scope
		}
		options := a.cfOptions
		options.ClientID = settings.ClientID
		options.Scopes = settings.Scopes
		if options.RedirectURL != "" || options.LoopbackRedirectURL == "" {
			if err := validateCloudflareRedirect(options.RedirectURL); err != nil {
				fail(w, 400, err.Error())
				return
			}
		}
		// A configuration change invalidates the old grant before instantiating
		// a manager for the newly registered application.
		var revokeWarning string
		if a.cf != nil {
			oldClient := a.cf.Status().ClientID
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			if err := a.cf.Disconnect(ctx); err != nil {
				revokeWarning = "Settings saved, but the previous OAuth grant could not be revoked. Check niceproxy authorizations in Cloudflare (client ID: " + oldClient + ")."
			}
			cancel()
		}
		if !a.cloudflareCredentialsCleared(w) {
			return
		}
		manager, err := cloudflare.New(options, a.db)
		if err != nil {
			fail(w, 400, "Не удалось настроить OAuth Cloudflare. Проверьте Client ID, scope ID и callback URL.")
			return
		}
		body, _ := json.Marshal(settings)
		if err := a.db.SetIntegration(cfSettingsName, body); err != nil {
			fail(w, 500, "Не удалось сохранить настройки Cloudflare.")
			return
		}
		a.cf = manager
		a.cfInitError = revokeWarning
		write(w, 200, a.cloudflareStatus())
		return
	}
	if r.URL.Path == "/api/cloudflare/disconnect" && r.Method == "POST" {
		response := map[string]any{"ok": true}
		if a.cf != nil {
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			err := a.cf.Disconnect(ctx)
			cancel()
			if err != nil {
				response["warning"] = "Локальное подключение удалено. Проверьте отзыв доступа в Cloudflare."
			}
		}
		if !a.cloudflareCredentialsCleared(w) {
			return
		}
		a.cfInitError = ""
		write(w, 200, response)
		return
	}
	if a.cf == nil || !a.cf.Status().Configured {
		fail(w, 409, "Сначала зарегистрируйте OAuth-приложение Cloudflare и сохраните публичные настройки.")
		return
	}
	if r.URL.Path == "/api/cloudflare/connect" && r.Method == "POST" {
		cookie, err := r.Cookie("niceproxy_session")
		if err != nil {
			fail(w, 401, "authentication required")
			return
		}
		session := hash(cookie.Value)
		if r.URL.Query().Get("mode") == "localhost" {
			authorization, err := a.cf.BeginLoopback(session)
			if err != nil {
				fail(w, 400, "Не удалось начать вход через localhost. Проверьте настройки OAuth.")
				return
			}
			a.cfInitError = ""
			write(w, 200, map[string]string{"url": authorization})
			return
		}
		redirect, _ := url.Parse(a.cf.Status().RedirectURL)
		if redirect == nil || redirect.Host != r.Host {
			fail(w, 400, "Откройте панель по адресу OAuth callback или начните вход через localhost.")
			return
		}
		authorization, state, err := a.cf.Begin(session)
		if err != nil {
			fail(w, 400, "Не удалось начать подключение Cloudflare.")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "niceproxy_cf_oauth", Value: state, Path: "/api/cloudflare/callback", HttpOnly: true, Secure: redirect.Scheme == "https", SameSite: http.SameSiteLaxMode, MaxAge: 600})
		a.cfInitError = ""
		write(w, 200, map[string]string{"url": authorization})
		return
	}
	if r.URL.Path == "/api/cloudflare/complete" && r.Method == "POST" {
		var input struct {
			CallbackURL string `json:"callbackUrl"`
		}
		if err := decode(w, r, &input); err != nil {
			fail(w, 400, err.Error())
			return
		}
		cookie, err := r.Cookie("niceproxy_session")
		if err != nil {
			fail(w, 401, "authentication required")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		if err := a.cf.CompleteLoopback(ctx, input.CallbackURL, hash(cookie.Value), a.db.Authenticated); err != nil {
			fail(w, 400, "Не удалось завершить OAuth. Скопируйте полный localhost URL из вкладки после подтверждения. Если попытка истекла или Cloudflare отклонил код, начните вход заново.")
			return
		}
		a.cfInitError = ""
		a.queuePanelAutomation()
		write(w, 200, a.cloudflareStatus())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
	defer cancel()
	if r.URL.Path == "/api/cloudflare/zones" && r.Method == "GET" {
		zones, err := a.cf.Zones(ctx)
		if err != nil {
			fail(w, 502, err.Error())
			return
		}
		if zones == nil {
			zones = []cloudflare.Zone{}
		}
		write(w, 200, map[string]any{"zones": zones})
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/cloudflare/zones/"), "/")
	if strings.HasPrefix(r.URL.Path, "/api/cloudflare/zones/") && (len(parts) == 2 || len(parts) == 3) && parts[1] == "records" {
		zoneID := parts[0]
		if len(parts) == 2 && r.Method == "GET" {
			records, err := a.cf.Records(ctx, zoneID)
			if err != nil {
				fail(w, 502, err.Error())
				return
			}
			if records == nil {
				records = []cloudflare.Record{}
			}
			write(w, 200, map[string]any{"records": records})
			return
		}
		if (len(parts) == 2 && r.Method == "POST") || (len(parts) == 3 && parts[2] != "" && r.Method == "PATCH") {
			var record cloudflare.Record
			if err := decode(w, r, &record); err != nil {
				fail(w, 400, err.Error())
				return
			}
			recordID := ""
			if len(parts) == 3 {
				recordID = parts[2]
			}
			result, err := a.cf.WriteRecord(ctx, zoneID, recordID, record)
			if err != nil {
				fail(w, 502, err.Error())
				return
			}
			write(w, 200, result)
			return
		}
	}
	fail(w, 404, "Cloudflare endpoint not found")
}

func (a *App) cloudflareCredentialsCleared(w http.ResponseWriter) bool {
	body, err := a.db.Integration("cloudflare")
	if err != nil || len(body) > 0 {
		fail(w, 500, "Не удалось удалить сохранённое подключение Cloudflare. Проверьте доступ к хранилищу и повторите отключение.")
		return false
	}
	return true
}

func (a *App) cloudflareCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		fail(w, 405, "GET required")
		return
	}
	a.cfMu.Lock()
	defer a.cfMu.Unlock()
	result := "error"
	cookie, cookieErr := r.Cookie("niceproxy_cf_oauth")
	if callback, _ := url.Parse(a.cfOptions.LoopbackRedirectURL); callback != nil && callback.Host == r.Host {
		state := r.URL.Query().Get("state")
		if cookieErr != nil || subtle.ConstantTimeCompare([]byte(state), []byte(cookie.Value)) != 1 {
			// Keep the address bar intact for an authenticated manual completion.
			w.Header().Set("Referrer-Policy", "no-referrer")
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("Скопируйте полный URL из адресной строки и вставьте его в niceproxy."))
			return
		}
	}
	if a.cf != nil && cookieErr == nil {
		u, _ := url.Parse(a.cf.Status().RedirectURL)
		query := r.URL.Query()
		state := query.Get("state")
		if u != nil && u.Host == r.Host && len(query["state"]) == 1 && subtle.ConstantTimeCompare([]byte(state), []byte(cookie.Value)) == 1 {
			http.SetCookie(w, &http.Cookie{Name: "niceproxy_cf_oauth", Value: "", Path: "/api/cloudflare/callback", HttpOnly: true, Secure: u.Scheme == "https", SameSite: http.SameSiteLaxMode, MaxAge: -1})
			code := query.Get("code")
			if query.Get("error") == "" && len(query["code"]) == 1 && len(code) <= 4096 {
				ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
				err := a.cf.Complete(ctx, code, state, cookie.Value, a.db.Authenticated)
				cancel()
				if err == nil {
					result = "connected"
					a.queuePanelAutomation()
				}
			}
			a.cfInitError = ""
			if result == "error" {
				a.cfInitError = "Cloudflare не подключён: вход отменён, истёк или не прошёл проверку. Повторите подключение."
			}
		}
	}
	http.Redirect(w, r, "/?cloudflare="+result+"#cloudflare", http.StatusSeeOther)
}

func validateCloudflareRedirect(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.Path != "/api/cloudflare/callback" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.Fragment != "" {
		return errors.New("Задайте NICEPROXY_CF_REDIRECT_URL с адресом панели и путём /api/cloudflare/callback.")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if u.Scheme != "https" && !(u.Scheme == "http" && (host == "localhost" || ip != nil && ip.IsLoopback())) {
		return errors.New("Для удалённого callback требуется HTTPS; HTTP допустим только на localhost.")
	}
	return nil
}
