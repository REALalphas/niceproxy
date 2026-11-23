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
	a.cfMu.Lock()
	defer a.cfMu.Unlock()
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
		a.cfInitError = "Could not read Cloudflare settings from storage."
		return err
	}
	if len(body) > 0 {
		var settings cloudflareSettings
		if err := json.Unmarshal(body, &settings); err != nil {
			a.cfInitError = "Saved Cloudflare settings are invalid. Set up the OAuth app again."
			return fmt.Errorf("invalid Cloudflare settings")
		}
		options.ClientID = settings.ClientID
		options.Scopes = settings.Scopes
	}
	a.cf, err = cloudflare.New(options, a.db)
	if err != nil {
		a.cfInitError = "Could not load the Cloudflare connection. Check the app settings and encryption key."
	}
	return err
}

func (a *App) cloudflareStatus() cloudflare.Status {
	status := cloudflare.Status{ClientID: a.cfOptions.ClientID, RedirectURL: a.cfOptions.RedirectURL, Scopes: []string{}}
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
			fail(w, 400, "Enter a public client ID and allowed OAuth scope IDs.")
			return
		}
		unique := map[string]bool{}
		for i, scope := range settings.Scopes {
			scope = strings.TrimSpace(scope)
			if scope == "" || len(scope) > 128 || strings.ContainsAny(scope, " \t\r\n,:/\\") {
				fail(w, 400, "Each OAuth scope ID must be a single value without spaces.")
				return
			}
			if unique[scope] {
				fail(w, 400, "OAuth scope IDs must be unique.")
				return
			}
			unique[scope] = true
			settings.Scopes[i] = scope
		}
		options := a.cfOptions
		options.ClientID = settings.ClientID
		options.Scopes = settings.Scopes
		if err := validateCloudflareRedirect(options.RedirectURL); err != nil {
			fail(w, 400, err.Error())
			return
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
			fail(w, 400, "Could not configure Cloudflare OAuth. Check the client ID, scope IDs, and callback URL.")
			return
		}
		body, _ := json.Marshal(settings)
		if err := a.db.SetIntegration(cfSettingsName, body); err != nil {
			fail(w, 500, "Could not save Cloudflare settings.")
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
				response["warning"] = "The local connection was removed. Check access revocation in Cloudflare."
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
		fail(w, 409, "Register a Cloudflare OAuth app and save its public settings first.")
		return
	}
	if r.URL.Path == "/api/cloudflare/connect" && r.Method == "POST" {
		redirect, _ := url.Parse(a.cf.Status().RedirectURL)
		if redirect == nil || redirect.Host != r.Host {
			fail(w, 400, "Open the panel at the address configured in the OAuth app callback URL.")
			return
		}
		cookie, err := r.Cookie("niceproxy_session")
		if err != nil {
			fail(w, 401, "authentication required")
			return
		}
		authorization, state, err := a.cf.Begin(hash(cookie.Value))
		if err != nil {
			fail(w, 400, "Could not start the Cloudflare connection.")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "niceproxy_cf_oauth", Value: state, Path: "/api/cloudflare/callback", HttpOnly: true, Secure: redirect.Scheme == "https", SameSite: http.SameSiteLaxMode, MaxAge: 600})
		a.cfInitError = ""
		write(w, 200, map[string]string{"url": authorization})
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
		fail(w, 500, "Could not remove the saved Cloudflare connection. Check storage access and try disconnecting again.")
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
	if a.cf != nil && cookieErr == nil {
		u, _ := url.Parse(a.cf.Status().RedirectURL)
		query := r.URL.Query()
		state := query.Get("state")
		// A callback from an older window must leave a newer attempt's
		// cookie and status intact.
		if u != nil && u.Host == r.Host && len(query["state"]) == 1 && subtle.ConstantTimeCompare([]byte(state), []byte(cookie.Value)) == 1 {
			http.SetCookie(w, &http.Cookie{Name: "niceproxy_cf_oauth", Value: "", Path: "/api/cloudflare/callback", HttpOnly: true, Secure: u.Scheme == "https", SameSite: http.SameSiteLaxMode, MaxAge: -1})
			code := query.Get("code")
			if query.Get("error") == "" && len(query["code"]) == 1 && len(code) <= 4096 {
				ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
				err := a.cf.Complete(ctx, code, state, cookie.Value, a.db.Authenticated)
				cancel()
				if err == nil {
					result = "connected"
				}
			}
			a.cfInitError = ""
			if result == "error" {
				a.cfInitError = "Cloudflare is not connected. Sign-in was cancelled, expired, or failed validation. Try again."
			}
		}
	}
	http.Redirect(w, r, "/?cloudflare="+result+"#cloudflare", http.StatusSeeOther)
}

func validateCloudflareRedirect(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.Host == "" || u.Path != "/api/cloudflare/callback" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.RawPath != "" || u.Fragment != "" {
		return errors.New("Set NICEPROXY_CF_REDIRECT_URL to the panel address with the /api/cloudflare/callback path.")
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	if u.Scheme != "https" && !(u.Scheme == "http" && (host == "localhost" || ip != nil && ip.IsLoopback())) {
		return errors.New("Remote callbacks require HTTPS. HTTP is allowed only on localhost.")
	}
	return nil
}
