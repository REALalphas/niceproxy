package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
	"niceproxy/internal/cloudflare"
	"niceproxy/internal/model"
	"niceproxy/internal/proxy"
	"niceproxy/internal/store"
)

type Caddy interface {
	Apply(context.Context, []model.HTTPRoute) error
	Healthy(context.Context) bool
}

type App struct {
	mu                    sync.Mutex
	db                    *store.Store
	caddy                 Caddy
	proxy                 *proxy.Manager
	config                model.Config
	applied               int64
	active                map[string]model.DirectRule
	httpActive            []model.HTTPRoute
	ruleErrors            map[string]string
	httpError, applyError string
	reserved              map[int]bool
	authMu                sync.Mutex
	authWindow            time.Time
	authAttempts          int
	authByClient          map[string]authBucket
	cfMu                  sync.Mutex
	cf                    *cloudflare.Manager
	cfOptions             cloudflare.Options
	cfDefaultRedirect     string
	cfCallbackDomain      string
	cfInitError           string
	cfCallbackHost        atomic.Value // explicit trusted callback host; never learned from a request
	cfHTTPSCallback       atomic.Bool
}
type authBucket struct {
	window   time.Time
	attempts int
}

func New(db *store.Store, c Caddy, p *proxy.Manager, reserved map[int]bool) (*App, error) {
	cfg, _, err := db.Load()
	if err != nil {
		return nil, err
	}
	if cfg.HTTPRoutes == nil {
		cfg.HTTPRoutes = []model.HTTPRoute{}
	}
	if cfg.DirectRules == nil {
		cfg.DirectRules = []model.DirectRule{}
	}
	a := &App{db: db, caddy: c, proxy: p, config: cfg, active: map[string]model.DirectRule{}, ruleErrors: map[string]string{}, reserved: reserved, authByClient: map[string]authBucket{}}
	good, err := db.LastGood()
	if err != nil {
		return nil, err
	}
	a.httpActive = append([]model.HTTPRoute{}, good.HTTPRoutes...)
	for _, r := range good.DirectRules {
		if !r.Enabled {
			continue
		}
		_, e := p.Add(r.ID, proxy.Rule{Protocol: r.Protocol, ListenAddress: r.ListenHost, ListenPort: r.ListenPort, TargetAddress: r.TargetHost, TargetPort: r.TargetPort})
		if e == nil {
			a.active[r.ID] = r
		}
	}
	return a, nil
}

func (a *App) Reconcile(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reconcile(ctx)
}

// SetHTTPActive records the exact routes used by Caddy during startup.
func (a *App) SetHTTPActive(routes []model.HTTPRoute) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.httpActive = append([]model.HTTPRoute{}, routes...)
}
func (a *App) reconcile(ctx context.Context) error {
	var errs []error
	a.httpError = ""
	if !reflect.DeepEqual(a.httpActive, a.config.HTTPRoutes) || !a.caddy.Healthy(ctx) {
		if err := a.caddy.Apply(ctx, a.config.HTTPRoutes); err != nil {
			a.httpError = err.Error()
			errs = append(errs, fmt.Errorf("Caddy: %w", err))
		} else {
			a.httpActive = append([]model.HTTPRoute{}, a.config.HTTPRoutes...)
		}
	}
	wanted := map[string]bool{}
	for _, r := range a.config.DirectRules {
		if r.Enabled {
			wanted[r.ID] = true
		}
	}
	for id := range a.active {
		if !wanted[id] {
			drain, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = a.proxy.Remove(drain, id)
			cancel()
			delete(a.active, id)
		}
	}
	a.ruleErrors = map[string]string{}
	for _, r := range a.config.DirectRules {
		if !r.Enabled {
			continue
		}
		pr := proxy.Rule{Protocol: r.Protocol, ListenAddress: r.ListenHost, ListenPort: r.ListenPort, TargetAddress: r.TargetHost, TargetPort: r.TargetPort}
		previous, exists := a.active[r.ID]
		if exists && reflect.DeepEqual(previous, r) {
			continue
		}
		var err error
		if exists {
			drain, cancel := context.WithTimeout(ctx, time.Second)
			_, e := a.proxy.Update(drain, r.ID, pr)
			cancel()
			err = e
		} else {
			_, err = a.proxy.Add(r.ID, pr)
		}
		if err != nil {
			a.ruleErrors[r.ID] = err.Error()
			errs = append(errs, fmt.Errorf("%s: %w", r.ID, err))
		} else {
			a.active[r.ID] = r
		}
	}
	if len(errs) == 0 {
		if err := a.db.MarkApplied(a.config); err != nil {
			errs = append(errs, err)
		} else {
			a.applied = a.config.Revision
		}
	}
	err := errors.Join(errs...)
	a.applyError = ""
	if err != nil {
		// Several subsystems may already have changed. No single revision can
		// truthfully describe a mixed runtime state.
		a.applied = -1
		a.applyError = err.Error()
	}
	return err
}

func (a *App) snapshot() model.Config {
	c := a.config
	c.HTTPRoutes = append([]model.HTTPRoute{}, c.HTTPRoutes...)
	c.DirectRules = append([]model.DirectRule{}, c.DirectRules...)
	for i := range c.HTTPRoutes {
		r := &c.HTTPRoutes[i]
		r.Status = "unknown"
		if r.Enabled {
			if a.httpError != "" {
				r.Status = "error"
				r.Error = a.httpError
			} else {
				r.Status = "healthy"
			}
		}
	}
	for i := range c.DirectRules {
		r := &c.DirectRules[i]
		r.Status = "unknown"
		if r.Enabled {
			if msg := a.ruleErrors[r.ID]; msg != "" {
				r.Status = "error"
				r.Error = msg
			} else if _, ok := a.active[r.ID]; ok {
				r.Status = "healthy"
			}
		}
	}
	return c
}

func (a *App) Handler(static http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		if !a.caddy.Healthy(ctx) {
			fail(w, 503, "Caddy unavailable")
			return
		}
		write(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("/api/", a.api)
	mux.Handle("/", static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		// Alpha UI sets icon URLs and motion variables on style attributes.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *App) authenticated(r *http.Request) bool {
	c, err := r.Cookie("niceproxy_session")
	return err == nil && a.db.Authenticated(hash(c.Value))
}
func hash(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }
func randomID() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func (a *App) api(w http.ResponseWriter, r *http.Request) {
	// The panel is configured on an IP listener. Reject arbitrary DNS Host
	// headers so a browser cannot rebind an attacker's domain onto loopback.
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if net.ParseIP(host) == nil && host != "localhost" && a.cfCallbackHost.Load() != r.Host {
		fail(w, 403, "management API requires an IP address or localhost host")
		return
	}
	if r.Method != "GET" {
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			fail(w, 403, "cross-site request rejected")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host != r.Host {
				fail(w, 403, "origin mismatch")
				return
			}
		}
	}
	if r.URL.Path == "/api/auth" && r.Method == "GET" {
		password, err := a.db.Password()
		if err != nil {
			fail(w, 500, "cannot read authentication state")
			return
		}
		write(w, 200, map[string]bool{"configured": len(password) > 0, "authenticated": a.authenticated(r)})
		return
	}
	if r.URL.Path == "/api/setup" || r.URL.Path == "/api/login" {
		a.login(w, r)
		return
	}
	// Cross-site OAuth GET returns without our SameSite=Strict admin cookie.
	// The callback instead validates a one-time Lax cookie and the session
	// that started the flow; it never creates an app login session.
	if r.URL.Path == "/api/cloudflare/callback" {
		a.cloudflareCallback(w, r)
		return
	}
	if !a.authenticated(r) {
		fail(w, 401, "authentication required")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/cloudflare") {
		a.cloudflareAPI(w, r)
		return
	}
	if r.URL.Path == "/api/logout" && r.Method == "POST" {
		c, _ := r.Cookie("niceproxy_session")
		_ = a.db.Logout(hash(c.Value))
		http.SetCookie(w, &http.Cookie{Name: "niceproxy_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		write(w, 200, map[string]bool{"ok": true})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.URL.Path == "/api/config" && r.Method == "GET" {
		write(w, 200, a.snapshot())
		return
	}
	if r.URL.Path == "/api/health" && r.Method == "GET" {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		ok := a.caddy.Healthy(ctx)
		status := "healthy"
		if !ok || a.applyError != "" {
			status = "error"
		}
		write(w, 200, model.Health{Status: status, Caddy: ok, Revision: a.config.Revision, AppliedRevision: a.applied, Error: a.applyError})
		return
	}
	if r.URL.Path == "/api/reconcile" && r.Method == "POST" {
		_ = a.reconcile(r.Context())
		write(w, 200, a.snapshot())
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/direct-rules") {
		a.direct(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/http-routes") {
		a.httpRoute(w, r)
		return
	}
	fail(w, 404, "endpoint not found")
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "POST required")
		return
	}
	a.authMu.Lock()
	defer a.authMu.Unlock()
	if time.Since(a.authWindow) > time.Minute {
		a.authWindow = time.Now()
		a.authAttempts = 0
		for key, bucket := range a.authByClient {
			if time.Since(bucket.window) > time.Minute {
				delete(a.authByClient, key)
			}
		}
	}
	password, err := a.db.Password()
	if err != nil {
		fail(w, 500, "cannot read password")
		return
	}
	if r.URL.Path == "/api/setup" && len(password) > 0 {
		fail(w, 409, "already configured")
		return
	}
	key := r.RemoteAddr
	if host, _, splitErr := net.SplitHostPort(r.RemoteAddr); splitErr == nil {
		key = host
	}
	// Only the bundled Caddy reaches the private Unix listener. Its default
	// proxy handler replaces untrusted client-supplied X-Forwarded-For.
	if r.RemoteAddr == "@" || r.RemoteAddr == "" {
		forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
		if net.ParseIP(forwarded) != nil {
			key = forwarded
		}
	}
	if len(a.authByClient) >= 4096 {
		if _, ok := a.authByClient[key]; !ok {
			fail(w, 429, "authentication client limit reached")
			return
		}
	}
	bucket := a.authByClient[key]
	if time.Since(bucket.window) > time.Minute {
		bucket = authBucket{window: time.Now()}
	}
	if bucket.attempts >= 10 || a.authAttempts >= 1000 {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "too many authentication attempts; retry in one minute")
		return
	}
	bucket.attempts++
	a.authByClient[key] = bucket
	a.authAttempts++
	var body struct {
		Password string `json:"password"`
	}
	if err := decode(w, r, &body); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if r.URL.Path == "/api/setup" {
		if len(body.Password) < 12 || len(body.Password) > 72 {
			fail(w, 400, "password must contain 12 to 72 bytes")
			return
		}
		password, err = bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err == nil {
			err = a.db.Setup(password)
		}
		if err != nil {
			fail(w, 500, "cannot save password")
			return
		}
	} else if len(password) == 0 || bcrypt.CompareHashAndPassword(password, []byte(body.Password)) != nil {
		fail(w, 401, "invalid credentials")
		return
	}
	token := randomID()
	if err := a.db.Session(hash(token), time.Now().Add(12*time.Hour)); err != nil {
		fail(w, 500, "cannot create session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "niceproxy_session", Value: token, Path: "/", MaxAge: 43200, HttpOnly: true, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" || (a.cfHTTPSCallback.Load() && a.cfCallbackHost.Load() == r.Host), SameSite: http.SameSiteStrictMode})
	a.authAttempts = 0
	delete(a.authByClient, key)
	write(w, 200, map[string]bool{"configured": true, "authenticated": true})
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return fmt.Errorf("Content-Type application/json required")
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("request must contain one JSON object")
	}
	return nil
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	write(w, status, map[string]string{"error": message})
}

func resourceID(path, base string) (string, bool) {
	if path == base {
		return "", true
	}
	if !strings.HasPrefix(path, base+"/") {
		return "", false
	}
	id := strings.TrimPrefix(path, base+"/")
	return id, id != "" && !strings.Contains(id, "/")
}
func (a *App) commit(ctx context.Context, c model.Config) error {
	c.Revision = a.config.Revision + 1
	if err := a.db.Save(c); err != nil {
		return err
	}
	a.config = c
	_ = a.reconcile(ctx)
	return nil
}

func (a *App) direct(w http.ResponseWriter, r *http.Request) {
	id, ok := resourceID(r.URL.Path, "/api/direct-rules")
	if !ok {
		fail(w, 404, "rule not found")
		return
	}
	c := a.config
	c.DirectRules = append([]model.DirectRule{}, c.DirectRules...)
	index := -1
	for i, v := range c.DirectRules {
		if v.ID == id {
			index = i
			break
		}
	}
	if id != "" && index < 0 {
		fail(w, 404, "rule not found")
		return
	}
	if r.Method == "DELETE" && index >= 0 {
		c.DirectRules = append(c.DirectRules[:index], c.DirectRules[index+1:]...)
		if err := a.commit(r.Context(), c); err != nil {
			fail(w, 500, err.Error())
			return
		}
		write(w, 200, map[string]bool{"ok": true})
		return
	}
	var item model.DirectRule
	if r.Method == "PATCH" && index >= 0 {
		item = c.DirectRules[index]
	} else if r.Method != "POST" || id != "" {
		fail(w, 405, "method not allowed")
		return
	}
	if err := decode(w, r, &item); err != nil {
		fail(w, 400, err.Error())
		return
	}
	item.ID = id
	if id == "" {
		item.ID = randomID()
	}
	item.Status = ""
	item.Error = ""
	if err := validateDirect(&item, a.reserved); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if len(c.DirectRules) >= 1024 && index < 0 {
		fail(w, 400, "maximum 1024 direct rules")
		return
	}
	for _, other := range c.DirectRules {
		if other.ID != item.ID && other.Enabled && item.Enabled && other.Protocol == item.Protocol && other.ListenPort == item.ListenPort && (other.ListenHost == item.ListenHost || other.ListenHost == "0.0.0.0" || item.ListenHost == "0.0.0.0" || other.ListenHost == "::" || item.ListenHost == "::") {
			fail(w, 409, "listener conflicts with another enabled rule")
			return
		}
	}
	if index < 0 {
		c.DirectRules = append(c.DirectRules, item)
	} else {
		c.DirectRules[index] = item
	}
	if err := a.commit(r.Context(), c); err != nil {
		fail(w, 500, err.Error())
		return
	}
	for _, saved := range a.snapshot().DirectRules {
		if saved.ID == item.ID {
			write(w, 200, saved)
			return
		}
	}
}

func (a *App) httpRoute(w http.ResponseWriter, r *http.Request) {
	id, ok := resourceID(r.URL.Path, "/api/http-routes")
	if !ok {
		fail(w, 404, "route not found")
		return
	}
	c := a.config
	c.HTTPRoutes = append([]model.HTTPRoute{}, c.HTTPRoutes...)
	index := -1
	for i, v := range c.HTTPRoutes {
		if v.ID == id {
			index = i
			break
		}
	}
	if id != "" && index < 0 {
		fail(w, 404, "route not found")
		return
	}
	if r.Method == "DELETE" && index >= 0 {
		c.HTTPRoutes = append(c.HTTPRoutes[:index], c.HTTPRoutes[index+1:]...)
		if err := a.commit(r.Context(), c); err != nil {
			fail(w, 500, err.Error())
			return
		}
		write(w, 200, map[string]bool{"ok": true})
		return
	}
	var item model.HTTPRoute
	if r.Method == "PATCH" && index >= 0 {
		item = c.HTTPRoutes[index]
	} else if r.Method != "POST" || id != "" {
		fail(w, 405, "method not allowed")
		return
	}
	if err := decode(w, r, &item); err != nil {
		fail(w, 400, err.Error())
		return
	}
	item.ID = id
	if id == "" {
		item.ID = randomID()
	}
	item.Status = ""
	item.Error = ""
	if err := validateHTTP(&item); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if len(c.HTTPRoutes) >= 1024 && index < 0 {
		fail(w, 400, "maximum 1024 HTTP routes")
		return
	}
	for _, other := range c.HTTPRoutes {
		if other.ID != item.ID && other.Host == item.Host {
			otherPath, _ := model.NormalizeRoutePath(other.Path)
			if otherPath == item.Path {
				fail(w, 409, "domain and path already configured")
				return
			}
			if other.TLS != item.TLS {
				fail(w, 409, "all paths of a domain must use the same TLS mode")
				return
			}
		}
	}
	if index < 0 {
		c.HTTPRoutes = append(c.HTTPRoutes, item)
	} else {
		c.HTTPRoutes[index] = item
	}
	if err := a.commit(r.Context(), c); err != nil {
		fail(w, 500, err.Error())
		return
	}
	for _, saved := range a.snapshot().HTTPRoutes {
		if saved.ID == item.ID {
			write(w, 200, saved)
			return
		}
	}
}
