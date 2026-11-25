package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"niceproxy/internal/model"
)

func TestInvalidRequestsDoNotAdvanceRevision(t *testing.T) {
	app, _, cookie := fixture(t)
	handler := app.Handler(http.NotFoundHandler())
	before, applied, err := app.db.Load()
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name, method, path, contentType, body, want string
		status                                      int
	}{
		{"wrong content type", "POST", "/api/http-routes", "text/plain", "{}", "Content-Type", 400},
		{"unknown JSON field", "POST", "/api/http-routes", "application/json", `{"unknown":true}`, "unknown field", 400},
		{"trailing JSON value", "POST", "/api/http-routes", "application/json", "{} []", "one JSON object", 400},
		{"body size limit", "POST", "/api/http-routes", "application/json", `{"host":"` + strings.Repeat("x", 16384) + `"}`, "request body too large", 400},
		{"unknown route", "PATCH", "/api/http-routes/missing", "application/json", "{}", "route not found", 404},
		{"nested rule path", "DELETE", "/api/direct-rules/missing/nested", "", "", "rule not found", 404},
		{"wrong owner method", "PUT", "/api/port-owners", "application/json", "{}", "method not allowed", 405},
		{"invalid owner", "PATCH", "/api/port-owners", "application/json", `{"https":""}`, "port owner", 400},
		{"invalid domain", "PUT", "/api/panel-domain", "application/json", `{"panelDomain":"127.0.0.1"}`, "DNS hostname", 400},
		{"unknown endpoint", "GET", "/api/missing", "", "", "endpoint not found", 404},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "http://localhost"+tt.path, strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)
			req.AddCookie(cookie)
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			var problem struct{ Error string }
			if err := json.Unmarshal(resp.Body.Bytes(), &problem); err != nil {
				t.Fatal(err)
			}
			if resp.Code != tt.status || !strings.Contains(problem.Error, tt.want) {
				t.Fatalf("response = %d %s, want %d containing %q", resp.Code, resp.Body, tt.status, tt.want)
			}
			if got := resp.Header().Get("Cache-Control"); got != "no-store" {
				t.Fatalf("Cache-Control = %q", got)
			}
			cfg, gotApplied, err := app.db.Load()
			if err != nil || cfg.Revision != before.Revision || gotApplied != applied {
				t.Fatalf("invalid request changed durable revision: desired=%d applied=%d err=%v", cfg.Revision, gotApplied, err)
			}
		})
	}
}

func TestLoginCookieAndServerSideSession(t *testing.T) {
	app, _, setupCookie := fixture(t)
	handler := app.Handler(http.NotFoundHandler())
	for _, tt := range []struct {
		name, scheme, forwarded string
		secure                  bool
	}{
		{"local HTTP", "http", "", false},
		{"TLS connection", "https", "", true},
		{"TLS terminated by Caddy", "http", "https", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", tt.scheme+"://localhost/api/login", strings.NewReader(`{"password":"a-test-password-123"}`))
			req.RemoteAddr = "@"
			req.Header.Set("Content-Type", "application/json; charset=utf-8")
			req.Header.Set("Origin", tt.scheme+"://localhost")
			req.Header.Set("X-Forwarded-Proto", tt.forwarded)
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			cookies := resp.Result().Cookies()
			if resp.Code != 200 || len(cookies) != 1 {
				t.Fatalf("login = %d, %s", resp.Code, resp.Body)
			}
			cookie := cookies[0]
			if cookie.Name != "niceproxy_session" || !cookie.HttpOnly || cookie.Secure != tt.secure ||
				cookie.Path != "/" || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 43200 ||
				cookie.Value == "" || cookie.Value == setupCookie.Value {
				t.Fatalf("invalid session cookie attributes: %s", cookie)
			}
			if !app.db.Authenticated(hash(cookie.Value)) || app.db.Authenticated(cookie.Value) {
				t.Fatal("session must be stored under its digest")
			}
		})
	}
}

func TestConcurrentConfigurationMutationsAreSerialized(t *testing.T) {
	app, _, cookie := fixture(t)
	handler := app.Handler(http.NotFoundHandler())
	before, _, err := app.db.Load()
	if err != nil {
		t.Fatal(err)
	}

	const routes = 12
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range routes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			body := fmt.Sprintf(`{"id":"client-supplied","host":"service-%d.test","target":"http://127.0.0.1:8080","tls":"off","enabled":false}`, i)
			req := httptest.NewRequest("POST", "http://localhost/api/http-routes", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(cookie)
			resp := httptest.NewRecorder()
			handler.ServeHTTP(resp, req)
			if resp.Code != 200 {
				t.Errorf("route %d: %d %s", i, resp.Code, resp.Body)
			}
		}()
	}
	close(start)
	wg.Wait()

	desired, applied, err := app.db.Load()
	if err != nil {
		t.Fatal(err)
	}
	lastGood, err := app.db.LastGood()
	if err != nil {
		t.Fatal(err)
	}
	if want := before.Revision + routes; desired.Revision != want || applied != want || lastGood.Revision != want {
		t.Fatalf("revisions = desired %d, applied %d, last-good %d, want %d", desired.Revision, applied, lastGood.Revision, want)
	}
	for _, cfg := range []model.Config{desired, lastGood} {
		if len(cfg.HTTPRoutes) != routes {
			t.Fatalf("revision %d has %d routes, want %d", cfg.Revision, len(cfg.HTTPRoutes), routes)
		}
		hosts, ids := map[string]bool{}, map[string]bool{}
		for _, route := range cfg.HTTPRoutes {
			if route.ID == "" || route.ID == "client-supplied" || ids[route.ID] || hosts[route.Host] {
				t.Fatalf("incorrect persisted route identity: %+v", route)
			}
			hosts[route.Host], ids[route.ID] = true, true
		}
		for i := range routes {
			if !hosts[fmt.Sprintf("service-%d.test", i)] {
				t.Fatalf("concurrent write for route %d disappeared", i)
			}
		}
	}
}

type responsiveCaddy struct{ fakeCaddy }

func (*responsiveCaddy) Healthy(context.Context) bool { return true }

func TestHealthReadinessTracksFailedApplyAndRecovery(t *testing.T) {
	app, _, cookie := fixture(t)
	caddy := &responsiveCaddy{}
	app.caddy = caddy
	handler := app.Handler(http.NotFoundHandler())
	request := func(method, path, body string, authenticated bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
		if body != "" {
			req.Header.Set("Content-Type", "application/json")
		}
		if authenticated {
			req.AddCookie(cookie)
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		return resp
	}
	check := func(status int, state string, revision, applied int64) {
		t.Helper()
		probe := request("GET", "/healthz", "", false)
		if probe.Code != status {
			t.Fatalf("readiness = %d, want %d", probe.Code, status)
		}
		response := request("GET", "/api/health", "", true)
		var health model.Health
		if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil {
			t.Fatal(err)
		}
		if response.Code != 200 || !health.Caddy || health.State != state || health.Revision != revision || health.AppliedRevision != applied {
			t.Fatalf("health = %+v (HTTP %d)", health, response.Code)
		}
		if status == 503 && (health.Status != "error" || health.Error == "") {
			t.Fatalf("failed apply was hidden: %+v", health)
		}
		if status == 200 && (health.Status != "healthy" || !health.Caddy || health.Error != "") {
			t.Fatalf("recovered apply was not healthy: %+v", health)
		}
	}
	check(200, "ready", 0, 0)

	caddy.err = fmt.Errorf("certificate temporarily unavailable")
	updated := request("POST", "/api/http-routes", `{"host":"service.test","target":"http://127.0.0.1:8080","tls":"off","enabled":true}`, true)
	if updated.Code != 200 {
		t.Fatalf("could not save desired config: %d %s", updated.Code, updated.Body)
	}
	check(503, "waiting_acme", 1, -1)

	caddy.err = nil
	reconciled := request("POST", "/api/reconcile", "", true)
	if reconciled.Code != 200 {
		t.Fatalf("reconcile: %d %s", reconciled.Code, reconciled.Body)
	}
	check(200, "ready", 1, 1)
}
