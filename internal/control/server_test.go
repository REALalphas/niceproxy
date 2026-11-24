package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"niceproxy/internal/model"
	"niceproxy/internal/proxy"
	"niceproxy/internal/store"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeCaddy struct{ err error }

func (f *fakeCaddy) Apply(context.Context, []model.HTTPRoute) error { return f.err }
func (f *fakeCaddy) Healthy(context.Context) bool                   { return f.err == nil }

func fixture(t *testing.T) (*App, *httptest.Server, *http.Cookie) {
	t.Helper()
	db, err := store.Open(filepath.Join(t.TempDir(), "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pm := proxy.NewManager(proxy.Options{})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = pm.Close(ctx)
	})
	app, err := New(db, &fakeCaddy{}, pm, map[int]bool{80: true, 443: true, 9080: true})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(app.Handler(http.NotFoundHandler()))
	t.Cleanup(srv.Close)
	resp := call(t, srv, "POST", "/api/setup", `{"password":"a-test-password-123"}`, nil)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("setup: %s", resp.Status)
	}
	return app, srv, resp.Cookies()[0]
}
func call(t *testing.T, s *httptest.Server, method, path, body string, cookie *http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(method, s.URL+path, bytes.NewBufferString(body))
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if cookie != nil {
		req.AddCookie(cookie)
	}
	r, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func TestAuthAndCSRF(t *testing.T) {
	_, s, c := fixture(t)
	resp := call(t, s, "GET", "/api/config", "", nil)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal(resp.Status)
	}
	req, _ := http.NewRequest("POST", s.URL+"/api/logout", nil)
	req.AddCookie(c)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal(resp.Status)
	}
	resp = call(t, s, "POST", "/api/setup", `{"password":"second-password-123"}`, nil)
	resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Fatal(resp.Status)
	}
	resp = call(t, s, "POST", "/api/logout", "", c)
	resp.Body.Close()
	resp = call(t, s, "GET", "/api/config", "", c)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal(resp.Status)
	}
	rebind, _ := http.NewRequest("GET", s.URL+"/api/auth", nil)
	rebind.Host = "attacker.example"
	resp, err = s.Client().Do(rebind)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal(resp.Status)
	}
}
func TestDirectApplyConflictAndPersistence(t *testing.T) {
	a, s, c := fixture(t)
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	port := busy.Addr().(*net.TCPAddr).Port
	body, _ := json.Marshal(model.DirectRule{Protocol: "tcp", ListenHost: "127.0.0.1", ListenPort: port, TargetHost: "127.0.0.1", TargetPort: 3300, Enabled: true})
	resp := call(t, s, "POST", "/api/direct-rules", string(body), c)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s", resp.Status, b)
	}
	var rule model.DirectRule
	if err := json.NewDecoder(resp.Body).Decode(&rule); err != nil {
		t.Fatal(err)
	}
	if rule.Status != "error" || rule.Error == "" {
		t.Fatalf("bind failure hidden: %+v", rule)
	}
	cfg, applied, err := a.db.Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Revision != 1 || applied == 1 || len(cfg.DirectRules) != 1 || cfg.DirectRules[0].TargetPort != 3300 {
		t.Fatalf("desired/applied: %+v %d", cfg, applied)
	}
	busy.Close()
	if err := a.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if a.snapshot().DirectRules[0].Status != "healthy" {
		t.Fatal("rule not recovered")
	}
	resp = call(t, s, "PATCH", "/api/direct-rules/"+rule.ID, `{"enabled":false}`, c)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	if len(a.active) != 0 {
		t.Fatal("disabled listener remains active")
	}
}
func TestCaddyFailureDoesNotClaimApplied(t *testing.T) {
	a, s, c := fixture(t)
	a.caddy.(*fakeCaddy).err = errors.New("load failed")
	resp := call(t, s, "POST", "/api/http-routes", `{"host":"app.example.com","target":"http://127.0.0.1:3300","tls":"auto","enabled":true}`, c)
	defer resp.Body.Close()
	var route model.HTTPRoute
	_ = json.NewDecoder(resp.Body).Decode(&route)
	if route.Status != "error" || route.Error == "" || a.applied != -1 {
		t.Fatalf("failure hidden: %+v", route)
	}
}
func TestRejectInvalidAndReservedRules(t *testing.T) {
	_, s, c := fixture(t)
	for _, body := range []string{
		`{"protocol":"tcp","listenPort":1234,"targetHost":"http://bad","targetPort":3300}`,
		`{"protocol":"tcp","listenPort":1234,"targetHost":"127.0.0.1","targetPort":0}`,
	} {
		resp := call(t, s, "POST", "/api/direct-rules", body, c)
		resp.Body.Close()
		if resp.StatusCode != 400 {
			t.Fatal(resp.Status)
		}
	}
	resp := call(t, s, "POST", "/api/http-routes", `{"host":"evil\n:2019","target":"http://127.0.0.1:3000","enabled":true}`, c)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal(resp.Status)
	}
}

func TestPanelDomainReservationNamesConflictAndRecovery(t *testing.T) {
	a, s, c := fixture(t)
	resp := call(t, s, "POST", "/api/http-routes", `{"host":"panel.example.com","target":"http://127.0.0.1:3000","tls":"off","enabled":true}`, c)
	var route model.HTTPRoute
	_ = json.NewDecoder(resp.Body).Decode(&route)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	resp = call(t, s, "PATCH", "/api/panel-domain", `{"domain":"panel.example.com"}`, c)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 409 || !strings.Contains(string(body), "panel.example.com") || !strings.Contains(string(body), route.ID) {
		t.Fatalf("conflict lacks recovery details: %s %s", resp.Status, body)
	}
	if cfg, _, _ := a.db.Load(); cfg.PanelDomain != "" {
		t.Fatal("conflicting domain persisted")
	}
	resp = call(t, s, "PATCH", "/api/panel-domain", `{"domain":"admin.example.com"}`, c)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	resp = call(t, s, "POST", "/api/http-routes", `{"host":"ADMIN.EXAMPLE.COM","target":"http://127.0.0.1:3001","tls":"off","enabled":false}`, c)
	resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Fatal("disabled conflicting route was accepted")
	}
}

func TestLoginLimitIsPerClientAndSetupCannotLockOut(t *testing.T) {
	a, _, _ := fixture(t)
	request := func(path, ip, password string) int {
		r := httptest.NewRequest("POST", path, bytes.NewBufferString(`{"password":"`+password+`"}`))
		r.RemoteAddr = ip + ":1234"
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		a.login(w, r)
		return w.Code
	}
	for i := 0; i < 12; i++ {
		if status := request("/api/setup", "192.0.2.1", "irrelevant"); status != 409 {
			t.Fatal(status)
		}
	}
	for i := 0; i < 10; i++ {
		if status := request("/api/login", "192.0.2.1", "wrong-password"); status != 401 {
			t.Fatal(status)
		}
	}
	if status := request("/api/login", "192.0.2.1", "wrong-password"); status != 429 {
		t.Fatal(status)
	}
	if status := request("/api/login", "192.0.2.2", "a-test-password-123"); status != 200 {
		t.Fatal(status)
	}
}

func TestHTTPPathsCRUDAndCompatibility(t *testing.T) {
	a, s, c := fixture(t)
	create := func(body string, status int) model.HTTPRoute {
		t.Helper()
		resp := call(t, s, "POST", "/api/http-routes", body, c)
		defer resp.Body.Close()
		if resp.StatusCode != status {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("HTTP %d want %d: %s", resp.StatusCode, status, b)
		}
		var item model.HTTPRoute
		if status == 200 {
			if err := json.NewDecoder(resp.Body).Decode(&item); err != nil {
				t.Fatal(err)
			}
		}
		return item
	}
	root := create(`{"host":"app.example.com","target":"http://127.0.0.1:3000","tls":"off","enabled":true}`, 200)
	if root.Path != "/" || root.StripPrefix {
		t.Fatal(root)
	}
	api := create(`{"host":"app.example.com","path":"/api/","target":"http://127.0.0.1:3300","tls":"off","enabled":true}`, 200)
	if api.Path != "/api" {
		t.Fatal(api)
	}
	create(`{"host":"app.example.com","path":"/api","target":"http://127.0.0.1:4400","tls":"off","enabled":true}`, 409)
	create(`{"host":"app.example.com","path":"/private","target":"http://127.0.0.1:4400","tls":"internal","enabled":true}`, 409)
	create(`{"host":"app.example.com","path":"/a/*","target":"http://127.0.0.1:4400","tls":"off","enabled":true}`, 400)
	resp := call(t, s, "PATCH", "/api/http-routes/"+api.ID, `{"path":"/service","stripPrefix":true}`, c)
	var patched model.HTTPRoute
	_ = json.NewDecoder(resp.Body).Decode(&patched)
	resp.Body.Close()
	if resp.StatusCode != 200 || patched.Path != "/service" || !patched.StripPrefix {
		t.Fatal(patched, resp.StatusCode)
	}
	saved, _, err := a.db.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.HTTPRoutes) != 2 || saved.HTTPRoutes[1].Path != "/service" || !saved.HTTPRoutes[1].StripPrefix {
		t.Fatal(saved)
	}
	resp = call(t, s, "PATCH", "/api/http-routes/"+root.ID, `{"path":"/"}`, c)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
}
