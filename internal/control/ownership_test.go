package control

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"niceproxy/internal/caddy"
	"niceproxy/internal/model"
	"niceproxy/internal/proxy"
	"niceproxy/internal/store"
)

func TestOwnershipConflictsDoNotSave(t *testing.T) {
	a, s, c := fixture(t)
	for _, tc := range []struct {
		method, path, body string
		status             int
	}{
		{"POST", "/api/direct-rules", `{"protocol":"tcp","listenPort":443,"targetHost":"127.0.0.1","targetPort":3300,"enabled":true}`, 409},
		{"POST", "/api/direct-rules", `{"protocol":"udp","listenPort":443,"targetHost":"127.0.0.1","targetPort":3300,"enabled":true}`, 409},
		{"PATCH", "/api/port-owners", `{"http":"invalid"}`, 400},
		{"PATCH", "/api/port-owners", `{"http":""}`, 400},
	} {
		resp := call(t, s, tc.method, tc.path, tc.body, c)
		resp.Body.Close()
		if resp.StatusCode != tc.status {
			t.Fatalf("%s: %s", tc.body, resp.Status)
		}
	}
	cfg, _, err := a.db.Load()
	if err != nil || cfg.Revision != 0 {
		t.Fatalf("conflict saved: %+v %v", cfg, err)
	}
	resp := call(t, s, "POST", "/api/http-routes", `{"host":"plain.example.com","tls":"off","target":"http://localhost:3000","enabled":true}`, c)
	resp.Body.Close()
	resp = call(t, s, "PATCH", "/api/port-owners", `{"http":"direct"}`, c)
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 409 || !strings.Contains(string(b), "HTTP route") {
		t.Fatalf("dependency: %s %s", resp.Status, b)
	}
	cfg, _, _ = a.db.Load()
	if cfg.Revision != 1 {
		t.Fatal(cfg.Revision)
	}
}

func TestDirectCanonicalConflictAndRuntimeStatsInput(t *testing.T) {
	a, s, c := fixture(t)
	port := unusedTCPPort(t)
	resp := call(t, s, "POST", "/api/direct-rules", fmt.Sprintf(`{"protocol":"tcp","listenHost":"::ffff:127.0.0.1","listenPort":%d,"targetHost":"127.0.0.1","targetPort":3300,"enabled":true,"stats":{"accepted":999}}`, port), c)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	resp = call(t, s, "POST", "/api/direct-rules", fmt.Sprintf(`{"protocol":"tcp","listenHost":"127.0.0.1","listenPort":%d,"targetHost":"127.0.0.1","targetPort":3300,"enabled":true}`, port), c)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 409 {
		t.Fatal(resp.Status)
	}
	if !strings.Contains(string(body), fmt.Sprintf("Forwarding 127.0.0.1:%d is already enabled on TCP.", port)) {
		t.Fatalf("unexpected conflict message: %s", body)
	}
	cfg, _, _ := a.db.Load()
	if cfg.Revision != 1 || cfg.DirectRules[0].Stats != nil {
		t.Fatalf("runtime input persisted: %+v", cfg)
	}
}

func unusedTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Real OS listeners verify both handover directions, including a desired-disabled
// direct listener left in the applied snapshot, without a second reconcile.
func TestOwnershipRuntimeAndManagementSurvivesBindFailure(t *testing.T) {
	binary := os.Getenv("NICEPROXY_CADDY_TEST_BINARY")
	if binary == "" {
		t.Skip("set NICEPROXY_CADDY_TEST_BINARY for real listener integration")
	}
	dir := t.TempDir()
	hp, sp, pp := unusedTCPPort(t), unusedTCPPort(t), unusedTCPPort(t)
	opts := caddy.Options{Binary: binary, RuntimeDir: filepath.Join(dir, "run"), DataDir: filepath.Join(dir, "data"), BackendSocket: filepath.Join(dir, "backend.sock"), PanelListen: fmt.Sprintf("127.0.0.1:%d", pp), HTTPPort: hp, HTTPSPort: sp}
	cm := caddy.New(opts)
	ctx := context.Background()
	if err := cm.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c, cancel := context.WithTimeout(ctx, 3*time.Second); defer cancel(); _ = cm.Close(c) })
	db, err := store.Open(filepath.Join(dir, "config.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	pm := proxy.NewManager(proxy.Options{})
	t.Cleanup(func() { c, cancel := context.WithTimeout(ctx, time.Second); defer cancel(); _ = pm.Close(c) })
	a, err := New(db, cm, pm, map[int]bool{hp: true, sp: true, pp: true})
	if err != nil {
		t.Fatal(err)
	}
	// Serve the management backend through the actual Caddy panel.
	backend, err := net.Listen("unix", opts.BackendSocket)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: a.Handler(http.NotFoundHandler())}
	go server.Serve(backend)
	t.Cleanup(func() { _ = server.Close() })
	s := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(s.Close)
	s.URL = fmt.Sprintf("http://127.0.0.1:%d", pp)
	resp := call(t, s, "POST", "/api/setup", `{"password":"ownership-test-password"}`, nil)
	cookies := resp.Cookies()
	resp.Body.Close()
	if len(cookies) == 0 {
		t.Fatal(resp.Status)
	}
	cookie := cookies[0]
	resp = call(t, s, "GET", "/api/port-owners", "", cookie)
	var ports struct{ HTTPPort, HTTPSPort int }
	_ = json.NewDecoder(resp.Body).Decode(&ports)
	resp.Body.Close()
	if ports.HTTPPort != hp || ports.HTTPSPort != sp {
		t.Fatalf("actual ports: %+v", ports)
	}
	request := func(method, path, body string) model.Config {
		t.Helper()
		resp := call(t, s, method, path, body, cookie)
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("%s: %s %s", path, resp.Status, b)
		}
		var cfg model.Config
		_ = json.NewDecoder(resp.Body).Decode(&cfg)
		return cfg
	}
	request("PATCH", "/api/port-owners", `{"http":"direct"}`)
	resp = call(t, s, "POST", "/api/direct-rules", fmt.Sprintf(`{"protocol":"tcp","listenHost":"127.0.0.1","listenPort":%d,"targetHost":"127.0.0.1","targetPort":1,"enabled":true}`, hp), cookie)
	var rule model.DirectRule
	_ = json.NewDecoder(resp.Body).Decode(&rule)
	resp.Body.Close()
	if rule.Status != "healthy" {
		t.Fatalf("direct handover: %+v", rule)
	}
	before, _, _ := db.Load()
	resp = call(t, s, "PATCH", "/api/port-owners", `{"http":"caddy"}`, cookie)
	dependency, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	after, _, _ := db.Load()
	if resp.StatusCode != 409 || !strings.Contains(string(dependency), rule.ID) || before.Revision != after.Revision {
		t.Fatalf("direct dependency saved: %s %s revision %d/%d", resp.Status, dependency, before.Revision, after.Revision)
	}
	// Simulate the persisted desired-disabled/applied-enabled state after an interrupted apply.
	a.mu.Lock()
	a.config.DirectRules[0].Enabled = false
	_ = a.db.Save(a.config)
	a.mu.Unlock()
	request("PATCH", "/api/port-owners", `{"http":"caddy"}`)
	resp = call(t, s, "POST", "/api/http-routes", `{"host":"switch.example.com","tls":"off","target":"http://127.0.0.1:1","enabled":true}`, cookie)
	var route model.HTTPRoute
	_ = json.NewDecoder(resp.Body).Decode(&route)
	resp.Body.Close()
	if route.Status != "healthy" {
		t.Fatalf("Caddy handover: %+v", route)
	}
	// Leave Caddy's applied HTTP listener stale while desired already disables it.
	a.mu.Lock()
	a.config.HTTPRoutes[0].Enabled = false
	_ = a.db.Save(a.config)
	a.mu.Unlock()
	request("PATCH", "/api/port-owners", `{"http":"direct"}`)
	request("PATCH", "/api/direct-rules/"+rule.ID, `{"enabled":true}`)
	if a.snapshot().DirectRules[0].Status != "healthy" {
		t.Fatal("stale Caddy listener not released")
	}
	request("PATCH", "/api/direct-rules/"+rule.ID, `{"enabled":false}`)
	busy, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", hp))
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	request("PATCH", "/api/port-owners", `{"http":"caddy"}`)
	request("PATCH", "/api/http-routes/"+route.ID, `{"enabled":true}`)
	resp = call(t, s, "GET", "/api/health", "", cookie)
	var health model.Health
	_ = json.NewDecoder(resp.Body).Decode(&health)
	resp.Body.Close()
	if resp.StatusCode != 200 || !health.Caddy || health.AppliedRevision != -1 || health.Error == "" {
		t.Fatalf("bind failure/panel: %s %+v", resp.Status, health)
	}
	_, applied, _ := db.Load()
	if applied != -1 {
		t.Fatalf("durable applied=%d", applied)
	}
	busy.Close()
	if err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeStatsAndRetirementKeepAcceptedStream(t *testing.T) {
	a, s, c := fixture(t)
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	go func() {
		conn, err := upstream.Accept()
		if err == nil {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}
	}()
	port := unusedTCPPort(t)
	body := fmt.Sprintf(`{"protocol":"tcp","listenHost":"127.0.0.1","listenPort":%d,"targetHost":"127.0.0.1","targetPort":%d,"enabled":true}`, port, upstream.Addr().(*net.TCPAddr).Port)
	resp := call(t, s, "POST", "/api/direct-rules", body, c)
	var rule model.DirectRule
	_ = json.NewDecoder(resp.Body).Decode(&rule)
	resp.Body.Close()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	echo := func() {
		t.Helper()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write([]byte("echo")); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil || string(b) != "echo" {
			t.Fatalf("stream continuity: %q %v", b, err)
		}
	}
	echo()
	resp = call(t, s, "PATCH", "/api/direct-rules/"+rule.ID, `{"enabled":false,"stats":{"accepted":999}}`, c)
	var disabled model.DirectRule
	_ = json.NewDecoder(resp.Body).Decode(&disabled)
	resp.Body.Close()
	if resp.StatusCode != 200 || disabled.Stats == nil || disabled.Stats.Accepted != 1 || disabled.Stats.Active != 1 {
		t.Fatalf("runtime stats: %s %+v", resp.Status, disabled.Stats)
	}
	if _, err := time.Parse(time.RFC3339Nano, disabled.Stats.StartedAt); err != nil {
		t.Fatal(err)
	}
	echo()
	// A new process can bind while the original accepted connection still works.
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	echo()
	saved, _, _ := a.db.Load()
	if saved.DirectRules[0].Stats != nil {
		t.Fatal("runtime counters saved")
	}
}

func TestDeletedDirectRuleReleasesRuntimeStats(t *testing.T) {
	a, s, cookie := fixture(t)
	port := unusedTCPPort(t)
	resp := call(t, s, "POST", "/api/direct-rules", fmt.Sprintf(`{"protocol":"tcp","listenHost":"127.0.0.1","listenPort":%d,"targetHost":"127.0.0.1","targetPort":9,"enabled":true}`, port), cookie)
	var rule model.DirectRule
	err := json.NewDecoder(resp.Body).Decode(&rule)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || rule.Stats == nil {
		t.Fatalf("create: %s %+v %v", resp.Status, rule, err)
	}
	resp = call(t, s, "DELETE", "/api/direct-rules/"+rule.ID, "", cookie)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	deadline := time.Now().Add(time.Second)
	for {
		if _, exists := a.proxy.Stats(rule.ID); !exists {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("deleted rule statistics were retained after its streams finished")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAutoSetupDirectPortOwners(t *testing.T) {
	for _, tc := range []struct {
		name, protocol string
		port           int
		want           model.PortOwners
	}{
		{"HTTP", "tcp", 80, model.PortOwners{HTTP: "direct"}},
		{"HTTPS TCP", "tcp", 443, model.PortOwners{HTTPS: "direct"}},
		{"HTTPS UDP", "udp", 443, model.PortOwners{HTTP3: "direct"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, s, cookie := fixture(t)
			a.mu.Lock()
			a.httpPort, a.httpsPort = unusedTCPPort(t), unusedTCPPort(t)
			if tc.name == "HTTP" {
				tc.port = a.httpPort
			} else {
				tc.port = a.httpsPort
			}
			a.reserved = map[int]bool{9080: true}
			a.mu.Unlock()
			resp := call(t, s, "POST", "/api/direct-rules", fmt.Sprintf(`{"protocol":%q,"listenHost":"127.0.0.1","listenPort":%d,"targetHost":"127.0.0.1","targetPort":3300,"enabled":true,"autoSetup":true}`, tc.protocol, tc.port), cookie)
			var saved model.DirectRule
			err := json.NewDecoder(resp.Body).Decode(&saved)
			resp.Body.Close()
			if resp.StatusCode != 200 || err != nil || saved.ID == "" || !saved.AutoSetup {
				t.Fatalf("create: %s %+v %v", resp.Status, saved, err)
			}
			cfg, _, err := a.db.Load()
			if err != nil || cfg.PortOwners != tc.want.Defaults() || !cfg.DirectRules[0].AutoSetup {
				t.Fatalf("saved config: %+v %v", cfg, err)
			}

			path := "/api/direct-rules/" + saved.ID
			for _, step := range []struct {
				method, body string
				want         model.PortOwners
			}{
				{"PATCH", `{"enabled":false}`, model.PortOwners{}},
				{"PATCH", `{"enabled":true}`, tc.want},
				{"DELETE", "", model.PortOwners{}},
			} {
				resp = call(t, s, step.method, path, step.body, cookie)
				resp.Body.Close()
				cfg, _, err = a.db.Load()
				if resp.StatusCode != 200 || err != nil || cfg.PortOwners != step.want.Defaults() {
					t.Fatalf("%s %s: %s owners=%+v %v", step.method, step.body, resp.Status, cfg.PortOwners, err)
				}
			}
		})
	}
}

func TestAutoSetupHTTPRouteOwnershipConflict(t *testing.T) {
	a, s, cookie := fixture(t)
	a.mu.Lock()
	a.httpPort = unusedTCPPort(t)
	a.reserved = map[int]bool{9080: true}
	httpPort := a.httpPort
	a.mu.Unlock()
	request := func(method, path, body string, status int) []byte {
		t.Helper()
		resp := call(t, s, method, path, body, cookie)
		defer resp.Body.Close()
		result, err := io.ReadAll(resp.Body)
		if resp.StatusCode != status || err != nil {
			t.Fatalf("%s %s: %s %s %v", method, path, resp.Status, result, err)
		}
		return result
	}
	request("PATCH", "/api/port-owners", `{"http":"direct"}`, 200)
	raw := request("POST", "/api/http-routes", `{"host":"plain.example.com","tls":"off","target":"http://localhost:3000","enabled":true,"autoSetup":true}`, 200)
	var route model.HTTPRoute
	if err := json.Unmarshal(raw, &route); err != nil || route.ID == "" || !route.AutoSetup {
		t.Fatalf("create route: %s %v", raw, err)
	}
	cfg, _, err := a.db.Load()
	if err != nil || cfg.PortOwners.HTTP != "caddy" || !cfg.HTTPRoutes[0].AutoSetup {
		t.Fatalf("saved route: %+v %v", cfg, err)
	}
	direct := fmt.Sprintf(`{"protocol":"tcp","listenHost":"127.0.0.1","listenPort":%d,"targetHost":"127.0.0.1","targetPort":3300,"enabled":true,"autoSetup":true}`, httpPort)
	result := request("POST", "/api/direct-rules", direct, 409)
	if !strings.Contains(string(result), "HTTP route") {
		t.Fatalf("expected HTTP route conflict: %s", result)
	}
	cfg, _, err = a.db.Load()
	if err != nil || cfg.Revision != 2 || cfg.PortOwners.HTTP != "caddy" || len(cfg.DirectRules) != 0 {
		t.Fatalf("conflicting mutation saved: %+v %v", cfg, err)
	}
	request("PATCH", "/api/http-routes/"+route.ID, `{"enabled":false}`, 200)
	request("POST", "/api/direct-rules", direct, 200)
}
