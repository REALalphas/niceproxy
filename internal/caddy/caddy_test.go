package caddy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"niceproxy/internal/model"
)

// The test executable doubles as a controlled subprocess, without shell scripts.
func TestMain(m *testing.M) {
	if os.Getenv("NICEPROXY_FAKE_CADDY") == "1" && len(os.Args) == 4 && os.Args[1] == "run" {
		fakeCaddy(os.Args[3])
		return
	}
	os.Exit(m.Run())
}

func fakeCaddy(configPath string) {
	mode := os.Getenv("NICEPROXY_FAKE_MODE")
	if mode == "exit" {
		os.Exit(17)
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		os.Exit(18)
	}
	var parsed struct{ Admin struct{ Listen string } }
	if json.Unmarshal(config, &parsed) != nil {
		os.Exit(19)
	}
	l, err := net.Listen("unix", strings.TrimPrefix(parsed.Admin.Listen, "unix/"))
	if err != nil {
		os.Exit(20)
	}
	if mode == "ignore" {
		signal.Ignore(syscall.SIGTERM)
	}
	if mode == "not-ready" {
		for {
			time.Sleep(time.Hour)
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/config/", func(w http.ResponseWriter, r *http.Request) {
		if mode == "die" {
			go func() { time.Sleep(150 * time.Millisecond); os.Exit(21) }()
		}
		_, _ = w.Write(config)
	})
	mux.HandleFunc("/load", func(w http.ResponseWriter, r *http.Request) {
		if mode == "reject" {
			http.Error(w, "sensitive config must not appear in errors", 400)
			return
		}
		config, _ = io.ReadAll(r.Body)
		w.WriteHeader(200)
	})
	_ = http.Serve(l, mux)
}

func options(t *testing.T) Options {
	t.Helper()
	dir := t.TempDir()
	return Options{RuntimeDir: filepath.Join(dir, "run"), DataDir: filepath.Join(dir, "data"), BackendSocket: filepath.Join(dir, "backend.sock")}
}

func TestBuildConfig(t *testing.T) {
	o := options(t)
	b, err := BuildConfig(o, []model.HTTPRoute{
		{Host: "auto.example.com", Target: "https://backend.example.com:8443", TLS: "auto", Enabled: true},
		{Host: "internal.example.com", Target: "http://[::1]:8080", TLS: "internal", Enabled: true},
		{Host: "plain.example.com", Target: "http://localhost", TLS: "off", Enabled: true},
		{Host: "disabled.example.com", Target: "http://localhost", Enabled: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	admin := c["admin"].(map[string]any)
	if admin["listen"] != "unix/"+filepath.Join(o.RuntimeDir, "caddy.sock") {
		t.Fatal(admin)
	}
	apps := c["apps"].(map[string]any)
	servers := apps["http"].(map[string]any)["servers"].(map[string]any)
	panel := servers["panel"].(map[string]any)
	if !reflect.DeepEqual(panel["listen"], []any{"127.0.0.1:9080"}) {
		t.Fatal(panel)
	}
	https := servers["public_https"].(map[string]any)
	if _, ok := https["tls_connection_policies"]; !ok {
		t.Fatal("HTTPS has no TLS listener policy")
	}
	for _, name := range []string{"public_http", "public_https"} {
		for _, raw := range servers[name].(map[string]any)["routes"].([]any) {
			if _, ok := raw.(map[string]any)["match"]; !ok {
				h := raw.(map[string]any)["handle"].([]any)
				if len(h) != 1 || h[0].(map[string]any)["handler"] != "static_response" || h[0].(map[string]any)["status_code"] != float64(404) {
					t.Fatal("public catch-all is not a 404 response")
				}
			}
		}
	}
	text := string(b)
	for _, s := range []string{`"module":"acme"`, `"module":"internal"`, `"tls":{"server_name":"backend.example.com"}`, `"dial":"[::1]:8080"`, `https://auto.example.com{http.request.uri}`} {
		if !strings.Contains(text, s) {
			t.Fatalf("missing %s", s)
		}
	}
	if strings.Contains(text, "disabled.example.com") || strings.Contains(text, "insecure_skip_verify") {
		t.Fatal(text)
	}
}

func TestBuildConfigReservesPanelDomain(t *testing.T) {
	o := options(t)
	o.PanelDomain = "Panel.Example.com."
	if _, err := BuildConfig(o, []model.HTTPRoute{{ID: "route-1", Host: "panel.example.com", Target: "http://localhost", TLS: "off", Enabled: true}}); err == nil || !strings.Contains(err.Error(), "panel domain") {
		t.Fatalf("panel domain conflict was not rejected: %v", err)
	}
	b, err := BuildConfig(o, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "panel.example.com") {
		t.Fatal("panel SNI route missing")
	}
	if !strings.Contains(string(b), `"module":"internal"`) {
		t.Fatal("panel TLS bootstrap fallback missing")
	}
}

func TestPanelRedirectDoesNotExposeInternalHTTPSPort(t *testing.T) {
	o := options(t)
	o.PanelDomain = "panel.example.com"
	o.HTTPSPort = 18443
	b, err := BuildConfig(o, nil)
	if err != nil {
		t.Fatal(err)
	}
	text := string(b)
	if strings.Contains(text, "https://panel.example.com:18443") {
		t.Fatalf("internal HTTPS port leaked into public redirect: %s", text)
	}
	if !strings.Contains(text, "https://panel.example.com{http.request.uri}") {
		t.Fatalf("public redirects missing: %s", text)
	}
}

func TestPanelBootstrapOnRealOrigin(t *testing.T) {
	binary := os.Getenv("NICEPROXY_CADDY_TEST_BINARY")
	if binary == "" {
		t.Skip("set NICEPROXY_CADDY_TEST_BINARY for integration")
	}
	o := options(t)
	o.Binary = binary
	o.HTTPPort, o.HTTPSPort = freePort(t), freePort(t)
	o.PanelListen = net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))
	o.PanelDomain = "localhost"
	o.PanelDomainProxied = true
	m := New(o)
	defer m.Close(context.Background())
	if err := m.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:"+strconv.Itoa(o.HTTPPort)+"/status?check=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = o.PanelDomain
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusPermanentRedirect || res.Header.Get("Location") != "https://localhost/status?check=1" {
		t.Fatalf("HTTP redirect: %d %s", res.StatusCode, res.Header.Get("Location"))
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(res.Body)
	res.Body.Close()
	if readErr != nil || res.StatusCode != http.StatusServiceUnavailable || res.Header.Get("Location") != "" || !strings.Contains(string(body), "Full (strict)") {
		t.Fatalf("HTTPS forwarded over HTTP: %d %q (%v)", res.StatusCode, body, readErr)
	}
	var status model.CertificateStatus
	for ctx.Err() == nil {
		status = m.CertificateStatus(ctx, o.PanelDomain)
		if status.TLSState == "bootstrap" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status.State != "pending" || status.TLSState != "bootstrap" || status.ExpiresAt == nil {
		t.Fatalf("live SNI certificate status: %+v", status)
	}
}

func TestPanelLoadsMountedCertificate(t *testing.T) {
	binary := os.Getenv("NICEPROXY_CADDY_TEST_BINARY")
	if binary == "" {
		t.Skip("set NICEPROXY_CADDY_TEST_BINARY for integration")
	}
	o := options(t)
	o.Binary = binary
	o.PanelDomain, o.PanelDomainProxied = "panel.example.test", true
	o.HTTPPort, o.HTTPSPort = freePort(t), freePort(t)
	o.PanelListen = net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))
	o.PanelCertFile = filepath.Join(t.TempDir(), "certificate.pem")
	o.PanelKeyFile = filepath.Join(filepath.Dir(o.PanelCertFile), "key.pem")
	now := time.Now()
	cert, key := testCertificatePair(t, []string{o.PanelDomain}, now.Add(-time.Hour), now.Add(time.Hour))
	if err := os.WriteFile(o.PanelCertFile, cert, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(o.PanelKeyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	wrongHost := o
	wrongHost.PanelDomain = "other.example.test"
	otherRoute := model.HTTPRoute{Host: "route.example.test", Target: "http://localhost:9000", TLS: "off", Enabled: true}
	fallback, err := BuildConfig(wrongHost, []model.HTTPRoute{otherRoute})
	if err != nil || strings.Contains(string(fallback), `"load_files"`) || !strings.Contains(string(fallback), otherRoute.Host) {
		t.Fatalf("wrong-host certificate must be ignored without disabling other routes: %v %s", err, fallback)
	}
	m := New(o)
	defer m.Close(context.Background())
	if err := m.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("test certificate cannot be used as a trust anchor")
	}
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(o.HTTPSPort))
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", addr, &tls.Config{ServerName: o.PanelDomain, RootCAs: roots, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatalf("Caddy did not serve the mounted certificate for panel SNI: %v", err)
	}
	conn.Close()
}

func TestPathPriorityAndDomainPolicy(t *testing.T) {
	o := options(t)
	routes := []model.HTTPRoute{
		{Host: "app.example.com", Path: "/", Target: "http://127.0.0.1:3000", TLS: "internal", Enabled: true},
		{Host: "app.example.com", Path: "/api", Target: "http://127.0.0.1:3300", TLS: "internal", Enabled: true},
		{Host: "app.example.com", Path: "/api/admin", StripPrefix: true, Target: "http://127.0.0.1:4400", TLS: "internal", Enabled: true},
	}
	b, err := BuildConfig(o, routes)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(b, &cfg)
	apps := cfg["apps"].(map[string]any)
	public := apps["http"].(map[string]any)["servers"].(map[string]any)["public_https"].(map[string]any)["routes"].([]any)
	first := public[0].(map[string]any)
	paths := first["match"].([]any)[0].(map[string]any)["path_regexp"].(map[string]any)["pattern"]
	if paths != "^/api/admin(/.*)?$" {
		t.Fatal(paths)
	}
	if first["handle"].([]any)[0].(map[string]any)["strip_path_prefix"] != "/api/admin" {
		t.Fatal(first)
	}
	policies := apps["tls"].(map[string]any)["automation"].(map[string]any)["policies"].([]any)
	if len(policies) != 1 {
		t.Fatal("duplicate certificate policies", len(policies))
	}
	if routes[0].Path != "/" {
		t.Fatal("input order mutated")
	}
	routes[1].TLS = "off"
	if _, err = BuildConfig(o, routes); err == nil {
		t.Fatal("accepted conflicting TLS modes")
	}
	routes[1].TLS = "internal"
	routes[1].Path = "/api/admin/"
	if _, err = BuildConfig(o, routes); err == nil {
		t.Fatal("accepted duplicate canonical path")
	}
}

func TestBuildConfigRejectsUnsafeInputs(t *testing.T) {
	base := model.HTTPRoute{Host: "example.com", Target: "http://localhost", TLS: "auto", Enabled: true}
	for _, host := range []string{"", "*.example.com", "localhost:443", "a/b", "a{env.SECRET}", "127.0.0.1", "x\nexample.com", "-bad.com", "a..com"} {
		t.Run("host="+host, func(t *testing.T) {
			r := base
			r.Host = host
			if _, e := BuildConfig(options(t), []model.HTTPRoute{r}); e == nil {
				t.Fatal("accepted invalid host")
			}
		})
	}
	for _, target := range []string{"unix//tmp/a", "ftp://localhost", "http://user:secret@localhost", "http://localhost/path", "http://localhost?", "http://localhost?x=1", "http://localhost/#frag", "http://{env.SECRET}", "http://localhost:0", "http://localhost:65536", "http://localhost:", "http://localhost\r\nHost:evil"} {
		t.Run("target="+target, func(t *testing.T) {
			r := base
			r.Target = target
			if _, e := BuildConfig(options(t), []model.HTTPRoute{r}); e == nil {
				t.Fatal("accepted invalid target")
			}
		})
	}
	r := base
	r.TLS = `{"admin":{"listen":":2019"}}`
	if _, e := BuildConfig(options(t), []model.HTTPRoute{r}); e == nil {
		t.Fatal("accepted injected TLS")
	}
	if _, e := BuildConfig(options(t), []model.HTTPRoute{base, base}); e == nil {
		t.Fatal("accepted duplicate host")
	}
	o := options(t)
	o.PanelListen = "0.0.0.0:80"
	if _, e := BuildConfig(o, nil); e == nil {
		t.Fatal("accepted panel/public collision")
	}
}

func fakeManager(t *testing.T, mode string) (*Manager, Options) {
	t.Helper()
	t.Setenv("NICEPROXY_FAKE_CADDY", "1")
	t.Setenv("NICEPROXY_FAKE_MODE", mode)
	o := options(t)
	var err error
	o.Binary, err = os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m := New(o)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = m.Close(ctx)
	})
	return m, o
}

func TestManagerLifecycle(t *testing.T) {
	m, o := fakeManager(t, "")
	if m.Healthy(context.Background()) {
		t.Fatal("healthy before start")
	}
	if err := m.Apply(context.Background(), nil); err == nil {
		t.Fatal("apply before start")
	}
	if err := m.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if !m.Healthy(context.Background()) {
		t.Fatal("unhealthy")
	}
	st, err := os.Stat(o.RuntimeDir)
	if err != nil || st.Mode().Perm() != 0700 {
		t.Fatalf("runtime permissions %v %v", st, err)
	}
	routes := []model.HTTPRoute{{Host: "example.com", Target: "http://localhost", TLS: "off", Enabled: true}}
	if err := m.Apply(context.Background(), routes); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(o.RuntimeDir, "caddy.json"))
	if err != nil {
		t.Fatal(err)
	}
	want, _ := BuildConfig(o, routes)
	if !reflect.DeepEqual(got, want) {
		t.Fatal("last-good differs")
	}
	if err := m.Start(context.Background(), nil); err == nil {
		t.Fatal("double start")
	}
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Healthy(context.Background()) {
		t.Fatal("healthy after close")
	}
	if err, ok := <-m.Done(); ok {
		t.Fatalf("intentional close reported unexpected exit: %v", err)
	}
}

func TestRejectedLoadPreservesLastGood(t *testing.T) {
	m, o := fakeManager(t, "reject")
	if err := m.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(filepath.Join(o.RuntimeDir, "caddy.json"))
	err := m.Apply(context.Background(), []model.HTTPRoute{{Host: "example.com", Target: "http://localhost", TLS: "off", Enabled: true}})
	if err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatalf("unexpected error: %v", err)
	}
	after, _ := os.ReadFile(filepath.Join(o.RuntimeDir, "caddy.json"))
	if !reflect.DeepEqual(before, after) {
		t.Fatal("rejected config persisted")
	}
}

func TestStartupFailureAndUnexpectedExit(t *testing.T) {
	for _, mode := range []string{"exit", "die"} {
		t.Run(mode, func(t *testing.T) {
			m, _ := fakeManager(t, mode)
			err := m.Start(context.Background(), nil)
			if mode == "exit" && err == nil {
				t.Fatal("startup succeeded")
			}
			select {
			case err, ok := <-m.Done():
				if !ok || err == nil {
					t.Fatal("missing unexpected exit")
				}
			case <-time.After(3 * time.Second):
				t.Fatal("exit not reported")
			}
		})
	}
}

func TestCloseKillsAndReaps(t *testing.T) {
	m, _ := fakeManager(t, "ignore")
	if err := m.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := m.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-m.waitDone:
	default:
		t.Fatal("child not reaped")
	}
}

func TestStartupCancellation(t *testing.T) {
	m, o := fakeManager(t, "not-ready")
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := m.Start(ctx, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("startup cancellation: %v", err)
	}
	select {
	case <-m.waitDone:
	default:
		t.Fatal("startup child was not reaped")
	}
	if _, err := os.Stat(filepath.Join(o.RuntimeDir, "caddy.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed startup persisted config: %v", err)
	}
}

func TestMissingBinary(t *testing.T) {
	o := options(t)
	o.Binary = filepath.Join(t.TempDir(), "missing-caddy")
	m := New(o)
	defer m.Close(context.Background())
	if err := m.Start(context.Background(), nil); err == nil {
		t.Fatal("missing binary started")
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// Set NICEPROXY_CADDY_TEST_BINARY to run an actual pinned Caddy integration test.
func TestRealCaddy(t *testing.T) {
	binary := os.Getenv("NICEPROXY_CADDY_TEST_BINARY")
	if binary == "" {
		t.Skip("set NICEPROXY_CADDY_TEST_BINARY for integration")
	}
	o := options(t)
	o.Binary = binary
	o.HTTPPort = freePort(t)
	o.HTTPSPort = freePort(t)
	o.PanelListen = net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))
	backend, err := net.Listen("unix", o.BackendSocket)
	if err != nil {
		t.Fatal(err)
	}
	panel := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "panel") })}
	go panel.Serve(backend)
	defer panel.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "upstream") }))
	defer upstream.Close()
	routes := []model.HTTPRoute{{Host: "local.example.test", Target: upstream.URL, TLS: "internal", Enabled: true}}
	m := New(o)
	defer m.Close(context.Background())
	if err := m.Start(context.Background(), routes); err != nil {
		t.Fatal(err)
	}
	get := func(client *http.Client, url, host string) (int, string) {
		t.Helper()
		req, _ := http.NewRequest("GET", url, nil)
		req.Host = host
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(body)
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if code, body := get(client, "http://"+o.PanelListen, "anything.test"); code != 200 || body != "panel" {
		t.Fatalf("panel: %d %s", code, body)
	}
	httpURL := "http://127.0.0.1:" + strconv.Itoa(o.HTTPPort)
	if code, _ := get(client, httpURL+"/hello?q=1", "local.example.test"); code != 308 {
		t.Fatalf("redirect: %d", code)
	}
	if _, body := get(client, httpURL, "unknown.test"); strings.Contains(body, "panel") {
		t.Fatal("panel leaked to public HTTP")
	}
	// Trust the private test CA, using the generated root rather than disabling verification.
	rootFile := filepath.Join(o.DataDir, "caddy", "pki", "authorities", "local", "root.crt")
	var pem []byte
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		pem, err = os.ReadFile(rootFile)
		if err == nil {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatalf("read CA: %v", err)
	}
	tlsClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, ServerName: "local.example.test"}}}
	defer tlsClient.CloseIdleConnections()
	var code int
	var body string
	// Cert issuance is asynchronous; wait for the TLS certificate to become available.
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		req, _ := http.NewRequest("GET", "https://127.0.0.1:"+strconv.Itoa(o.HTTPSPort), nil)
		req.Host = "local.example.test"
		res, e := tlsClient.Do(req)
		if e == nil {
			code = res.StatusCode
			b, _ := io.ReadAll(res.Body)
			res.Body.Close()
			body = string(b)
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if code != 200 || body != "upstream" {
		t.Fatalf("TLS proxy: %d %q", code, body)
	}
	if _, body := get(tlsClient, "https://127.0.0.1:"+strconv.Itoa(o.HTTPSPort), "unknown.test"); strings.Contains(body, "panel") {
		t.Fatal("panel leaked to public HTTPS")
	}
	untrusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "untrusted") }))
	defer untrusted.Close()
	routes[0].Target = untrusted.URL
	if err := m.Apply(context.Background(), routes); err != nil {
		t.Fatal(err)
	}
	if code, _ := get(tlsClient, "https://127.0.0.1:"+strconv.Itoa(o.HTTPSPort), "local.example.test"); code != http.StatusBadGateway {
		t.Fatalf("untrusted HTTPS upstream was not rejected: %d", code)
	}
	routes[0].Target = upstream.URL
	routes[0].TLS = "off"
	if err := m.Apply(context.Background(), routes); err != nil {
		t.Fatal(err)
	}
	if code, body := get(client, httpURL, "local.example.test"); code != 200 || body != "upstream" {
		t.Fatalf("off: %d %q", code, body)
	}
}

func TestOwnershipProtocolsAndChallenges(t *testing.T) {
	for _, tc := range []struct {
		name      string
		owners    model.PortOwners
		mode      string
		protocols string
		redirect  bool
		invalid   bool
	}{
		{"no h3", model.PortOwners{HTTP3: "direct"}, "auto", `["h1","h2"]`, true, false},
		{"h3 only", model.PortOwners{HTTPS: "direct"}, "internal", `["h3"]`, false, false},
		{"no HTTP challenge", model.PortOwners{HTTP: "direct"}, "auto", `["h1","h2","h3"]`, false, false},
		{"no TCP challenge", model.PortOwners{HTTP: "direct", HTTPS: "direct"}, "auto", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := options(t)
			o.PortOwners = tc.owners
			b, err := BuildConfig(o, []model.HTTPRoute{{ID: "route", Host: "test.example.com", Target: "http://localhost:3000", TLS: tc.mode, Enabled: true}})
			if tc.invalid {
				if err == nil {
					t.Fatal("accepted unreachable ACME challenges")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), `"protocols":`+tc.protocols) {
				t.Fatalf("protocols: %s", b)
			}
			if strings.Contains(string(b), `"status_code":308`) != tc.redirect {
				t.Fatalf("redirect: %s", b)
			}
			if tc.name == "no HTTP challenge" && !strings.Contains(string(b), `"http":{"disabled":true}`) {
				t.Fatalf("HTTP challenge: %s", b)
			}
		})
	}
}

func TestRealOwnershipH3OnlyAndNoH3(t *testing.T) {
	binary := os.Getenv("NICEPROXY_CADDY_TEST_BINARY")
	if binary == "" {
		t.Skip("set NICEPROXY_CADDY_TEST_BINARY for integration")
	}
	freePort := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	for _, h3Only := range []bool{false, true} {
		t.Run(fmt.Sprintf("h3Only=%t", h3Only), func(t *testing.T) {
			o := options(t)
			o.Binary = binary
			o.HTTPPort = freePort()
			o.HTTPSPort = freePort()
			o.PanelListen = net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort()))
			owners := model.PortOwners{HTTP: "direct", HTTP3: "direct"}
			if h3Only {
				owners.HTTPS = "direct"
				owners.HTTP3 = "caddy"
			}
			m := New(o)
			ctx := context.Background()
			if err := m.Start(ctx, []model.HTTPRoute{{Host: "ownership.test", TLS: "internal", Target: "http://127.0.0.1:1", Enabled: true}}, owners); err != nil {
				t.Fatal(err)
			}
			defer func() { ctx, cancel := context.WithTimeout(ctx, 3*time.Second); defer cancel(); _ = m.Close(ctx) }()
			addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(o.HTTPSPort))
			if h3Only {
				l, err := net.Listen("tcp", addr)
				if err != nil {
					t.Fatalf("H3-only took TCP socket: %v", err)
				}
				l.Close()
			} else {
				l, err := net.ListenPacket("udp", addr)
				if err != nil {
					t.Fatalf("disabled H3 took UDP socket: %v", err)
				}
				l.Close()
			}
			l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(o.HTTPPort)))
			if err != nil {
				t.Fatalf("direct HTTP port taken: %v", err)
			}
			l.Close()
		})
	}
}
