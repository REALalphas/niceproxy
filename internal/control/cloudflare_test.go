package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"niceproxy/internal/cloudflare"
)

func TestCloudflarePKCECallbackAndDNS(t *testing.T) {
	a, s, session := fixture(t)
	zone := strings.Repeat("a", 32)
	var verifier string
	var writes atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/token" {
			_ = r.ParseForm()
			verifier = r.Form.Get("code_verifier")
			if r.Form.Get("client_secret") != "" || r.Form.Get("client_id") != "registered-public-test-client" {
				t.Error("unexpected client authentication")
			}
			fmt.Fprint(w, `{"access_token":"test-only-access-token","refresh_token":"test-only-refresh-token","token_type":"Bearer","expires_in":3600}`)
			return
		}
		if r.URL.Path == "/revoke" {
			w.WriteHeader(503)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-only-access-token" {
			t.Error("missing server-side bearer token")
		}
		switch r.URL.Path {
		case "/zones":
			fmt.Fprintf(w, `{"success":true,"result":[{"id":%q,"name":"example.test","status":"active","account":{"id":"account","name":"Test"}}],"result_info":{"total_pages":1}}`, zone)
		case "/zones/" + zone:
			fmt.Fprintf(w, `{"success":true,"result":{"id":%q,"name":"example.test"}}`, zone)
		case "/zones/" + zone + "/dns_records":
			if r.Method == "GET" {
				fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"total_pages":1}}`)
				return
			}
			writes.Add(1)
			var record cloudflare.Record
			if err := json.NewDecoder(r.Body).Decode(&record); err != nil {
				t.Error(err)
			}
			record.ID = strings.Repeat("b", 32)
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": record})
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	options := cloudflare.Options{DataDir: t.TempDir(), RedirectURL: s.URL + "/api/cloudflare/callback", AuthURL: provider.URL + "/auth", TokenURL: provider.URL + "/token", RevokeURL: provider.URL + "/revoke", APIBase: provider.URL}
	if err := a.ConfigureCloudflare(options); err != nil {
		t.Fatal(err)
	}
	resp := call(t, s, "GET", "/api/cloudflare", "", session)
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte(`"scopes":[]`)) {
		t.Fatalf("%s %s", resp.Status, body)
	}
	resp = call(t, s, "POST", "/api/cloudflare/settings", `{"clientId":"registered-public-test-client","scopes":["test.zone-read","test.dns-write"]}`, session)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	if err := a.ConfigureCloudflare(options); err != nil {
		t.Fatal(err)
	}
	resp = call(t, s, "POST", "/api/cloudflare/connect", "", session)
	var auth struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	stateCookie := resp.Cookies()[0]
	if stateCookie.SameSite != http.SameSiteLaxMode || !stateCookie.HttpOnly || stateCookie.Path != "/api/cloudflare/callback" {
		t.Fatal("unsafe OAuth cookie", stateCookie)
	}
	parsed, _ := url.Parse(auth.URL)
	state := parsed.Query().Get("state")
	if parsed.Query().Get("code_challenge_method") != "S256" || parsed.Query().Get("code_challenge") == "" || state == "" {
		t.Fatal("missing PKCE")
	}
	// A cross-site top-level callback has the Lax state cookie, but intentionally
	// lacks the Strict niceproxy_session cookie.
	callback := s.URL + "/api/cloudflare/callback?code=test-only-code&state=" + url.QueryEscape(state)
	request, _ := http.NewRequest("GET", callback, nil)
	request.AddCookie(stateCookie)
	client := *s.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	stale, _ := http.NewRequest("GET", s.URL+"/api/cloudflare/callback?error=access_denied&state=older-attempt", nil)
	stale.AddCookie(stateCookie)
	resp, err := client.Do(stale)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 || !strings.Contains(resp.Header.Get("Location"), "cloudflare=error") || len(resp.Cookies()) != 0 {
		t.Fatal("stale callback disturbed the current attempt", resp.Status, resp.Header)
	}
	resp = call(t, s, "GET", "/api/cloudflare", "", session)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if bytes.Contains(body, []byte(`"error":`)) {
		t.Fatal("stale callback appeared in connection status", string(body))
	}
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 303 || !strings.Contains(resp.Header.Get("Location"), "cloudflare=connected") {
		t.Fatal(resp.Status, resp.Header.Get("Location"))
	}
	if verifier == "" {
		t.Fatal("PKCE verifier not exchanged")
	}
	resp = call(t, s, "GET", "/api/cloudflare", "", session)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if !bytes.Contains(body, []byte(`"connected":true`)) || bytes.Contains(body, []byte("test-only-access")) || bytes.Contains(body, []byte("test-only-refresh")) {
		t.Fatal(string(body))
	}
	saved, err := a.db.Integration("cloudflare")
	if err != nil {
		t.Fatal(err)
	}
	if len(saved) == 0 || bytes.Contains(saved, []byte("test-only-access")) {
		t.Fatal("unencrypted grant")
	}
	if writes.Load() != 0 {
		t.Fatal("login unexpectedly changed DNS")
	}
	resp = call(t, s, "POST", "/api/cloudflare/zones/"+zone+"/records", `{"type":"A","name":"app.example.test","content":"192.0.2.10","proxied":false,"ttl":1}`, session)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || writes.Load() != 1 {
		t.Fatalf("%s %s", resp.Status, body)
	}
	resp, err = client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if strings.Contains(resp.Header.Get("Location"), "cloudflare=connected") {
		t.Fatal("replayed callback accepted")
	}
	resp = call(t, s, "POST", "/api/cloudflare/settings", `{"clientId":"replacement-public-client","scopes":["test.zone-read"]}`, session)
	body, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !bytes.Contains(body, []byte("previous OAuth grant")) {
		t.Fatalf("revocation failure hidden: %s %s", resp.Status, body)
	}
}

func TestCloudflareRequiresAuthAndRejectsForeignStart(t *testing.T) {
	a, s, session := fixture(t)
	if err := a.ConfigureCloudflare(cloudflare.Options{DataDir: t.TempDir(), RedirectURL: s.URL + "/api/cloudflare/callback"}); err != nil {
		t.Fatal(err)
	}
	resp := call(t, s, "GET", "/api/cloudflare", "", nil)
	resp.Body.Close()
	if resp.StatusCode != 401 {
		t.Fatal(resp.Status)
	}
	req, _ := http.NewRequest("POST", s.URL+"/api/cloudflare/connect", nil)
	req.AddCookie(session)
	req.Header.Set("Origin", "https://evil.example")
	resp, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal(resp.Status)
	}
	resp = call(t, s, "POST", "/api/cloudflare/settings", `{"clientId":"test-client","scopes":["test.read"],"apiToken":"must-not-be-accepted"}`, session)
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatal("API token accepted", resp.Status)
	}
}

func TestExplicitHTTPSCallbackHostIsAllowed(t *testing.T) {
	a, s, session := fixture(t)
	if err := a.ConfigureCloudflare(cloudflare.Options{DataDir: t.TempDir(), RedirectURL: "https://panel.example/api/cloudflare/callback"}); err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", s.URL+"/api/cloudflare", nil)
	req.Host = "panel.example"
	req.AddCookie(session)
	resp, err := s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	req, _ = http.NewRequest("GET", s.URL+"/api/cloudflare", nil)
	req.Host = "untrusted.example"
	req.AddCookie(session)
	resp, err = s.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 403 {
		t.Fatal(resp.Status)
	}
}

func TestPanelCallbackFollowsDomainAndReturnsToLocalOnRemoval(t *testing.T) {
	a, s, session := fixture(t)
	if err := a.ConfigurePanelDomain("first.example.com"); err != nil {
		t.Fatal(err)
	}
	local := s.URL + "/api/cloudflare/callback"
	if err := a.ConfigureCloudflare(cloudflare.Options{DataDir: t.TempDir(), RedirectURL: local}); err != nil {
		t.Fatal(err)
	}
	check := func(want string) {
		t.Helper()
		resp := call(t, s, http.MethodGet, "/api/cloudflare", "", session)
		defer resp.Body.Close()
		var status cloudflare.Status
		if err := json.NewDecoder(resp.Body).Decode(&status); err != nil || status.RedirectURL != want {
			t.Fatalf("OAuth callback = %q, want %q (%v)", status.RedirectURL, want, err)
		}
	}
	check("https://first.example.com/api/cloudflare/callback")
	for _, tc := range []struct{ body, callback string }{
		{`{"panelDomain":"second.example.com"}`, "https://second.example.com/api/cloudflare/callback"},
		{`{"panelDomain":""}`, local},
	} {
		resp := call(t, s, http.MethodPatch, "/api/panel-domain", tc.body, session)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatal(resp.Status)
		}
		check(tc.callback)
	}
}

func TestCloudflareLoopbackBootstrapsPublicPanelFromLAN(t *testing.T) {
	ctx := context.Background()
	a, s, session := fixture(t)
	c := &testPanelOrigin{
		tlsState: "handshake_failed", storedState: "missing",
		csr: func(host string) string {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}}, key)
			if err != nil {
				t.Fatal(err)
			}
			return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}))
		},
	}
	a.caddy = c
	if err := a.ConfigurePanelDomain(automationPanel); err != nil {
		t.Fatal(err)
	}

	const loopback = "http://localhost:9080/api/cloudflare/callback"
	zone := strings.Repeat("a", 32)
	var challenge atomic.Value
	var tokenCalls, issued, rules atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			tokenCalls.Add(1)
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("redirect_uri") != loopback || r.Form.Get("code") != "example-code" ||
				base64.RawURLEncoding.EncodeToString(sum[:]) != challenge.Load() {
				t.Error("exchange must use the loopback redirect and initiating PKCE verifier")
				http.Error(w, "unexpected token form", 400)
				return
			}
			fmt.Fprint(w, `{"access_token":"example-access","refresh_token":"example-refresh","expires_in":3600}`)
			return
		}
		if r.Header.Get("Authorization") != "Bearer example-access" {
			t.Error("automation did not use the OAuth access token")
			http.Error(w, "missing OAuth bearer", 401)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /zones":
			fmt.Fprintf(w, `{"success":true,"result":[{"id":%q,"name":"example.com","status":"active"}]}`, zone)
		case "GET /zones/" + zone + "/dns_records":
			fmt.Fprintf(w, `{"success":true,"result":[{"type":"A","name":%q,"proxied":true}]}`, automationPanel)
		case "GET /zones/" + zone + "/settings/ssl":
			fmt.Fprint(w, `{"success":true,"result":{"value":"flexible"}}`)
		case "GET /zones/" + zone + "/settings/ssl_automatic_mode":
			fmt.Fprint(w, `{"success":true,"result":{"value":"auto"}}`)
		case "POST /certificates":
			issued.Add(1)
			fmt.Fprint(w, `{"success":true,"result":{"certificate":"test-pem"}}`)
		case "GET /zones/" + zone + "/rulesets/phases/http_config_settings/entrypoint":
			http.NotFound(w, r)
		case "POST /zones/" + zone + "/rulesets":
			rules.Add(1)
			fmt.Fprint(w, `{"success":true,"result":{}}`)
		default:
			t.Errorf("unexpected Cloudflare request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	options := cloudflare.Options{
		DataDir: t.TempDir(), RedirectURL: s.URL + "/api/cloudflare/callback",
		LoopbackRedirectURL: loopback, AuthURL: provider.URL + "/auth", TokenURL: provider.URL + "/token", APIBase: provider.URL,
	}
	if err := a.ConfigureCloudflare(options); err != nil {
		t.Fatal(err)
	}
	post := func(path, body string, cookie *http.Cookie, code int) []byte {
		t.Helper()
		r := call(t, s, http.MethodPost, path, body, cookie)
		defer r.Body.Close()
		data, err := io.ReadAll(r.Body)
		if err != nil || r.StatusCode != code {
			t.Fatalf("%s: %s, %s (%v)", path, r.Status, data, err)
		}
		return data
	}
	post("/api/cloudflare/settings", `{"clientId":"example-client","scopes":["example.zone-read","example.origin-ca"]}`, session, 200)
	var auth struct{ URL string }
	if err := json.Unmarshal(post("/api/cloudflare/connect?mode=localhost", "", session, 200), &auth); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(auth.URL)
	if err != nil || u.Query().Get("redirect_uri") != loopback || u.Query().Get("state") == "" || u.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("invalid loopback authorization: %v", err)
	}
	challenge.Store(u.Query().Get("code_challenge"))
	callback := "?code=example-code&state=" + url.QueryEscape(u.Query().Get("state"))
	body := func(redirect string) string {
		raw, _ := json.Marshal(map[string]string{"callbackUrl": redirect + callback})
		return string(raw)
	}

	login := call(t, s, http.MethodPost, "/api/login", `{"password":"a-test-password-123"}`, nil)
	login.Body.Close()
	if login.StatusCode != http.StatusOK || len(login.Cookies()) == 0 {
		t.Fatal(login.Status)
	}
	post("/api/cloudflare/complete", body(loopback), login.Cookies()[0], 400)
	post("/api/cloudflare/complete", body(loopback), nil, 401)
	post("/api/cloudflare/complete", body("http://localhost:9081/api/cloudflare/callback"), session, 400)
	post("/api/cloudflare/complete", body("https://panel.example.com/api/cloudflare/callback"), session, 400)
	if tokenCalls.Load() != 0 {
		t.Fatal("invalid callback reached token endpoint")
	}
	var status cloudflare.Status
	if err := json.Unmarshal(post("/api/cloudflare/complete", body(loopback), session, 200), &status); err != nil ||
		!status.Connected || status.RedirectURL != "https://"+automationPanel+"/api/cloudflare/callback" {
		t.Fatalf("bad connection status: %+v (%v)", status, err)
	}
	post("/api/cloudflare/complete", body(loopback), session, 400)

	a.checkPanelEdge(ctx)
	if tokenCalls.Load() != 1 || issued.Load() != 1 || rules.Load() != 1 ||
		a.panelEdge.State != "strict_ready" || !c.loaded.PanelDomainProxied {
		t.Fatalf("OAuth did not converge the panel: %+v, issues=%d, rules=%d", a.panelEdge, issued.Load(), rules.Load())
	}

	rename := call(t, s, http.MethodPatch, "/api/panel-domain", `{"panelDomain":"new.example.com"}`, session)
	rename.Body.Close()
	if rename.StatusCode != http.StatusOK {
		t.Fatal(rename.Status)
	}
	status = a.cloudflareStatus()
	if !status.Connected || status.RedirectURL != "https://new.example.com/api/cloudflare/callback" {
		t.Fatalf("OAuth grant or callback lost on hostname change: %+v", status)
	}
	if err := a.ConfigureCloudflare(options); err != nil {
		t.Fatal(err)
	}
	status = a.cloudflareStatus()
	if !status.Connected || status.LoopbackRedirectURL != loopback || status.RedirectURL != "https://new.example.com/api/cloudflare/callback" {
		t.Fatalf("OAuth grant or callback lost on startup: %+v", status)
	}
}

func TestCloudflareSettingsAllowLoopbackWithoutDirectCallback(t *testing.T) {
	a, s, session := fixture(t)
	const loopback = "http://localhost:9080/api/cloudflare/callback"
	if err := a.ConfigureCloudflare(cloudflare.Options{
		DataDir: t.TempDir(), LoopbackRedirectURL: loopback,
	}); err != nil {
		t.Fatal(err)
	}
	resp := call(t, s, http.MethodPost, "/api/cloudflare/settings", `{"clientId":"example-client","scopes":["example.zone-read"]}`, session)
	defer resp.Body.Close()
	var status cloudflare.Status
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil || resp.StatusCode != http.StatusOK ||
		!status.Configured || status.RedirectURL != "" || status.LoopbackRedirectURL != loopback {
		t.Fatalf("loopback-only settings: %s %+v (%v)", resp.Status, status, err)
	}
}
