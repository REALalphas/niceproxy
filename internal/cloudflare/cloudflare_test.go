package cloudflare

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type memoryStore struct {
	mu   sync.Mutex
	b    []byte
	fail bool
}

func (s *memoryStore) Integration(string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.b...), nil
}
func (s *memoryStore) SetIntegration(_ string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail {
		return errors.New("secret unsafe storage failure")
	}
	s.b = append([]byte(nil), b...)
	return nil
}
func opts(t *testing.T, s *httptest.Server) Options {
	t.Helper()
	return Options{ClientID: "registered-public-client", RedirectURL: "http://127.0.0.1:8080/api/cloudflare/callback", Scopes: []string{"configured-scope-id"}, DataDir: t.TempDir(), HTTPClient: s.Client(), AuthURL: s.URL + "/auth", TokenURL: s.URL + "/token", RevokeURL: s.URL + "/revoke", APIBase: s.URL}
}
func manager(t *testing.T, o Options, p Persistence) *Manager {
	t.Helper()
	m, e := New(o, p)
	if e != nil {
		t.Fatal(e)
	}
	return m
}
func login(t *testing.T, m *Manager) {
	t.Helper()
	_, state, e := m.Begin("session-hash")
	if e != nil {
		t.Fatal(e)
	}
	if e = m.Complete(context.Background(), "secret-code", state, state, func(s string) bool { return s == "session-hash" }); e != nil {
		t.Fatal(e)
	}
}
func token(w http.ResponseWriter) {
	fmt.Fprint(w, `{"access_token":"secret-access","refresh_token":"secret-refresh","expires_in":3600,"token_type":"Bearer"}`)
}

func TestPKCEAndEncryptedRestart(t *testing.T) {
	var verifier string
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/token" {
			t.Errorf("unexpected %s", r.URL)
		}
		r.ParseForm()
		verifier = r.Form.Get("code_verifier")
		if len(verifier) < 43 || r.Form.Get("client_secret") != "" || r.Header.Get("Authorization") != "" || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("client_id") != "registered-public-client" || r.Form.Get("code") != "secret-code" || r.Form.Get("redirect_uri") == "" {
			t.Error("invalid public client exchange")
		}
		token(w)
	}))
	defer s.Close()
	p := &memoryStore{}
	o := opts(t, s)
	m := manager(t, o, p)
	u, state, e := m.Begin("session-hash")
	if e != nil {
		t.Fatal(e)
	}
	parsed, _ := url.Parse(u)
	q := parsed.Query()
	if q.Get("state") != state || len(state) < 43 || q.Get("code_challenge_method") != "S256" || q.Get("scope") != "configured-scope-id" {
		t.Fatal(q)
	}
	e = m.Complete(context.Background(), "secret-code", state, state, func(s string) bool { return s == "session-hash" })
	if e != nil {
		t.Fatal(e)
	}
	sum := sha256.Sum256([]byte(verifier))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("challenge mismatch")
	}
	if m.Complete(context.Background(), "secret-code", state, state, func(string) bool { return true }) == nil {
		t.Fatal("replay accepted")
	}
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
	b, _ := p.Integration("cloudflare")
	if strings.Contains(string(b), "secret-") {
		t.Fatal("plaintext tokens persisted")
	}
	key, e := os.Stat(filepath.Join(o.DataDir, "cloudflare.key"))
	if e != nil || key.Mode().Perm() != 0600 {
		t.Fatal("insecure key")
	}
	restarted := manager(t, o, p)
	if !restarted.Status().Connected {
		t.Fatal(restarted.Status())
	}
	status, _ := json.Marshal(restarted.Status())
	if strings.Contains(string(status), "secret-") {
		t.Fatal("status leaks credentials")
	}
	o.ClientID = "different-client"
	mismatch := manager(t, o, p)
	if mismatch.Status().Connected || mismatch.Status().Error == "" {
		t.Fatal("wrong-client credentials loaded")
	}
	o.ClientID = "registered-public-client"
	o.Scopes = []string{"different-scope"}
	if manager(t, o, p).Status().Connected {
		t.Fatal("wrong scope loaded")
	}
	o.Scopes = []string{"configured-scope-id"}
	o.RedirectURL = "https://app.example/api/cloudflare/callback"
	if !manager(t, o, p).Status().Connected {
		t.Fatal("changing the redirect discarded the still-valid OAuth grant")
	}
	os.Remove(filepath.Join(o.DataDir, "cloudflare.key"))
	lost := manager(t, o, p)
	if lost.Status().Connected || lost.Status().Error == "" {
		t.Fatal("key loss ignored")
	}
	if _, e = os.Stat(filepath.Join(o.DataDir, "cloudflare.key")); !os.IsNotExist(e) {
		t.Fatal("missing key regenerated")
	}
}
func TestInvalidAuthorizationState(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); token(w) }))
	defer s.Close()
	m := manager(t, opts(t, s), nil)
	tests := []string{"mismatch", "expired", "session", "empty-code"}
	for _, name := range tests {
		t.Run(name, func(t *testing.T) {
			_, state, e := m.Begin("session-hash")
			if e != nil {
				t.Fatal(e)
			}
			cookie := state
			code := "secret"
			valid := func(string) bool { return true }
			switch name {
			case "mismatch":
				cookie = "other-state"
			case "expired":
				m.mu.Lock()
				v := m.pending[state]
				v.until = time.Now().Add(-time.Second)
				m.pending[state] = v
				m.mu.Unlock()
			case "session":
				valid = func(string) bool { return false }
			case "empty-code":
				code = ""
			}
			if m.Complete(context.Background(), code, state, cookie, valid) == nil {
				t.Fatal("invalid flow accepted")
			}
			if m.Complete(context.Background(), "secret", state, state, func(string) bool { return true }) == nil {
				t.Fatal("consumed flow accepted")
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid states hit token endpoint")
	}
	if _, _, e := m.Begin(""); e == nil {
		t.Fatal("empty session accepted")
	}
	for i := 0; i < 32; i++ {
		if _, _, e := m.Begin("s"); e != nil {
			t.Fatal(e)
		}
	}
	if _, _, e := m.Begin("s"); e == nil {
		t.Fatal("unbounded pending states")
	}
}
func TestDisabledAndRedirectValidation(t *testing.T) {
	for _, o := range []Options{{}, {ClientID: "client"}, {Scopes: []string{"scope"}}} {
		m, e := New(o, nil)
		if e != nil || m.Status().Configured {
			t.Fatal("disabled config rejected")
		}
		if _, _, e = m.Begin("s"); e == nil {
			t.Fatal("disabled OAuth began")
		}
	}
	for _, s := range []string{"https://app.example/api/cloudflare/callback", "http://localhost:8080/api/cloudflare/callback", "http://[::1]/api/cloudflare/callback", "http://127.0.0.2/api/cloudflare/callback"} {
		if e := validRedirect(s); e != nil {
			t.Fatal(s, e)
		}
	}
	for _, s := range []string{"", "https:///api/cloudflare/callback", "http://example.com/api/cloudflare/callback", "http://127.0.0.1.evil/api/cloudflare/callback", "https://user:pass@app.example/api/cloudflare/callback", "https://app.example/other", "https://app.example/api/cloudflare/callback?a=1", "https://app.example/api/cloudflare/callback#x", "https://app.example/api/cloudflare/callback?"} {
		if validRedirect(s) == nil {
			t.Fatal("accepted", s)
		}
	}
}
func TestKeySecurityAndConcurrentCreation(t *testing.T) {
	s := httptest.NewServer(http.NotFoundHandler())
	defer s.Close()
	for _, kind := range []string{"symlink", "mode", "size"} {
		t.Run(kind, func(t *testing.T) {
			o := opts(t, s)
			path := filepath.Join(o.DataDir, "cloudflare.key")
			switch kind {
			case "symlink":
				target := filepath.Join(t.TempDir(), "target")
				os.WriteFile(target, make([]byte, 32), 0600)
				os.Symlink(target, path)
			case "mode":
				os.WriteFile(path, make([]byte, 32), 0644)
			case "size":
				os.WriteFile(path, []byte("bad"), 0600)
			}
			m := manager(t, o, &memoryStore{})
			if m.Status().Error == "" {
				t.Fatal("unsafe key accepted")
			}
			if _, _, e := m.Begin("s"); e == nil {
				t.Fatal("unsafe key allowed OAuth")
			}
		})
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "cloudflare.key")
	var wg sync.WaitGroup
	keys := make(chan string, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			k, e := createKey(path)
			if e != nil {
				t.Error(e)
				return
			}
			keys <- string(k)
		}()
	}
	wg.Wait()
	close(keys)
	var first string
	for k := range keys {
		if first == "" {
			first = k
		}
		if k != first {
			t.Fatal("key creation race")
		}
	}
}
func TestRefreshRotationSerializedAndRevocationFailure(t *testing.T) {
	var refresh atomic.Int32
	var revokes atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			r.ParseForm()
			if r.Form.Get("grant_type") == "refresh_token" {
				refresh.Add(1)
				if r.Form.Get("refresh_token") != "secret-refresh" || r.Form.Get("client_secret") != "" {
					t.Error("bad refresh")
				}
				fmt.Fprint(w, `{"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":3600}`)
			} else {
				token(w)
			}
		case "/zones":
			if r.Header.Get("Authorization") != "Bearer rotated-access" {
				t.Error("old token used")
			}
			fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"total_pages":1}}`)
		case "/revoke":
			revokes.Add(1)
			http.Error(w, "secret unsafe provider error", 503)
		}
	}))
	defer s.Close()
	o := opts(t, s)
	p := &memoryStore{}
	m := manager(t, o, p)
	login(t, m)
	m.mu.Lock()
	m.tok.ExpiresAt = time.Now().Add(-time.Second)
	m.mu.Unlock()
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := m.Zones(context.Background()); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if refresh.Load() != 1 {
		t.Fatal("parallel refresh", refresh.Load())
	}
	restarted := manager(t, o, p)
	if restarted.tok.Refresh != "rotated-refresh" {
		t.Fatal("rotation not saved")
	}
	_, state, _ := m.Begin("s")
	e := m.Disconnect(context.Background())
	if e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal("unsafe revoke error", e)
	}
	if revokes.Load() != 2 || m.Status().Connected {
		t.Fatal("disconnect failed")
	}
	b, _ := p.Integration("cloudflare")
	if len(b) != 0 {
		t.Fatal("local credentials retained")
	}
	if manager(t, o, p).Status().Connected {
		t.Fatal("disconnected state resurrected")
	}
	if m.Complete(context.Background(), "code", state, state, func(string) bool { return true }) == nil {
		t.Fatal("pending survived disconnect")
	}
}

const zoneID = "0123456789abcdef0123456789abcdef"
const recordID = "abcdef0123456789abcdef0123456789"

func TestDNSPaginationAndExactMutations(t *testing.T) {
	var writes atomic.Int32
	var pages atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/token":
			token(w)
		case r.URL.Path == "/zones":
			pages.Add(1)
			if r.URL.Query().Get("per_page") != "50" {
				t.Error("bad page size")
			}
			page := r.URL.Query().Get("page")
			fmt.Fprintf(w, `{"success":true,"result":[{"id":%q,"name":%q}],"result_info":{"total_pages":2}}`, zoneID, "page"+page+".example")
		case r.URL.Path == "/zones/"+zoneID:
			fmt.Fprintf(w, `{"success":true,"result":{"id":%q,"name":"example.com"}}`, zoneID)
		case strings.HasPrefix(r.URL.Path, "/zones/"+zoneID+"/dns_records"):
			if r.Method == "GET" {
				fmt.Fprint(w, `{"success":true,"result":[{"id":"record","type":"TXT"}],"result_info":{"total_pages":1}}`)
				return
			}
			writes.Add(1)
			if r.Method == "POST" && r.URL.Path != "/zones/"+zoneID+"/dns_records" || r.Method == "PATCH" && r.URL.Path != "/zones/"+zoneID+"/dns_records/"+recordID {
				t.Error("wrong mutation URL", r.Method, r.URL.Path)
			}
			var record Record
			json.NewDecoder(r.Body).Decode(&record)
			if record.Proxied || record.TTL != 1 || record.ID != "" {
				t.Error("unsafe defaults", record)
			}
			record.ID = recordID
			b, _ := json.Marshal(record)
			fmt.Fprintf(w, `{"success":true,"result":%s}`, b)
		default:
			t.Error("unexpected path", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer s.Close()
	m := manager(t, opts(t, s), nil)
	login(t, m)
	zones, e := m.Zones(context.Background())
	if e != nil || len(zones) != 2 || pages.Load() != 2 {
		t.Fatal(zones, e)
	}
	records, e := m.Records(context.Background(), zoneID)
	if e != nil || len(records) != 1 || records[0].Type != "TXT" {
		t.Fatal(records, e)
	}
	for _, id := range []string{"", recordID} {
		out, e := m.WriteRecord(context.Background(), zoneID, id, Record{Type: "A", Name: "Home.Example.Com.", Content: "192.0.2.1"})
		if e != nil || out.ID != recordID {
			t.Fatal(out, e)
		}
	}
	for _, name := range []string{"example.com.evil", "badexample.com", "outside.test", "a..example.com", "a/b.example.com", "bad_thing.example.com"} {
		if _, e = m.WriteRecord(context.Background(), zoneID, "", Record{Type: "A", Name: name, Content: "192.0.2.1"}); e == nil {
			t.Fatal("accepted outside name", name)
		}
	}
	for _, r := range []Record{{Type: "A", Name: "a.example.com", Content: "::1"}, {Type: "AAAA", Name: "a.example.com", Content: "192.0.2.1"}, {Type: "CNAME", Name: "a.example.com", Content: "not-a-fqdn"}, {Type: "CNAME", Name: "a.example.com", Content: "192.0.2.1"}, {Type: "TXT", Name: "a.example.com", Content: "text"}} {
		if _, e = m.WriteRecord(context.Background(), zoneID, "", r); e == nil {
			t.Fatal("invalid content accepted", r)
		}
	}
	if _, e = m.WriteRecord(context.Background(), zoneID, "../record", Record{}); e == nil {
		t.Fatal("invalid record id accepted")
	}
	if _, e = m.Records(context.Background(), "../zone"); e == nil {
		t.Fatal("invalid zone accepted")
	}
	if writes.Load() != 2 {
		t.Fatal("unexpected mutations", writes.Load())
	}
}
func TestNoRedirectLeaksAnd401Clears(t *testing.T) {
	var leaked atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer target.Close()
	var unauthorized atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			token(w)
			return
		}
		if unauthorized.Load() {
			http.Error(w, "secret-token", 401)
			return
		}
		http.Redirect(w, r, target.URL, 307)
	}))
	defer s.Close()
	p := &memoryStore{}
	o := opts(t, s)
	m := manager(t, o, p)
	login(t, m)
	if _, e := m.Zones(context.Background()); e == nil {
		t.Fatal("redirect accepted")
	}
	if leaked.Load() != 0 {
		t.Fatal("followed redirect")
	}
	unauthorized.Store(true)
	if _, e := m.Zones(context.Background()); e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal("unsafe 401", e)
	}
	if m.Status().Connected || manager(t, o, p).Status().Connected {
		t.Fatal("401 retained authorization")
	}
}
func TestPersistenceFailureAndResponseBounds(t *testing.T) {
	var huge atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if huge.Load() {
			fmt.Fprint(w, strings.Repeat("x", (1<<20)+1))
			return
		}
		token(w)
	}))
	defer s.Close()
	p := &memoryStore{}
	m := manager(t, opts(t, s), p)
	p.mu.Lock()
	p.fail = true
	p.mu.Unlock()
	_, state, _ := m.Begin("s")
	e := m.Complete(context.Background(), "code", state, state, func(string) bool { return true })
	if e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal("unsafe persistence failure", e)
	}
	if m.Status().Connected {
		t.Fatal("reported unpersisted connection")
	}
	huge.Store(true)
	_, state, _ = m.Begin("s")
	if e = m.Complete(context.Background(), "code", state, state, func(string) bool { return true }); e == nil {
		t.Fatal("oversized token response accepted")
	}
}

func TestRejectedRefreshClearsPersistedAuthorization(t *testing.T) {
	var reject atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if reject.Load() {
			http.Error(w, `{"error":"invalid_grant","description":"secret-refresh"}`, 400)
			return
		}
		token(w)
	}))
	defer s.Close()
	o := opts(t, s)
	p := &memoryStore{}
	m := manager(t, o, p)
	login(t, m)
	m.mu.Lock()
	m.tok.ExpiresAt = time.Now().Add(-time.Minute)
	m.mu.Unlock()
	reject.Store(true)
	if _, e := m.Zones(context.Background()); e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal(e)
	}
	if m.Status().Connected || manager(t, o, p).Status().Connected {
		t.Fatal("revoked refresh retained authorization")
	}
}

func TestPaginationCap(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			token(w)
			return
		}
		calls.Add(1)
		fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"total_pages":101}}`)
	}))
	defer s.Close()
	m := manager(t, opts(t, s), nil)
	login(t, m)
	if _, e := m.Zones(context.Background()); e == nil {
		t.Fatal("unbounded zone pagination")
	}
	if calls.Load() != 100 {
		t.Fatal(calls.Load())
	}
	calls.Store(0)
	if _, e := m.Records(context.Background(), zoneID); e == nil {
		t.Fatal("unbounded record pagination")
	}
	if calls.Load() != 100 {
		t.Fatal(calls.Load())
	}
}

func TestExpiresAtAndTransientRefreshFailure(t *testing.T) {
	var fail atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "secret-provider-body", 503)
			return
		}
		fmt.Fprintf(w, `{"access_token":"secret-access","refresh_token":"secret-refresh","expires_at":%q}`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	defer s.Close()
	o := opts(t, s)
	p := &memoryStore{}
	m := manager(t, o, p)
	login(t, m)
	m.mu.Lock()
	m.tok.ExpiresAt = time.Now().Add(-time.Minute)
	m.mu.Unlock()
	fail.Store(true)
	if _, e := m.Zones(context.Background()); e == nil || strings.Contains(e.Error(), "secret") {
		t.Fatal(e)
	}
	if !m.Status().Connected {
		t.Fatal("transient refresh failure destroyed authorization")
	}
}

func TestRotatedTokenPersistenceRetry(t *testing.T) {
	var refreshes atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			_ = r.ParseForm()
			if r.Form.Get("grant_type") == "refresh_token" {
				refreshes.Add(1)
				fmt.Fprint(w, `{"access_token":"rotated-access","refresh_token":"rotated-refresh","expires_in":3600,"token_type":"Bearer"}`)
			} else {
				token(w)
			}
			return
		}
		if r.Header.Get("Authorization") != "Bearer rotated-access" {
			t.Error("wrong access token after retry")
		}
		fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"total_pages":1}}`)
	}))
	defer s.Close()
	p := &memoryStore{}
	o := opts(t, s)
	m := manager(t, o, p)
	login(t, m)
	m.mu.Lock()
	m.tok.ExpiresAt = time.Now().Add(-time.Minute)
	m.mu.Unlock()
	p.mu.Lock()
	p.fail = true
	p.mu.Unlock()
	if _, err := m.Zones(context.Background()); err == nil {
		t.Fatal("storage error hidden")
	}
	if !m.Status().Connected || m.Status().Error == "" {
		t.Fatal("rotated token lost")
	}
	p.mu.Lock()
	p.fail = false
	p.mu.Unlock()
	if _, err := m.Zones(context.Background()); err != nil {
		t.Fatal(err)
	}
	if refreshes.Load() != 1 {
		t.Fatal("refresh was repeated with an invalid old token")
	}
	restored := manager(t, o, p)
	if restored.tok.Refresh != "rotated-refresh" || restored.Status().Error != "" {
		t.Fatal("replacement not persisted")
	}
}

func TestDisconnectRetriesDurableDeletion(t *testing.T) {
	var revokes atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			token(w)
		} else {
			revokes.Add(1)
			w.WriteHeader(200)
		}
	}))
	defer s.Close()
	p := &memoryStore{}
	m := manager(t, opts(t, s), p)
	login(t, m)
	p.mu.Lock()
	p.fail = true
	p.mu.Unlock()
	if m.Disconnect(context.Background()) == nil {
		t.Fatal("delete failure hidden")
	}
	if !m.Status().Connected {
		t.Fatal("grant unavailable for retry")
	}
	p.mu.Lock()
	p.fail = false
	p.mu.Unlock()
	if err := m.Disconnect(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m.Status().Connected || revokes.Load() != 2 {
		t.Fatal("disconnect did not retry revocation")
	}
}

func TestLoopbackGrantSurvivesRefreshWithNoDirectCallback(t *testing.T) {
	const loopback = "http://localhost:9080/api/cloudflare/callback"
	var refreshes atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("grant_type") == "refresh_token" {
				refreshes.Add(1)
				if r.Form.Has("redirect_uri") {
					t.Error("refresh must not send the panel callback")
				}
				token(w)
				return
			}
			fmt.Fprint(w, `{"access_token":"example-access","refresh_token":"example-refresh","expires_in":1}`)
			return
		}
		fmt.Fprint(w, `{"success":true,"result":[]}`)
	}))
	defer s.Close()
	o := opts(t, s)
	o.RedirectURL, o.LoopbackRedirectURL = "", loopback
	p := &memoryStore{}
	m := manager(t, o, p)
	raw, err := m.BeginLoopback("initiating-session")
	if err != nil {
		t.Fatal(err)
	}
	auth, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	state := auth.Query().Get("state")
	if err := m.CompleteLoopback(context.Background(), loopback+"?code=example-code&state="+state, "initiating-session", func(s string) bool { return s == "initiating-session" }); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Zones(context.Background()); err != nil {
		t.Fatal(err)
	}
	if restarted := manager(t, o, p).Status(); refreshes.Load() != 1 || !restarted.Connected {
		t.Fatalf("grant did not survive refresh and restart: %+v, refreshes=%d", restarted, refreshes.Load())
	}
}
