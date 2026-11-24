// Package cloudflare authorizes one administrator's Cloudflare API access using public-client PKCE.
package cloudflare

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
)

type Persistence interface {
	Integration(string) ([]byte, error)
	SetIntegration(string, []byte) error
}
type Options struct {
	ClientID, RedirectURL, DataDir        string
	Scopes                                []string
	HTTPClient                            *http.Client
	AuthURL, TokenURL, RevokeURL, APIBase string
}
type Status struct {
	Configured  bool       `json:"configured"`
	Connected   bool       `json:"connected"`
	ClientID    string     `json:"clientId"`
	RedirectURL string     `json:"redirectUrl"`
	Scopes      []string   `json:"scopes"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	Error       string     `json:"error,omitempty"`
}
type Zone struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Account struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"account"`
}
type Record struct {
	ID      string `json:"id,omitempty"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
	TTL     int    `json:"ttl"`
}
type pending struct {
	verifier, origin string
	until            time.Time
}
type stored struct {
	ClientID, RedirectURL string
	Scopes                []string
	Access, Refresh       string
	ExpiresAt             time.Time
}

var errTokenRejected = errors.New("Cloudflare token request rejected")

type Manager struct {
	op      sync.Mutex // Serializes connection changes and DNS mutations.
	mu      sync.Mutex // Serializes token use, refresh, rotation, and persistence.
	o       Options
	p       Persistence
	pending map[string]pending
	tok     stored
	key     []byte
	err     string
	dirty   bool // a rotated grant that must be saved before further use
}

// SetRedirectURL keeps the provider's advertised callback synchronized with
// the validated panel domain. A redirect change invalidates the old grant,
// because Cloudflare binds grants to the registered callback configuration.
func (m *Manager) SetRedirectURL(value string) error {
	if err := validRedirect(value); err != nil {
		return err
	}
	m.op.Lock()
	defer m.op.Unlock()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.o.RedirectURL = value
	m.pending = make(map[string]pending)
	m.tok = stored{}
	m.dirty = false
	if m.p != nil {
		if err := m.p.SetIntegration("cloudflare", nil); err != nil {
			return err
		}
	}
	return nil
}

func New(o Options, p Persistence) (*Manager, error) {
	o.Scopes = append([]string(nil), o.Scopes...)
	sort.Strings(o.Scopes)
	if o.AuthURL == "" {
		o.AuthURL = "https://dash.cloudflare.com/oauth2/auth"
	}
	if o.TokenURL == "" {
		o.TokenURL = "https://dash.cloudflare.com/oauth2/token"
	}
	if o.RevokeURL == "" {
		o.RevokeURL = "https://dash.cloudflare.com/oauth2/revoke"
	}
	if o.APIBase == "" {
		o.APIBase = "https://api.cloudflare.com/client/v4"
	}
	client := http.Client{Timeout: 20 * time.Second}
	if o.HTTPClient != nil {
		client = *o.HTTPClient
		if client.Timeout <= 0 || client.Timeout > 20*time.Second {
			client.Timeout = 20 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	o.HTTPClient = &client
	m := &Manager{o: o, p: p, pending: make(map[string]pending)}
	if !m.configured() {
		return m, nil
	}
	if err := validRedirect(o.RedirectURL); err != nil {
		return nil, err
	}
	for _, s := range o.Scopes {
		if s == "" || strings.ContainsAny(s, " \t\r\n") {
			return nil, errors.New("invalid configured OAuth scope")
		}
	}
	for _, s := range []string{o.AuthURL, o.TokenURL, o.RevokeURL, o.APIBase} {
		u, e := url.Parse(s)
		if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && u.Scheme != "http") {
			return nil, errors.New("invalid Cloudflare endpoint")
		}
	}
	if p != nil {
		if err := m.load(); err != nil {
			m.err = err.Error()
		}
	}
	return m, nil
}
func (m *Manager) configured() bool { return m.o.ClientID != "" && len(m.o.Scopes) > 0 }
func validRedirect(s string) error {
	u, e := url.Parse(s)
	if e != nil || !u.IsAbs() || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || strings.Contains(s, "#") || u.Path != "/api/cloudflare/callback" || u.RawPath != "" {
		return errors.New("invalid redirect URL")
	}
	if u.Scheme == "https" {
		return nil
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && (u.Hostname() == "localhost" || ip != nil && ip.IsLoopback()) {
		return nil
	}
	return errors.New("redirect must be HTTPS or loopback HTTP")
}

// load never replaces an existing key, including when its contents or permissions are invalid.
func (m *Manager) load() error {
	b, e := m.p.Integration("cloudflare")
	if e != nil {
		return errors.New("cannot load Cloudflare credentials")
	}
	if m.o.DataDir == "" {
		return errors.New("Cloudflare data directory required")
	}
	if e = os.MkdirAll(m.o.DataDir, 0700); e != nil {
		return errors.New("cannot access Cloudflare data directory")
	}
	path := filepath.Join(m.o.DataDir, "cloudflare.key")
	key, e := readKey(path)
	if os.IsNotExist(e) {
		if len(b) > 0 {
			return errors.New("Cloudflare encryption key missing")
		}
		key, e = createKey(path)
	}
	if e != nil {
		return errors.New("cannot read secure Cloudflare encryption key")
	}
	m.key = key
	if len(b) == 0 {
		return nil
	}
	plain, e := decrypt(key, b)
	if e != nil {
		return errors.New("cannot decrypt Cloudflare credentials")
	}
	var t stored
	if json.Unmarshal(plain, &t) != nil {
		return errors.New("invalid saved Cloudflare credentials")
	}
	if t.ClientID != m.o.ClientID || t.RedirectURL != m.o.RedirectURL || !reflect.DeepEqual(t.Scopes, m.o.Scopes) {
		return errors.New("saved Cloudflare authorization configuration changed")
	}
	m.tok = t
	return nil
}
func readKey(path string) ([]byte, error) {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return nil, e
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if st.Mode() != 0600 {
		return nil, errors.New("insecure key permissions")
	}
	if s, ok := st.Sys().(*syscall.Stat_t); !ok || s.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("invalid key owner")
	}
	b, e := io.ReadAll(io.LimitReader(f, 33))
	if e != nil || len(b) != 32 {
		return nil, errors.New("invalid key")
	}
	return b, nil
}
func createKey(path string) ([]byte, error) {
	// Publish an already-written inode atomically: concurrent initializers cannot observe a partial key.
	f, e := os.CreateTemp(filepath.Dir(path), ".cloudflare-key-*")
	if e != nil {
		return nil, e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	k := make([]byte, 32)
	if _, e = rand.Read(k); e != nil {
		return nil, e
	}
	if e = f.Chmod(0600); e != nil {
		return nil, e
	}
	if _, e = f.Write(k); e != nil {
		return nil, e
	}
	if e = f.Sync(); e != nil {
		return nil, e
	}
	if e = os.Link(f.Name(), path); e != nil && !os.IsExist(e) {
		return nil, e
	}
	return readKey(path)
}
func encrypt(k, p []byte) ([]byte, error) {
	b, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	n := make([]byte, g.NonceSize())
	if _, e = rand.Read(n); e != nil {
		return nil, e
	}
	return g.Seal(n, n, p, []byte("niceproxy/cloudflare/v1")), nil
}
func decrypt(k, p []byte) ([]byte, error) {
	b, e := aes.NewCipher(k)
	if e != nil {
		return nil, e
	}
	g, e := cipher.NewGCM(b)
	if e != nil {
		return nil, e
	}
	if len(p) < g.NonceSize() {
		return nil, errors.New("bad ciphertext")
	}
	return g.Open(nil, p[:g.NonceSize()], p[g.NonceSize():], []byte("niceproxy/cloudflare/v1"))
}
func (m *Manager) saveLocked(t stored) error {
	if m.p == nil {
		return nil
	}
	if t.Access == "" && t.Refresh == "" {
		if m.p.SetIntegration("cloudflare", nil) != nil {
			return errors.New("cannot clear saved Cloudflare credentials")
		}
		return nil
	}
	if len(m.key) != 32 {
		return errors.New("Cloudflare encryption unavailable")
	}
	b, _ := json.Marshal(t)
	enc, e := encrypt(m.key, b)
	if e != nil {
		return errors.New("cannot encrypt Cloudflare credentials")
	}
	if m.p.SetIntegration("cloudflare", enc) != nil {
		return errors.New("cannot save Cloudflare credentials")
	}
	return nil
}
func (m *Manager) Status() Status {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := Status{Configured: m.configured(), Connected: m.tok.Access != "", ClientID: m.o.ClientID, RedirectURL: m.o.RedirectURL, Scopes: append([]string(nil), m.o.Scopes...), Error: m.err}
	if !m.tok.ExpiresAt.IsZero() {
		t := m.tok.ExpiresAt
		s.ExpiresAt = &t
	}
	return s
}
func randstr() (string, error) {
	b := make([]byte, 32)
	_, e := rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b), e
}
func (m *Manager) Begin(sessionHash string) (string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.configured() {
		return "", "", errors.New("Cloudflare not configured")
	}
	if sessionHash == "" || len(sessionHash) > 1024 {
		return "", "", errors.New("valid originating session required")
	}
	if m.p != nil && len(m.key) != 32 {
		return "", "", errors.New("Cloudflare encryption unavailable")
	}
	for k, v := range m.pending {
		if !time.Now().Before(v.until) {
			delete(m.pending, k)
		}
	}
	if len(m.pending) >= 32 {
		return "", "", errors.New("too many pending authorizations")
	}
	state, e := randstr()
	if e != nil {
		return "", "", errors.New("cannot create authorization state")
	}
	ver, e := randstr()
	if e != nil {
		return "", "", errors.New("cannot create authorization verifier")
	}
	m.pending[state] = pending{verifier: ver, origin: sessionHash, until: time.Now().Add(10 * time.Minute)}
	sum := sha256.Sum256([]byte(ver))
	q := url.Values{"response_type": {"code"}, "client_id": {m.o.ClientID}, "redirect_uri": {m.o.RedirectURL}, "scope": {strings.Join(m.o.Scopes, " ")}, "state": {state}, "code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	return m.o.AuthURL + "?" + q.Encode(), state, nil
}
func (m *Manager) Complete(ctx context.Context, code, state, cookie string, valid func(string) bool) error {
	m.op.Lock()
	defer m.op.Unlock()
	m.mu.Lock()
	v, ok := m.pending[state]
	delete(m.pending, state)
	m.mu.Unlock()
	a, b := sha256.Sum256([]byte(state)), sha256.Sum256([]byte(cookie))
	if !ok || code == "" || !time.Now().Before(v.until) || subtle.ConstantTimeCompare(a[:], b[:]) != 1 || valid == nil || !valid(v.origin) {
		return errors.New("invalid authorization state")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	t, e := m.exchange(ctx, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {m.o.ClientID}, "redirect_uri": {m.o.RedirectURL}, "code_verifier": {v.verifier}}, "")
	if e != nil {
		return e
	}
	// Recheck the originating login after the potentially slow exchange, too.
	if !valid(v.origin) {
		return errors.New("originating session expired")
	}
	if e = m.saveLocked(t); e != nil {
		m.err = e.Error()
		return e
	}
	m.tok = t
	m.err = ""
	return nil
}
func (m *Manager) exchange(ctx context.Context, form url.Values, oldRefresh string) (stored, error) {
	req, e := http.NewRequestWithContext(ctx, "POST", m.o.TokenURL, strings.NewReader(form.Encode()))
	if e != nil {
		return stored{}, errors.New("invalid token endpoint")
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, e := m.o.HTTPClient.Do(req)
	if e != nil {
		return stored{}, errors.New("Cloudflare token request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 429 {
			return stored{}, errTokenRejected
		}
		return stored{}, errors.New("Cloudflare token request failed")
	}
	var x struct {
		Access    string          `json:"access_token"`
		Refresh   string          `json:"refresh_token"`
		ExpiresIn int64           `json:"expires_in"`
		ExpiresAt json.RawMessage `json:"expires_at"`
		Type      string          `json:"token_type"`
	}
	if readJSON(resp.Body, 1<<20, &x) != nil || x.Access == "" || (x.Type != "" && !strings.EqualFold(x.Type, "bearer")) {
		return stored{}, errors.New("invalid Cloudflare token response")
	}
	t := stored{ClientID: m.o.ClientID, RedirectURL: m.o.RedirectURL, Scopes: append([]string(nil), m.o.Scopes...), Access: x.Access, Refresh: x.Refresh}
	if t.Refresh == "" {
		t.Refresh = oldRefresh
	}
	if x.ExpiresIn > 0 && x.ExpiresIn <= 315360000 {
		t.ExpiresAt = time.Now().Add(time.Duration(x.ExpiresIn) * time.Second)
	} else if len(x.ExpiresAt) > 0 {
		var seconds int64
		var date string
		if json.Unmarshal(x.ExpiresAt, &seconds) == nil && seconds > 0 {
			t.ExpiresAt = time.Unix(seconds, 0)
		} else if json.Unmarshal(x.ExpiresAt, &date) == nil {
			t.ExpiresAt, _ = time.Parse(time.RFC3339, date)
		}
	}
	if t.ExpiresAt.IsZero() || !t.ExpiresAt.After(time.Now()) {
		return stored{}, errors.New("invalid Cloudflare token expiry")
	}
	return t, nil
}
func readJSON(r io.Reader, limit int64, out any) error {
	b, e := io.ReadAll(io.LimitReader(r, limit+1))
	if e != nil || int64(len(b)) > limit {
		return errors.New("response too large or unreadable")
	}
	return json.Unmarshal(b, out)
}
func (m *Manager) tokenLocked(ctx context.Context) (string, error) {
	if m.dirty {
		if err := m.saveLocked(m.tok); err != nil {
			m.err = err.Error()
			return "", err
		}
		m.dirty = false
		m.err = ""
	}
	if m.tok.Access == "" {
		return "", errors.New("Cloudflare not connected")
	}
	if time.Now().Add(30 * time.Second).Before(m.tok.ExpiresAt) {
		return m.tok.Access, nil
	}
	if m.tok.Refresh == "" {
		m.invalidateLocked()
		return "", errors.New("Cloudflare authorization expired")
	}
	t, e := m.exchange(ctx, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {m.tok.Refresh}, "client_id": {m.o.ClientID}}, m.tok.Refresh)
	if e != nil {
		if errors.Is(e, errTokenRejected) {
			m.invalidateLocked()
			return "", errors.New("Cloudflare authorization expired")
		}
		m.err = "Cloudflare refresh failed"
		return "", errors.New(m.err)
	}
	if e = m.saveLocked(t); e != nil {
		// The old refresh token may already be invalid. Retain its replacement
		// and retry durable storage before allowing another API operation.
		m.tok = t
		m.dirty = true
		m.err = e.Error()
		return "", e
	}
	m.tok = t
	m.err = ""
	return t.Access, nil
}
func (m *Manager) invalidateLocked() {
	m.tok = stored{}
	m.dirty = false
	m.err = "Cloudflare authorization expired"
	if e := m.saveLocked(m.tok); e != nil {
		m.err = e.Error()
	}
}
func (m *Manager) Disconnect(ctx context.Context) error {
	m.op.Lock()
	defer m.op.Unlock()
	m.mu.Lock()
	t := m.tok
	m.pending = make(map[string]pending)
	e := m.saveLocked(stored{})
	if e != nil {
		m.err = e.Error()
		m.mu.Unlock()
		return e
	}
	m.tok = stored{}
	m.dirty = false
	m.err = ""
	m.mu.Unlock()
	var revokeErr error
	for _, token := range []string{t.Refresh, t.Access} {
		if token == "" {
			continue
		}
		req, x := http.NewRequestWithContext(ctx, "POST", m.o.RevokeURL, strings.NewReader(url.Values{"token": {token}, "client_id": {m.o.ClientID}}.Encode()))
		if x != nil {
			revokeErr = errors.New("Cloudflare revocation failed")
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, x := m.o.HTTPClient.Do(req)
		if x != nil {
			revokeErr = errors.New("Cloudflare revocation failed")
			continue
		}
		resp.Body.Close()
		if resp.StatusCode/100 != 2 {
			revokeErr = errors.New("Cloudflare revocation failed")
		}
	}
	if e != nil {
		m.mu.Lock()
		m.err = e.Error()
		m.mu.Unlock()
		return e
	}
	return revokeErr
}

type envelope struct {
	Result  json.RawMessage `json:"result"`
	Success bool            `json:"success"`
	Errors  []struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
	ResultInfo struct {
		Page       int `json:"page"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func (m *Manager) api(ctx context.Context, method, path string, body any, out any) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	token, e := m.tokenLocked(ctx)
	if e != nil {
		return 0, e
	}
	var r io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return 0, errors.New("invalid Cloudflare request")
		}
		r = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(m.o.APIBase, "/")+path, r)
	if e != nil {
		return 0, errors.New("invalid Cloudflare API endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, e := m.o.HTTPClient.Do(req)
	if e != nil {
		return 0, errors.New("Cloudflare API request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 {
		m.invalidateLocked()
		return 0, errors.New("Cloudflare authorization expired")
	}
	if resp.StatusCode/100 != 2 {
		return 0, fmt.Errorf("Cloudflare API request failed (HTTP %d)", resp.StatusCode)
	}
	var env envelope
	if readJSON(resp.Body, 4<<20, &env) != nil {
		return 0, errors.New("invalid Cloudflare API response")
	}
	if !env.Success || len(env.Errors) > 0 {
		return 0, errors.New("Cloudflare API request rejected")
	}
	if out != nil && json.Unmarshal(env.Result, out) != nil {
		return 0, errors.New("invalid Cloudflare API result")
	}
	return env.ResultInfo.TotalPages, nil
}
func (m *Manager) Zones(ctx context.Context) ([]Zone, error) {
	all := []Zone{}
	for p := 1; p <= 100; p++ {
		var z []Zone
		pages, e := m.api(ctx, "GET", fmt.Sprintf("/zones?page=%d&per_page=50", p), nil, &z)
		if e != nil {
			return nil, e
		}
		all = append(all, z...)
		if pages > 0 && p >= pages || pages == 0 && len(z) < 50 {
			return all, nil
		}
		if p == 100 {
			return nil, errors.New("Cloudflare zone pagination limit exceeded")
		}
	}
	return all, nil
}
func validHex(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, e := hex.DecodeString(s)
	return e == nil
}
func (m *Manager) Records(ctx context.Context, zone string) ([]Record, error) {
	if !validHex(zone) {
		return nil, errors.New("invalid zone id")
	}
	all := []Record{}
	for p := 1; p <= 100; p++ {
		var r []Record
		pages, e := m.api(ctx, "GET", fmt.Sprintf("/zones/%s/dns_records?page=%d&per_page=50", zone, p), nil, &r)
		if e != nil {
			return nil, e
		}
		all = append(all, r...)
		if pages > 0 && p >= pages || pages == 0 && len(r) < 50 {
			return all, nil
		}
		if p == 100 {
			return nil, errors.New("Cloudflare record pagination limit exceeded")
		}
	}
	return all, nil
}
func hostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func (m *Manager) WriteRecord(ctx context.Context, zone, id string, r Record) (Record, error) {
	m.op.Lock()
	defer m.op.Unlock()
	if !validHex(zone) || (id != "" && !validHex(id)) {
		return Record{}, errors.New("invalid zone or record id")
	}
	r.Type = strings.ToUpper(r.Type)
	r.Name = strings.ToLower(strings.TrimSuffix(r.Name, "."))
	r.ID = ""
	if r.Type != "A" && r.Type != "AAAA" && r.Type != "CNAME" {
		return Record{}, errors.New("unsupported record type")
	}
	if !hostname(r.Name) {
		return Record{}, errors.New("invalid record hostname")
	}
	if r.TTL == 0 {
		r.TTL = 1
	}
	if r.TTL != 1 && (r.TTL < 60 || r.TTL > 86400) {
		return Record{}, errors.New("invalid TTL")
	}
	ip := net.ParseIP(r.Content)
	switch r.Type {
	case "A":
		if ip == nil || ip.To4() == nil {
			return Record{}, errors.New("invalid IPv4 content")
		}
	case "AAAA":
		if ip == nil || ip.To4() != nil {
			return Record{}, errors.New("invalid IPv6 content")
		}
	case "CNAME":
		r.Content = strings.ToLower(strings.TrimSuffix(r.Content, "."))
		if !hostname(r.Content) || !strings.Contains(r.Content, ".") || net.ParseIP(r.Content) != nil {
			return Record{}, errors.New("invalid CNAME target")
		}
	}
	var actual Zone
	if _, e := m.api(ctx, "GET", "/zones/"+zone, nil, &actual); e != nil {
		return Record{}, e
	}
	name := strings.ToLower(strings.TrimSuffix(actual.Name, "."))
	if actual.ID != zone || !hostname(name) || !(r.Name == name || strings.HasSuffix(r.Name, "."+name)) {
		return Record{}, errors.New("record hostname is outside selected zone")
	}
	path := "/zones/" + zone + "/dns_records"
	method := "POST"
	if id != "" {
		method = "PATCH"
		path += "/" + id
	}
	var out Record
	if _, e := m.api(ctx, method, path, r, &out); e != nil {
		return Record{}, e
	}
	return out, nil
}
