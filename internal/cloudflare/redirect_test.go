package cloudflare

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func TestRedirectChangePreservesLoopbackAttemptAndGrant(t *testing.T) {
	const loopback = "http://localhost:9080/api/cloudflare/callback"
	const firstPanel = "https://first.example.test/api/cloudflare/callback"
	const nextPanel = "https://next.example.test/api/cloudflare/callback"

	var exchanges atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			exchanges.Add(1)
			if err := r.ParseForm(); err != nil || r.Form.Get("redirect_uri") != loopback {
				t.Errorf("loopback exchange redirect = %q, parse error = %v", r.Form.Get("redirect_uri"), err)
			}
			token(w)
		case "/zones":
			if r.Header.Get("Authorization") != "Bearer secret-access" {
				t.Error("the saved grant was not used")
			}
			fmt.Fprint(w, `{"success":true,"result":[]}`)
		default:
			t.Errorf("unexpected provider request %s", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	options := opts(t, provider)
	options.RedirectURL, options.LoopbackRedirectURL = firstPanel, loopback
	db := &memoryStore{}
	m := manager(t, options, db)
	const session = "admin-session"
	valid := func(value string) bool { return value == session }
	_, oldState, err := m.Begin(session)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := m.BeginLoopback(session)
	if err != nil {
		t.Fatal(err)
	}
	auth, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	callbackURL := loopback + "?" + url.Values{"code": {"example-code"}, "state": {auth.Query().Get("state")}}.Encode()

	if err := m.SetRedirectURL("http://remote.example.test/api/cloudflare/callback"); err == nil || m.Status().RedirectURL != firstPanel {
		t.Fatalf("invalid redirect update: error=%v, redirect=%q", err, m.Status().RedirectURL)
	}
	if err := m.SetRedirectURL(nextPanel); err != nil {
		t.Fatal(err)
	}
	if err := m.Complete(context.Background(), "old-code", oldState, oldState, valid); err == nil || exchanges.Load() != 0 {
		t.Fatalf("previous browser callback remained active: error=%v, exchanges=%d", err, exchanges.Load())
	}
	if err := m.CompleteLoopback(context.Background(), callbackURL, session, valid); err != nil {
		t.Fatal(err)
	}
	raw, _, err = m.Begin(session)
	if err != nil {
		t.Fatal(err)
	}
	auth, err = url.Parse(raw)
	if err != nil || auth.Query().Get("redirect_uri") != nextPanel {
		t.Fatalf("new authorization = %q, error=%v", raw, err)
	}

	options.RedirectURL = nextPanel
	restarted := manager(t, options, db)
	if status := restarted.Status(); !status.Connected || status.RedirectURL != nextPanel {
		t.Fatalf("grant was lost after the redirect changed: %+v", status)
	}
	if err := restarted.SetRedirectURL(""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := restarted.Begin(session); err == nil {
		t.Fatal("direct OAuth still starts without a direct callback")
	}
	if _, err := restarted.Zones(context.Background()); err != nil || exchanges.Load() != 1 {
		t.Fatalf("retained grant unavailable: %v, exchanges=%d", err, exchanges.Load())
	}
}

func TestOriginatingSessionMustSurviveTokenExchange(t *testing.T) {
	var session atomic.Bool
	session.Store(true)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session.Store(false)
		token(w)
	}))
	defer provider.Close()
	db := &memoryStore{}
	m := manager(t, opts(t, provider), db)
	_, state, err := m.Begin("admin-session")
	if err != nil {
		t.Fatal(err)
	}
	err = m.Complete(context.Background(), "example-code", state, state, func(string) bool { return session.Load() })
	if err == nil || err.Error() != "originating session expired" || m.Status().Connected {
		t.Fatalf("grant activated for an expired session: error=%v status=%+v", err, m.Status())
	}
	persisted, err := db.Integration("cloudflare")
	if err != nil || len(persisted) != 0 {
		t.Fatalf("grant was persisted after the session expired: saved=%t error=%v", len(persisted) != 0, err)
	}
	if err := m.Complete(context.Background(), "example-code", state, state, func(string) bool { return true }); err == nil {
		t.Fatal("consumed OAuth state could be replayed")
	}
}
