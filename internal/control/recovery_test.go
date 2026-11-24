package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"

	"niceproxy/internal/model"
)

// This Caddy keeps serving a newly loaded config even when its acknowledgement
// is lost, as can happen when the admin request times out after application.
type uncertainCaddy struct {
	mu       sync.Mutex
	loads    int
	failNext bool
	routes   []model.HTTPRoute
}

func (c *uncertainCaddy) Apply(_ context.Context, routes []model.HTTPRoute) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loads++
	c.routes = append([]model.HTTPRoute{}, routes...)
	if c.failNext {
		c.failNext = false
		return errors.New("load applied but acknowledgement lost")
	}
	return nil
}
func (c *uncertainCaddy) Healthy(context.Context) bool { return true }

func TestRevertingAfterUnconfirmedCaddyLoadRequiresConfirmation(t *testing.T) {
	a, server, cookie := fixture(t)
	caddy := &uncertainCaddy{}
	a.mu.Lock()
	a.caddy = caddy
	a.mu.Unlock()
	resp := call(t, server, http.MethodPost, "/api/http-routes", `{"host":"recover.example.com","target":"http://127.0.0.1:31001","tls":"off","enabled":true}`, cookie)
	var route model.HTTPRoute
	err := json.NewDecoder(resp.Body).Decode(&route)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || route.Status != "healthy" {
		t.Fatalf("create: %s %+v %v", resp.Status, route, err)
	}
	caddy.mu.Lock()
	caddy.failNext = true
	caddy.mu.Unlock()
	resp = call(t, server, http.MethodPatch, "/api/http-routes/"+route.ID, `{"target":"http://127.0.0.1:31002"}`, cookie)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	a.mu.Lock()
	unconfirmed, applied := a.caddyUnconfirmed, a.applied
	a.mu.Unlock()
	if !unconfirmed || applied != -1 {
		t.Fatalf("unconfirmed=%v applied=%d", unconfirmed, applied)
	}
	resp = call(t, server, http.MethodPatch, "/api/http-routes/"+route.ID, `{"target":"http://127.0.0.1:31001"}`, cookie)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	caddy.mu.Lock()
	loads, actual := caddy.loads, caddy.routes[0].Target
	caddy.mu.Unlock()
	if loads != 3 || actual != "http://127.0.0.1:31001" {
		t.Fatalf("revert was not confirmed: loads=%d target=%s", loads, actual)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.caddyUnconfirmed || a.applied != a.config.Revision {
		t.Fatalf("final desired/applied: %d/%d unknown=%v", a.config.Revision, a.applied, a.caddyUnconfirmed)
	}
}

func TestReconcileRestoresMissingListener(t *testing.T) {
	a, server, cookie := fixture(t)
	port := unusedTCPPort(t)
	resp := call(t, server, http.MethodPost, "/api/direct-rules", fmt.Sprintf(`{"protocol":"tcp","listenHost":"127.0.0.1","listenPort":%d,"targetHost":"127.0.0.1","targetPort":9,"enabled":true}`, port), cookie)
	var rule model.DirectRule
	err := json.NewDecoder(resp.Body).Decode(&rule)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || !a.proxy.HasListener(rule.ID) {
		t.Fatalf("create: %s %+v %v", resp.Status, rule, err)
	}
	// A failed overlapping replacement and rollback has the same observable
	// outcome: the listener is gone, while control still knows the old spec.
	if err := a.proxy.Retire(rule.ID); err != nil {
		t.Fatal(err)
	}
	if a.proxy.HasListener(rule.ID) {
		t.Fatal("retired listener reported as bound")
	}
	resp = call(t, server, http.MethodPost, "/api/reconcile", "", cookie)
	resp.Body.Close()
	if resp.StatusCode != 200 || !a.proxy.HasListener(rule.ID) {
		t.Fatalf("listener not restored: %s", resp.Status)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.applied != a.config.Revision || a.applyError != "" {
		t.Fatalf("recovery state: %+v", a.snapshot())
	}
}
