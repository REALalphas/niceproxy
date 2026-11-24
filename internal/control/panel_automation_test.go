package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"niceproxy/internal/model"
	"niceproxy/internal/proxy"
)

const automationPanel = "panel.example.com"

type testPanelOrigin struct {
	recordingPanelCaddy
	tlsState, storedState string
	nextTLS               string
	failProbe             bool
	loads, issues         int
	csr                   func(string) string
}

func (c *testPanelOrigin) ApplyConfig(ctx context.Context, cfg model.Config) error {
	c.loads++
	if c.nextTLS != "" {
		c.tlsState, c.nextTLS = c.nextTLS, ""
	}
	return c.recordingPanelCaddy.ApplyConfig(ctx, cfg)
}

func (c *testPanelOrigin) CertificateState(context.Context, string) (string, error) {
	return c.storedState, nil
}

func (c *testPanelOrigin) CertificateStatus(_ context.Context, host string) model.CertificateStatus {
	return model.CertificateStatus{Configured: true, Domain: host, State: "pending", TLSState: c.tlsState}
}

func (c *testPanelOrigin) PreparePanelOrigin(ctx context.Context, host string, issue func(context.Context, string, string) (string, error)) (bool, error) {
	c.issues++
	request := "test-csr"
	if c.csr != nil {
		request = c.csr(host)
	}
	if _, err := issue(ctx, host, request); err != nil {
		return false, err
	}
	if !c.failProbe {
		c.nextTLS = "cloudflare_origin"
	}
	return true, nil
}

type testPanelEdge struct {
	proxied, needsOverride               bool
	mode, selection                      string
	dnsErr, issueErr, ruleErr, removeErr error
	sslReads, issues, ensures            int
	removed                              []panelRule
	beforeRecord, beforeEnsure           func()
}

func (p *testPanelEdge) PanelRecord(context.Context, string) (string, bool, error) {
	if p.beforeRecord != nil {
		p.beforeRecord()
	}
	return "example-zone", p.proxied, p.dnsErr
}
func (p *testPanelEdge) PanelSSLMode(context.Context, string) (string, string, error) {
	p.sslReads++
	return p.mode, p.selection, nil
}
func (p *testPanelEdge) IssuePanelOrigin(context.Context, string, string) (string, error) {
	p.issues++
	return "test-pem", p.issueErr
}
func (p *testPanelEdge) PanelStrictOverrideNeeded(context.Context, string, string) (bool, error) {
	return p.needsOverride, nil
}
func (p *testPanelEdge) EnsurePanelStrict(context.Context, string, string) error {
	p.ensures++
	if p.beforeEnsure != nil {
		p.beforeEnsure()
	}
	return p.ruleErr
}
func (p *testPanelEdge) RemovePanelStrict(_ context.Context, zone, host string) error {
	p.removed = append(p.removed, panelRule{ZoneID: zone, Domain: host})
	return p.removeErr
}

func TestPanelAutomationModes(t *testing.T) {
	const denied = "permission denied"
	for _, tc := range []struct {
		name, mode, selection, initialTLS, want string
		proxied, failProbe, needsOverride       bool
		issueErr, ruleErr                       error
		issues, ensures                         int
	}{
		{name: "DNS Only while ACME is pending", initialTLS: "handshake_failed", want: "waiting_acme"},
		{name: "DNS Only public cert", initialTLS: "served", want: "dns_only_ready"},
		{name: "Automatic currently Flexible", mode: "flexible", selection: "automatic", proxied: true, initialTLS: "bootstrap", want: "strict_ready", issues: 1, ensures: 1},
		{name: "Custom Flexible", mode: "flexible", selection: "custom", proxied: true, initialTLS: "bootstrap", want: "strict_ready", issues: 1, ensures: 1},
		{name: "Full", mode: "full", proxied: true, initialTLS: "served", want: "strict_ready", ensures: 1},
		{name: "Full strict preserves setting", mode: "strict", proxied: true, initialTLS: "handshake_failed", want: "strict_ready", issues: 1},
		{name: "Strict with a weaker override", mode: "strict", proxied: true, initialTLS: "served", needsOverride: true, want: "strict_ready", ensures: 1},
		{name: "Strict origin pull preserves setting", mode: "origin_pull", proxied: true, initialTLS: "served", want: "strict_ready"},
		{name: "failed local verification prevents mutation", mode: "full", proxied: true, initialTLS: "wrong_host", failProbe: true, want: "waiting_origin", issues: 1},
		{name: "Origin CA permission", mode: "flexible", proxied: true, initialTLS: "bootstrap", issueErr: errors.New(denied), want: "waiting_origin", issues: 1},
		{name: "Config Rule permission", mode: "flexible", proxied: true, initialTLS: "served", ruleErr: errors.New(denied), want: "waiting_access", ensures: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			a, s, cookie := fixture(t)
			c := &testPanelOrigin{tlsState: tc.initialTLS, storedState: "missing", failProbe: tc.failProbe}
			a.caddy = c
			if err := a.ConfigurePanelDomain(automationPanel); err != nil {
				t.Fatal(err)
			}
			p := &testPanelEdge{proxied: tc.proxied, mode: tc.mode, selection: tc.selection, needsOverride: tc.needsOverride, issueErr: tc.issueErr, ruleErr: tc.ruleErr}
			p.beforeEnsure = func() {
				if c.tlsState != "served" && c.tlsState != "cloudflare_origin" {
					t.Fatal("strict rule attempted before validated origin TLS")
				}
			}
			a.reconcilePanelEdge(ctx, p, automationPanel)
			resp := call(t, s, http.MethodGet, "/api/panel-domain", "", cookie)
			defer resp.Body.Close()
			var state struct {
				PanelDomain string
				Proxied     bool
				Automation  panelEdgeStatus
			}
			if err := json.NewDecoder(resp.Body).Decode(&state); err != nil {
				t.Fatal(err)
			}
			if state.Automation.State != tc.want || state.Automation.SSLSelection != tc.selection || state.Proxied != tc.proxied || state.Automation.Detail == "" {
				t.Fatalf("panel API: %+v", state)
			}
			if state.PanelDomain != automationPanel || c.loaded.PanelDomainProxied != tc.proxied || a.applied != a.config.Revision {
				t.Fatalf("DNS detection changed the desired/applied revision: %+v, %+v", state, c.loaded)
			}
			if p.issues != tc.issues || p.ensures != tc.ensures || (!tc.proxied && p.sslReads != 0) {
				t.Fatalf("unexpected Cloudflare operations: %+v", p)
			}
			if (tc.issueErr != nil || tc.ruleErr != nil) && !strings.Contains(state.Automation.Detail, denied) {
				t.Fatalf("missing permission diagnostic: %+v", state)
			}
		})
	}
}

func TestPanelAutomationRecoversAppliedRevisionWithStaleProxyFlag(t *testing.T) {
	ctx := context.Background()
	a, s, cookie := fixture(t)
	c := &testPanelOrigin{tlsState: "handshake_failed", storedState: "missing"}
	a.caddy = c
	a.config = model.Config{
		Revision:    27,
		PanelDomain: automationPanel,
		HTTPRoutes: []model.HTTPRoute{{
			ID: "example-route", Host: "upstream.example.com", Path: "/",
			Target: "http://192.0.2.10", TLS: "auto", Enabled: true,
		}},
	}
	a.config.ApplyDefaults()
	if err := a.db.Save(a.config); err != nil {
		t.Fatal(err)
	}
	if err := a.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	p := &testPanelEdge{proxied: true, mode: "flexible", selection: "automatic"}
	a.reconcilePanelEdge(ctx, p, automationPanel)
	a.reconcilePanelEdge(ctx, p, automationPanel)
	cfg, applied, err := a.db.Load()
	if err != nil || cfg.Revision != 27 || applied != 27 || cfg.PanelDomainProxied || len(cfg.HTTPRoutes) != 1 {
		t.Fatalf("desired config changed during automation: %+v %d %v", cfg, applied, err)
	}
	if p.issues != 1 || c.loads != 3 || a.panelEdge.State != "strict_ready" {
		t.Fatalf("expected one bootstrap and stable recheck: %+v %+v", p, a.panelEdge)
	}
	resp := call(t, s, http.MethodGet, "/api/config", "", cookie)
	defer resp.Body.Close()
	var publicConfig model.Config
	if err := json.NewDecoder(resp.Body).Decode(&publicConfig); err != nil || len(publicConfig.HTTPRoutes) != 2 || !publicConfig.HTTPRoutes[0].SystemManaged {
		t.Fatalf("system route and saved route disagree: %+v (%v)", publicConfig, err)
	}

	restarted, err := New(a.db, c, proxy.NewManager(proxy.Options{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	p.dnsErr = errors.New("Cloudflare temporarily unavailable")
	restarted.reconcilePanelEdge(ctx, p, automationPanel)
	if !restarted.effectiveCaddyConfig().PanelDomainProxied || restarted.panelEdge.State != "waiting_dns" {
		t.Fatalf("observed DNS mode lost on restart: %+v", restarted.panelEdge)
	}
	p.dnsErr, p.proxied = nil, false
	c.tlsState = "handshake_failed"
	restarted.reconcilePanelEdge(ctx, p, automationPanel)
	if restarted.effectiveCaddyConfig().PanelDomainProxied || restarted.panelEdge.State != "waiting_acme" ||
		len(p.removed) != 1 || p.removed[0].Domain != automationPanel {
		t.Fatalf("expected DNS Only, ACME and owned rule cleanup: %+v %+v", restarted.panelEdge, p.removed)
	}
}

func TestPanelAutomationRetiresOldRuleWhileNewDNSIsUnavailable(t *testing.T) {
	for _, newDomain := range []string{"", "localhost", "new.example.com"} {
		t.Run(newDomain, func(t *testing.T) {
			a, _, _ := fixture(t)
			a.config.PanelDomain = newDomain
			rule := panelRule{Domain: automationPanel, ZoneID: "example-zone"}
			body, err := json.Marshal(rule)
			if err != nil {
				t.Fatal(err)
			}
			if err := a.db.SetIntegration(panelRuleSetting, body); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			p := &testPanelEdge{dnsErr: errors.New("no exact DNS record"), removeErr: errors.New("permission denied")}
			a.checkPanelEdge(ctx)
			if a.panelEdge.State != "waiting_access" || a.panelEdge.Detail == "" {
				t.Fatalf("missing cleanup prerequisite: %+v", a.panelEdge)
			}
			a.reconcilePanelEdge(ctx, p, newDomain)
			if !strings.Contains(a.panelEdge.Detail, "permission denied") {
				t.Fatalf("missing cleanup error: %+v", a.panelEdge)
			}
			p.removeErr = nil
			a.reconcilePanelEdge(ctx, p, newDomain)
			if len(p.removed) != 2 || p.removed[1] != rule {
				t.Fatalf("previous hostname rule not cleaned up: %+v", p.removed)
			}
			if got, err := a.db.Integration(panelRuleSetting); err != nil || len(got) != 0 {
				t.Fatalf("managed rule reference survived cleanup: %s (%v)", got, err)
			}
		})
	}
}

func TestPanelAutomationDiscardsDNSObservationFromEarlierRevision(t *testing.T) {
	a, _, _ := fixture(t)
	a.config.PanelDomain = automationPanel
	rule := panelRule{Domain: automationPanel, ZoneID: "example-zone"}
	body, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.db.SetIntegration(panelRuleSetting, body); err != nil {
		t.Fatal(err)
	}
	p := &testPanelEdge{
		beforeRecord: func() {
			// A pending DNS lookup must be discarded even if two edits return
			// the panel to the same hostname before that lookup finishes.
			a.mu.Lock()
			a.config.Revision += 2
			a.mu.Unlock()
		},
	}
	a.reconcilePanelEdge(context.Background(), p, automationPanel)
	if len(p.removed) != 0 || a.panelEdge.DNSMode != "" {
		t.Fatalf("outdated DNS result was applied: %+v %+v", a.panelEdge, p.removed)
	}
}
