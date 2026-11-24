package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"niceproxy/internal/model"
)

const (
	panelRuleSetting = "cloudflare.panel.rule"
	panelRuleTimeout = 8 * time.Second
)

type panelEdgeProvider interface {
	PanelRecord(context.Context, string) (string, bool, error)
	PanelSSLMode(context.Context, string) (string, string, error)
	IssuePanelOrigin(context.Context, string, string) (string, error)
	PanelStrictOverrideNeeded(context.Context, string, string) (bool, error)
	EnsurePanelStrict(context.Context, string, string) error
	RemovePanelStrict(context.Context, string, string) error
}

type panelEdgeStatus struct {
	Domain       string `json:"domain,omitempty"`
	DNSMode      string `json:"dnsMode,omitempty"`
	ZoneSSL      string `json:"zoneSSL,omitempty"`
	SSLSelection string `json:"sslSelection,omitempty"`
	State        string `json:"state"`
	Detail       string `json:"detail,omitempty"`
	revision     int64
}

type panelRule struct {
	Domain string
	ZoneID string
}

// RunPanelAutomation checks Cloudflare outside the request path.
func (a *App) RunPanelAutomation(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		attempt, cancel := context.WithTimeout(ctx, 40*time.Second)
		a.checkPanelEdge(attempt)
		cancel()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-a.panelEdgeWake:
		}
	}
}

func (a *App) queuePanelAutomation() {
	select {
	case a.panelEdgeWake <- struct{}{}:
	default:
	}
}

func (a *App) checkPanelEdge(ctx context.Context) {
	a.mu.Lock()
	status := a.panelEdge
	if status.Domain != a.config.PanelDomain {
		status = panelEdgeStatus{Domain: a.config.PanelDomain}
	}
	status.revision = a.config.Revision
	a.mu.Unlock()
	public := strings.Contains(status.Domain, ".")
	if !public {
		savedRule, err := a.db.Integration(panelRuleSetting)
		if err != nil {
			a.setPanelEdge(status, "waiting_access", "Cannot read the managed Cloudflare rule reference: "+err.Error())
			return
		}
		if len(savedRule) == 0 {
			a.setPanelEdge(status, "", "")
			return
		}
	}
	a.cfMu.Lock()
	provider := a.cf
	a.cfMu.Unlock()
	if provider == nil || !provider.Status().Connected {
		detail := "Cloudflare DNS mode is unverified. To automate Proxied TLS, connect Cloudflare from the management panel using the localhost OAuth callback. DNS Only can use public ACME."
		if !public {
			detail = "The previous panel's managed Cloudflare rule is pending cleanup. Reconnect Cloudflare with Config Settings Write for its zone."
		}
		a.setPanelEdge(status, "waiting_access", detail)
		return
	}
	a.reconcilePanelEdge(ctx, provider, status.Domain)
}

func (a *App) setPanelEdge(status panelEdgeStatus, state, detail string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.config.PanelDomain == status.Domain && a.config.Revision == status.revision {
		status.State, status.Detail = state, detail
		a.panelEdge = status
	}
}

func (a *App) reconcilePanelEdge(ctx context.Context, provider panelEdgeProvider, domain string) {
	a.mu.Lock()
	if a.config.PanelDomain != domain {
		a.mu.Unlock()
		return
	}
	revision := a.config.Revision
	prior := a.panelEdge
	a.mu.Unlock()
	status := panelEdgeStatus{Domain: domain, revision: revision}
	if !strings.Contains(domain, ".") {
		if err := a.cleanPanelRule(ctx, provider, domain, revision, panelRule{}); err != nil {
			a.setPanelEdge(status, "waiting_access", err.Error())
		} else {
			a.setPanelEdge(status, "", "")
		}
		return
	}
	// Retire a previous hostname independently of DNS for its replacement.
	cleanupErr := a.cleanPanelRule(ctx, provider, domain, revision, panelRule{Domain: domain})
	zoneID, proxied, err := provider.PanelRecord(ctx, domain)
	if err != nil {
		if prior.Domain == domain {
			status = prior
			status.revision = revision
		}
		a.setPanelEdge(status, "waiting_dns", errors.Join(err, cleanupErr).Error())
		return
	}
	status.DNSMode = "dns_only"
	if proxied {
		status.DNSMode = "proxied"
	}
	if !a.applyPanelEdge(ctx, status, false) {
		return
	}
	certificate := a.certificateStatus(ctx)
	if certificate.Domain != domain {
		return
	}
	if !proxied {
		if err := a.cleanPanelRule(ctx, provider, domain, revision, panelRule{}); err != nil {
			a.setPanelEdge(status, "waiting_access", err.Error())
		} else if certificate.TLSState == "served" {
			a.setPanelEdge(status, "dns_only_ready", "Origin TLS is verified for direct HTTPS. Public reachability depends on DNS and router forwarding.")
		} else {
			a.setPanelEdge(status, "waiting_acme", "DNS Only detected. Caddy is obtaining a public certificate over HTTP-01 or TLS-ALPN-01. Keep the public challenge ports reachable.")
		}
		return
	}

	var modeErr error
	status.ZoneSSL, status.SSLSelection, modeErr = provider.PanelSSLMode(ctx, zoneID)
	trusted := certificate.TLSState == "served" || certificate.TLSState == "cloudflare_origin"
	renew := trusted && certificate.ExpiresAt != nil && time.Until(*certificate.ExpiresAt) < 30*24*time.Hour
	if !trusted || renew {
		origin, ok := a.caddy.(interface {
			PreparePanelOrigin(context.Context, string, func(context.Context, string, string) (string, error)) (bool, error)
		})
		if !ok {
			a.setPanelEdge(status, "waiting_origin", "Automatic Cloudflare Origin CA is unavailable on this origin")
			return
		}
		changed, err := origin.PreparePanelOrigin(ctx, domain, provider.IssuePanelOrigin)
		if err != nil {
			a.setPanelEdge(status, "waiting_origin", err.Error())
			return
		}
		// Reload after an interrupted issue/reload as well as after issuance.
		if (changed || !trusted) && !a.applyPanelEdge(ctx, status, true) {
			return
		}
		certificate = a.certificateStatus(ctx)
		if certificate.Domain != domain {
			return
		}
		if certificate.TLSState != "served" && certificate.TLSState != "cloudflare_origin" {
			a.setPanelEdge(status, "waiting_origin", "The origin listener must serve a trusted certificate for the panel SNI before Cloudflare can use Full (strict). Check the local TLS diagnostic and HTTPS TCP port.")
			return
		}
	}
	if modeErr != nil {
		a.setPanelEdge(status, "waiting_access", modeErr.Error())
		return
	}
	rule := panelRule{Domain: domain, ZoneID: zoneID}
	if err := a.cleanPanelRule(ctx, provider, domain, revision, rule); err != nil {
		a.setPanelEdge(status, "waiting_access", err.Error())
		return
	}
	switch status.ZoneSSL {
	case "strict", "origin_pull":
		needsOverride, err := provider.PanelStrictOverrideNeeded(ctx, zoneID, domain)
		if err != nil {
			a.setPanelEdge(status, "waiting_access", err.Error())
			return
		}
		if !needsOverride {
			a.setPanelEdge(status, "strict_ready", "Cloudflare uses strict origin TLS, and the local SNI check passed. Public HTTPS requires TCP 443 forwarded to the Caddy HTTPS listener.")
			return
		}
		if status.ZoneSSL == "origin_pull" {
			a.setPanelEdge(status, "waiting_edge", "A Cloudflare Configuration Rule can override Strict (SSL-Only Origin Pull) for the panel. Verify the matching rule in Cloudflare.")
			return
		}
	case "off", "flexible", "full":
	default:
		a.setPanelEdge(status, "waiting_edge", fmt.Sprintf("Unexpected Cloudflare SSL mode %q", status.ZoneSSL))
		return
	}
	if err := a.ensurePanelRule(ctx, provider, rule, revision); err != nil {
		a.setPanelEdge(status, "waiting_access", err.Error())
		return
	}
	a.setPanelEdge(status, "strict_ready", "Full (strict) is configured for the panel hostname, and the local SNI check passed. Public HTTPS requires TCP 443 forwarded to the Caddy HTTPS listener.")
}

func (a *App) effectiveCaddyConfig() model.Config {
	cfg := a.config
	if a.panelEdge.Domain == cfg.PanelDomain && a.panelEdge.DNSMode != "" {
		cfg.PanelDomainProxied = a.panelEdge.DNSMode == "proxied"
		cfg.PanelDNSObserved = true
	}
	return cfg
}

func (a *App) applyPanelEdge(ctx context.Context, status panelEdgeStatus, reload bool) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if ctx.Err() != nil || a.config.PanelDomain != status.Domain || a.config.Revision != status.revision {
		return false
	}
	status.State = "checking_tls"
	a.panelEdge = status
	if !reload && !a.caddyUnconfirmed && a.activePanelDNSObserved && a.applied == a.config.Revision &&
		a.activePanelDomain == status.Domain && a.activePanelProxied == (status.DNSMode == "proxied") {
		return true
	}
	a.caddyUnconfirmed = a.caddyUnconfirmed || reload
	if err := a.reconcile(ctx); err != nil {
		a.panelEdge.State, a.panelEdge.Detail = "waiting_origin", err.Error()
		return false
	}
	return true
}

func (a *App) ensurePanelRule(ctx context.Context, provider panelEdgeProvider, rule panelRule, revision int64) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.config.Revision != revision || a.applied != revision || a.caddyUnconfirmed ||
		a.activePanelDomain != rule.Domain || !a.activePanelProxied {
		return fmt.Errorf("panel configuration changed during the origin TLS check; retrying Cloudflare setup")
	}
	prior, err := a.db.Integration(panelRuleSetting)
	if err != nil {
		return err
	}
	if len(prior) == 0 {
		body, _ := json.Marshal(rule)
		if err := a.db.SetIntegration(panelRuleSetting, body); err != nil {
			return fmt.Errorf("save managed Cloudflare rule reference: %w", err)
		}
	}
	request, cancel := context.WithTimeout(ctx, panelRuleTimeout)
	defer cancel()
	return provider.EnsurePanelStrict(request, rule.ZoneID, rule.Domain)
}

func (a *App) cleanPanelRule(ctx context.Context, provider panelEdgeProvider, domain string, revision int64, retain panelRule) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.config.PanelDomain != domain || a.config.Revision != revision {
		return fmt.Errorf("panel configuration changed; retrying Cloudflare rule cleanup")
	}
	body, err := a.db.Integration(panelRuleSetting)
	if err != nil || len(body) == 0 {
		return err
	}
	var rule panelRule
	if err := json.Unmarshal(body, &rule); err != nil {
		return fmt.Errorf("read managed Cloudflare rule reference: %w", err)
	}
	if rule.Domain == retain.Domain && (retain.ZoneID == "" || rule.ZoneID == retain.ZoneID) {
		return nil
	}
	if rule.Domain != domain && rule.Domain == a.activePanelDomain {
		return fmt.Errorf("the previous panel hostname is still active; reconcile the desired configuration before removing its Cloudflare rule")
	}
	request, cancel := context.WithTimeout(ctx, panelRuleTimeout)
	defer cancel()
	if err := provider.RemovePanelStrict(request, rule.ZoneID, rule.Domain); err != nil {
		return fmt.Errorf("clean up previous managed panel TLS rule: %w", err)
	}
	return a.db.SetIntegration(panelRuleSetting, nil)
}
