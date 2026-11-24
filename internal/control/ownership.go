package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"niceproxy/internal/model"
)

func (a *App) panelDomainConflict(c model.Config) error {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.PanelDomain), "."))
	if domain == "" {
		return nil
	}
	if err := validatePanelDomain(domain); err != nil {
		return err
	}
	for _, r := range c.HTTPRoutes {
		if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(r.Host), "."), domain) {
			return conflict("configured panel domain %q conflicts with HTTP route %s; choose another panel domain or disable/delete that route", domain, r.ID)
		}
	}
	return nil
}

type conflictError struct{ message string }

func (e *conflictError) Error() string          { return e.message }
func conflict(format string, args ...any) error { return &conflictError{fmt.Sprintf(format, args...)} }
func mutationFail(w http.ResponseWriter, err error) {
	var c *conflictError
	if errors.As(err, &c) {
		fail(w, 409, err.Error())
	} else {
		fail(w, 500, err.Error())
	}
}

func (a *App) ownershipConflict(c model.Config) error {
	if err := a.panelDomainConflict(c); err != nil {
		return err
	}
	o := c.PortOwners.Defaults()
	for _, r := range c.HTTPRoutes {
		if !r.Enabled {
			continue
		}
		if r.TLS == "off" && o.HTTP != "caddy" {
			return conflict("HTTP route %s requires HTTP owner caddy; disable it first", r.ID)
		}
		if r.TLS != "off" && o.HTTPS != "caddy" && o.HTTP3 != "caddy" {
			return conflict("HTTP route %s requires HTTPS or HTTP3 owner caddy; disable it first", r.ID)
		}
		if (r.TLS == "auto" || r.TLS == "") && o.HTTP != "caddy" && o.HTTPS != "caddy" {
			return conflict("HTTP route %s requires a Caddy TCP ACME challenge port; disable it first", r.ID)
		}
	}
	for i, r := range c.DirectRules {
		if !r.Enabled {
			continue
		}
		if a.reserved[r.ListenPort] {
			return conflict("direct rule %s uses reserved management port %d", r.ID, r.ListenPort)
		}
		owner := "direct"
		if r.Protocol == "tcp" && r.ListenPort == a.httpPort {
			owner = o.HTTP
		}
		if r.Protocol == "tcp" && r.ListenPort == a.httpsPort {
			owner = o.HTTPS
		}
		if r.Protocol == "udp" && r.ListenPort == a.httpsPort {
			owner = o.HTTP3
		}
		if owner == "caddy" {
			return conflict("direct rule %s conflicts with Caddy ownership of %s port %d; disable it first", r.ID, r.Protocol, r.ListenPort)
		}
		for _, other := range c.DirectRules[:i] {
			if !other.Enabled || other.Protocol != r.Protocol || other.ListenPort != r.ListenPort {
				continue
			}
			x, y := net.ParseIP(r.ListenHost), net.ParseIP(other.ListenHost)
			if x != nil && y != nil && (x.Equal(y) || (x.IsUnspecified() && (x.To4() == nil || y.To4() != nil)) || (y.IsUnspecified() && (y.To4() == nil || x.To4() != nil))) {
				return conflict("direct rule %s conflicts with enabled direct rule %s", r.ID, other.ID)
			}
		}
	}
	return nil
}

func (a *App) panelDomainAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		warning := ""
		if a.config.PanelDomain != "" && (a.panelEdge.Domain != a.config.PanelDomain || a.panelEdge.DNSMode == "") && a.certificateState() != "valid" {
			if a.effectiveCaddyConfig().PanelDomainProxied {
				warning = "The local setting says Cloudflare Proxied. Configure Cloudflare API access to detect the record and provision Origin CA, or mount a trusted origin certificate and use Full (strict)."
			} else {
				warning = "The local setting says DNS-only. Check the actual Cloudflare record and public forwarding of TCP 80 for HTTP-01 or TCP 443 for TLS-ALPN-01."
			}
		}
		response := map[string]any{"panelDomain": a.config.PanelDomain, "proxied": a.effectiveCaddyConfig().PanelDomainProxied, "proxyWarning": warning}
		if a.panelEdge.Domain == a.config.PanelDomain && a.panelEdge.State != "" {
			response["automation"] = a.panelEdge
		}
		write(w, 200, response)
		return
	}
	if r.Method != "PATCH" && r.Method != "PUT" {
		fail(w, 405, "PATCH required")
		return
	}
	var body struct {
		PanelDomain *string `json:"panelDomain"`
		Domain      *string `json:"domain"`
		Proxied     *bool   `json:"proxied"`
	}
	if err := decode(w, r, &body); err != nil {
		fail(w, 400, err.Error())
		return
	}
	c := a.config
	domain := body.PanelDomain
	if domain == nil {
		domain = body.Domain
	}
	if domain != nil {
		c.PanelDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(*domain), "."))
	}
	if err := validatePanelDomain(c.PanelDomain); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if body.Proxied != nil {
		c.PanelDomainProxied = *body.Proxied
	}
	previousDomain := a.config.PanelDomain
	if err := a.commit(r.Context(), c); err != nil {
		mutationFail(w, err)
		return
	}
	if previousDomain != c.PanelDomain {
		if err := a.syncCloudflareRedirect(c.PanelDomain); err != nil {
			a.state = "waiting_acme"
			a.applyError = err.Error()
		}
	}
	a.queuePanelAutomation()
	write(w, 200, a.snapshot())
}

func classifyState(message string) string {
	l := strings.ToLower(message)
	switch {
	case strings.Contains(l, "dns"):
		return "waiting_dns"
	case strings.Contains(l, "acme") || strings.Contains(l, "certificate") || strings.Contains(l, "tls"):
		return "waiting_acme"
	case strings.Contains(l, "corrupt") || strings.Contains(l, "invalid saved"):
		return "unrecoverable_corruption"
	default:
		return "partially_applied"
	}
}

func (a *App) certificateState() string {
	if a.config.PanelDomain == "" {
		return "not_configured"
	}
	if c, ok := a.caddy.(interface {
		CertificateState(context.Context, string) (string, error)
	}); ok {
		state, err := c.CertificateState(context.Background(), a.config.PanelDomain)
		if err != nil && state == "" {
			return "invalid"
		}
		return state
	}
	return "unknown"
}

func (a *App) portOwners(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		write(w, 200, map[string]any{"httpPort": a.httpPort, "httpsPort": a.httpsPort, "owners": a.config.PortOwners})
		return
	}
	if r.Method != "PATCH" {
		fail(w, 405, "method not allowed")
		return
	}
	// Pointer fields distinguish an omitted field from an invalid empty owner.
	var patch struct {
		HTTP  *string `json:"http"`
		HTTPS *string `json:"https"`
		HTTP3 *string `json:"http3"`
	}
	if err := decode(w, r, &patch); err != nil {
		fail(w, 400, err.Error())
		return
	}
	c := a.config
	if patch.HTTP != nil {
		c.PortOwners.HTTP = *patch.HTTP
	}
	if patch.HTTPS != nil {
		c.PortOwners.HTTPS = *patch.HTTPS
	}
	if patch.HTTP3 != nil {
		c.PortOwners.HTTP3 = *patch.HTTP3
	}
	if err := c.PortOwners.Validate(); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if err := a.commit(r.Context(), c); err != nil {
		mutationFail(w, err)
		return
	}
	write(w, 200, a.snapshot())
}

func (a *App) applyCaddy(ctx context.Context, cfg model.Config) error {
	if c, ok := a.caddy.(interface {
		ApplyConfig(context.Context, model.Config) error
	}); ok {
		return c.ApplyConfig(ctx, cfg)
	}
	return a.caddy.Apply(ctx, a.config.HTTPRoutes)
}
func (a *App) retire(id string) error { return a.proxy.Retire(id) }
