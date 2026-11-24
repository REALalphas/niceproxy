package model

import (
	"fmt"
	"strings"
)

type HTTPRoute struct {
	ID          string `json:"id"`
	Host        string `json:"host"`
	Path        string `json:"path"`
	StripPrefix bool   `json:"stripPrefix"`
	Target      string `json:"target"`
	TLS         string `json:"tls"` // auto, internal, off
	Enabled     bool   `json:"enabled"`
	Status      string `json:"status,omitempty"`
	Error       string `json:"error,omitempty"`
}

// ApplyDefaults keeps configurations written before path routing compatible.
func (c *Config) ApplyDefaults() {
	c.PanelDomain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(c.PanelDomain, ".")))
	c.PortOwners = c.PortOwners.Defaults()
	if c.HTTPRoutes == nil {
		c.HTTPRoutes = []HTTPRoute{}
	}
	if c.DirectRules == nil {
		c.DirectRules = []DirectRule{}
	}
	for i := range c.HTTPRoutes {
		if c.HTTPRoutes[i].Path == "" {
			c.HTTPRoutes[i].Path = "/"
		}
		if c.HTTPRoutes[i].TLS == "" {
			c.HTTPRoutes[i].TLS = "auto"
		}
	}
}

type ConnectionStats struct {
	Accepted  uint64 `json:"accepted"`
	Active    uint64 `json:"active"`
	Closed    uint64 `json:"closed"`
	Errors    uint64 `json:"errors"`
	Rejects   uint64 `json:"rejects"`
	StartedAt string `json:"startedAt"`
}

type PortOwners struct {
	HTTP  string `json:"http"`
	HTTPS string `json:"https"`
	HTTP3 string `json:"http3"`
}

func (p PortOwners) Defaults() PortOwners {
	if p.HTTP == "" {
		p.HTTP = "caddy"
	}
	if p.HTTPS == "" {
		p.HTTPS = "caddy"
	}
	if p.HTTP3 == "" {
		p.HTTP3 = "caddy"
	}
	return p
}
func (p PortOwners) Validate() error {
	for _, v := range []string{p.HTTP, p.HTTPS, p.HTTP3} {
		if v != "caddy" && v != "direct" {
			return fmt.Errorf("port owner must be caddy or direct")
		}
	}
	return nil
}

type DirectRule struct {
	Stats      *ConnectionStats `json:"stats,omitempty"`
	ID         string           `json:"id"`
	Protocol   string           `json:"protocol"`
	ListenHost string           `json:"listenHost"`
	ListenPort int              `json:"listenPort"`
	TargetHost string           `json:"targetHost"`
	TargetPort int              `json:"targetPort"`
	Enabled    bool             `json:"enabled"`
	Status     string           `json:"status,omitempty"`
	Error      string           `json:"error,omitempty"`
}

type Config struct {
	PortOwners PortOwners `json:"portOwners"`
	// PanelDomain is the optional public hostname reserved for the management panel.
	PanelDomain string `json:"panelDomain,omitempty"`
	// PanelDomainProxied records the Cloudflare proxy mode observed for the
	// panel record. Proxied mode requires an origin certificate or DNS-01.
	PanelDomainProxied bool         `json:"panelDomainProxied,omitempty"`
	Revision           int64        `json:"revision"`
	HTTPRoutes         []HTTPRoute  `json:"httpRoutes"`
	DirectRules        []DirectRule `json:"directRules"`
}

type Health struct {
	Status          string `json:"status"`
	State           string `json:"state,omitempty"`
	Caddy           bool   `json:"caddy"`
	Revision        int64  `json:"revision"`
	AppliedRevision int64  `json:"appliedRevision"`
	Error           string `json:"error,omitempty"`
	PanelDomain     string `json:"panelDomain,omitempty"`
	Certificate     string `json:"certificate,omitempty"`
}
