package model

import "time"

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

type DirectRule struct {
	ID         string `json:"id"`
	Protocol   string `json:"protocol"`
	ListenHost string `json:"listenHost"`
	ListenPort int    `json:"listenPort"`
	TargetHost string `json:"targetHost"`
	TargetPort int    `json:"targetPort"`
	Enabled    bool   `json:"enabled"`
	Status     string `json:"status,omitempty"`
	Error      string `json:"error,omitempty"`
}

type Config struct {
	Revision    int64        `json:"revision"`
	HTTPRoutes  []HTTPRoute  `json:"httpRoutes"`
	DirectRules []DirectRule `json:"directRules"`
}

type Health struct {
	Status          string `json:"status"`
	Caddy           bool   `json:"caddy"`
	Revision        int64  `json:"revision"`
	AppliedRevision int64  `json:"appliedRevision"`
	Error           string `json:"error,omitempty"`
}

type CertificateStatus struct {
	Configured bool       `json:"configured"`
	Domain     string     `json:"domain"`
	State      string     `json:"state"` // not_configured, pending, issued, expired, error
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	Error      string     `json:"error,omitempty"`
}
