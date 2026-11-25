package model

import (
	"strings"
	"testing"
)

func TestConfigDefaultsPreserveExplicitSettings(t *testing.T) {
	c := Config{
		PanelDomain: "  EXAMPLE.COM.",
		PortOwners:  PortOwners{HTTPS: "direct"},
		HTTPRoutes:  []HTTPRoute{{}, {Path: "/api", TLS: "off", StripPrefix: true}},
	}
	c.ApplyDefaults()
	if c.PanelDomain != "example.com" || c.DirectRules == nil || c.HTTPRoutes[0].Path != "/" || c.HTTPRoutes[0].TLS != "auto" {
		t.Fatalf("missing defaults: %+v", c)
	}
	if c.PortOwners != (PortOwners{HTTP: "caddy", HTTPS: "direct", HTTP3: "caddy"}) {
		t.Fatalf("owners: %+v", c.PortOwners)
	}
	if c.HTTPRoutes[1] != (HTTPRoute{Path: "/api", TLS: "off", StripPrefix: true}) {
		t.Fatalf("explicit route changed: %+v", c.HTTPRoutes[1])
	}
	var empty Config
	empty.ApplyDefaults()
	if empty.HTTPRoutes == nil || empty.DirectRules == nil {
		t.Fatalf("empty route lists must be initialized: %+v", empty)
	}
}

func TestPortOwnersValidation(t *testing.T) {
	for _, tc := range []struct {
		name   string
		owners PortOwners
		valid  bool
	}{
		{"all caddy", PortOwners{"caddy", "caddy", "caddy"}, true},
		{"mixed", PortOwners{"direct", "caddy", "direct"}, true},
		{"invalid http", PortOwners{"other", "caddy", "caddy"}, false},
		{"invalid https", PortOwners{"caddy", "", "caddy"}, false},
		{"invalid http3", PortOwners{"caddy", "caddy", "Caddy"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.owners.Validate(); (err == nil) != tc.valid {
				t.Fatalf("Validate() = %v, want valid=%v", err, tc.valid)
			}
		})
	}
}

func TestNormalizeRoutePathBoundaries(t *testing.T) {
	maximum := "/" + strings.Repeat("é", 1023) + "a"
	for _, tc := range []struct {
		name  string
		input string
		valid bool
	}{
		{"2048 bytes", maximum, true},
		{"2049 bytes", maximum + "a", false},
		{"unicode whitespace", "/a\u00a0b", false},
		{"unicode control", "/a\u0001b", false},
		{"terminal dot segment", "/a/..", false},
		{"literal dots", "/a/..name", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeRoutePath(tc.input)
			if (err == nil) != tc.valid || (tc.valid && got != tc.input) {
				t.Fatalf("path normalization returned %q, %v", got, err)
			}
		})
	}
}
