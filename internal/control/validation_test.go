package control

import (
	"strings"
	"testing"

	"niceproxy/internal/model"
)

func TestValidateHTTPBoundaries(t *testing.T) {
	for _, tt := range []struct {
		name   string
		mutate func(*model.HTTPRoute)
		want   string
	}{
		{"defaults and normalization", func(r *model.HTTPRoute) {}, ""},
		{"invalid TLS", func(r *model.HTTPRoute) { r.TLS = "manual" }, "TLS"},
		{"empty host", func(r *model.HTTPRoute) { r.Host = "" }, "host"},
		{"IP host", func(r *model.HTTPRoute) { r.Host = "127.0.0.1" }, "host"},
		{"wildcard host", func(r *model.HTTPRoute) { r.Host = "*.example" }, "host"},
		{"strip root", func(r *model.HTTPRoute) { r.StripPrefix = true }, "stripPrefix"},
		{"invalid target scheme", func(r *model.HTTPRoute) { r.Target = "ftp://127.0.0.1:3000" }, "target"},
		{"target credentials", func(r *model.HTTPRoute) { r.Target = "http://u:p@127.0.0.1:3000" }, "target"},
		{"target query", func(r *model.HTTPRoute) { r.Target = "http://127.0.0.1:3000/?bad=1" }, "target"},
		{"target path", func(r *model.HTTPRoute) { r.Target = "http://127.0.0.1:3000/app" }, "target"},
		{"invalid port", func(r *model.HTTPRoute) { r.Target = "http://127.0.0.1:65536" }, "port"},
		{"malformed target", func(r *model.HTTPRoute) { r.Target = "http://[::1" }, "target"},
		{"invalid path", func(r *model.HTTPRoute) { r.Path = "/a/*" }, "path"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			route := model.HTTPRoute{Host: " App.Example ", Target: "http://127.0.0.1:3000"}
			tt.mutate(&route)
			err := validateHTTP(&route)
			if tt.want == "" {
				if err != nil || route.Host != "app.example" || route.Path != "/" || route.TLS != "auto" {
					t.Fatalf("validateHTTP = %+v, %v", route, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateHTTP error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateDirectBoundaries(t *testing.T) {
	t.Run("empty listen host", func(t *testing.T) {
		rule := model.DirectRule{Protocol: "udp", ListenPort: 10000, TargetHost: "::1", TargetPort: 3000}
		if err := validateDirect(&rule, nil); err != nil || rule.ListenHost != "0.0.0.0" {
			t.Fatalf("default listen host = %q, error = %v", rule.ListenHost, err)
		}
	})
	for _, tt := range []struct {
		name   string
		mutate func(*model.DirectRule, map[int]bool)
		want   string
	}{
		{"protocol and IP normalization", func(r *model.DirectRule, _ map[int]bool) {}, ""},
		{"invalid protocol", func(r *model.DirectRule, _ map[int]bool) { r.Protocol = "http" }, "protocol"},
		{"invalid listen host", func(r *model.DirectRule, _ map[int]bool) { r.ListenHost = "example.test" }, "listenHost"},
		{"invalid listen port", func(r *model.DirectRule, _ map[int]bool) { r.ListenPort = 0 }, "ports"},
		{"invalid target port", func(r *model.DirectRule, _ map[int]bool) { r.TargetPort = 65536 }, "ports"},
		{"reserved port", func(r *model.DirectRule, reserved map[int]bool) { reserved[r.ListenPort] = true }, "reserved"},
		{"invalid target host", func(r *model.DirectRule, _ map[int]bool) { r.TargetHost = "http://example.test" }, "targetHost"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rule := model.DirectRule{Protocol: " TCP ", ListenHost: "::ffff:127.0.0.1", ListenPort: 10000, TargetHost: " Example.Test ", TargetPort: 3000}
			reserved := map[int]bool{}
			tt.mutate(&rule, reserved)
			err := validateDirect(&rule, reserved)
			if tt.want == "" {
				if err != nil || rule.Protocol != "tcp" || rule.TargetHost != "Example.Test" || rule.ListenHost != "127.0.0.1" {
					t.Fatalf("validateDirect = %+v, %v", rule, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateDirect error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestPanelDomainAndHostnameBoundaries(t *testing.T) {
	maxHost := strings.Repeat(strings.Repeat("a", 63)+".", 3) + strings.Repeat("b", 61)
	for _, value := range []string{"", "panel.example", "a-b.example", strings.Repeat("a", 63) + ".example", maxHost} {
		if err := validatePanelDomain(value); err != nil {
			t.Errorf("validatePanelDomain(%q) = %v", value, err)
		}
	}
	for _, value := range []string{"127.0.0.1", "panel.example:443", "-panel.example", "panel..example",
		"panel_name.example", strings.Repeat("a", 64) + ".example", maxHost + "b"} {
		if err := validatePanelDomain(value); err == nil {
			t.Errorf("validatePanelDomain(%q) accepted", value)
		}
	}
}
