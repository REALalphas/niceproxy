package control

import (
	"fmt"
	"net"
	"net/url"
	"niceproxy/internal/model"
	"strconv"
	"strings"
)

func validateHTTP(r *model.HTTPRoute) error {
	r.Host = strings.ToLower(strings.TrimSpace(r.Host))
	if r.TLS == "" {
		r.TLS = "auto"
	}
	if r.TLS != "auto" && r.TLS != "internal" && r.TLS != "off" {
		return fmt.Errorf("TLS must be auto, internal or off")
	}
	if !validHostname(r.Host) || net.ParseIP(r.Host) != nil {
		return fmt.Errorf("host must be a DNS hostname without scheme, port or path")
	}
	var pathErr error
	r.Path, pathErr = model.NormalizeRoutePath(r.Path)
	if pathErr != nil {
		return pathErr
	}
	if r.Path == "/" && r.StripPrefix {
		return fmt.Errorf("stripPrefix requires a non-root path")
	}
	u, err := url.Parse(r.Target)
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("target must be an http(s) origin, for example http://127.0.0.1:3000")
	}
	if u.Port() != "" {
		p, e := strconv.Atoi(u.Port())
		if e != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid upstream port")
		}
	}
	return nil
}
func validHostname(s string) bool {
	if s == "" || len(s) > 253 || strings.ContainsAny(s, " \t\r\n/:*\\@") {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
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
func validateDirect(r *model.DirectRule, reserved map[int]bool) error {
	r.Protocol = strings.ToLower(strings.TrimSpace(r.Protocol))
	if r.Protocol != "tcp" && r.Protocol != "udp" {
		return fmt.Errorf("protocol must be tcp or udp")
	}
	if r.ListenHost == "" {
		r.ListenHost = "0.0.0.0"
	}
	if net.ParseIP(r.ListenHost) == nil {
		return fmt.Errorf("listenHost must be a literal IP address")
	}
	if r.ListenPort < 1 || r.ListenPort > 65535 || r.TargetPort < 1 || r.TargetPort > 65535 {
		return fmt.Errorf("ports must be integers from 1 to 65535")
	}
	if reserved[r.ListenPort] {
		return fmt.Errorf("port %d is reserved for Caddy or the management panel", r.ListenPort)
	}
	r.TargetHost = strings.TrimSpace(r.TargetHost)
	if net.ParseIP(r.TargetHost) == nil && !validHostname(strings.ToLower(r.TargetHost)) {
		return fmt.Errorf("targetHost must be an IP address or hostname")
	}
	return nil
}
