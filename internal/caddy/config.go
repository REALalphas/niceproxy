// Package caddy controls the bundled Caddy subprocess through a private Unix socket.
package caddy

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"niceproxy/internal/model"
)

type Options struct {
	PortOwners                                              model.PortOwners
	Binary, RuntimeDir, DataDir, PanelListen, BackendSocket string
	PanelDomain                                             string
	PanelDomainProxied                                      bool
	HTTPPort, HTTPSPort                                     int
}

func defaults(o Options) Options {
	if o.Binary == "" {
		o.Binary = "caddy"
	}
	if o.PanelListen == "" {
		o.PanelListen = "127.0.0.1:9080"
	}
	if o.HTTPPort == 0 {
		o.HTTPPort = 80
	}
	if o.HTTPSPort == 0 {
		o.HTTPSPort = 443
	}
	return o
}

type object = map[string]any

func hostname(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
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

func validPath(s string) bool { return filepath.IsAbs(s) && !strings.ContainsAny(s, "\x00\r\n{}") }

// BuildConfig produces a complete Caddy JSON config; callers cannot supply raw JSON.
func BuildConfig(options Options, routes []model.HTTPRoute) ([]byte, error) {
	o := defaults(options)
	owners := o.PortOwners.Defaults()
	if err := owners.Validate(); err != nil {
		return nil, err
	}
	if !validPath(o.RuntimeDir) || !validPath(o.DataDir) || !validPath(o.BackendSocket) {
		return nil, fmt.Errorf("runtime, data and backend socket paths must be absolute")
	}
	if o.HTTPPort < 1 || o.HTTPPort > 65535 || o.HTTPSPort < 1 || o.HTTPSPort > 65535 || o.HTTPPort == o.HTTPSPort {
		return nil, fmt.Errorf("invalid public ports")
	}
	ph, pp, err := net.SplitHostPort(o.PanelListen)
	pn, perr := strconv.Atoi(pp)
	if err != nil || perr != nil || net.ParseIP(ph) == nil || pn < 1 || pn > 65535 || pn == o.HTTPPort || pn == o.HTTPSPort {
		return nil, fmt.Errorf("panel listen must be a literal IP and a distinct valid port")
	}
	panelDomain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(o.PanelDomain), "."))
	if panelDomain != "" && (!hostname(panelDomain) || net.ParseIP(panelDomain) != nil) {
		return nil, fmt.Errorf("invalid panel domain %q", o.PanelDomain)
	}
	if panelDomain != "" && owners.HTTPS != "caddy" && owners.HTTP3 != "caddy" {
		return nil, fmt.Errorf("panel domain %q requires Caddy ownership of HTTPS TCP or HTTP3 UDP", panelDomain)
	}
	proxy := func(dial string, transport object) object {
		h := object{"handler": "reverse_proxy", "upstreams": []object{{"dial": dial}}}
		if transport != nil {
			h["transport"] = transport
		}
		return h
	}
	servers := object{"panel": object{"listen": []string{o.PanelListen}, "automatic_https": object{"disable": true}, "routes": []object{{"handle": []object{proxy("unix/"+o.BackendSocket, nil)}}}}}
	var plain, secure []object
	var policies []object
	hasInternal := false
	seen := map[string]bool{}
	domainTLS := map[string]string{}
	if panelDomain != "" {
		domainTLS[panelDomain] = "auto"
		secure = append(secure, object{
			"match":    []object{{"host": []string{panelDomain}}},
			"handle":   []object{proxy("unix/"+o.BackendSocket, nil)},
			"terminal": true,
		})
		issuerConfig := object{"module": "acme", "challenges": object{
			// Caddy's challenge handler runs before user routes. Keeping both
			// challenge methods enabled avoids redirect loops for DNS-only records.
			"http":     object{"disabled": o.PanelDomainProxied || owners.HTTP != "caddy"},
			"tls-alpn": object{"disabled": o.PanelDomainProxied || owners.HTTPS != "caddy"},
		}}
		policies = append(policies, object{"subjects": []string{panelDomain}, "issuers": []object{issuerConfig}})
		if owners.HTTP == "caddy" && owners.HTTPS == "caddy" {
			location := "https://" + panelDomain
			if o.HTTPSPort != 443 {
				location += ":" + strconv.Itoa(o.HTTPSPort)
			}
			plain = append(plain, object{"match": []object{{"host": []string{panelDomain}}}, "handle": []object{{"handler": "static_response", "status_code": 308, "headers": object{"Location": []string{location + "{http.request.uri}"}}}}, "terminal": true})
		}
	}
	// Caddy JSON evaluates routes in order. Longer segment prefixes must win
	// over /api and the root fallback regardless of creation order.
	routes = append([]model.HTTPRoute{}, routes...)
	for i := range routes {
		var e error
		routes[i].Path, e = model.NormalizeRoutePath(routes[i].Path)
		if e != nil {
			return nil, e
		}
		if routes[i].Path == "/" && routes[i].StripPrefix {
			return nil, fmt.Errorf("cannot strip the root path")
		}
	}
	sort.SliceStable(routes, func(i, j int) bool { return len(routes[i].Path) > len(routes[j].Path) })
	for _, r := range routes {
		host := strings.ToLower(r.Host)
		if !hostname(host) || net.ParseIP(host) != nil {
			return nil, fmt.Errorf("invalid route hostname")
		}
		if panelDomain != "" && host == panelDomain {
			return nil, fmt.Errorf("route %s conflicts with reserved panel domain %q", r.ID, panelDomain)
		}
		mode := r.TLS
		if mode == "" {
			mode = "auto"
		}
		if mode != "auto" && mode != "internal" && mode != "off" {
			return nil, fmt.Errorf("invalid TLS mode")
		}
		u, err := url.Parse(r.Target)
		if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Hostname() == "" || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" {
			return nil, fmt.Errorf("target must be an http(s) origin")
		}
		uphost := u.Hostname()
		if net.ParseIP(uphost) == nil && !hostname(strings.ToLower(uphost)) {
			return nil, fmt.Errorf("invalid upstream hostname")
		}
		port := u.Port()
		if port == "" {
			if strings.HasSuffix(u.Host, ":") {
				return nil, fmt.Errorf("invalid upstream port")
			}
			port = "80"
			if u.Scheme == "https" {
				port = "443"
			}
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid upstream port")
		}
		if !r.Enabled {
			continue
		}
		if mode == "off" && owners.HTTP != "caddy" {
			return nil, fmt.Errorf("route %s requires HTTP owner caddy", r.ID)
		}
		if mode != "off" && owners.HTTPS != "caddy" && owners.HTTP3 != "caddy" {
			return nil, fmt.Errorf("route %s requires HTTPS or HTTP3 owner caddy", r.ID)
		}
		if mode == "auto" && owners.HTTP != "caddy" && owners.HTTPS != "caddy" {
			return nil, fmt.Errorf("route %s requires a Caddy TCP ACME challenge port", r.ID)
		}
		key := host + "\x00" + r.Path
		if seen[key] {
			return nil, fmt.Errorf("duplicate enabled domain and path")
		}
		seen[key] = true
		previousMode, domainSeen := domainTLS[host]
		if domainSeen && previousMode != mode {
			return nil, fmt.Errorf("all paths of a domain must use the same TLS mode")
		}
		domainTLS[host] = mode
		var transport object
		if u.Scheme == "https" {
			transport = object{"protocol": "http", "tls": object{"server_name": uphost}}
		}
		match := object{"host": []string{host}}
		if r.Path != "/" {
			// Caddy's basic path matcher ignores case. URL paths here are
			// case-sensitive, with an exact or slash-delimited prefix boundary.
			match["path_regexp"] = object{"pattern": "^" + regexp.QuoteMeta(r.Path) + "(/.*)?$"}
		}
		handlers := []object{}
		if r.StripPrefix {
			handlers = append(handlers, object{"handler": "rewrite", "strip_path_prefix": r.Path})
			// strip_path_prefix can leave a leading escaped slash (%2Ffoo)
			// in RawPath. An upstream needs an origin-form request target.
			handlers = append(handlers, object{"handler": "rewrite", "path_regexp": []object{{"find": "^(%2[fF])+", "replace": "/"}}})
		}
		handlers = append(handlers, proxy(net.JoinHostPort(uphost, port), transport))
		route := object{"match": []object{match}, "handle": handlers, "terminal": true}
		if mode == "off" {
			plain = append(plain, route)
			continue
		}
		secure = append(secure, route)
		if domainSeen {
			continue
		}
		issuer := "acme"
		if mode == "internal" {
			issuer = "internal"
			hasInternal = true
		}
		issuerConfig := object{"module": issuer}
		if issuer == "acme" {
			issuerConfig["challenges"] = object{"http": object{"disabled": owners.HTTP != "caddy"}, "tls-alpn": object{"disabled": owners.HTTPS != "caddy"}}
		}
		policies = append(policies, object{"subjects": []string{host}, "issuers": []object{issuerConfig}})
		if owners.HTTP != "caddy" || owners.HTTPS != "caddy" {
			continue
		}
		location := "https://" + host
		if o.HTTPSPort != 443 {
			location += ":" + strconv.Itoa(o.HTTPSPort)
		}
		plain = append(plain, object{"match": []object{{"host": []string{host}}}, "handle": []object{{"handler": "static_response", "status_code": 308, "headers": object{"Location": []string{location + "{http.request.uri}"}}}}, "terminal": true})
	}
	if len(plain) > 0 {
		plain = append(plain, object{"handle": []object{{"handler": "static_response", "status_code": 404}}, "terminal": true})
		servers["public_http"] = object{"listen": []string{":" + strconv.Itoa(o.HTTPPort)}, "automatic_https": object{"disable": true}, "routes": plain}
	}
	if len(secure) > 0 {
		secure = append(secure, object{"handle": []object{{"handler": "static_response", "status_code": 404}}, "terminal": true})
		protocols := []string{"h1", "h2", "h3"}
		if owners.HTTP3 != "caddy" {
			protocols = []string{"h1", "h2"}
		} else if owners.HTTPS != "caddy" {
			protocols = []string{"h3"}
		}
		servers["public_https"] = object{"protocols": protocols, "listen": []string{":" + strconv.Itoa(o.HTTPSPort)}, "automatic_https": object{"disable_redirects": true}, "tls_connection_policies": []object{{}}, "routes": secure}
	}
	apps := object{"http": object{"http_port": o.HTTPPort, "https_port": o.HTTPSPort, "servers": servers}}
	if len(policies) > 0 {
		apps["tls"] = object{"automation": object{"policies": policies}}
	}
	if hasInternal {
		// A private issuer must not modify the container or host trust store.
		apps["pki"] = object{"certificate_authorities": object{"local": object{"install_trust": false}}}
	}
	return json.Marshal(object{"admin": object{"listen": "unix/" + filepath.Join(o.RuntimeDir, "caddy.sock"), "config": object{"persist": false}}, "apps": apps})
}
