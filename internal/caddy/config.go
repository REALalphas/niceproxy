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
	Binary, RuntimeDir, DataDir, PanelListen, PanelDomain, BackendSocket string
	HTTPPort, HTTPSPort                                                  int
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
	o.PanelDomain = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(o.PanelDomain, ".")))
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
	if o.PanelDomain != "" && (!hostname(o.PanelDomain) || !strings.Contains(o.PanelDomain, ".") || net.ParseIP(o.PanelDomain) != nil) {
		return nil, fmt.Errorf("invalid panel domain")
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
	publicHTTPSLocation := func(host string) string {
		location := "https://" + host
		if o.HTTPSPort != 443 && o.PanelDomain == "" {
			location += ":" + strconv.Itoa(o.HTTPSPort)
		}
		return location
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
		if o.PanelDomain != "" && host == o.PanelDomain {
			return nil, fmt.Errorf("panel domain is reserved: %s", o.PanelDomain)
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
		policies = append(policies, object{"subjects": []string{host}, "issuers": []object{{"module": issuer}}})
		plain = append(plain, object{"match": []object{{"host": []string{host}}}, "handle": []object{{"handler": "static_response", "status_code": 308, "headers": object{"Location": []string{publicHTTPSLocation(host) + "{http.request.uri}"}}}}, "terminal": true})
	}
	if o.PanelDomain != "" {
		panelProxy := proxy("unix/"+o.BackendSocket, nil)
		panelProxy["headers"] = object{"request": object{"set": object{"Host": []string{"{http.request.host}"}}}}
		secure = append(secure, object{
			"match":    []object{{"host": []string{o.PanelDomain}}},
			"handle":   []object{panelProxy},
			"terminal": true,
		})
		location := "https://" + o.PanelDomain
		plain = append(plain, object{
			"match":    []object{{"host": []string{o.PanelDomain}}},
			"handle":   []object{{"handler": "static_response", "status_code": 308, "headers": object{"Location": []string{location + "{http.request.uri}"}}}},
			"terminal": true,
		})
		policies = append(policies, object{"subjects": []string{o.PanelDomain}, "issuers": []object{{"module": "acme"}}})
	}
	if len(plain) > 0 {
		plain = append(plain, object{"handle": []object{{"handler": "static_response", "status_code": 404}}, "terminal": true})
		servers["public_http"] = object{"listen": []string{":" + strconv.Itoa(o.HTTPPort)}, "automatic_https": object{"disable": true}, "routes": plain}
	}
	if len(secure) > 0 {
		secure = append(secure, object{"handle": []object{{"handler": "static_response", "status_code": 404}}, "terminal": true})
		servers["public_https"] = object{"listen": []string{":" + strconv.Itoa(o.HTTPSPort)}, "automatic_https": object{"disable_redirects": true}, "tls_connection_policies": []object{{}}, "routes": secure}
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
