// Package caddy controls the bundled Caddy subprocess through a private Unix socket.
package caddy

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"niceproxy/internal/model"
)

type Options struct {
	PortOwners                                              model.PortOwners
	Binary, RuntimeDir, DataDir, PanelListen, BackendSocket string
	PanelDomain, PanelCertFile, PanelKeyFile                string
	PanelDomainProxied, PanelDNSObserved                    bool
	PanelCloudflareCIDRs                                    string
	HTTPPort, HTTPSPort                                     int
}

const (
	PanelPeerIPHeader       = "X-Niceproxy-Peer-IP"
	PanelCloudflareIPHeader = "X-Niceproxy-Cloudflare-IP"
)

// Cloudflare's public IPv4 and IPv6 ranges from https://api.cloudflare.com/client/v4/ips.
const cloudflarePanelCIDRs = `
173.245.48.0/20
103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
141.101.64.0/18
108.162.192.0/18
190.93.240.0/20
188.114.96.0/20
197.234.240.0/22
198.41.128.0/17
162.158.0.0/15
104.16.0.0/13
104.24.0.0/14
172.64.0.0/13
131.0.72.0/22
2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
`

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

const panelOriginCertTag = "niceproxy-panel-origin"

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
	var cloudflareRanges []string
	if panelDomain != "" {
		panelCIDRs := strings.TrimSpace(o.PanelCloudflareCIDRs)
		if panelCIDRs == "" {
			panelCIDRs = cloudflarePanelCIDRs
		}
		for _, value := range strings.FieldsFunc(panelCIDRs, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		}) {
			prefix, err := netip.ParsePrefix(value)
			if err != nil || prefix.Bits() == 0 || prefix.Addr().Is4In6() {
				return nil, fmt.Errorf("invalid Cloudflare panel proxy CIDR %q", value)
			}
			cloudflareRanges = append(cloudflareRanges, prefix.Masked().String())
		}
	}
	proxy := func(dial string, transport object) object {
		h := object{"handler": "reverse_proxy", "upstreams": []object{{"dial": dial}}}
		if transport != nil {
			h["transport"] = transport
		}
		return h
	}
	panelProxy := func(cloudflare bool) object {
		h := proxy("unix/"+o.BackendSocket, nil)
		set := object{PanelPeerIPHeader: []string{"{http.request.remote.host}"}}
		headers := object{"set": set}
		if cloudflare {
			// Caddy joins repeated fields with commas. The panel validates the
			// result as a single address before treating it as a client IP.
			set[PanelCloudflareIPHeader] = []string{"{http.request.header.CF-Connecting-IP}"}
		} else {
			headers["delete"] = []string{PanelCloudflareIPHeader}
		}
		h["headers"] = object{"request": headers}
		return h
	}
	servers := object{"panel": object{"listen": []string{o.PanelListen}, "automatic_https": object{"disable": true}, "routes": []object{{"handle": []object{panelProxy(false)}}}}}
	var plain, secure []object
	var policies []object
	var panelCertificate object
	var panelCertTag string
	hasInternal := false
	seen := map[string]bool{}
	domainTLS := map[string]string{}
	if panelDomain != "" {
		domainTLS[panelDomain] = "auto"
		handler := panelProxy(false)
		if len(cloudflareRanges) > 0 {
			// Match the hostname first. Caddy's IP matcher can return HTTP 425
			// before the TLS handshake finishes on an HTTP/3 request.
			handler = object{
				"handler": "subroute",
				"routes": []object{{
					"match":    []object{{"remote_ip": object{"ranges": cloudflareRanges}}},
					"handle":   []object{panelProxy(true)},
					"terminal": true,
				}, {
					"handle":   []object{handler},
					"terminal": true,
				}},
			}
		}
		secure = append(secure, object{
			"match":    []object{{"host": []string{panelDomain}}},
			"handle":   []object{handler},
			"terminal": true,
		})
		certFile, keyFile, chain, _, err := panelCertificateFiles(o.DataDir, o.PanelCertFile, o.PanelKeyFile, panelDomain, o.panelDNSMode())
		if err == nil && len(chain) != 0 {
			panelCertTag = fmt.Sprintf("%s-%x", panelOriginCertTag, sha256.Sum256(chain[0].Raw))
			panelCertificate = object{"certificate": certFile, "key": keyFile, "tags": []string{panelCertTag}}
		}
		if panelCertificate == nil {
			issuer := object{"module": "acme", "challenges": object{
				"http":     object{"disabled": owners.HTTP != "caddy"},
				"tls-alpn": object{"disabled": owners.HTTPS != "caddy"},
			}}
			if o.PanelDomainProxied {
				hasInternal = true
				issuer = object{"module": "internal"}
			}
			policies = append(policies, object{"subjects": []string{panelDomain}, "issuers": []object{issuer}})
		}
		if owners.HTTP == "caddy" && owners.HTTPS == "caddy" {
			// An HTTPS request forwarded over plain HTTP would otherwise loop
			// back to the same public URL (for example with Cloudflare Flexible).
			plain = append(plain, object{
				"match": []object{{"host": []string{panelDomain}, "header": object{"X-Forwarded-Proto": []string{"https"}}}},
				"handle": []object{{"handler": "static_response", "status_code": 503,
					"headers": object{"Cache-Control": []string{"no-store"}},
					"body":    "The HTTPS request reached the panel origin over HTTP. Configure the proxy to use HTTPS to the origin. For Cloudflare, use Full (strict) with a trusted origin certificate.\n",
				}},
				"terminal": true,
			})
			location := "https://" + panelDomain
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
		autoHTTPS := object{"disable_redirects": true}
		connectionPolicies := []object{{}}
		if panelCertificate != nil {
			autoHTTPS["skip_certificates"] = []string{panelDomain}
			connectionPolicies = []object{{
				"match":                 object{"sni": []string{panelDomain}},
				"certificate_selection": object{"any_tag": []string{panelCertTag}},
			}, {}}
		}
		servers["public_https"] = object{"protocols": protocols, "listen": []string{":" + strconv.Itoa(o.HTTPSPort)}, "automatic_https": autoHTTPS, "tls_connection_policies": connectionPolicies, "routes": secure}
	}
	apps := object{"http": object{"http_port": o.HTTPPort, "https_port": o.HTTPSPort, "servers": servers}}
	tlsApp := object{}
	if len(policies) > 0 {
		tlsApp["automation"] = object{"policies": policies}
	}
	if panelCertificate != nil {
		tlsApp["certificates"] = object{"load_files": []object{panelCertificate}}
	}
	if len(tlsApp) > 0 {
		apps["tls"] = tlsApp
	}
	if hasInternal {
		// A private issuer must not modify the container or host trust store.
		apps["pki"] = object{"certificate_authorities": object{"local": object{"install_trust": false}}}
	}
	return json.Marshal(object{"admin": object{"listen": "unix/" + filepath.Join(o.RuntimeDir, "caddy.sock"), "config": object{"persist": false}}, "apps": apps})
}
