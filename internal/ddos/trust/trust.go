// Package trust attributes HTTP client addresses using local proxy trust and
// a periodically refreshed Cloudflare network list.
package trust

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultIPv4URL = "https://www.cloudflare.com/ips-v4"
	defaultIPv6URL = "https://www.cloudflare.com/ips-v6"
	maxListBytes   = 64 << 10
	maxNetworks    = 1024
	maxXFFBytes    = 4096
	maxXFFHops     = 32
)

type Config struct {
	Enabled        bool     `json:"enabled"`
	IPv4URL        string   `json:"ipv4URL,omitempty"`
	IPv6URL        string   `json:"ipv6URL,omitempty"`
	TrustedProxies []string `json:"trustedProxies,omitempty"`
}

func (c Config) Validate() error {
	_, _, err := c.parse()
	return err
}

func (c Config) parse() (Snapshot, []netip.Prefix, error) {
	s := Snapshot{
		ConfiguredIPv4URL: c.IPv4URL,
		ConfiguredIPv6URL: c.IPv6URL,
		EffectiveIPv4URL:  c.IPv4URL,
		EffectiveIPv6URL:  c.IPv6URL,
	}
	if s.EffectiveIPv4URL == "" {
		s.EffectiveIPv4URL = defaultIPv4URL
	}
	if s.EffectiveIPv6URL == "" {
		s.EffectiveIPv6URL = defaultIPv6URL
	}
	for _, raw := range []string{s.EffectiveIPv4URL, s.EffectiveIPv6URL} {
		u, err := url.Parse(raw)
		if err != nil || !isHTTPS(u) {
			return Snapshot{}, nil, fmt.Errorf("Cloudflare list URL must be an absolute HTTPS URL without credentials or fragment: %q", raw)
		}
	}
	proxies := make([]netip.Prefix, 0, len(c.TrustedProxies))
	for _, raw := range c.TrustedProxies {
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			a, err := netip.ParseAddr(raw)
			if err != nil || a.Zone() != "" {
				return Snapshot{}, nil, fmt.Errorf("invalid trusted proxy IP or CIDR: %q", raw)
			}
			a = a.Unmap()
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4In6() {
			if p.Bits() < 96 {
				return Snapshot{}, nil, fmt.Errorf("ambiguous IPv4-mapped trusted proxy CIDR: %q", raw)
			}
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		proxies = append(proxies, p.Masked())
	}
	return s, proxies, nil
}

func isHTTPS(u *url.URL) bool {
	return u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == ""
}

// Snapshot contains the last complete list pair and its publication time.
// Error describes the latest refresh failure, if any.
type Snapshot struct {
	IPv4, IPv6                           []netip.Prefix
	ConfiguredIPv4URL, ConfiguredIPv6URL string
	EffectiveIPv4URL, EffectiveIPv6URL   string
	UpdatedAt                            time.Time
	Error                                string
}

type Identity struct {
	Address    netip.Addr
	Reason     string
	Cloudflare bool
}

type Resolver struct {
	enabled bool
	proxies []netip.Prefix
	client  *http.Client
	mu      sync.Mutex
	current atomic.Pointer[Snapshot]
}

func New(cfg Config) (*Resolver, error) {
	s, proxies, err := cfg.parse()
	if err != nil {
		return nil, err
	}
	r := &Resolver{
		enabled: cfg.Enabled,
		proxies: proxies,
		client: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 || !isHTTPS(req.URL) {
					return fmt.Errorf("Cloudflare list redirect rejected")
				}
				return nil
			},
		},
	}
	r.current.Store(&s)
	return r, nil
}

// Snapshot returns a copy that callers can modify independently.
func (r *Resolver) Snapshot() Snapshot {
	s := *r.current.Load()
	s.IPv4 = append([]netip.Prefix(nil), s.IPv4...)
	s.IPv6 = append([]netip.Prefix(nil), s.IPv6...)
	return s
}

// Refresh loads and publishes both families together. Calls are serialized.
func (r *Resolver) Refresh(ctx context.Context) error {
	if !r.enabled {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s := *r.current.Load()
	v4, err := r.fetch(ctx, s.EffectiveIPv4URL, true)
	if err == nil {
		var v6 []netip.Prefix
		v6, err = r.fetch(ctx, s.EffectiveIPv6URL, false)
		if err == nil {
			s.IPv4, s.IPv6 = v4, v6
			s.UpdatedAt = time.Now().UTC()
			s.Error = ""
		}
	}
	if err != nil {
		s.Error = err.Error()
	}
	r.current.Store(&s)
	return err
}

func (r *Resolver) fetch(ctx context.Context, endpoint string, ipv4 bool) ([]netip.Prefix, error) {
	networks, err := r.readList(ctx, endpoint, ipv4)
	if err != nil {
		return nil, fmt.Errorf("Cloudflare list %s: %w", endpoint, err)
	}
	return networks, nil
}

func (r *Resolver) readList(ctx context.Context, endpoint string, ipv4 bool) ([]netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxListBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxListBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxListBytes)
	}
	var prefixes []netip.Prefix
	lines := bufio.NewScanner(bytes.NewReader(body))
	for lines.Scan() {
		p, err := netip.ParsePrefix(strings.TrimSpace(lines.Text()))
		if err != nil || p.Addr().Is4() != ipv4 || p.Addr().Is4In6() || p.Bits() == 0 || p != p.Masked() {
			return nil, fmt.Errorf("invalid CIDR on line %d", len(prefixes)+1)
		}
		if len(prefixes) == maxNetworks {
			return nil, fmt.Errorf("response exceeds %d networks", maxNetworks)
		}
		prefixes = append(prefixes, p)
	}
	if err := lines.Err(); err != nil {
		return nil, err
	}
	if len(prefixes) == 0 {
		return nil, fmt.Errorf("empty response")
	}
	return prefixes, nil
}

func contains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func (s *Snapshot) cloudflare(addr netip.Addr) bool {
	if addr.Is4() {
		return contains(s.IPv4, addr)
	}
	return contains(s.IPv6, addr)
}

// Client uses only the transport peer and the current in-memory snapshot.
// Trusted intermediates must append their observed peer to X-Forwarded-For and
// preserve Cloudflare's authoritative CF-Connecting-IP on Cloudflare traffic.
func (r *Resolver) Client(peer netip.Addr, headers http.Header) Identity {
	peer = peer.WithZone("").Unmap()
	fallback := Identity{Address: peer, Reason: "untrusted_peer"}
	if !peer.IsValid() {
		fallback.Reason = "invalid_peer"
		return fallback
	}
	s := r.current.Load()
	if s.cloudflare(peer) {
		return cloudflareClient(fallback, headers)
	}
	if !contains(r.proxies, peer) {
		return fallback
	}
	raw, reason := singleHeader(headers, "X-Forwarded-For", maxXFFBytes)
	if reason != "" {
		fallback.Reason = "xff_" + reason
		return fallback
	}
	parts := strings.Split(raw, ",")
	if len(parts) > maxXFFHops {
		fallback.Reason = "xff_invalid"
		return fallback
	}
	var hops [maxXFFHops]netip.Addr
	for i, part := range parts {
		addr, err := parseHeaderAddr(part)
		if err != nil {
			fallback.Reason = "xff_invalid"
			return fallback
		}
		hops[i] = addr
	}
	for i := len(parts) - 1; i >= 0; i-- {
		addr := hops[i]
		// Stop at Cloudflare or the first untrusted hop. Addresses farther
		// left cannot establish who forwarded the request to our proxies.
		if s.cloudflare(addr) {
			return cloudflareClient(fallback, headers)
		}
		if !contains(r.proxies, addr) {
			return Identity{Address: addr, Reason: "xff"}
		}
	}
	fallback.Reason = "xff_no_untrusted_hop"
	return fallback
}

func cloudflareClient(fallback Identity, headers http.Header) Identity {
	fallback.Cloudflare = true
	raw, reason := singleHeader(headers, "CF-Connecting-IP", 64)
	if reason != "" {
		fallback.Reason = "cf_connecting_ip_" + reason
		return fallback
	}
	addr, err := parseHeaderAddr(raw)
	if err != nil {
		fallback.Reason = "cf_connecting_ip_invalid"
		return fallback
	}
	return Identity{Address: addr, Reason: "cf_connecting_ip", Cloudflare: true}
}

func parseHeaderAddr(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.Trim(raw, " \t"))
	if err != nil {
		return netip.Addr{}, err
	}
	if addr.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("scoped address")
	}
	return addr.Unmap(), nil
}

// Check case-insensitively even for headers constructed outside net/http.
func singleHeader(headers http.Header, name string, maxBytes int) (string, string) {
	var value string
	found := false
	for key, values := range headers {
		if !strings.EqualFold(key, name) {
			continue
		}
		if found || len(values) != 1 || len(values[0]) > maxBytes {
			return "", "invalid"
		}
		value, found = values[0], true
	}
	if !found {
		return "", "missing"
	}
	return value, ""
}
