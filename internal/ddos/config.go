// Package ddos implements process-local admission budgets and attack detection.
package ddos

import (
	"crypto/x509"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"niceproxy/internal/ddos/trust"
)

type Config struct {
	Listener   *Policy            `json:"listener,omitempty"`
	Endpoints  map[string]*Policy `json:"endpoints,omitempty"`
	Cloudflare *trust.Config      `json:"cloudflare,omitempty"`
}

type Policy struct {
	Detect            bool    `json:"detect"`
	AutoFilter        bool    `json:"autoFilter"`
	EnforceLimits     bool    `json:"enforceLimits"`
	StableWindows     int     `json:"stableWindows,omitempty"`
	Group             string  `json:"group,omitempty"`
	Limits            []Limit `json:"limits,omitempty"`
	Rules             []Rule  `json:"rules,omitempty"`
	ExpectUDPResponse bool    `json:"expectUDPResponse,omitempty"`
	CloudflareOnly    bool    `json:"cloudflareOnly,omitempty"`
	OriginPullCA      string  `json:"originPullCA,omitempty"`
}

type Limit struct {
	ID            string  `json:"id"`
	Metric        string  `json:"metric"`
	Value         float64 `json:"value"`
	Unit          string  `json:"unit"`
	WindowSeconds int     `json:"windowSeconds,omitempty"`
	Burst         float64 `json:"burst,omitempty"`
	Scope         string  `json:"scope"`
	Action        Action  `json:"action"`
	TTLSeconds    int     `json:"ttlSeconds,omitempty"`
}

type Rule struct {
	ID              string  `json:"id"`
	Signal          string  `json:"signal"`
	Scope           string  `json:"scope"`
	Threshold       float64 `json:"threshold"`
	ClearThreshold  float64 `json:"clearThreshold"`
	WindowSeconds   int     `json:"windowSeconds"`
	Burst           float64 `json:"burst"`
	MinSamples      int     `json:"minSamples"`
	Action          Action  `json:"action"`
	CooldownSeconds int     `json:"cooldownSeconds"`
}

type Action string

const (
	Pass   Action = "pass"
	Slow   Action = "slow"
	Reject Action = "reject"
	Block  Action = "block"
)

func (a Action) rank() int {
	switch a {
	case Pass:
		return 1
	case Slow:
		return 2
	case Reject:
		return 3
	case Block:
		return 4
	}
	return 0
}

const (
	Listener = "listener"
	TCP      = "tcp"
	UDP      = "udp"
	HTTP     = "http"
	HTTPTCP  = "http_tcp"
	HTTPUDP  = "http_udp"
)

type measurement uint8

const (
	rate measurement = iota
	active
	maximum
	resource
)

type metricSpec struct {
	unit string
	mode measurement
}

var metrics = map[string]metricSpec{
	"tcp_new": {"count", rate}, "tcp_active": {"count", active},
	"tls_new": {"count", rate}, "tls_active": {"count", active},
	"first_byte_ms": {"ms", maximum}, "header_ms": {"ms", maximum}, "idle_ms": {"ms", maximum},
	"udp_packets": {"count", rate}, "udp_bytes": {"bytes", rate}, "udp_datagram_bytes": {"bytes", maximum},
	"cpu_percent": {"percent", resource}, "memory_bytes": {"bytes", resource},
	"backlog": {"count", resource}, "queue": {"count", resource},
	"http_requests": {"count", rate}, "http_active": {"count", active}, "http_connection_active": {"count", active},
	"tls_sessions": {"count", active}, "header_bytes": {"bytes", maximum}, "body_bytes": {"bytes", maximum},
	"response_ms": {"ms", maximum}, "tcp_bytes": {"bytes", maximum}, "backend_active": {"count", active},
	"backend_tcp_new": {"count", rate}, "backend_tcp_bytes": {"bytes", maximum},
	"backend_udp_packets": {"count", rate}, "backend_udp_bytes": {"bytes", rate},
	"backend_response_ms": {"ms", maximum}, "backend_datagrams": {"count", maximum},
	"backend_request_bytes": {"bytes", maximum}, "backend_bytes": {"bytes", rate},
}

var allowedMetrics = map[string]string{
	Listener: "tcp_new tcp_active tls_new tls_active first_byte_ms header_ms idle_ms udp_packets udp_bytes udp_datagram_bytes cpu_percent memory_bytes backlog queue",
	TCP:      "tcp_new tcp_active tcp_bytes idle_ms backend_active",
	UDP:      "udp_packets udp_bytes udp_datagram_bytes backend_active",
	HTTP:     "http_requests http_active http_connection_active tls_sessions header_bytes body_bytes response_ms backend_active",
	HTTPTCP:  "http_requests http_active http_connection_active tls_sessions header_bytes body_bytes response_ms backend_active backend_tcp_new backend_tcp_bytes backend_response_ms backend_bytes",
	HTTPUDP:  "http_requests http_active http_connection_active tls_sessions header_bytes body_bytes response_ms backend_active backend_udp_packets backend_udp_bytes backend_response_ms backend_datagrams backend_request_bytes",
}

var signals = [...]string{
	"tcp_new", "tls_new", "requests", "udp_packets", "udp_bytes", "protocol_errors", "timeouts", "short_connections",
	"backend_errors", "backend_latency_ms", "pressure", "distinct_sources", "distinct_subnets", "kernel_drops", "udp_unanswered",
}

var signalIndex = func() map[string]int {
	m := make(map[string]int, len(signals))
	for i, signal := range signals {
		m[signal] = i
	}
	return m
}()

var identifier = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func ScopeValid(scope string) bool {
	switch scope {
	case "ip", "subnet", "listener", "endpoint", "group", "all_instances":
		return true
	}
	return false
}

func sourceScope(scope string) bool { return scope == "ip" || scope == "subnet" }

func (p *Policy) Validate(kind string) error {
	if p == nil {
		return nil
	}
	if _, ok := allowedMetrics[kind]; !ok {
		return fmt.Errorf("unknown protection target %q", kind)
	}
	if len(p.Limits) > 32 || len(p.Rules) > 16 {
		return fmt.Errorf("maximum 32 limits and 16 rules per protection policy")
	}
	if p.StableWindows < 0 || p.StableWindows > 60 {
		return fmt.Errorf("stableWindows must be between 1 and 60, or zero for the default")
	}
	if p.Group != "" && !identifier.MatchString(p.Group) {
		return fmt.Errorf("group must contain 1–64 letters, digits, dots, dashes or underscores")
	}
	if p.ExpectUDPResponse && kind != UDP && kind != HTTPUDP {
		return fmt.Errorf("expectUDPResponse requires a UDP endpoint")
	}
	if p.CloudflareOnly || p.OriginPullCA != "" {
		if kind != HTTP && kind != HTTPTCP && kind != HTTPUDP {
			return fmt.Errorf("Cloudflare-only protection requires an HTTPS route")
		}
		if _, err := p.CertPool(); err != nil {
			return err
		}
	}
	validScope := func(scope string) bool {
		return ScopeValid(scope) && (scope != "group" || p.Group != "") &&
			(scope != "endpoint" || kind != Listener) && (scope != "listener" || kind == Listener)
	}
	seen := make(map[string]bool, len(p.Limits)+len(p.Rules))
	for _, l := range p.Limits {
		spec, known := metrics[l.Metric]
		if !identifier.MatchString(l.ID) || seen[l.ID] || !known || !strings.Contains(" "+allowedMetrics[kind]+" ", " "+l.Metric+" ") {
			return fmt.Errorf("invalid or duplicate limit %q for %s (%s)", l.ID, kind, l.Metric)
		}
		seen[l.ID] = true
		if !validScope(l.Scope) || l.Action.rank() == 0 || l.Unit != spec.unit || !positive(l.Value) || l.Burst < 0 || l.Burst > 1e12 || l.TTLSeconds < 0 || l.TTLSeconds > 86400 {
			return fmt.Errorf("limit %q has invalid value, unit (expected %s), scope, action, burst or TTL", l.ID, spec.unit)
		}
		if spec.mode == rate && (l.WindowSeconds < 1 || l.WindowSeconds > 300) {
			return fmt.Errorf("rate limit %q needs a window of 1 to 300 seconds", l.ID)
		}
		if spec.mode != rate && (l.Burst != 0 || l.WindowSeconds != 0) {
			return fmt.Errorf("burst and window apply only to rate limits (%s)", l.ID)
		}
		if spec.mode == resource && sourceScope(l.Scope) {
			return fmt.Errorf("resource limit %q requires a listener or shared scope", l.ID)
		}
		if spec.unit != "percent" && l.Value != math.Trunc(l.Value) {
			return fmt.Errorf("limit %q needs an integer value", l.ID)
		}
		if spec.unit == "ms" && l.Value > float64((24*time.Hour)/time.Millisecond) {
			return fmt.Errorf("limit %q exceeds one day", l.ID)
		}
	}
	for _, r := range p.Rules {
		_, known := signalIndex[r.Signal]
		if !identifier.MatchString(r.ID) || seen[r.ID] || !known || !validScope(r.Scope) || r.Action.rank() == 0 {
			return fmt.Errorf("invalid or duplicate detection rule %q (%s)", r.ID, r.Signal)
		}
		seen[r.ID] = true
		if !positive(r.Threshold) || r.ClearThreshold < 0 || r.ClearThreshold >= r.Threshold || r.Burst < 0 || r.Burst > 1e12 ||
			r.WindowSeconds < 1 || r.WindowSeconds > 300 || r.MinSamples < 1 || r.MinSamples > 1e9 || r.CooldownSeconds < 1 || r.CooldownSeconds > 86400 {
			return fmt.Errorf("invalid thresholds, burst, window, minimum sample size or cooldown for rule %q", r.ID)
		}
		if sourceScope(r.Scope) && (r.Signal == "pressure" || r.Signal == "kernel_drops" || r.Signal == "distinct_sources" || r.Signal == "distinct_subnets") {
			return fmt.Errorf("signal %s needs an aggregate scope", r.Signal)
		}
	}
	return nil
}

func positive(n float64) bool { return n > 0 && n <= 1e12 }

func (p *Policy) CertPool() (*x509.CertPool, error) {
	if len(p.OriginPullCA) == 0 || len(p.OriginPullCA) > 16384 {
		return nil, fmt.Errorf("Cloudflare-only protection requires a PEM Origin Pull CA (up to 16 KiB)")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(p.OriginPullCA)) {
		return nil, fmt.Errorf("Origin Pull CA contains no valid certificate")
	}
	return pool, nil
}

func (p Policy) stable() int {
	if p.StableWindows != 0 {
		return p.StableWindows
	}
	return 5
}

func (l Limit) ttl() time.Duration {
	if l.TTLSeconds != 0 {
		return time.Duration(l.TTLSeconds) * time.Second
	}
	return time.Minute
}
