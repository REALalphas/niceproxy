package ddos

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"niceproxy/internal/linuxstats"
)

const (
	maxSources      = 128
	maxRestrictions = 512
	maxEvents       = 64
	maxHistory      = 120
)

// Spec describes a live admission point. A Binding retains its policy for the
// lifetime of an operation, even when the published configuration changes.
type Spec struct {
	ID, Label, Kind, Protocol string
	Policy                    *Policy
	Version                   int64
	PreFilter                 string
	BeforeListenerFilter      bool
}

type Engine struct {
	mu      sync.RWMutex
	targets map[string]*target
	live    []*Binding
	quotas  [32]quotaShard
	slots   chan struct{}
	clock   func() time.Time
	lastCut atomic.Int64
	sampler linuxstats.Sampler
	lastNet *float64
}

func NewEngine() *Engine {
	return &Engine{targets: make(map[string]*target), slots: make(chan struct{}, 128), clock: time.Now}
}

type Binding struct {
	engine *Engine
	target *target
	Spec
	policy Policy
}

func (e *Engine) Bind(spec Spec) *Binding {
	e.mu.Lock()
	t := e.targets[spec.ID]
	if t == nil {
		t = newTarget()
		e.targets[spec.ID] = t
	}
	e.mu.Unlock()
	b := &Binding{engine: e, target: t, Spec: spec}
	if spec.Policy != nil {
		b.policy = *spec.Policy
	}
	return b
}

// Publish makes confirmed bindings visible to the sampler and admin API.
// Old, draining bindings retain their counters and operation policies.
func (e *Engine) Publish(bindings []*Binding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.clock()
	live := make(map[string]bool, len(bindings))
	seen := make(map[string]bool, len(bindings))
	unique := bindings[:0]
	for _, b := range bindings {
		if b == nil || seen[b.ID] {
			continue
		}
		seen[b.ID] = true
		unique = append(unique, b)
		live[b.ID] = true
		b.target.configure(b, now)
	}
	for id := range e.targets {
		if !live[id] {
			delete(e.targets, id)
		}
	}
	e.live = append(e.live[:0], unique...)
}

func (e *Engine) Run(ctx context.Context) {
	e.sample(e.clock())
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.sample(e.clock())
		}
	}
}

func (e *Engine) sample(now time.Time) {
	e.mu.RLock()
	live := append([]*Binding(nil), e.live...)
	e.mu.RUnlock()
	sample := e.sampler.Read()
	var queues map[uint64]linuxstats.SocketQueue
	for _, b := range live {
		if b.target.socket.Load() != 0 {
			queues = linuxstats.SocketQueues()
			break
		}
	}
	var kernelDrops *float64
	if sample.ListenDrops != nil && sample.UDPReceiveBufferErrors != nil {
		value := *sample.ListenDrops + *sample.UDPReceiveBufferErrors
		if e.lastNet != nil && value >= *e.lastNet {
			delta := value - *e.lastNet
			kernelDrops = &delta
		}
		e.lastNet = &value
	}
	cut := e.lastCut.Load() >= now.Add(-2*time.Second).UnixNano()
	e.mu.RLock()
	defer e.mu.RUnlock()
	// Publish cannot change policies halfway through sampling.
	for _, b := range e.live {
		b.target.tick(b, now, sample, queues[b.target.socket.Load()], kernelDrops, cut)
	}
}

func (b *Binding) ExpectsUDPResponse() bool { return b != nil && b.policy.ExpectUDPResponse }
func (b *Binding) CloudflareOnly() bool     { return b != nil && b.policy.CloudflareOnly }

func (b *Binding) Socket(inode uint64) {
	if b != nil {
		b.target.socket.Store(inode)
	}
}

const (
	PreFilter       = "pre_filter"
	Accepted        = "accepted"
	Routed          = "routed"
	Forwarded       = "forwarded"
	Dropped         = "dropped"
	BackendRejected = "backend_rejected"
)

var phaseNames = [...]string{PreFilter, Accepted, Routed, Forwarded, Dropped, BackendRejected, "bytes_in", "bytes_out", "new_connections", "requests", "packets"}
var phaseIndex = func() map[string]int {
	m := make(map[string]int, len(phaseNames))
	for i, phase := range phaseNames {
		m[phase] = i
	}
	return m
}()

func (b *Binding) Count(phase string, n uint64) {
	if b != nil && n != 0 {
		if i, ok := phaseIndex[phase]; ok {
			b.target.counts[i].Add(n)
		}
	}
}

func (b *Binding) InFlight(delta int64) {
	if b != nil {
		b.target.active.Add(delta)
	}
}

func (b *Binding) Queue(delta int64) {
	if b != nil {
		b.target.queue.Add(delta)
	}
}

func (b *Binding) QueueBytes(delta int64) {
	if b != nil {
		b.target.queueBytes.Add(delta)
	}
}

func (b *Binding) Observe(signal string, ip netip.Addr, value float64) {
	if b == nil {
		return
	}
	if i, ok := signalIndex[signal]; ok {
		b.target.observe(ip, i, value)
	}
}

func (b *Binding) Source(ip netip.Addr, reason string) {
	if b != nil && ip.IsValid() {
		b.target.source(ip.Unmap(), reason)
	}
}

func (b *Binding) Backend(ip netip.Addr, started time.Time, err error) {
	if b == nil {
		return
	}
	if err != nil {
		b.Count(BackendRejected, 1)
		b.Observe("backend_errors", ip, 1)
		return
	}
	b.Observe("backend_latency_ms", ip, float64(time.Since(started))/float64(time.Millisecond))
}

// Maximum returns the smallest admission-time limit for the operation. All the
// corresponding rules are still evaluated when the boundary is hit.
func (b *Binding) Maximum(metric string) int64 {
	if b == nil || !b.policy.EnforceLimits {
		return 0
	}
	var limit int64
	for _, p := range b.policy.Limits {
		if p.Metric == metric && p.Action.rank() >= Reject.rank() && (limit == 0 || int64(p.Value) < limit) {
			limit = int64(p.Value)
		}
	}
	return limit
}

func IP(addr net.Addr) netip.Addr {
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.AddrPort().Addr().WithZone("").Unmap()
	case *net.UDPAddr:
		return a.AddrPort().Addr().WithZone("").Unmap()
	default:
		if addr != nil {
			host, _, err := net.SplitHostPort(addr.String())
			if err == nil {
				ip, _ := netip.ParseAddr(host)
				return ip.WithZone("").Unmap()
			}
		}
	}
	return netip.Addr{}
}

func IPFromRemote(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		host = remote
	}
	ip, _ := netip.ParseAddr(host)
	return ip.Unmap()
}

func Subnet(ip netip.Addr) string {
	if !ip.IsValid() {
		return ""
	}
	bits := 64
	if ip.Is4() {
		bits = 24
	}
	return netip.PrefixFrom(ip, bits).Masked().String()
}

type Metric struct {
	Value  *float64 `json:"value"`
	Source string   `json:"source"`
}

type Event struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
	Action Action    `json:"action"`
	Rules  []string  `json:"rules"`
}

type Point struct {
	At         time.Time `json:"at"`
	Load       float64   `json:"load"`
	NormalLow  *float64  `json:"normalLow,omitempty"`
	NormalHigh *float64  `json:"normalHigh,omitempty"`
}

type Source struct {
	Address string `json:"address"`
	Subnet  string `json:"subnet"`
	Count   uint64 `json:"count"`
	Reason  string `json:"reason,omitempty"`
}

type Snapshot struct {
	ID            string            `json:"id"`
	Label         string            `json:"label"`
	Kind          string            `json:"kind"`
	Protocol      string            `json:"protocol"`
	Version       int64             `json:"version"`
	Policy        Policy            `json:"policy"`
	State         string            `json:"state"`
	Score         int               `json:"score"`
	Reason        string            `json:"reason"`
	Observability string            `json:"observability"`
	Metrics       map[string]Metric `json:"metrics"`
	Restrictions  []Restriction     `json:"restrictions,omitempty"`
	Events        []Event           `json:"events,omitempty"`
	History       []Point           `json:"history,omitempty"`
	Sources       []Source          `json:"sources,omitempty"`
	DropReasons   map[string]uint64 `json:"dropReasons,omitempty"`
}

func (e *Engine) Snapshots() []Snapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()
	s := make([]Snapshot, 0, len(e.live))
	for _, b := range e.live {
		s = append(s, b.target.snapshot(b, e.clock()))
	}
	sort.Slice(s, func(i, j int) bool { return s[i].ID < s[j].ID })
	return s
}

func (e *Engine) Binding(id string) *Binding {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, b := range e.live {
		if b.ID == id {
			return b
		}
	}
	return nil
}

type Restriction struct {
	Rule      string    `json:"rule"`
	Scope     string    `json:"scope"`
	Target    string    `json:"target"`
	Action    Action    `json:"action"`
	ExpiresAt time.Time `json:"expiresAt"`
	Automatic bool      `json:"automatic"`
}

type Override struct {
	Rule     string    `json:"rule"`
	Scope    string    `json:"scope"`
	Target   string    `json:"target"`
	Subject  string    `json:"subject"`
	Until    time.Time `json:"until"`
	Operator string    `json:"operator"`
	Instance string    `json:"instance,omitempty"`
}

func (b *Binding) Clear(rule, subject, operator string, ttl time.Duration) []Override {
	if b == nil {
		return nil
	}
	now := b.engine.clock()
	t := b.target
	t.mu.Lock()
	defer t.mu.Unlock()
	var restored []Override
	for k, r := range t.restrictions {
		if !r.Automatic || !r.ExpiresAt.After(now) || rule != "" && rule != r.Rule || subject != "" && subject != r.Target {
			continue
		}
		o := Override{Rule: r.Rule, Scope: r.Scope, Target: b.ID, Subject: r.Target, Until: now.Add(ttl), Operator: operator}
		if t.override(k, o, now) {
			restored = append(restored, o)
		}
	}
	return restored
}

func (b *Binding) Restore(overrides []Override) {
	if b == nil {
		return
	}
	now := b.engine.clock()
	b.target.mu.Lock()
	defer b.target.mu.Unlock()
	for _, o := range overrides {
		if o.Target == b.ID && o.Until.After(now) {
			b.target.override(restrictionKey{o.Rule, o.Scope, o.Subject, true}, o, now)
		}
	}
}

func (t *target) override(key restrictionKey, o Override, now time.Time) bool {
	if _, ok := t.overrides[key]; !ok && len(t.overrides) >= maxRestrictions {
		for k, old := range t.overrides {
			if !old.Until.After(now) {
				delete(t.overrides, k)
			}
		}
		if len(t.overrides) >= maxRestrictions {
			return false
		}
	}
	t.removeRestriction(key)
	t.overrides[key] = o
	if w := t.rules[key.rule]; w != nil {
		delete(w.streak, key.subject)
	}
	t.recordEvent(now, "manual_clear", Pass, []string{key.rule})
	return true
}

func (b *Binding) Denied(reason string) {
	if b == nil {
		return
	}
	b.Count(Dropped, 1)
	if b.Kind == Listener {
		b.engine.lastCut.Store(b.engine.clock().UnixNano())
	}
	b.target.mu.Lock()
	if _, exists := b.target.dropReasons[reason]; exists || len(b.target.dropReasons) < 64 {
		b.target.dropReasons[reason]++
	} else {
		b.target.dropReasons["other"]++
	}
	b.target.mu.Unlock()
}

func valueOf(n float64) *float64 { return &n }

func (b *Binding) String() string { return fmt.Sprintf("%s (%s)", b.ID, b.Kind) }
