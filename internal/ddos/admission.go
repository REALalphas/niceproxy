package ddos

import (
	"context"
	"hash/maphash"
	"math"
	"net/netip"
	"sync"
	"time"
)

type Amount struct {
	Metric string
	Value  float64
	// Connection disambiguates streams multiplexed on the same connection.
	Connection string
}

type hit struct {
	rule, reason string
	action       Action
	binding      *Binding
	priority     int
}

type reservation struct {
	shard *quotaShard
	key   quotaKey
}

type Decision struct {
	first hit
	hits  []hit
	held  []reservation
}

func (d *Decision) add(h hit) {
	if h.action.rank() > d.first.action.rank() || h.action == d.first.action && h.priority < d.first.priority {
		d.first = h
	}
	d.hits = append(d.hits, h)
}

func (d *Decision) Combine(other Decision) {
	for _, h := range other.hits {
		d.add(h)
	}
	d.held = append(d.held, other.held...)
}

func (d *Decision) Fail(b *Binding, reason string) {
	if b != nil {
		d.add(hit{rule: reason, reason: reason, action: Reject, binding: b})
	}
}

func (d *Decision) Rejected() bool { return d.first.action.rank() >= Reject.rank() }
func (d *Decision) Action() Action {
	if d.first.action == "" {
		return Pass
	}
	return d.first.action
}

// Record assigns the work to a single drop reason, retaining every rule hit
// in the accompanying event. Call it once after composing the admission stages.
func (d *Decision) Record() {
	if len(d.hits) == 0 {
		return
	}
	b := d.first.binding
	if d.Rejected() {
		b.Denied(d.first.reason)
	}
	if b == nil || b.target == nil {
		return
	}
	rules := make([]string, 0, len(d.hits))
	for _, h := range d.hits {
		rules = append(rules, h.binding.ID+":"+h.rule)
	}
	b.target.mu.Lock()
	b.target.recordEvent(b.engine.clock(), d.first.reason, d.first.action, rules)
	b.target.mu.Unlock()
}

func (d *Decision) Release() {
	for _, h := range d.held {
		h.shard.mu.Lock()
		q := h.shard.entries[h.key]
		q.used--
		if q.used == 0 {
			delete(h.shard.entries, h.key)
		}
		h.shard.mu.Unlock()
	}
	d.held = nil
}

// Wait implements bounded pacing. Under queue pressure a slow decision cannot
// create arbitrarily many waiting operations.
func (d *Decision) Wait(ctx context.Context) bool {
	if d.Rejected() {
		return false
	}
	if d.first.action != Slow {
		return true
	}
	b := d.first.binding
	select {
	case b.engine.slots <- struct{}{}:
		defer func() { <-b.engine.slots }()
	default:
		b.Denied("pacing_queue_full")
		return false
	}
	b.Queue(1)
	defer b.Queue(-1)
	t := time.NewTimer(10 * time.Millisecond)
	defer t.Stop()
	select {
	case <-t.C:
		return true
	case <-ctx.Done():
		return false
	}
}

// Check evaluates resource budgets, existing restrictions, and the explicit
// limits for these measurements. A caller holding work retains the returned
// reservations until it completes or is rejected by a later layer.
func (b *Binding) Check(ip netip.Addr, amounts ...Amount) Decision {
	return b.check(ip, true, amounts)
}

// CheckOperation evaluates a measurement from work that has already passed
// admission, using that work's immutable policy and without re-admitting it.
func (b *Binding) CheckOperation(ip netip.Addr, amounts ...Amount) Decision {
	return b.check(ip, false, amounts)
}

func priority(b *Binding, spec metricSpec, scope string, metric string) int {
	switch {
	case spec.mode == resource:
		return 0
	case b.Kind == Listener && !sourceScope(scope):
		return 1
	case b.Kind == Listener:
		return 2
	case len(metric) >= 8 && metric[:8] == "backend_":
		return 4
	default:
		return 3
	}
}

func (b *Binding) check(ip netip.Addr, admission bool, amounts []Amount) Decision {
	if b == nil {
		return Decision{}
	}
	now := b.engine.clock()
	var d Decision
	if admission {
		b.target.restrictionHits(b, ip, now, &d)
	}
	if !b.policy.EnforceLimits {
		return d
	}
	for _, l := range b.policy.Limits {
		spec := metrics[l.Metric]
		var a Amount
		if admission && spec.mode == resource {
			v := b.target.resource(l.Metric)
			if v == nil {
				continue
			}
			a = Amount{Metric: l.Metric, Value: *v}
		} else {
			for _, candidate := range amounts {
				if candidate.Metric == l.Metric {
					a = candidate
					break
				}
			}
			if a.Metric == "" {
				continue
			}
		}
		subject := subjectFor(l.Scope, ip)
		if subject == "" {
			continue
		}
		exceeded := a.Value > l.Value
		if spec.mode == rate || spec.mode == active {
			var held reservation
			exceeded, held = b.quota(l, a, subject, now, spec.mode)
			if held.shard != nil {
				d.held = append(d.held, held)
			}
		}
		if exceeded {
			d.add(hit{rule: l.ID, reason: "limit:" + l.Metric, action: l.Action, binding: b, priority: priority(b, spec, l.Scope, l.Metric)})
			if l.Action == Block {
				banScope := l.Scope
				// A block on a non-source quota still blocks the triggering source.
				if !sourceScope(l.Scope) && ip.IsValid() {
					banScope, subject = "ip", ip.String()
				}
				b.target.block(l.ID, banScope, subject, now, l.ttl())
			}
		}
	}
	return d
}

func subjectFor(scope string, ip netip.Addr) string {
	switch scope {
	case "ip":
		if ip.IsValid() {
			return ip.Unmap().String()
		}
	case "subnet":
		return Subnet(ip.Unmap())
	default:
		return "*"
	}
	return ""
}

type quotaKey struct {
	limit                Limit
	owner, subject, conn string
}

type quotaEntry struct {
	tokens  float64
	touched time.Time
	used    int64
}

type quotaShard struct {
	mu        sync.Mutex
	entries   map[quotaKey]*quotaEntry
	lastPurge time.Time
}

var hashSeed = maphash.MakeSeed()

func (b *Binding) quota(l Limit, a Amount, subject string, now time.Time, mode measurement) (bool, reservation) {
	owner := b.ID
	switch l.Scope {
	case "group":
		owner = "group:" + b.policy.Group
	case "all_instances":
		owner = "all_instances"
	}
	key := quotaKey{l, owner, subject, a.Connection}
	s := &b.engine.quotas[maphash.String(hashSeed, owner+"\x00"+subject+"\x00"+a.Connection)%uint64(len(b.engine.quotas))]
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.entries == nil {
		s.entries = make(map[quotaKey]*quotaEntry)
	}
	q := s.entries[key]
	if q == nil {
		if len(s.entries) >= 2048 && now.Sub(s.lastPurge) >= time.Second {
			for key, old := range s.entries {
				if key.limit.WindowSeconds > 0 && now.Sub(old.touched) >= refillDuration(key.limit) {
					delete(s.entries, key)
				}
			}
			s.lastPurge = now
		}
		if len(s.entries) >= 2048 {
			return true, reservation{}
		}
		q = &quotaEntry{tokens: l.Value + l.Burst, touched: now}
		s.entries[key] = q
	}
	if mode == active {
		exceeded := float64(q.used)+a.Value > l.Value
		if exceeded && l.Action.rank() >= Reject.rank() {
			return true, reservation{}
		}
		q.used++
		return exceeded, reservation{s, key}
	}
	q.tokens = math.Min(l.Value+l.Burst, q.tokens+now.Sub(q.touched).Seconds()*l.Value/float64(l.WindowSeconds))
	q.touched = now
	if a.Value > q.tokens {
		return true, reservation{}
	}
	q.tokens -= a.Value
	return false, reservation{}
}

func refillDuration(l Limit) time.Duration {
	seconds := float64(l.WindowSeconds) * (1 + l.Burst/l.Value)
	if seconds > float64((24*time.Hour)/time.Second) {
		return 24 * time.Hour
	}
	return time.Duration(seconds * float64(time.Second))
}
