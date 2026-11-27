package ddos

import (
	"math"
	"net/netip"
	"reflect"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"niceproxy/internal/linuxstats"
)

type restrictionKey struct {
	rule, scope, subject string
	automatic            bool
}

type restrictionState struct {
	Restriction
	stable int
}

type reading struct {
	sum float64
	n   uint64
}

func (r *reading) add(value float64) { r.sum += value; r.n++ }

func (r reading) value(signal string) float64 {
	if r.n != 0 && signal == "backend_latency_ms" {
		return r.sum / float64(r.n)
	}
	return r.sum
}

type ruleWindow struct {
	rule      Rule
	from      time.Time
	samples   uint64
	aggregate reading
	subjects  map[string]reading
	streak    map[string]int
	pressure  bool
	partial   bool
}

type target struct {
	mu         sync.Mutex
	counts     [len(phaseNames)]atomic.Uint64
	active     atomic.Int64
	queue      atomic.Int64
	queueBytes atomic.Int64
	socket     atomic.Uint64
	resources  atomic.Pointer[map[string]Metric]
	tracking   atomic.Bool
	hasFilters atomic.Bool

	policy       Policy
	configured   bool
	rules        map[string]*ruleWindow
	restrictions map[restrictionKey]*restrictionState
	bySubject    map[string]map[restrictionKey]*restrictionState
	overrides    map[restrictionKey]Override
	reasons      [len(signals)]reading
	sources      map[netip.Addr]Source
	seenSources  map[netip.Addr]struct{}
	seenSubnets  map[netip.Prefix]struct{}
	last         [len(phaseNames)]uint64
	updated      time.Time
	metrics      map[string]Metric
	lastGood     time.Time
	lastBad      time.Time
	lastDrops    *float64
	state        string
	reason       string
	partial      bool
	score        int
	normal       float64
	deviation    float64
	trained      int
	warm         int
	recovery     int
	cooldown     time.Time
	history      []Point
	events       []Event
	dropReasons  map[string]uint64
}

func newTarget() *target {
	return &target{
		rules: make(map[string]*ruleWindow), restrictions: make(map[restrictionKey]*restrictionState),
		bySubject: make(map[string]map[restrictionKey]*restrictionState), overrides: make(map[restrictionKey]Override),
		dropReasons: make(map[string]uint64), state: "off", reason: "detector_disabled",
	}
}

func (t *target) configure(b *Binding, now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.configured && reflect.DeepEqual(t.policy, b.policy) {
		return
	}
	if b.policy.Detect && !t.policy.Detect {
		t.trained, t.warm, t.recovery = 0, 0, 0
		t.state, t.reason = "collecting", "warming_up"
	}
	if !b.policy.Detect {
		t.state, t.reason = "off", "detector_disabled"
	}
	t.rules = make(map[string]*ruleWindow, len(b.policy.Rules))
	if b.policy.Detect {
		for _, r := range b.policy.Rules {
			t.rules[r.ID] = &ruleWindow{rule: r, from: now, subjects: make(map[string]reading), streak: make(map[string]int)}
		}
	}
	t.policy = b.policy
	t.configured = true
	t.tracking.Store(b.policy.Detect)
}

func (t *target) source(ip netip.Addr, reason string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.sources == nil {
		t.sources = make(map[netip.Addr]Source)
	}
	s, ok := t.sources[ip]
	if !ok {
		if len(t.sources) >= maxSources {
			return
		}
		s = Source{Address: ip.String(), Subnet: Subnet(ip)}
	}
	s.Count++
	if reason != "" {
		s.Reason = reason
	}
	t.sources[ip] = s
	if !t.policy.Detect || len(t.seenSources) >= maxSources {
		return
	}
	if t.seenSources == nil {
		t.seenSources = make(map[netip.Addr]struct{})
		t.seenSubnets = make(map[netip.Prefix]struct{})
	}
	t.seenSources[ip] = struct{}{}
	if subnet, err := netip.ParsePrefix(s.Subnet); err == nil {
		t.seenSubnets[subnet] = struct{}{}
	}
}

func (t *target) observe(ip netip.Addr, i int, value float64) {
	signal := signals[i]
	if !t.tracking.Load() && signal != "backend_errors" && signal != "backend_latency_ms" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.reasons[i].add(value)
	for _, w := range t.rules {
		if w.rule.Signal != signal {
			continue
		}
		w.aggregate.add(value)
		if sourceScope(w.rule.Scope) {
			subject := subjectFor(w.rule.Scope, ip)
			if stat, found := w.subjects[subject]; subject != "" && (found || len(w.subjects) < maxSources) {
				stat.add(value)
				w.subjects[subject] = stat
			}
		}
	}
}

func (t *target) recordEvent(now time.Time, reason string, action Action, rules []string) {
	if n := len(t.events); n != 0 {
		last := t.events[n-1]
		if now.Sub(last.At) < time.Second && reason == last.Reason && action == last.Action && slices.Equal(rules, last.Rules) {
			return
		}
	}
	t.events = appendBounded(t.events, Event{At: now, Reason: reason, Action: action, Rules: rules}, maxEvents)
}

func appendBounded[T any](items []T, item T, limit int) []T {
	if len(items) == limit {
		copy(items, items[1:])
		items[limit-1] = item
		return items
	}
	return append(items, item)
}

func (t *target) setRestriction(key restrictionKey, r *restrictionState) {
	t.restrictions[key] = r
	if t.bySubject[key.subject] == nil {
		t.bySubject[key.subject] = make(map[restrictionKey]*restrictionState)
	}
	t.bySubject[key.subject][key] = r
	t.hasFilters.Store(true)
}

func (t *target) removeRestriction(key restrictionKey) {
	delete(t.restrictions, key)
	delete(t.bySubject[key.subject], key)
	if len(t.bySubject[key.subject]) == 0 {
		delete(t.bySubject, key.subject)
	}
	t.hasFilters.Store(len(t.restrictions) > 0)
}

func (t *target) restrictionHits(b *Binding, ip netip.Addr, now time.Time, d *Decision) {
	if !t.hasFilters.Load() {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, subject := range [...]string{"*", subjectFor("ip", ip), subjectFor("subnet", ip)} {
		for _, r := range t.bySubject[subject] {
			if r.ExpiresAt.After(now) {
				reason := "temporary_block"
				if r.Automatic {
					reason = "auto_filter"
				}
				d.add(hit{rule: r.Rule, reason: reason, action: r.Action, binding: b, priority: priority(b, metricSpec{}, r.Scope, "")})
			}
		}
	}
}

func (t *target) block(ruleID, scope, subject string, now time.Time, ttl time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()
	key := restrictionKey{ruleID, scope, subject, false}
	if old := t.restrictions[key]; old != nil && old.ExpiresAt.After(now) {
		return
	}
	if len(t.restrictions) < maxRestrictions {
		t.setRestriction(key, &restrictionState{Restriction: Restriction{ruleID, scope, subject, Block, now.Add(ttl), false}})
	}
}

func (t *target) resource(name string) *float64 {
	if name == "queue" {
		return valueOf(float64(t.queue.Load()))
	}
	if m := t.resources.Load(); m != nil {
		return (*m)[name].Value
	}
	return nil
}

func (t *target) tick(b *Binding, now time.Time, sample linuxstats.Sample, queue linuxstats.SocketQueue, kernelDrops *float64, upstreamCut bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	elapsed := now.Sub(t.updated).Seconds()
	if t.updated.IsZero() || elapsed <= 0 {
		elapsed = 1
	}
	counts := t.loadCounts()
	load := float64(counts[0]-t.last[0]) / elapsed
	bad := t.reasons[signalIndex["protocol_errors"]].sum + t.reasons[signalIndex["timeouts"]].sum +
		t.reasons[signalIndex["short_connections"]].sum + t.reasons[signalIndex["udp_unanswered"]].sum
	backendFailures := t.reasons[signalIndex["backend_errors"]].sum
	latency := t.reasons[signalIndex["backend_latency_ms"]]
	if latency.n != 0 {
		t.lastGood = now
	}
	if backendFailures > 0 {
		t.lastBad = now
	}
	backendKnown := !t.lastGood.IsZero() && now.Sub(t.lastGood) <= 2*time.Minute
	backendHealthy := backendKnown && t.lastGood.After(t.lastBad)
	if b.Kind == Listener && t.lastBad.IsZero() {
		backendHealthy = true // Backend health is evaluated at the routed target.
	}

	resources := map[string]Metric{
		"cpu_percent":        {sample.CPUPercent, "/proc/self/stat, GOMAXPROCS"},
		"memory_bytes":       {sample.MemoryBytes, "/proc/self/status · VmRSS"},
		"kernel_drops":       {kernelDrops, "/proc/net/netstat + /proc/net/snmp · network namespace"},
		"listen_overflows":   {sample.ListenOverflows, "/proc/net/netstat · network namespace"},
		"udp_input_errors":   {sample.UDPInErrors, "/proc/net/snmp · network namespace"},
		"backlog":            {nil, "/proc/net/tcp · socket"},
		"socket_queue_bytes": {nil, "/proc/net/udp · socket"},
		"socket_drops":       {queue.Drops, "/proc/net/udp · socket"},
	}
	if b.Protocol == "udp" || b.Protocol == "http3" {
		resources["socket_queue_bytes"] = Metric{queue.Receive, "/proc/net/udp · socket"}
	} else {
		resources["backlog"] = Metric{queue.Receive, "/proc/net/tcp · listen socket"}
	}
	t.resources.Store(&resources)
	pressure := sample.CPUPercent != nil && *sample.CPUPercent >= 95
	for _, limit := range t.policy.Limits {
		if !t.policy.EnforceLimits || metrics[limit.Metric].mode != resource {
			continue
		}
		v := resources[limit.Metric].Value
		if limit.Metric == "queue" {
			v = valueOf(float64(t.queue.Load()))
		}
		pressure = pressure || v != nil && *v > limit.Value
	}
	socketDrops := 0.0
	if queue.Drops != nil && t.lastDrops != nil && *queue.Drops >= *t.lastDrops {
		socketDrops = *queue.Drops - *t.lastDrops
	}
	t.lastDrops = queue.Drops
	drops := socketDrops
	if kernelDrops != nil {
		drops = math.Max(drops, *kernelDrops)
	}
	bump := func(signal string, value float64) {
		for _, w := range t.rules {
			if w.rule.Signal == signal {
				w.aggregate.add(value)
			}
		}
	}
	if pressure {
		bump("pressure", 1)
	}
	bump("kernel_drops", drops)
	bump("distinct_sources", float64(len(t.seenSources)))
	bump("distinct_subnets", float64(len(t.seenSubnets)))
	// Socket loss and a filter upstream both hide offered load from this
	// admission point. Neither can be treated as a quiet input window.
	t.partial = b.PreFilter == "" || b.Kind != Listener && !b.BeforeListenerFilter && upstreamCut || drops > 0
	resourcesKnown := sample.CPUPercent != nil && sample.MemoryBytes != nil && kernelDrops != nil
	healthy := !pressure && resourcesKnown && backendHealthy && bad == 0 && backendFailures == 0 && !t.partial
	t.detect(now, uint64(counts[0]-t.last[0]), load, bad, backendFailures, pressure, healthy, drops)

	out := make(map[string]Metric, len(resources)+len(phaseNames)+8)
	for name, value := range resources {
		out[name] = value
	}
	for i, name := range phaseNames {
		out[name] = Metric{valueOf(float64(counts[i])), "proxy · " + b.Protocol}
	}
	out[PreFilter] = Metric{valueOf(float64(counts[0])), b.PreFilter}
	if b.PreFilter == "" {
		out[PreFilter] = Metric{nil, "no observation before filter"}
	}
	if b.Kind == Listener {
		out[Routed] = Metric{nil, "matched endpoint counter"}
		out[Forwarded] = Metric{nil, "endpoint forwarding counter"}
		out[BackendRejected] = Metric{nil, "backend endpoint counter"}
	}
	for _, name := range [...]string{"bytes_in", "bytes_out", "new_connections", "requests", "packets"} {
		i := phaseIndex[name]
		value := out[name].Value
		if value != nil && counts[i] == 0 && !b.measures(name) {
			out[name] = Metric{nil, out[name].Source}
			value = nil
		}
		if value != nil {
			value = valueOf(float64(counts[i]-t.last[i]) / elapsed)
		}
		out[name+"_per_second"] = Metric{value, out[name].Source}
	}
	out["active"] = Metric{valueOf(float64(t.active.Load())), "proxy · " + b.Protocol}
	out["queue"] = Metric{valueOf(float64(t.queue.Load())), "proxy · pending work"}
	out["queue_bytes"] = Metric{valueOf(float64(t.queueBytes.Load())), "proxy · queued datagrams"}
	out["backend_latency_ms"] = Metric{nil, "observed backend work"}
	out["backend_healthy"] = Metric{nil, "observed backend work"}
	if latency.n > 0 {
		out["backend_latency_ms"] = Metric{valueOf(latency.value("backend_latency_ms")), "observed backend work"}
	}
	if backendKnown || backendFailures > 0 {
		v := 0.0
		if backendHealthy {
			v = 1
		}
		out["backend_healthy"] = Metric{&v, "observed backend work"}
	}
	out["asn"] = Metric{nil, "ASN provider not configured"}
	t.metrics, t.last, t.updated = out, counts, now
	clear(t.seenSources)
	clear(t.seenSubnets)
	clear(t.reasons[:])
}

func (b *Binding) measures(name string) bool {
	switch name {
	case "bytes_in", "bytes_out":
		return true
	case "requests":
		return b.Kind == HTTP || b.Kind == HTTPTCP || b.Kind == HTTPUDP || b.Protocol == "http" || b.Protocol == "https"
	case "new_connections":
		return b.Kind == TCP || b.Protocol == "http" || b.Protocol == "https"
	case "packets":
		return b.Protocol == "udp" || b.Protocol == "http3"
	}
	return false
}

func (t *target) loadCounts() (counts [len(phaseNames)]uint64) {
	for i := range counts {
		counts[i] = t.counts[i].Load()
	}
	return counts
}

func (t *target) detect(now time.Time, samples uint64, load, bad, backendErrors float64, pressure, healthy bool, drops float64) {
	for key, r := range t.restrictions {
		w := t.rules[key.rule]
		if r.Automatic && t.policy.AutoFilter && w != nil {
			if !r.ExpiresAt.After(now.Add(time.Second)) {
				r.ExpiresAt = now.Add(time.Duration(w.rule.CooldownSeconds) * time.Second)
			}
			continue
		}
		if !r.ExpiresAt.After(now) {
			t.removeRestriction(key)
			t.recordEvent(now, "ttl_expired", Pass, []string{key.rule})
		}
	}
	for k, v := range t.overrides {
		if !v.Until.After(now) {
			delete(t.overrides, k)
		}
	}
	if !t.policy.Detect {
		return
	}
	t.score = 0
	badWindow := bad > 0 || backendErrors > 0 || pressure || drops > 0
	suspected, confirmed := badWindow, false
	for _, w := range t.rules {
		w.samples += samples
		w.partial = w.partial || !healthy
		w.pressure = w.pressure || badWindow
		if now.Sub(w.from) < time.Duration(w.rule.WindowSeconds)*time.Second {
			continue
		}
		s, a := t.evaluate(w, now)
		suspected, confirmed = suspected || s, confirmed || a
		w.from, w.samples, w.aggregate, w.pressure, w.partial = now, 0, reading{}, false, false
		clear(w.subjects)
	}
	hasAuto := false
	for _, r := range t.restrictions {
		hasAuto = hasAuto || r.Automatic
	}
	if hasAuto && !healthy {
		t.recovery = 0
	}
	previous := t.state
	switch {
	case t.partial && (hasAuto || t.trained >= t.policy.stable()):
		t.state, t.reason, t.score = "partial", "pre_filter_incomplete", 70
	case confirmed || (hasAuto && badWindow):
		t.state, t.reason, t.score = "attack", "corroborated_rule", 100
		t.recovery = 0
	case hasAuto || previous == "attack" || previous == "recovering" || previous == "partial":
		if healthy {
			t.recovery++
		} else {
			t.recovery = 0
		}
		if !hasAuto && t.recovery >= t.policy.stable() {
			t.state, t.reason = "normal", "input_and_backend_stable"
			t.cooldown = now.Add(time.Duration(t.policy.stable()) * time.Second)
		} else {
			t.state, t.reason, t.score = "recovering", "stable_windows_required", 50
		}
	case suspected:
		t.state, t.reason, t.score = "suspected", "anomalies_or_resource_pressure", 35
		t.warm = 0
	case t.trained >= t.policy.stable() && healthy:
		t.state, t.reason = "normal", "input_and_backend_stable"
	case t.trained >= t.policy.stable():
		t.state, t.reason = "collecting", "resource_or_backend_observation_missing"
	default:
		t.state, t.reason = "collecting", "warming_up"
	}
	if previous != t.state {
		t.recordEvent(now, "state:"+t.state, Pass, nil)
	}
	p := Point{At: now, Load: load}
	if t.trained >= t.policy.stable() {
		width := math.Max(t.normal*0.25, 3*t.deviation+1)
		p.NormalLow, p.NormalHigh = valueOf(math.Max(0, t.normal-width)), valueOf(t.normal+width)
	}
	t.history = appendBounded(t.history, p, maxHistory)
	if !healthy || t.state == "attack" || t.state == "partial" || t.state == "recovering" || now.Before(t.cooldown) {
		t.warm = 0
		return
	}
	t.warm++
	if t.trained != 0 && t.warm < t.policy.stable() {
		return
	}
	// Limit how quickly an already learned profile can widen.
	learn := load
	if t.trained >= t.policy.stable() {
		learn = math.Min(load, t.normal*1.25+1)
	}
	if t.trained == 0 {
		t.normal = learn
	} else {
		t.deviation = 0.9*t.deviation + 0.1*math.Abs(learn-t.normal)
		t.normal = 0.9*t.normal + 0.1*learn
	}
	if t.trained <= 60 {
		t.trained++
	}
}

func (t *target) evaluate(w *ruleWindow, now time.Time) (suspected, attack bool) {
	r := w.rule
	streak := make(map[string]int)
	evaluate := func(subject string, stat reading) {
		key := restrictionKey{r.ID, r.Scope, subject, true}
		v := stat.value(r.Signal)
		n := stat.n
		if !sourceScope(r.Scope) {
			n = max(n, w.samples)
		}
		// Volume or cardinality by itself can be organic demand.
		corroborated := w.pressure || nonVolume(r.Signal)
		breach := v >= r.Threshold && n >= uint64(r.MinSamples)
		if breach {
			suspected = suspected || corroborated
			if !t.overrides[key].Until.After(now) {
				streak[subject] = min(w.streak[subject]+1, 2)
			}
		}
		confirmed := breach && corroborated && (streak[subject] >= 2 || r.Burst > 0 && v >= r.Threshold+r.Burst)
		if t.trained >= t.policy.stable() && confirmed {
			attack = true
			if t.policy.AutoFilter && r.Action != Pass && !t.overrides[key].Until.After(now) {
				ttl := time.Duration(r.CooldownSeconds) * time.Second
				if restr := t.restrictions[key]; restr != nil {
					if restr.Action != r.Action {
						t.recordEvent(now, "filter_restored", r.Action, []string{r.ID})
					}
					restr.Action, restr.ExpiresAt, restr.stable = r.Action, now.Add(ttl), 0
				} else if len(t.restrictions) < maxRestrictions {
					t.setRestriction(key, &restrictionState{Restriction: Restriction{r.ID, r.Scope, subject, r.Action, now.Add(ttl), true}})
					t.recordEvent(now, "filter_enabled", r.Action, []string{r.ID})
				}
			}
		}
		if restr := t.restrictions[key]; restr != nil && t.policy.AutoFilter {
			if v > r.ClearThreshold || w.partial {
				restr.stable = 0
			} else {
				restr.stable++
				if restr.stable >= t.policy.stable() {
					restr.stable = 0
					restr.Action = relax(restr.Action)
					t.recordEvent(now, "filter_relaxed", restr.Action, []string{r.ID})
					if restr.Action == Pass {
						t.removeRestriction(key)
					}
				}
			}
		}
	}
	if sourceScope(r.Scope) {
		for subject, stat := range w.subjects {
			evaluate(subject, stat)
		}
		for key := range t.restrictions {
			if _, seen := w.subjects[key.subject]; key.rule == r.ID && key.automatic && !seen {
				evaluate(key.subject, reading{})
			}
		}
	} else {
		evaluate("*", w.aggregate)
	}
	w.streak = streak
	return
}

func nonVolume(signal string) bool {
	switch signal {
	case "tcp_new", "tls_new", "requests", "udp_packets", "udp_bytes", "distinct_sources", "distinct_subnets":
		return false
	}
	return true
}

func relax(a Action) Action {
	switch a {
	case Block:
		return Reject
	case Reject:
		return Slow
	default:
		return Pass
	}
}

func (t *target) snapshot(b *Binding, now time.Time) Snapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	s := Snapshot{ID: b.ID, Label: b.Label, Kind: b.Kind, Protocol: b.Protocol, Version: b.Version, Policy: b.policy, State: t.state, Score: t.score, Reason: t.reason}
	s.Observability = "socket"
	if b.PreFilter == "" || t.partial {
		s.Observability = "partial"
	}
	if t.policy.Detect && b.PreFilter == "" {
		s.State, s.Reason = "partial", "pre_filter_incomplete"
	}
	s.Metrics = make(map[string]Metric, len(t.metrics)+len(phaseNames))
	for k, v := range t.metrics {
		s.Metrics[k] = v
	}
	for i, name := range phaseNames {
		if m, sampled := s.Metrics[name]; sampled && m.Value == nil {
			continue
		}
		if b.Kind == Listener && (name == Routed || name == Forwarded || name == BackendRejected) || name == PreFilter && b.PreFilter == "" {
			s.Metrics[name] = Metric{nil, "unavailable at this admission point"}
			continue
		}
		if !t.updated.IsZero() || i <= phaseIndex[BackendRejected] || b.measures(name) {
			source := "proxy · " + b.Protocol
			if name == PreFilter {
				source = b.PreFilter
			}
			s.Metrics[name] = Metric{valueOf(float64(t.counts[i].Load())), source}
		}
	}
	s.Metrics["active"] = Metric{valueOf(float64(t.active.Load())), "proxy · in-flight work"}
	for _, r := range t.restrictions {
		if r.ExpiresAt.After(now) {
			s.Restrictions = append(s.Restrictions, r.Restriction)
		}
	}
	sort.Slice(s.Restrictions, func(i, j int) bool {
		if s.Restrictions[i].Rule == s.Restrictions[j].Rule {
			return s.Restrictions[i].Target < s.Restrictions[j].Target
		}
		return s.Restrictions[i].Rule < s.Restrictions[j].Rule
	})
	s.Events = slices.Clone(t.events)
	s.History = slices.Clone(t.history)
	for _, source := range t.sources {
		s.Sources = append(s.Sources, source)
	}
	sort.Slice(s.Sources, func(i, j int) bool {
		if s.Sources[i].Count == s.Sources[j].Count {
			return s.Sources[i].Address < s.Sources[j].Address
		}
		return s.Sources[i].Count > s.Sources[j].Count
	})
	s.DropReasons = make(map[string]uint64, len(t.dropReasons))
	for k, v := range t.dropReasons {
		s.DropReasons[k] = v
	}
	return s
}
