// Package proxy manages direct TCP and UDP forwarding rules.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"niceproxy/internal/ddos"
	"niceproxy/internal/linuxstats"
)

// Rule identifies a listener and its upstream. Port zero may be used for an ephemeral listener.
type Rule struct {
	Protocol, ListenAddress string
	ListenPort              int
	TargetAddress           string
	TargetPort              int
}

// Options limits resources per rule. TCPTimeout is the maximum stream lifetime
// after dialing (not an idle timeout); zero leaves stream lifetime unlimited.
type Options struct {
	DialTimeout, TCPTimeout, UDPIdleTimeout              time.Duration
	MaxTCPConnections, MaxUDPAssociations, UDPBufferSize int
}

func (o Options) defaults() Options {
	if o.DialTimeout <= 0 {
		o.DialTimeout = 5 * time.Second
	}
	if o.UDPIdleTimeout <= 0 {
		o.UDPIdleTimeout = time.Minute
	}
	if o.MaxTCPConnections <= 0 {
		o.MaxTCPConnections = 1024
	}
	if o.MaxUDPAssociations <= 0 {
		o.MaxUDPAssociations = 1024
	}
	if o.UDPBufferSize <= 0 {
		o.UDPBufferSize = 65535
	}
	if o.UDPBufferSize > 65535 {
		o.UDPBufferSize = 65535
	}
	return o
}
func (r Rule) validate() error {
	if r.Protocol != "tcp" && r.Protocol != "udp" {
		return errors.New("protocol must be tcp or udp")
	}
	if r.ListenPort < 0 || r.ListenPort > 65535 || r.TargetPort < 1 || r.TargetPort > 65535 || r.TargetAddress == "" {
		return errors.New("invalid address or port")
	}
	return nil
}
func address(host string, port int) string { return net.JoinHostPort(host, strconv.Itoa(port)) }

// Stats is a process-local snapshot. TCP Accepted counts OS accepts (including
// rejected connections); UDP Accepted counts admitted association attempts,
// including queued setups and pending dials. Active includes both; Closed
// counts finished accepted work. Rejects counts observed admission failures, never unreachable
// ports. Repeated UDP attempts from an unadmitted sender can each be rejected;
// no per-client rejection tombstones are retained. Errors counts failed
// lifecycles, not packets or bytes. Administrative
// shutdown and UDP idle expiry are not errors. Fields are loaded independently.
// StartedAt is the first successful bind for this retained rule ID.
type Stats struct {
	Accepted, Active, Closed, Errors, Rejects uint64
	StartedAt                                 time.Time
}

type counters struct {
	accepted, active, closed, errors, rejects atomic.Uint64
	tcpActive, udpActive                      atomic.Int64
	startedAt                                 time.Time
	refs                                      int // manager lock
	forget                                    bool
}

func (c *counters) snapshot() Stats {
	return Stats{c.accepted.Load(), c.active.Load(), c.closed.Load(), c.errors.Load(), c.rejects.Load(), c.startedAt}
}
func admit(n *atomic.Int64, limit int) bool {
	for {
		old := n.Load()
		if old >= int64(limit) {
			return false
		}
		if n.CompareAndSwap(old, old+1) {
			return true
		}
	}
}

// ErrRetiredLimit means a listener handover would exceed the draining bound.
var ErrRetiredLimit = errors.New("retired listener limit reached")

const maxRetiredRules = 1024
const maxInactiveStats = 1024

type instance interface {
	stop()
	wait(context.Context) error
	addr() net.Addr
	metrics() *counters
}
type Manager struct {
	mu               sync.Mutex
	rules            map[string]instance
	specs            map[string]Rule
	opts             Options
	closed           bool
	retired          map[instance]struct{}
	stats            map[string]*counters
	cleanup          sync.WaitGroup
	defense          *ddos.Engine
	protection       map[string]Protection
	httpProtection   map[string]Protection
	globalProtection Protection
}

func NewManager(o Options) *Manager {
	return &Manager{rules: make(map[string]instance), specs: make(map[string]Rule), opts: o.defaults(), retired: make(map[instance]struct{}), stats: make(map[string]*counters), defense: ddos.NewEngine(), protection: make(map[string]Protection), httpProtection: make(map[string]Protection)}
}

type ProtectionConfig struct {
	Version            int64
	Listener, Endpoint *ddos.Policy
}

func (m *Manager) Defense() *ddos.Engine { return m.defense }

type HTTPProtectionConfig struct {
	ID, Label, Network string
	Version            int64
	Listener, Endpoint *ddos.Policy
}

func (m *Manager) SetHTTPProtection(specs []HTTPProtectionConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.httpProtection = make(map[string]Protection, len(specs))
	for _, spec := range specs {
		listener := m.defense.Bind(ddos.Spec{ID: "listener:global", Label: "all listeners", Kind: ddos.Listener, Protocol: spec.Network, Version: spec.Version, Policy: spec.Listener, PreFilter: "caddy · listener"})
		endpoint := m.defense.Bind(ddos.Spec{ID: "http:" + spec.ID, Label: spec.Label, Kind: spec.Network, Protocol: spec.Network, Version: spec.Version, Policy: spec.Endpoint, PreFilter: "caddy · request"})
		m.httpProtection[spec.ID] = Protection{Listener: listener, Endpoint: endpoint}
	}
}

func (m *Manager) SetGlobalProtection(policy *ddos.Policy, version int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.globalProtection = Protection{Listener: m.defense.Bind(ddos.Spec{ID: "listener:global", Label: "all listeners", Kind: ddos.Listener, Version: version, Policy: policy, PreFilter: "proxy · admission"})}
}

func (m *Manager) HTTPProtection(id string) Protection {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.httpProtection[id]
}

func (m *Manager) protectionFor(id string, r Rule, cfg *ProtectionConfig) Protection {
	if cfg == nil {
		return Protection{}
	}
	source := "socket · accept"
	if r.Protocol == "udp" {
		source = "socket · recvmsg"
	}
	listener := m.defense.Bind(ddos.Spec{ID: "listener:global", Label: "all listeners", Kind: ddos.Listener, Protocol: r.Protocol, Version: cfg.Version, Policy: cfg.Listener, PreFilter: source})
	endpoint := m.defense.Bind(ddos.Spec{ID: id, Label: address(r.ListenAddress, r.ListenPort), Kind: r.Protocol, Protocol: r.Protocol, Version: cfg.Version, Policy: cfg.Endpoint, PreFilter: source, BeforeListenerFilter: true})
	return Protection{Listener: listener, Endpoint: endpoint}
}

func (m *Manager) PublishProtection() {
	m.mu.Lock()
	defer m.mu.Unlock()
	var bindings []*ddos.Binding
	for id, p := range m.protection {
		if m.rules[id] != nil && p.Listener != nil {
			bindings = append(bindings, p.Listener, p.Endpoint)
		}
	}
	for _, p := range m.httpProtection {
		bindings = append(bindings, p.Listener, p.Endpoint)
	}
	if m.globalProtection.Listener != nil {
		bindings = append(bindings, m.globalProtection.Listener)
	}
	m.defense.Publish(bindings)
}

// Stats returns retained statistics for a rule ID, including retired streams.
// At most maxInactiveStats inactive IDs are retained; active IDs are never evicted.
func (m *Manager) Stats(id string) (Stats, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.stats[id]
	if !ok {
		return Stats{}, false
	}
	return c.snapshot(), true
}

// ForgetStats releases statistics for an explicitly deleted rule once its last
// generation finishes. Re-adding before then preserves counters and admission.
func (m *Manager) ForgetStats(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c := m.stats[id]; c != nil {
		c.forget = true
		if c.refs == 0 {
			delete(m.stats, id)
		}
	}
}
func (m *Manager) trimStats() {
	inactive := 0
	for _, c := range m.stats {
		if c.refs == 0 {
			inactive++
		}
	}
	for id, c := range m.stats {
		if c.refs == 0 && (c.forget || inactive > maxInactiveStats) {
			delete(m.stats, id)
			inactive--
		}
	}
}

// retireLocked registers exactly one cleanup owner. Its entry remains visible to
// Close until all traffic has finished. Caller holds m.mu.
func (m *Manager) retireLocked(i instance) {
	i.stop()
	m.retired[i] = struct{}{}
	m.cleanup.Add(1)
	go func() {
		defer m.cleanup.Done()
		_ = i.wait(context.Background())
		m.mu.Lock()
		delete(m.retired, i)
		i.metrics().refs--
		m.trimStats()
		m.mu.Unlock()
	}()
}

// Retire releases the listener immediately while accepted TCP streams finish
// naturally. Admission is shared by rule ID across re-adds and rebinds. A global
// bound of 1024 draining generations rejects further handovers until one drains.
func (m *Manager) Retire(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return net.ErrClosed
	}
	i, ok := m.rules[id]
	if !ok {
		return fmt.Errorf("rule %q not found", id)
	}
	if len(m.retired) >= maxRetiredRules {
		return ErrRetiredLimit
	}
	delete(m.rules, id)
	delete(m.specs, id)
	delete(m.protection, id)
	m.retireLocked(i)
	return nil
}

// HasListener reports current listener ownership, excluding retired streams.
// Reconciliation uses it after a failed replacement/rollback; statistics alone
// cannot prove a listener is still bound.
func (m *Manager) HasListener(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.rules[id]
	return ok
}

// Add starts a rule. The OS performs the authoritative bind-conflict check.
func (m *Manager) Add(id string, r Rule) (net.Addr, error) {
	return m.AddProtected(id, r, nil)
}

func (m *Manager) AddProtected(id string, r Rule, cfg *ProtectionConfig) (net.Addr, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, net.ErrClosed
	}
	if id == "" {
		return nil, errors.New("empty rule ID")
	}
	if _, ok := m.rules[id]; ok {
		return nil, fmt.Errorf("rule %q already exists", id)
	}
	return m.add(id, r, m.protectionFor(id, r, cfg))
}
func (m *Manager) add(id string, r Rule, protection Protection) (net.Addr, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	c := m.stats[id]
	if c == nil {
		c = &counters{startedAt: time.Now()}
	}
	var inst instance
	if r.Protocol == "tcp" {
		l, err := net.Listen("tcp", address(r.ListenAddress, r.ListenPort))
		if err != nil {
			return nil, err
		}
		forceCtx, forceCancel := context.WithCancel(context.Background())
		t := &tcpRule{stats: c, forceCtx: forceCtx, forceCancel: forceCancel, listener: l.(*net.TCPListener), rule: r, protection: protection, opts: m.opts, conns: make(map[*net.TCPConn]struct{}), done: make(chan struct{})}
		inst = t
		protection.socket(linuxstats.SocketInode(t.listener))
		go t.serve()
	} else {
		a, err := net.ResolveUDPAddr("udp", address(r.ListenAddress, r.ListenPort))
		if err != nil {
			return nil, err
		}
		l, err := net.ListenUDP("udp", a)
		if err != nil {
			return nil, err
		}
		forceCtx, forceCancel := context.WithCancel(context.Background())
		u := &udpRule{stats: c, forceCtx: forceCtx, forceCancel: forceCancel, listener: l, rule: r, protection: protection, opts: m.opts, clients: make(map[string]*udpClient), pending: make(map[string]*udpSetup), done: make(chan struct{})}
		inst = u
		protection.socket(linuxstats.SocketInode(l))
		go u.serve()
	}
	c.refs++
	c.forget = false
	m.stats[id] = c
	m.trimStats()
	m.rules[id] = inst
	m.specs[id] = r
	m.protection[id] = protection
	return inst.addr(), nil
}

// Update changes a target in place when the listener is unchanged. Otherwise it
// binds the replacement before retiring the old listener; failed binds leave it intact.
// Existing TCP streams keep their target; UDP associations are reset. ctx bounds
// draining the retired listener after a successful replacement.
func (m *Manager) Update(ctx context.Context, id string, r Rule) (net.Addr, error) {
	return m.UpdateProtected(ctx, id, r, nil)
}

func (m *Manager) UpdateProtected(ctx context.Context, id string, r Rule, cfg *ProtectionConfig) (net.Addr, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, net.ErrClosed
	}
	old, ok := m.rules[id]
	if !ok {
		m.mu.Unlock()
		return nil, fmt.Errorf("rule %q not found", id)
	}
	if err := r.validate(); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	prev := m.specs[id]
	previousProtection := m.protection[id]
	protection := previousProtection
	if cfg != nil {
		protection = m.protectionFor(id, r, cfg)
	}
	if r.Protocol == prev.Protocol && r.ListenAddress == prev.ListenAddress && r.ListenPort == prev.ListenPort {
		switch i := old.(type) {
		case *tcpRule:
			i.mu.Lock()
			i.rule, i.protection = r, protection
			i.mu.Unlock()
		case *udpRule:
			i.reconfigure(r, protection)
		}
		m.specs[id] = r
		m.protection[id] = protection
		a := old.addr()
		m.mu.Unlock()
		return a, nil
	}
	if len(m.retired) >= maxRetiredRules {
		m.mu.Unlock()
		return nil, ErrRetiredLimit
	}
	// Overlapping listeners (wildcard <-> a specific address on the same
	// port) cannot coexist. Stop accepting first and restore the old listener
	// if the replacement bind fails. Existing TCP streams can still drain.
	_, boundPort, _ := net.SplitHostPort(old.addr().String())
	actualPort, _ := strconv.Atoi(boundPort)
	overlaps := r.Protocol == prev.Protocol && r.ListenPort == actualPort && r.ListenPort != 0
	if overlaps {
		old.stop()
		delete(m.rules, id)
		delete(m.specs, id)
		delete(m.protection, id)
	}
	a, err := m.add(id, r, protection)
	if err != nil {
		if overlaps {
			_, rollback := m.add(id, prev, previousProtection)
			m.retireLocked(old)
			m.mu.Unlock()
			_ = m.wait(ctx, old)
			if rollback != nil {
				return nil, errors.Join(err, fmt.Errorf("restore previous listener: %w", rollback))
			}
			return nil, err
		}
		m.mu.Unlock()
		return nil, err
	}
	m.retireLocked(old)
	m.mu.Unlock()
	// The replacement is live even if the old listener needed forced draining.
	// Keep the drain result out of the desired-rule result; callers can observe
	// closed old streams through their connections and logs.
	_ = m.wait(ctx, old)
	return a, nil
}

// Remove stops accepting traffic and waits for TCP streams to finish. If ctx
// expires, remaining streams are forcibly closed and ctx's error is returned.
// ErrRetiredLimit leaves the active listener intact when the draining bound is full.
func (m *Manager) Remove(ctx context.Context, id string) error {
	m.mu.Lock()
	inst, ok := m.rules[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("rule %q not found", id)
	}
	if len(m.retired) >= maxRetiredRules {
		m.mu.Unlock()
		return ErrRetiredLimit
	}
	delete(m.rules, id)
	delete(m.specs, id)
	delete(m.protection, id)
	m.retireLocked(inst)
	m.mu.Unlock()
	return m.wait(ctx, inst)
}

func (m *Manager) wait(ctx context.Context, inst instance) error { return inst.wait(ctx) }

// Close permanently closes the manager, including rules already draining.
// ctx bounds graceful shutdown; cancellation closes and joins all remaining work.
func (m *Manager) Close(ctx context.Context) error {
	m.mu.Lock()
	m.closed = true
	all := make([]instance, 0, len(m.rules)+len(m.retired))
	for i := range m.retired {
		all = append(all, i)
	}
	for id, i := range m.rules {
		all = append(all, i)
		m.retireLocked(i)
		delete(m.rules, id)
		delete(m.specs, id)
		delete(m.protection, id)
	}
	m.mu.Unlock()
	var errs []error
	for _, i := range all {
		if err := m.wait(ctx, i); err != nil {
			errs = append(errs, err)
		}
	}
	m.cleanup.Wait()
	return errors.Join(errs...)
}

// CheckBind checks whether the operating system can bind the requested address.
// The result is advisory: another process can bind before Add or Update.
func CheckBind(r Rule) error {
	if err := r.validate(); err != nil {
		return err
	}
	if r.Protocol == "tcp" {
		l, e := net.Listen("tcp", address(r.ListenAddress, r.ListenPort))
		if e == nil {
			_ = l.Close()
		}
		return e
	}
	a, e := net.ResolveUDPAddr("udp", address(r.ListenAddress, r.ListenPort))
	if e != nil {
		return e
	}
	l, e := net.ListenUDP("udp", a)
	if e == nil {
		_ = l.Close()
	}
	return e
}

type tcpRule struct {
	stats       *counters
	forceCtx    context.Context
	forceCancel context.CancelFunc
	listener    *net.TCPListener
	mu          sync.Mutex
	rule        Rule
	protection  Protection
	opts        Options
	conns       map[*net.TCPConn]struct{}
	stopping    bool
	wg          sync.WaitGroup
	done        chan struct{}
}

func (t *tcpRule) metrics() *counters { return t.stats }
func (t *tcpRule) addr() net.Addr     { return t.listener.Addr() }
func (t *tcpRule) stop()              { t.mu.Lock(); t.stopping = true; _ = t.listener.Close(); t.mu.Unlock() }
func (t *tcpRule) wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		t.forceCancel()
		t.mu.Lock()
		for c := range t.conns {
			_ = c.Close()
		}
		t.mu.Unlock()
		<-t.done
		return err
	}
	select {
	case <-t.done:
		t.forceCancel()
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	case <-ctx.Done():
		t.forceCancel()
		t.mu.Lock()
		for c := range t.conns {
			_ = c.Close()
		}
		t.mu.Unlock()
		<-t.done
		return ctx.Err()
	}
}
func (t *tcpRule) serve() {
	defer func() { t.wg.Wait(); close(t.done) }()
	backoff := time.Duration(0)
	for {
		c, err := t.listener.AcceptTCP()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				t.stats.errors.Add(1)
			}
			if e, ok := err.(net.Error); ok && e.Temporary() {
				if backoff == 0 {
					backoff = 5 * time.Millisecond
				} else {
					backoff *= 2
				}
				if backoff > time.Second {
					backoff = time.Second
				}
				select {
				case <-t.forceCtx.Done():
					return
				case <-time.After(backoff):
				}
				continue
			}
			break
		}
		backoff = 0
		t.stats.accepted.Add(1)
		t.mu.Lock()
		if t.stopping {
			t.stats.closed.Add(1)
			t.mu.Unlock()
			_ = c.Close()
			break
		}
		r, p := t.rule, t.protection
		ip := ddos.IP(c.RemoteAddr())
		for _, b := range [...]*ddos.Binding{p.Listener, p.Endpoint} {
			b.Count(ddos.PreFilter, 1)
			b.Count("new_connections", 1)
			b.Observe("tcp_new", ip, 1)
			b.Source(ip, "peer")
		}
		d := p.Listener.Check(ip, ddos.Amount{Metric: "tcp_new", Value: 1}, ddos.Amount{Metric: "tcp_active", Value: 1})
		d.Combine(p.Endpoint.Check(ip, ddos.Amount{Metric: "tcp_new", Value: 1}, ddos.Amount{Metric: "tcp_active", Value: 1}, ddos.Amount{Metric: "backend_active", Value: 1}))
		allowed := !d.Rejected() && admit(&t.stats.tcpActive, t.opts.MaxTCPConnections)
		if !allowed {
			if !d.Rejected() {
				d.Fail(p.Listener, "tcp_capacity")
			}
			d.Record()
			d.Release()
			t.stats.rejects.Add(1)
			t.stats.closed.Add(1)
			t.mu.Unlock()
			_ = c.Close()
			continue
		}
		d.Record()
		p.Listener.InFlight(1)
		p.Endpoint.InFlight(1)
		p.Listener.Count(ddos.Accepted, 1)
		p.Endpoint.Count(ddos.Accepted, 1)
		p.Endpoint.Count(ddos.Routed, 1)
		t.stats.active.Add(1)
		t.conns[c] = struct{}{}
		t.wg.Add(1)
		t.mu.Unlock()
		go t.handle(c, r, p, d)
	}
}
func (t *tcpRule) handle(client *net.TCPConn, r Rule, p Protection, d ddos.Decision) {
	ip := ddos.IP(client.RemoteAddr())
	started := time.Now()
	defer d.Release()
	defer p.Listener.InFlight(-1)
	defer p.Endpoint.InFlight(-1)
	defer t.wg.Done()
	defer func() { t.stats.active.Add(^uint64(0)); t.stats.tcpActive.Add(-1); t.stats.closed.Add(1) }()
	defer func() { t.mu.Lock(); delete(t.conns, client); t.mu.Unlock(); _ = client.Close() }()
	if !d.Wait(t.forceCtx) {
		return
	}
	if millis := p.Listener.Maximum("first_byte_ms"); millis > 0 {
		if err := firstByte(client, started.Add(time.Duration(millis)*time.Millisecond)); err != nil {
			if isTimeout(err) {
				p.Listener.Observe("timeouts", ip, 1)
				exceeded := p.Listener.CheckOperation(ip, ddos.Amount{Metric: "first_byte_ms", Value: float64(millis) + 1})
				exceeded.Record()
			}
			return
		}
	}
	ctx, cancel := context.WithTimeout(t.forceCtx, t.opts.DialTimeout)
	defer cancel()
	dialed := time.Now()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", address(r.TargetAddress, r.TargetPort))
	if err != nil {
		if t.forceCtx.Err() == nil {
			t.stats.errors.Add(1)
			p.Endpoint.Backend(ip, dialed, err)
			p.Listener.Backend(ip, dialed, err)
		}
		return
	}
	p.Endpoint.Backend(ip, dialed, nil)
	p.Listener.Backend(ip, dialed, nil)
	p.Endpoint.Count(ddos.Forwarded, 1)
	p.Listener.Count(ddos.Forwarded, 1)
	upstream := c.(*net.TCPConn)
	defer upstream.Close()
	t.mu.Lock()
	if t.forceCtx.Err() != nil {
		t.mu.Unlock()
		return
	}
	t.conns[upstream] = struct{}{}
	t.mu.Unlock()
	defer func() { t.mu.Lock(); delete(t.conns, upstream); t.mu.Unlock() }()
	if t.opts.TCPTimeout > 0 {
		_ = client.SetDeadline(time.Now().Add(t.opts.TCPTimeout))
		_ = upstream.SetDeadline(time.Now().Add(t.opts.TCPTimeout))
	}
	done := make(chan error, 2)
	flow := newTCPFlow(p.Endpoint.Maximum("tcp_bytes"))
	listenerIdle, endpointIdle := p.Listener.Maximum("idle_ms"), p.Endpoint.Maximum("idle_ms")
	idleMillis := listenerIdle
	if endpointIdle > 0 && (idleMillis == 0 || endpointIdle < idleMillis) {
		idleMillis = endpointIdle
	}
	if flow.byteLimit > 0 || idleMillis > 0 {
		if idleMillis > 0 {
			ctx, cancel := context.WithCancel(t.forceCtx)
			defer cancel()
			go flow.watchIdle(ctx, time.Duration(idleMillis)*time.Millisecond, client, upstream, func(elapsed time.Duration) {
				p.Listener.Observe("timeouts", ip, 1)
				p.Endpoint.Observe("timeouts", ip, 1)
				amount := ddos.Amount{Metric: "idle_ms", Value: float64(elapsed)/float64(time.Millisecond) + 0.001}
				d := p.Listener.CheckOperation(ip, amount)
				d.Combine(p.Endpoint.CheckOperation(ip, amount))
				d.Record()
			})
		}
		go flow.copy(upstream, client, func(n int64) { p.bytes("bytes_in", n) }, done, idleMillis > 0)
		go flow.copy(client, upstream, func(n int64) { p.bytes("bytes_out", n) }, done, idleMillis > 0)
	} else {
		go tcpCopy(upstream, client, done, func(n int64) { p.bytes("bytes_in", n); flow.total.Add(n) })
		go tcpCopy(client, upstream, done, func(n int64) { p.bytes("bytes_out", n); flow.total.Add(n) })
	}
	e1, e2 := <-done, <-done
	if errors.Is(e1, errTrafficLimit) || errors.Is(e2, errTrafficLimit) {
		exceeded := p.Endpoint.CheckOperation(ip, ddos.Amount{Metric: "tcp_bytes", Value: float64(flow.byteLimit) + 1})
		exceeded.Record()
	}
	if (e1 != nil || e2 != nil) && t.forceCtx.Err() == nil {
		t.stats.errors.Add(1)
	}
	if t.forceCtx.Err() == nil && flow.total.Load() == 0 && time.Since(started) < time.Second {
		p.Endpoint.Observe("short_connections", ip, 1)
		p.Listener.Observe("short_connections", ip, 1)
	}
}

// Keep the concrete TCP connections in io.Copy so Go can use Linux splice.
func tcpCopy(dst, src *net.TCPConn, done chan<- error, count func(int64)) {
	n, err := io.Copy(dst, src)
	count(n)
	if err != nil {
		_ = dst.Close()
		_ = src.Close()
	}
	_ = dst.CloseWrite()
	_ = src.CloseRead()
	done <- err
}

type udpClient struct {
	failed     atomic.Bool
	conn       *net.UDPConn
	client     *net.UDPAddr
	protection Protection
	decision   ddos.Decision
	replied    atomic.Bool
	firstWrite time.Time
}

// Setup retains only the first datagram per client. Limits include running
// dials as well as queued work; no buffers or workers are preallocated per rule.
const udpSetupParallelism = 32
const udpSetupLimit = 128
const udpSetupBytes = 1 << 20

type udpSetup struct {
	key        string
	client     *net.UDPAddr
	packet     []byte
	protection Protection
	decision   ddos.Decision
	rule       Rule
	generation uint64
	ctx        context.Context
	cancel     context.CancelFunc
	conn       *net.UDPConn // guarded by udpRule.mu, including before publication
}

type udpRule struct {
	stats        *counters
	forceCtx     context.Context
	forceCancel  context.CancelFunc
	writeMu      sync.Mutex
	generation   uint64
	listener     *net.UDPConn
	mu           sync.Mutex
	rule         Rule
	protection   Protection
	opts         Options
	clients      map[string]*udpClient
	pending      map[string]*udpSetup
	pendingCount int
	pendingBytes int
	setupQueue   []*udpSetup
	setupWorkers int
	stopping     bool
	wg           sync.WaitGroup
	done         chan struct{}
}

func (u *udpRule) metrics() *counters { return u.stats }
func (u *udpRule) addr() net.Addr     { return u.listener.LocalAddr() }
func (u *udpRule) update(r Rule)      { u.reconfigure(r, u.protection) }
func (u *udpRule) reconfigure(r Rule, p Protection) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.protection = p
	if u.rule == r {
		return
	}
	u.rule = r
	u.generation++
	u.cancelSetups()
	u.forceCtx, u.forceCancel = context.WithCancel(context.Background())
	for _, c := range u.clients {
		_ = c.conn.Close()
	}
	u.clients = make(map[string]*udpClient)
}
func (u *udpRule) stop() {
	u.mu.Lock()
	u.stopping = true
	u.cancelSetups()
	_ = u.listener.Close()
	for _, c := range u.clients {
		_ = c.conn.Close()
	}
	u.mu.Unlock()
}
func (u *udpRule) wait(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		u.stop()
		<-u.done
		return err
	}
	select {
	case <-u.done:
		if err := ctx.Err(); err != nil {
			return err
		}
		return nil
	case <-ctx.Done():
		u.stop()
		<-u.done
		return ctx.Err()
	}
}
func (u *udpRule) serve() {
	defer close(u.done)
	defer u.wg.Wait()
	buf := make([]byte, u.opts.UDPBufferSize)
	for {
		n, _, flags, client, err := u.listener.ReadMsgUDP(buf, nil)
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				u.stats.errors.Add(1)
			}
			return
		}
		key := client.String()
		ip := ddos.IP(client)
		u.mu.Lock()
		if u.stopping {
			u.mu.Unlock()
			return
		}
		p, ctx := u.protection, u.forceCtx
		for _, b := range [...]*ddos.Binding{p.Listener, p.Endpoint} {
			b.Count(ddos.PreFilter, 1)
			b.Count("packets", 1)
			b.Observe("udp_packets", ip, 1)
			b.Observe("udp_bytes", ip, float64(n))
			b.Source(ip, "peer")
		}
		if flags&syscall.MSG_TRUNC != 0 {
			p.Listener.Observe("protocol_errors", ip, 1)
			p.Listener.Denied("truncated_datagram")
			u.mu.Unlock()
			continue
		}
		amounts := [...]ddos.Amount{{Metric: "udp_packets", Value: 1}, {Metric: "udp_bytes", Value: float64(n)}, {Metric: "udp_datagram_bytes", Value: float64(n)}}
		d := p.Listener.Check(ip, amounts[:]...)
		if !d.Rejected() {
			p.Listener.Count(ddos.Accepted, 1)
			p.Endpoint.Count(ddos.Routed, 1)
		}
		c := u.clients[key]
		if c == nil && u.pending[key] == nil {
			d.Combine(p.Endpoint.Check(ip, append(amounts[:], ddos.Amount{Metric: "backend_active", Value: 1})...))
		} else {
			d.Combine(p.Endpoint.Check(ip, amounts[:]...))
		}
		if d.Rejected() {
			d.Record()
			d.Release()
			u.stats.rejects.Add(1)
			u.mu.Unlock()
			continue
		}
		if c != nil {
			u.mu.Unlock()
			d.Record()
			if d.Wait(ctx) {
				p.Endpoint.Count(ddos.Accepted, 1)
				u.send(c, buf[:n], p)
			}
			d.Release()
			continue
		}
		if u.pending[key] != nil || u.pendingCount >= udpSetupLimit || n > udpSetupBytes-u.pendingBytes || !admit(&u.stats.udpActive, u.opts.MaxUDPAssociations) {
			if u.pending[key] == nil {
				u.stats.rejects.Add(1)
			}
			d.Fail(p.Endpoint, "udp_setup_queue")
			d.Record()
			d.Release()
			u.mu.Unlock()
			continue
		}
		d.Record()
		ctx, cancel := context.WithTimeout(ctx, u.opts.DialTimeout)
		task := &udpSetup{key: key, client: client, packet: append([]byte{}, buf[:n]...), rule: u.rule, generation: u.generation, ctx: ctx, cancel: cancel, protection: p, decision: d}
		u.stats.accepted.Add(1)
		u.stats.active.Add(1)
		p.Endpoint.Count(ddos.Accepted, 1)
		p.Listener.InFlight(1)
		p.Endpoint.InFlight(1)
		p.Listener.Queue(1)
		p.Listener.QueueBytes(int64(n))
		u.pending[key] = task
		u.pendingCount++
		u.pendingBytes += n
		u.setupQueue = append(u.setupQueue, task)
		if u.setupWorkers < udpSetupParallelism {
			u.setupWorkers++
			u.wg.Add(1)
			go u.setupWorker()
		}
		u.mu.Unlock()
	}
}

func (u *udpRule) finishAssociation() {
	u.stats.active.Add(^uint64(0))
	u.stats.udpActive.Add(-1)
	u.stats.closed.Add(1)
}
func (u *udpRule) failed(c *udpClient, err error) {
	if err == nil || errors.Is(err, net.ErrClosed) {
		return
	}
	if c.failed.CompareAndSwap(false, true) {
		u.stats.errors.Add(1)
	}
}
func (u *udpRule) send(c *udpClient, packet []byte, p Protection) {
	started := time.Now()
	err := u.sendUntil(c, packet, started.Add(u.opts.DialTimeout))
	u.udpForwarded(c, packet, p, started, err)
}

func (u *udpRule) udpForwarded(c *udpClient, packet []byte, p Protection, started time.Time, err error) {
	if err == nil {
		p.bytes("bytes_in", int64(len(packet)))
		p.Endpoint.Count(ddos.Forwarded, 1)
		p.Listener.Count(ddos.Forwarded, 1)
	}
	if !errors.Is(err, net.ErrClosed) && (err != nil || !p.Endpoint.ExpectsUDPResponse()) {
		p.Endpoint.Backend(ddos.IP(c.client), started, err)
		p.Listener.Backend(ddos.IP(c.client), started, err)
	}
}

func releaseUDP(p Protection, d *ddos.Decision) {
	d.Release()
	p.Listener.InFlight(-1)
	p.Endpoint.InFlight(-1)
}
func (u *udpRule) sendUntil(c *udpClient, packet []byte, deadline time.Time) error {
	_ = c.conn.SetReadDeadline(time.Now().Add(u.opts.UDPIdleTimeout))
	_ = c.conn.SetWriteDeadline(deadline)
	_, err := c.conn.Write(packet)
	if err != nil {
		u.failed(c, err)
		_ = c.conn.Close()
	}
	return err
}

// cancelSetups runs under mu. Running dials retain their admission slots until
// they exit; queued work can release its slots immediately. Identity checks keep
// an old generation from deleting a new setup for the same client.
func (u *udpRule) cancelSetups() {
	u.forceCancel()
	for _, task := range u.pending {
		if task.conn != nil {
			_ = task.conn.Close()
		}
	}
	for _, task := range u.setupQueue {
		u.finishSetup(task)
		releaseUDP(task.protection, &task.decision)
		u.finishAssociation()
	}
	u.setupQueue = nil
	clear(u.pending)
}
func (u *udpRule) finishSetup(task *udpSetup) {
	task.cancel()
	if u.pending[task.key] == task {
		delete(u.pending, task.key)
	}
	u.pendingCount--
	u.pendingBytes -= len(task.packet)
	task.protection.Listener.Queue(-1)
	task.protection.Listener.QueueBytes(-int64(len(task.packet)))
}
func (u *udpRule) setupWorker() {
	defer u.wg.Done()
	for {
		u.mu.Lock()
		if len(u.setupQueue) == 0 {
			u.setupWorkers--
			u.mu.Unlock()
			return
		}
		task := u.setupQueue[0]
		u.setupQueue[0] = nil
		u.setupQueue = u.setupQueue[1:]
		u.mu.Unlock()
		u.associate(task)
	}
}

// registerSetup makes a dialed socket cancelable before the first write. The
// worker can be paused at this point without hiding a socket from update/stop.
func (u *udpRule) registerSetup(task *udpSetup, conn *net.UDPConn) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.stopping || u.generation != task.generation || task.ctx.Err() != nil {
		return false
	}
	task.conn = conn
	return true
}

func (u *udpRule) associate(task *udpSetup) {
	var conn net.Conn
	var c *udpClient
	var err error
	started := time.Now()
	if !task.decision.Wait(task.ctx) {
		u.completeSetup(task, nil, nil, task.ctx.Err())
		return
	}
	if err = task.ctx.Err(); err == nil {
		conn, err = (&net.Dialer{}).DialContext(task.ctx, "udp", address(task.rule.TargetAddress, task.rule.TargetPort))
	}
	if err == nil && u.registerSetup(task, conn.(*net.UDPConn)) {
		c = &udpClient{conn: conn.(*net.UDPConn), client: task.client, protection: task.protection, decision: task.decision, firstWrite: started}
		// Followups cannot overtake the first packet. Its deadline includes
		// time already spent queued and dialing, rather than restarting it.
		deadline, _ := task.ctx.Deadline()
		err = u.sendUntil(c, task.packet, deadline)
		u.udpForwarded(c, task.packet, task.protection, started, err)
	} else if err != nil && task.ctx.Err() == nil {
		task.protection.Endpoint.Backend(ddos.IP(task.client), started, err)
	}
	u.completeSetup(task, c, conn, err)
}

func (u *udpRule) completeSetup(task *udpSetup, c *udpClient, conn net.Conn, err error) {
	u.mu.Lock()
	if err == nil {
		err = task.ctx.Err()
	}
	valid := err == nil && c != nil && !u.stopping && u.generation == task.generation
	u.finishSetup(task)
	if !valid {
		if err != nil && !u.stopping && u.generation == task.generation {
			if c == nil {
				u.stats.errors.Add(1)
			} else {
				u.failed(c, err)
			}
		}
		u.finishAssociation()
		releaseUDP(task.protection, &task.decision)
		u.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	u.clients[task.key] = c
	u.wg.Add(1)
	go u.reply(task.key, c)
	u.mu.Unlock()
}

func (u *udpRule) reply(key string, c *udpClient) {
	defer u.wg.Done()
	defer u.finishAssociation()
	defer releaseUDP(c.protection, &c.decision)
	defer func() {
		u.mu.Lock()
		if u.clients[key] == c {
			delete(u.clients, key)
		}
		u.mu.Unlock()
		_ = c.conn.Close()
	}()
	buf := make([]byte, u.opts.UDPBufferSize)
	for {
		n, _, flags, _, err := c.conn.ReadMsgUDP(buf, nil)
		if err != nil {
			if !isTimeout(err) {
				u.failed(c, err)
			} else if c.protection.Endpoint.ExpectsUDPResponse() && !c.replied.Load() {
				ip := ddos.IP(c.client)
				c.protection.Endpoint.Observe("udp_unanswered", ip, 1)
				c.protection.Endpoint.Backend(ip, c.firstWrite, err)
			}
			return
		}
		if flags&syscall.MSG_TRUNC != 0 {
			continue
		}
		u.mu.Lock()
		if u.clients[key] != c {
			u.mu.Unlock()
			return
		}
		_ = c.conn.SetReadDeadline(time.Now().Add(u.opts.UDPIdleTimeout))
		u.mu.Unlock()
		u.writeMu.Lock()
		_ = u.listener.SetWriteDeadline(time.Now().Add(u.opts.DialTimeout))
		_, err = u.listener.WriteToUDP(buf[:n], c.client)
		u.writeMu.Unlock()
		if err == nil {
			c.protection.bytes("bytes_out", int64(n))
			if c.replied.CompareAndSwap(false, true) && c.protection.Endpoint.ExpectsUDPResponse() {
				c.protection.Endpoint.Backend(ddos.IP(c.client), c.firstWrite, nil)
			}
		}
		if err != nil {
			u.failed(c, err)
			return
		}
	}
}

// NormalizeProtocol is useful when accepting a protocol from user input.
func NormalizeProtocol(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
