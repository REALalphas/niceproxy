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
	update(Rule)
	metrics() *counters
}
type Manager struct {
	mu      sync.Mutex
	rules   map[string]instance
	specs   map[string]Rule
	opts    Options
	closed  bool
	retired map[instance]struct{}
	stats   map[string]*counters
	cleanup sync.WaitGroup
}

func NewManager(o Options) *Manager {
	return &Manager{rules: make(map[string]instance), specs: make(map[string]Rule), opts: o.defaults(), retired: make(map[instance]struct{}), stats: make(map[string]*counters)}
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
	return m.add(id, r)
}
func (m *Manager) add(id string, r Rule) (net.Addr, error) {
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
		t := &tcpRule{stats: c, forceCtx: forceCtx, forceCancel: forceCancel, listener: l.(*net.TCPListener), rule: r, opts: m.opts, conns: make(map[*net.TCPConn]struct{}), done: make(chan struct{})}
		inst = t
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
		u := &udpRule{stats: c, forceCtx: forceCtx, forceCancel: forceCancel, listener: l, rule: r, opts: m.opts, clients: make(map[string]*udpClient), pending: make(map[string]*udpSetup), done: make(chan struct{})}
		inst = u
		go u.serve()
	}
	c.refs++
	c.forget = false
	m.stats[id] = c
	m.trimStats()
	m.rules[id] = inst
	m.specs[id] = r
	return inst.addr(), nil
}

// Update changes a target in place when the listener is unchanged. Otherwise it
// binds the replacement before retiring the old listener; failed binds leave it intact.
// Existing TCP streams keep their target; UDP associations are reset. ctx bounds
// draining the retired listener after a successful replacement.
func (m *Manager) Update(ctx context.Context, id string, r Rule) (net.Addr, error) {
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
	if r.Protocol == prev.Protocol && r.ListenAddress == prev.ListenAddress && r.ListenPort == prev.ListenPort {
		old.update(r)
		m.specs[id] = r
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
	}
	a, err := m.add(id, r)
	if err != nil {
		if overlaps {
			_, rollback := m.add(id, prev)
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
	opts        Options
	conns       map[*net.TCPConn]struct{}
	stopping    bool
	wg          sync.WaitGroup
	done        chan struct{}
}

func (t *tcpRule) metrics() *counters { return t.stats }
func (t *tcpRule) addr() net.Addr     { return t.listener.Addr() }
func (t *tcpRule) update(r Rule)      { t.mu.Lock(); t.rule = r; t.mu.Unlock() }
func (t *tcpRule) stop()              { t.mu.Lock(); t.stopping = true; _ = t.listener.Close(); t.mu.Unlock() }
func (t *tcpRule) wait(ctx context.Context) error {
	select {
	case <-t.done:
		t.forceCancel()
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
		if !admit(&t.stats.tcpActive, t.opts.MaxTCPConnections) {
			t.stats.rejects.Add(1)
			t.stats.closed.Add(1)
			t.mu.Unlock()
			_ = c.Close()
			continue
		}
		t.stats.active.Add(1)
		r := t.rule
		t.conns[c] = struct{}{}
		t.wg.Add(1)
		t.mu.Unlock()
		go t.handle(c, r)
	}
}
func (t *tcpRule) handle(client *net.TCPConn, r Rule) {
	defer t.wg.Done()
	defer func() { t.stats.active.Add(^uint64(0)); t.stats.tcpActive.Add(-1); t.stats.closed.Add(1) }()
	defer func() { t.mu.Lock(); delete(t.conns, client); t.mu.Unlock(); _ = client.Close() }()
	ctx, cancel := context.WithTimeout(t.forceCtx, t.opts.DialTimeout)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", address(r.TargetAddress, r.TargetPort))
	if err != nil {
		if t.forceCtx.Err() == nil {
			t.stats.errors.Add(1)
		}
		return
	}
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
	go tcpCopy(upstream, client, done)
	go tcpCopy(client, upstream, done)
	e1, e2 := <-done, <-done
	if (e1 != nil || e2 != nil) && t.forceCtx.Err() == nil {
		t.stats.errors.Add(1)
	}
}

// Keep the concrete TCP connections in io.Copy: Go may use Linux splice for
// this path when supported. Actual kernel/runtime behavior must be measured.
func tcpCopy(dst, src *net.TCPConn, done chan<- error) {
	_, err := io.Copy(dst, src)
	if err != nil {
		_ = dst.Close()
		_ = src.Close()
	}
	_ = dst.CloseWrite()
	_ = src.CloseRead()
	done <- err
}

type udpClient struct {
	failed atomic.Bool
	conn   *net.UDPConn
	client *net.UDPAddr
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
func (u *udpRule) update(r Rule) {
	u.mu.Lock()
	u.rule = r
	u.generation++
	u.cancelSetups()
	u.forceCtx, u.forceCancel = context.WithCancel(context.Background())
	for _, c := range u.clients {
		_ = c.conn.Close()
	}
	u.clients = make(map[string]*udpClient)
	u.mu.Unlock()
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
	select {
	case <-u.done:
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
		if flags&syscall.MSG_TRUNC != 0 {
			continue
		}
		key := client.String()
		u.mu.Lock()
		c := u.clients[key]
		canCreate := c == nil && u.pending[key] == nil && !u.stopping &&
			u.pendingCount < udpSetupLimit && n <= udpSetupBytes-u.pendingBytes
		if canCreate && !admit(&u.stats.udpActive, u.opts.MaxUDPAssociations) {
			canCreate = false
		}
		if c == nil && u.pending[key] == nil && !u.stopping && !canCreate {
			u.stats.rejects.Add(1)
		}
		if canCreate {
			ctx, cancel := context.WithTimeout(u.forceCtx, u.opts.DialTimeout)
			task := &udpSetup{key: key, client: client, packet: append([]byte{}, buf[:n]...),
				rule: u.rule, generation: u.generation, ctx: ctx, cancel: cancel}
			u.stats.accepted.Add(1)
			u.stats.active.Add(1)
			u.pending[key] = task
			u.pendingCount++
			u.pendingBytes += n
			u.setupQueue = append(u.setupQueue, task)
			if u.setupWorkers < udpSetupParallelism {
				u.setupWorkers++
				u.wg.Add(1)
				go u.setupWorker()
			}
		}
		u.mu.Unlock()
		// Pending-client followups are still dropped. Established clients bypass
		// the setup queue, so slow DNS cannot block their receive path.
		if c != nil {
			u.send(c, buf[:n])
		}
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
func (u *udpRule) send(c *udpClient, packet []byte) {
	_ = u.sendUntil(c, packet, time.Now().Add(u.opts.DialTimeout))
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
	if err = task.ctx.Err(); err == nil {
		conn, err = (&net.Dialer{}).DialContext(task.ctx, "udp", address(task.rule.TargetAddress, task.rule.TargetPort))
	}
	if err == nil && u.registerSetup(task, conn.(*net.UDPConn)) {
		c = &udpClient{conn: conn.(*net.UDPConn), client: task.client}
		// Followups cannot overtake the first packet. Its deadline includes
		// time already spent queued and dialing, rather than restarting it.
		deadline, _ := task.ctx.Deadline()
		err = u.sendUntil(c, task.packet, deadline)
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
			if e, ok := err.(net.Error); !ok || !e.Timeout() {
				u.failed(c, err)
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
		if err != nil {
			u.failed(c, err)
			return
		}
	}
}

// NormalizeProtocol is useful when accepting a protocol from user input.
func NormalizeProtocol(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
