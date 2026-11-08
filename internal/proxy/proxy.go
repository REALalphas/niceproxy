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

type instance interface {
	stop()
	wait(context.Context) error
	addr() net.Addr
	update(Rule)
}
type Manager struct {
	mu      sync.Mutex
	rules   map[string]instance
	specs   map[string]Rule
	opts    Options
	closed  bool
	retired map[instance]struct{}
}

func NewManager(o Options) *Manager {
	return &Manager{rules: make(map[string]instance), specs: make(map[string]Rule), opts: o.defaults(), retired: make(map[instance]struct{})}
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
	var inst instance
	if r.Protocol == "tcp" {
		l, err := net.Listen("tcp", address(r.ListenAddress, r.ListenPort))
		if err != nil {
			return nil, err
		}
		forceCtx, forceCancel := context.WithCancel(context.Background())
		t := &tcpRule{forceCtx: forceCtx, forceCancel: forceCancel, listener: l.(*net.TCPListener), rule: r, opts: m.opts, conns: make(map[*net.TCPConn]struct{}), done: make(chan struct{})}
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
		u := &udpRule{forceCtx: forceCtx, forceCancel: forceCancel, listener: l, rule: r, opts: m.opts, clients: make(map[string]*udpClient), pending: make(map[string]bool), done: make(chan struct{})}
		inst = u
		go u.serve()
	}
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
			m.retired[old] = struct{}{}
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
	if !overlaps {
		old.stop()
	}
	m.retired[old] = struct{}{}
	m.mu.Unlock()
	// The replacement is live even if the old listener needed forced draining.
	// Keep the drain result out of the desired-rule result; callers can observe
	// closed old streams through their connections and logs.
	_ = m.wait(ctx, old)
	return a, nil
}

// Remove stops accepting traffic and waits for TCP streams to finish. If ctx
// expires, remaining streams are forcibly closed and ctx's error is returned.
func (m *Manager) Remove(ctx context.Context, id string) error {
	m.mu.Lock()
	inst, ok := m.rules[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("rule %q not found", id)
	}
	delete(m.rules, id)
	delete(m.specs, id)
	inst.stop()
	m.retired[inst] = struct{}{}
	m.mu.Unlock()
	return m.wait(ctx, inst)
}

func (m *Manager) wait(ctx context.Context, inst instance) error {
	err := inst.wait(ctx)
	m.mu.Lock()
	delete(m.retired, inst)
	m.mu.Unlock()
	return err
}

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
		m.retired[i] = struct{}{}
		i.stop()
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
	forceCtx    context.Context
	forceCancel context.CancelFunc
	listener    *net.TCPListener
	mu          sync.Mutex
	rule        Rule
	opts        Options
	conns       map[*net.TCPConn]struct{}
	stopping    bool
	active      int
	wg          sync.WaitGroup
	done        chan struct{}
}

func (t *tcpRule) addr() net.Addr { return t.listener.Addr() }
func (t *tcpRule) update(r Rule)  { t.mu.Lock(); t.rule = r; t.mu.Unlock() }
func (t *tcpRule) stop()          { t.mu.Lock(); t.stopping = true; _ = t.listener.Close(); t.mu.Unlock() }
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
		t.mu.Lock()
		if t.stopping {
			t.mu.Unlock()
			_ = c.Close()
			break
		}
		if t.active >= t.opts.MaxTCPConnections {
			t.mu.Unlock()
			_ = c.Close()
			continue
		}
		t.active++
		r := t.rule
		t.conns[c] = struct{}{}
		t.wg.Add(1)
		t.mu.Unlock()
		go t.handle(c, r)
	}
}
func (t *tcpRule) handle(client *net.TCPConn, r Rule) {
	defer t.wg.Done()
	defer func() { t.mu.Lock(); delete(t.conns, client); t.active--; t.mu.Unlock(); _ = client.Close() }()
	ctx, cancel := context.WithTimeout(t.forceCtx, t.opts.DialTimeout)
	defer cancel()
	c, err := (&net.Dialer{}).DialContext(ctx, "tcp", address(r.TargetAddress, r.TargetPort))
	if err != nil {
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
	done := make(chan struct{}, 2)
	go tcpCopy(upstream, client, done)
	go tcpCopy(client, upstream, done)
	<-done
	<-done
}

// Keep the concrete TCP connections in io.Copy: Go may use Linux splice for
// this path when supported. Actual kernel/runtime behavior must be measured.
func tcpCopy(dst, src *net.TCPConn, done chan<- struct{}) {
	_, err := io.Copy(dst, src)
	if err != nil {
		_ = dst.Close()
		_ = src.Close()
	}
	_ = dst.CloseWrite()
	_ = src.CloseRead()
	done <- struct{}{}
}

type udpClient struct {
	conn   *net.UDPConn
	client *net.UDPAddr
}
type udpRule struct {
	forceCtx     context.Context
	forceCancel  context.CancelFunc
	writeMu      sync.Mutex
	generation   uint64
	active       int
	listener     *net.UDPConn
	mu           sync.Mutex
	rule         Rule
	opts         Options
	clients      map[string]*udpClient
	pending      map[string]bool
	pendingCount int
	stopping     bool
	wg           sync.WaitGroup
	done         chan struct{}
}

func (u *udpRule) addr() net.Addr { return u.listener.LocalAddr() }
func (u *udpRule) update(r Rule) {
	u.mu.Lock()
	u.rule = r
	u.generation++
	for _, c := range u.clients {
		_ = c.conn.Close()
	}
	u.clients = make(map[string]*udpClient)
	u.mu.Unlock()
}
func (u *udpRule) stop() {
	u.mu.Lock()
	u.stopping = true
	u.forceCancel()
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
			return
		}
		if flags&syscall.MSG_TRUNC != 0 {
			continue
		}
		key := client.String()
		u.mu.Lock()
		c := u.clients[key]
		r, generation := u.rule, u.generation
		canCreate := c == nil && !u.pending[key] && !u.stopping && u.active+u.pendingCount < u.opts.MaxUDPAssociations && u.pendingCount < 32
		if canCreate {
			u.pending[key] = true
			u.pendingCount++
			u.wg.Add(1)
		}
		u.mu.Unlock()
		if canCreate {
			// Keep slow DNS and connection setup out of the receive loop.
			// At most 32 first packets can be pending; later packets from a
			// pending client are dropped until its association is ready.
			packet := append([]byte{}, buf[:n]...)
			go u.associate(key, client, packet, r, generation)
		} else if c != nil {
			u.send(c, buf[:n])
		}
	}
}
func (u *udpRule) send(c *udpClient, packet []byte) {
	_ = c.conn.SetReadDeadline(time.Now().Add(u.opts.UDPIdleTimeout))
	_ = c.conn.SetWriteDeadline(time.Now().Add(u.opts.DialTimeout))
	if _, err := c.conn.Write(packet); err != nil {
		_ = c.conn.Close()
	}
}
func (u *udpRule) associate(key string, client *net.UDPAddr, packet []byte, r Rule, generation uint64) {
	defer u.wg.Done()
	ctx, cancel := context.WithTimeout(u.forceCtx, u.opts.DialTimeout)
	conn, err := (&net.Dialer{}).DialContext(ctx, "udp", address(r.TargetAddress, r.TargetPort))
	cancel()
	u.mu.Lock()
	delete(u.pending, key)
	u.pendingCount--
	if err != nil || u.stopping || u.generation != generation {
		u.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		return
	}
	c := &udpClient{conn: conn.(*net.UDPConn), client: client}
	_ = c.conn.SetReadDeadline(time.Now().Add(u.opts.UDPIdleTimeout))
	u.clients[key] = c
	u.active++
	u.wg.Add(1)
	go u.reply(key, c)
	u.mu.Unlock()
	u.send(c, packet)
}

func (u *udpRule) reply(key string, c *udpClient) {
	defer u.wg.Done()
	defer func() {
		u.mu.Lock()
		u.active--
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
			return
		}
	}
}

// NormalizeProtocol is useful when accepting a protocol from user input.
func NormalizeProtocol(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
