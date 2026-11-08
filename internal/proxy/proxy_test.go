package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

func port(a net.Addr) int {
	_, p, _ := net.SplitHostPort(a.String())
	n, _ := strconv.Atoi(p)
	return n
}
func TestTCPMapping(t *testing.T) {
	upstream, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer upstream.Close()
	go func() {
		c, e := upstream.Accept()
		if e == nil {
			defer c.Close()
			b, _ := io.ReadAll(c)
			_, _ = c.Write(append([]byte("3300:"), b...))
		}
	}()
	m := NewManager(Options{})
	defer m.Close(context.Background())
	addr, e := m.Add("1234-to-3300", Rule{"tcp", "127.0.0.1", 0, "127.0.0.1", port(upstream.Addr())})
	if e != nil {
		t.Fatal(e)
	}
	c, e := net.DialTCP("tcp", nil, addr.(*net.TCPAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	_, _ = c.Write([]byte("1234"))
	_ = c.CloseWrite()
	b, e := io.ReadAll(c)
	if e != nil || string(b) != "3300:1234" {
		t.Fatalf("reply %q: %v", b, e)
	}
}
func TestUDPReplyIdleAndLimit(t *testing.T) {
	upstream, e := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if e != nil {
		t.Fatal(e)
	}
	defer upstream.Close()
	go func() {
		b := make([]byte, 128)
		for {
			n, a, e := upstream.ReadFromUDP(b)
			if e != nil {
				return
			}
			_, _ = upstream.WriteToUDP(b[:n], a)
		}
	}()
	m := NewManager(Options{UDPIdleTimeout: 150 * time.Millisecond, MaxUDPAssociations: 1, UDPBufferSize: 32})
	defer m.Close(context.Background())
	a, e := m.Add("udp", Rule{"udp", "127.0.0.1", 0, "127.0.0.1", port(upstream.LocalAddr())})
	if e != nil {
		t.Fatal(e)
	}
	c1, e := net.DialUDP("udp", nil, a.(*net.UDPAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer c1.Close()
	c2, e := net.DialUDP("udp", nil, a.(*net.UDPAddr))
	if e != nil {
		t.Fatal(e)
	}
	defer c2.Close()
	exchange := func(c *net.UDPConn, msg string, timeout time.Duration) (string, error) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(timeout))
		if _, err := c.Write([]byte(msg)); err != nil {
			return "", err
		}
		b := make([]byte, 64)
		n, err := c.Read(b)
		return string(b[:n]), err
	}
	if got, e := exchange(c1, "hello", time.Second); e != nil || got != "hello" {
		t.Fatalf("reply %q: %v", got, e)
	}
	if got, e := exchange(c2, "blocked", 50*time.Millisecond); e == nil {
		t.Fatalf("limit allowed %q", got)
	}
	time.Sleep(200 * time.Millisecond)
	if got, e := exchange(c2, "after idle", time.Second); e != nil || got != "after idle" {
		t.Fatalf("idle reply %q: %v", got, e)
	}
}
func TestBindConflictAndUpdate(t *testing.T) {
	m := NewManager(Options{})
	defer m.Close(context.Background())
	r := Rule{"tcp", "127.0.0.1", 0, "127.0.0.1", 1}
	a, e := m.Add("a", r)
	if e != nil {
		t.Fatal(e)
	}
	r.ListenPort = port(a)
	if e = CheckBind(r); e == nil {
		t.Fatal("expected conflict")
	}
	if _, e = m.Add("b", r); e == nil {
		t.Fatal("expected bind failure")
	}
	if e = m.Remove(context.Background(), "a"); e != nil {
		t.Fatal(e)
	}
	if e = CheckBind(r); e != nil {
		t.Fatal(e)
	}
}

func tcpFixture(t *testing.T, opts Options) (*Manager, net.Addr, <-chan net.Conn) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 8)
	go func() {
		defer close(accepted)
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	m := NewManager(opts)
	a, err := m.Add("tcp", Rule{"tcp", "127.0.0.1", 0, "127.0.0.1", port(l.Addr())})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_ = m.Close(ctx)
		_ = l.Close()
		for c := range accepted {
			_ = c.Close()
		}
	})
	return m, a, accepted
}

func connectTCP(t *testing.T, a net.Addr, accepted <-chan net.Conn) (*net.TCPConn, net.Conn) {
	t.Helper()
	c, err := net.DialTCP("tcp", nil, a.(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	select {
	case upstream := <-accepted:
		t.Cleanup(func() { _ = upstream.Close() })
		_ = upstream.SetDeadline(time.Now().Add(3 * time.Second))
		return c, upstream
	case <-time.After(3 * time.Second):
		t.Fatal("upstream was not connected")
	}
	return nil, nil
}

func TestTCPConnectionLimitAndForcedRemove(t *testing.T) {
	m, a, accepted := tcpFixture(t, Options{MaxTCPConnections: 1})
	client, upstream := connectTCP(t, a, accepted)
	extra, err := net.Dial("tcp", a.String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	_ = extra.SetDeadline(time.Now().Add(time.Second))
	if _, err := extra.Read(make([]byte, 1)); err == nil {
		t.Fatal("extra connection stayed open")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("limit did not reject extra connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err := m.Remove(ctx, "tcp"); err != context.DeadlineExceeded {
		t.Fatalf("remove: %v", err)
	}
	for _, c := range []net.Conn{client, upstream} {
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Fatal("forced removal left connection open")
		}
	}
	if _, err := net.DialTimeout("tcp", a.String(), time.Second); err == nil {
		t.Fatal("removed listener still accepts")
	}
}

func TestTCPGracefulRemoveAndHalfClose(t *testing.T) {
	m, a, accepted := tcpFixture(t, Options{})
	client, upstream := connectTCP(t, a, accepted)
	removed := make(chan error, 1)
	go func() { removed <- m.Remove(context.Background(), "tcp") }()
	select {
	case err := <-removed:
		t.Fatalf("returned before stream drained: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	_, _ = client.Write([]byte("request"))
	_ = client.CloseWrite()
	b, err := io.ReadAll(upstream)
	if err != nil || string(b) != "request" {
		t.Fatalf("request %q: %v", b, err)
	}
	_, _ = upstream.Write([]byte("reply"))
	_ = upstream.(*net.TCPConn).CloseWrite()
	b, err = io.ReadAll(client)
	if err != nil || string(b) != "reply" {
		t.Fatalf("reply %q: %v", b, err)
	}
	select {
	case err := <-removed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("remove did not finish")
	}
}

func TestCloseIncludesDrainingRules(t *testing.T) {
	m, a, accepted := tcpFixture(t, Options{})
	_, _ = connectTCP(t, a, accepted)
	removed := make(chan error, 1)
	go func() { removed <- m.Remove(context.Background(), "tcp") }()
	deadline := time.Now().Add(time.Second)
	for {
		m.mu.Lock()
		n := len(m.retired)
		m.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("remove did not start draining")
		}
		time.Sleep(time.Millisecond)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := m.Close(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("close: %v", err)
	}
	select {
	case <-removed:
	case <-time.After(time.Second):
		t.Fatal("draining rule survived Close")
	}
	if _, err := m.Add("new", Rule{"tcp", "127.0.0.1", 0, "127.0.0.1", 1}); err != net.ErrClosed {
		t.Fatalf("add after close: %v", err)
	}
}

func TestTCPTimeout(t *testing.T) {
	_, a, accepted := tcpFixture(t, Options{TCPTimeout: 40 * time.Millisecond})
	client, _ := connectTCP(t, a, accepted)
	if _, err := client.Read(make([]byte, 1)); err == nil {
		t.Fatal("stream did not expire")
	} else if e, ok := err.(net.Error); ok && e.Timeout() {
		t.Fatal("proxy did not enforce timeout")
	}
}

func TestFailedUpdatePreservesListener(t *testing.T) {
	m, a, accepted := tcpFixture(t, Options{})
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	if _, err := m.Update(context.Background(), "tcp", Rule{"tcp", "127.0.0.1", port(occupied.Addr()), "127.0.0.1", 1}); err == nil {
		t.Fatal("expected bind conflict")
	}
	client, upstream := connectTCP(t, a, accepted)
	_, _ = client.Write([]byte("x"))
	b := make([]byte, 1)
	if _, err := io.ReadFull(upstream, b); err != nil || string(b) != "x" {
		t.Fatalf("original listener lost: %q, %v", b, err)
	}
}

func TestWildcardAddressUpdate(t *testing.T) {
	m := NewManager(Options{})
	defer m.Close(context.Background())
	r := Rule{"tcp", "0.0.0.0", 0, "127.0.0.1", 9}
	a, err := m.Add("wildcard", r)
	if err != nil {
		t.Fatal(err)
	}
	r.ListenPort = port(a)
	r.ListenAddress = "127.0.0.1"
	if _, err = m.Update(context.Background(), "wildcard", r); err != nil {
		t.Fatal(err)
	}
	r.ListenAddress = "0.0.0.0"
	if _, err = m.Update(context.Background(), "wildcard", r); err != nil {
		t.Fatal(err)
	}
}

func TestUDPUpdateAndTruncation(t *testing.T) {
	makeEcho := func(prefix string) *net.UDPConn {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		go func() {
			b := make([]byte, 1024)
			for {
				n, a, err := c.ReadFromUDP(b)
				if err != nil {
					return
				}
				_, _ = c.WriteToUDP(append([]byte(prefix), b[:n]...), a)
			}
		}()
		return c
	}
	first, second := makeEcho("a:"), makeEcho("b:")
	m := NewManager(Options{UDPBufferSize: 16})
	defer m.Close(context.Background())
	r := Rule{"udp", "127.0.0.1", 0, "127.0.0.1", port(first.LocalAddr())}
	a, err := m.Add("udp", r)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialUDP("udp", nil, a.(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	exchange := func(msg, want string) {
		t.Helper()
		_ = c.SetDeadline(time.Now().Add(time.Second))
		if _, err := c.Write([]byte(msg)); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 128)
		n, err := c.Read(b)
		if err != nil || string(b[:n]) != want {
			t.Fatalf("got %q, want %q: %v", b[:n], want, err)
		}
	}
	exchange("one", "a:one")
	r.TargetPort = port(second.LocalAddr())
	if next, err := m.Update(context.Background(), "udp", r); err != nil || next.String() != a.String() {
		t.Fatalf("update: %v %v", next, err)
	}
	exchange("two", "b:two")
	exchange("", "b:")
	for _, msg := range []string{"01234567890123456789", "012345678901234"} {
		_ = c.SetDeadline(time.Now().Add(40 * time.Millisecond))
		_, _ = c.Write([]byte(msg))
		if _, err := c.Read(make([]byte, 128)); err == nil {
			t.Fatal("truncated datagram was forwarded")
		}
	}
	exchange("ok", "b:ok")
}

func TestConcurrentRuleLifecycle(t *testing.T) {
	m := NewManager(Options{})
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := strconv.Itoa(i)
			r := Rule{"udp", "127.0.0.1", 0, "localhost", 9}
			a, err := m.Add(id, r)
			if err != nil {
				return
			} // Close may have won the race.
			c, err := net.Dial("udp", a.String())
			if err == nil {
				defer c.Close()
				for j := 0; j < 10; j++ {
					_, _ = c.Write([]byte("packet"))
					r.TargetPort = 10 + j
					_, _ = m.Update(context.Background(), id, r)
				}
			}
			_ = m.Remove(context.Background(), id)
		}(i)
	}
	wg.Wait()
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}
