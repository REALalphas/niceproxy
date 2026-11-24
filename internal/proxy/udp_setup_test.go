package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// The resolver holds all setups until release, then answers A queries with the
// local echo backend. No external DNS or scheduler timing controls admission.
func udpSetupFixture(t *testing.T, opts Options) (*Manager, net.Addr, chan struct{}) {
	t.Helper()
	backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { backend.Close() })
	go func() {
		b := make([]byte, 65535)
		for {
			n, a, e := backend.ReadFromUDP(b)
			if e != nil {
				return
			}
			backend.WriteToUDP(b[:n], a)
		}
	}()
	dns, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dns.Close() })
	go func() {
		b := make([]byte, 4096)
		for {
			n, a, e := dns.ReadFromUDP(b)
			if e != nil {
				return
			}
			if n < 17 {
				continue
			}
			// Locate the end of the single DNS question (queries have no compression).
			end := 12
			for end < n && b[end] != 0 {
				end += 1 + int(b[end])
			}
			end += 5
			if end > n {
				continue
			}
			reply := append([]byte(nil), b[:end]...)
			reply[2], reply[3] = 0x81, 0x80
			clear(reply[6:12])
			if binary.BigEndian.Uint16(b[end-4:end-2]) == 1 {
				reply[7] = 1
				reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1)
			}
			dns.WriteToUDP(reply, a)
		}
	}()
	release := make(chan struct{}, 2)
	original := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-release:
		}
		return (&net.Dialer{Resolver: original}).DialContext(ctx, "udp4", dns.LocalAddr().String())
	}}
	t.Cleanup(func() { net.DefaultResolver = original })
	m := NewManager(opts)
	t.Cleanup(func() { m.Close(context.Background()) })
	addr, err := m.Add("burst", Rule{"udp", "127.0.0.1", 0, "cold.niceproxy.test", port(backend.LocalAddr())})
	if err != nil {
		t.Fatal(err)
	}
	return m, addr, release
}

func udpBurst(t *testing.T, addr net.Addr, count, size int) []*net.UDPConn {
	t.Helper()
	clients := make([]*net.UDPConn, count)
	for i := range clients {
		c, err := net.DialUDP("udp", nil, addr.(*net.UDPAddr))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		clients[i] = c
		packet := make([]byte, size)
		copy(packet, fmt.Sprintf("first:%03d", i))
		if _, err = c.Write(packet); err != nil {
			t.Fatal(err)
		}
	}
	return clients
}

func TestUDPColdBurst(t *testing.T) {
	for _, count := range []int{64, 128} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			m, addr, release := udpSetupFixture(t, Options{MaxUDPAssociations: 1024, DialTimeout: 5 * time.Second})
			clients := udpBurst(t, addr, count, 256)
			awaitStats(t, m, "burst", func(s Stats) bool { return s.Accepted == uint64(count) && s.Active == uint64(count) && s.Rejects == 0 })
			close(release)
			for i, c := range clients {
				c.SetReadDeadline(time.Now().Add(5 * time.Second))
				b := make([]byte, 512)
				n, err := c.Read(b)
				if err != nil || n != 256 || string(b[:9]) != fmt.Sprintf("first:%03d", i) {
					t.Fatalf("client %d: n=%d err=%v payload=%q", i, n, err, b[:n])
				}
			}
			if err := m.Remove(context.Background(), "burst"); err != nil {
				t.Fatal(err)
			}
			awaitStats(t, m, "burst", func(s Stats) bool {
				return s.Accepted == uint64(count) && s.Closed == s.Accepted && s.Active == 0 && s.Errors == 0 && s.Rejects == 0
			})
		})
	}
}

func TestUDPSetupBoundsAndCancellation(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		limit, count, size, accepted int
	}{
		{"configured", 48, 64, 256, 48},
		{"tasks", 1024, 129, 256, udpSetupLimit},
		{"bytes", 1024, 17, 65507, udpSetupBytes / 65507},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, addr, _ := udpSetupFixture(t, Options{MaxUDPAssociations: tc.limit, DialTimeout: time.Minute})
			// Wait per datagram here to avoid confusing kernel receive-buffer overflow
			// with the explicit application byte bound for maximum-size packets.
			for i := 0; i < tc.count; i++ {
				udpBurst(t, addr, 1, tc.size)
				awaitStats(t, m, "burst", func(s Stats) bool { return s.Accepted+s.Rejects == uint64(i+1) })
			}
			s, _ := m.Stats("burst")
			if s.Accepted != uint64(tc.accepted) || s.Rejects != uint64(tc.count-tc.accepted) {
				t.Fatalf("bounds: %+v", s)
			}
			m.mu.Lock()
			u := m.rules["burst"].(*udpRule)
			m.mu.Unlock()
			u.mu.Lock()
			if u.setupWorkers > udpSetupParallelism || u.pendingCount != tc.accepted || u.pendingBytes > udpSetupBytes {
				t.Errorf("workers=%d pending=%d bytes=%d", u.setupWorkers, u.pendingCount, u.pendingBytes)
			}
			u.mu.Unlock()
			if err := m.Remove(context.Background(), "burst"); err != nil {
				t.Fatal(err)
			}
			awaitStats(t, m, "burst", func(s Stats) bool { return s.Active == 0 && s.Closed == s.Accepted && s.Errors == 0 })
			u.mu.Lock()
			defer u.mu.Unlock()
			if len(u.pending) != 0 || len(u.setupQueue) != 0 || u.pendingCount != 0 || u.pendingBytes != 0 || u.setupWorkers != 0 {
				t.Fatal("setup resources retained after stop")
			}
		})
	}
}

func TestUDPSetupUpdateCancelsOldGeneration(t *testing.T) {
	m, addr, release := udpSetupFixture(t, Options{DialTimeout: time.Minute})
	clients := udpBurst(t, addr, 64, 256)
	awaitStats(t, m, "burst", func(s Stats) bool { return s.Accepted == 64 })
	m.mu.Lock()
	r := m.specs["burst"]
	m.mu.Unlock()
	r.TargetAddress = "127.0.0.1"
	if _, err := m.Update(context.Background(), "burst", r); err != nil {
		t.Fatal(err)
	}
	awaitStats(t, m, "burst", func(s Stats) bool { return s.Closed == 64 && s.Active == 0 && s.Errors == 0 })
	// Reuse the exact client keys: canceled tasks must leave no tombstones.
	for _, c := range clients {
		if _, err := c.Write([]byte("new")); err != nil {
			t.Fatal(err)
		}
	}
	for i, c := range clients {
		c.SetReadDeadline(time.Now().Add(5 * time.Second))
		b := make([]byte, 512)
		n, err := c.Read(b)
		if err != nil || string(b[:n]) != "new" {
			t.Fatalf("client %d: %q %v", i, b[:n], err)
		}
	}
	close(release)
	awaitStats(t, m, "burst", func(s Stats) bool {
		return s.Accepted == 128 && s.Active == 64 && s.Closed == 64 && s.Rejects == 0 && s.Errors == 0
	})
}

func TestUDPSetupQueueDoesNotBlockEstablishedClient(t *testing.T) {
	m, addr, release := udpSetupFixture(t, Options{DialTimeout: time.Minute})
	// Permit A and AAAA resolution for the first client only.
	release <- struct{}{}
	release <- struct{}{}
	first := udpBurst(t, addr, 1, 256)[0]
	first.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 512)
	if _, err := first.Read(b); err != nil {
		t.Fatal(err)
	}
	udpBurst(t, addr, 128, 256)
	awaitStats(t, m, "burst", func(s Stats) bool { return s.Accepted == 129 && s.Active == 129 && s.Rejects == 0 })
	if _, err := first.Write([]byte("established")); err != nil {
		t.Fatal(err)
	}
	first.SetReadDeadline(time.Now().Add(time.Second))
	n, err := first.Read(b)
	if err != nil || string(b[:n]) != "established" {
		t.Fatalf("established flow: %q %v", b[:n], err)
	}
	close(release)
}

func TestUDPQueuedSetupDeadline(t *testing.T) {
	m, addr, _ := udpSetupFixture(t, Options{DialTimeout: 250 * time.Millisecond})
	udpBurst(t, addr, 128, 256)
	awaitStats(t, m, "burst", func(s Stats) bool {
		return s.Accepted == 128 && s.Active == 0 && s.Closed == 128 && s.Errors == 128 && s.Rejects == 0
	})
	m.mu.Lock()
	u := m.rules["burst"].(*udpRule)
	m.mu.Unlock()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.pending) != 0 || u.pendingCount != 0 || u.pendingBytes != 0 {
		t.Fatal("expired setups retained client keys or packet storage")
	}
}

// Pause a real dialed socket at the setup/publication boundary. This lets
// cancellation race with the first write without scheduler or routing tricks.
func TestUDPUnpublishedSetupCancellation(t *testing.T) {
	for _, action := range []string{"update", "stop", "deadline", "deadline-write"} {
		t.Run(action, func(t *testing.T) {
			backend, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer backend.Close()
			listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			conn, err := net.DialUDP("udp4", nil, backend.LocalAddr().(*net.UDPAddr))
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			force, stop := context.WithCancel(context.Background())
			u := &udpRule{listener: listener, opts: (Options{}).defaults(), stats: &counters{},
				forceCtx: force, forceCancel: stop, clients: map[string]*udpClient{}, pending: map[string]*udpSetup{}}
			defer func() { u.stop(); u.wg.Wait() }()
			ctx, cancel := context.WithTimeout(force, 30*time.Millisecond)
			defer cancel()
			task := &udpSetup{key: "paused", client: backend.LocalAddr().(*net.UDPAddr),
				packet: []byte("first"), ctx: ctx, cancel: cancel}
			u.pending[task.key], u.pendingCount, u.pendingBytes = task, 1, len(task.packet)
			u.stats.accepted.Add(1)
			u.stats.active.Add(1)
			u.stats.udpActive.Add(1)
			if !u.registerSetup(task, conn) {
				t.Fatal("could not register freshly dialed setup")
			}
			client := &udpClient{conn: conn, client: task.client}
			var sendErr error
			switch action {
			case "update":
				u.update(Rule{Protocol: "udp", TargetAddress: "127.0.0.1", TargetPort: port(backend.LocalAddr())})
			case "stop":
				u.stop()
			default:
				<-ctx.Done()
				if action == "deadline-write" {
					deadline, _ := ctx.Deadline()
					sendErr = u.sendUntil(client, task.packet, deadline)
					if sendErr == nil {
						t.Fatal("first write ignored expired admission deadline")
					}
				}
			}
			if action == "update" || action == "stop" {
				if _, err := conn.Write(task.packet); !errors.Is(err, net.ErrClosed) {
					t.Fatalf("unpublished socket survived %s: %v", action, err)
				}
			}
			u.completeSetup(task, client, conn, sendErr)
			u.mu.Lock()
			pending, count, stored, published := len(u.pending), u.pendingCount, u.pendingBytes, len(u.clients)
			u.mu.Unlock()
			stats := u.stats.snapshot()
			wantErrors := uint64(0)
			if action == "deadline" || action == "deadline-write" {
				wantErrors = 1
			}
			if pending != 0 || count != 0 || stored != 0 || published != 0 || stats.Active != 0 || stats.Closed != 1 || stats.Errors != wantErrors {
				t.Fatalf("canceled setup leaked/published/double-counted: pending=%d count=%d bytes=%d published=%d stats=%+v", pending, count, stored, published, stats)
			}
		})
	}
}
