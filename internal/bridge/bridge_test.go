package bridge

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"niceproxy/internal/ddos"
)

var clientIP = netip.MustParseAddr("192.0.2.1")

func TestTCP(t *testing.T) {
	address, finished := tcpBackend(t, func(conn net.Conn) error {
		body, err := io.ReadAll(conn)
		if err != nil {
			return err
		}
		_, err = conn.Write(append([]byte{0xff}, body...))
		return err
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/ignored-target", bytes.NewReader([]byte{0, 1}))
	if err := Handle(w, r, Config{"tcp", address}, nil, clientIP); err != nil {
		t.Fatal(err)
	}
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || w.Header().Get("Content-Type") != "application/octet-stream" || !bytes.Equal(w.Body.Bytes(), []byte{0xff, 0, 1}) {
		t.Fatalf("unexpected TCP response %d %v %x", w.Code, w.Header(), w.Body.Bytes())
	}
}

func TestUDP(t *testing.T) {
	for _, tc := range []struct {
		name        string
		body        []byte
		expectReply bool
		status      int
	}{
		{"empty datagram", nil, false, http.StatusNoContent},
		{"single reply", []byte{0, 1}, true, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			received := make(chan []byte, 1)
			finished := make(chan error, 1)
			go func() {
				buf := make([]byte, 100)
				n, addr, err := conn.ReadFromUDP(buf)
				if err == nil {
					received <- buf[:n]
					if tc.expectReply {
						_, err = conn.WriteToUDP([]byte{0xff}, addr)
					}
				}
				finished <- err
			}()
			b := ddos.NewEngine().Bind(ddos.Spec{ID: "udp", Kind: ddos.HTTPUDP, Policy: &ddos.Policy{ExpectUDPResponse: tc.expectReply}})
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(tc.body))
			if err := Handle(w, r, Config{"udp", conn.LocalAddr().String()}, b, clientIP); err != nil {
				t.Fatal(err)
			}
			if err := <-finished; err != nil {
				t.Fatal(err)
			}
			var wantReply []byte
			if tc.expectReply {
				wantReply = []byte{0xff}
			}
			if got := <-received; !bytes.Equal(got, tc.body) || w.Code != tc.status || !bytes.Equal(w.Body.Bytes(), wantReply) {
				t.Fatalf("received %x, response %d %x", got, w.Code, w.Body.Bytes())
			}
		})
	}
}

func TestBodyLimit(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, udpMaxBytes+1)))
	r.ContentLength = -1
	w := httptest.NewRecorder()
	err := Handle(w, r, Config{"udp", "127.0.0.1:1"}, nil, clientIP)
	if !errors.Is(err, ErrBodyTooLarge) || w.Flushed || w.Body.Len() != 0 {
		t.Fatalf("expected body limit error, got %v", err)
	}
}

func TestBackendLimits(t *testing.T) {
	for _, tc := range []struct {
		metric string
		unit   string
		value  float64
	}{
		{"backend_tcp_bytes", "bytes", 2},
		{"backend_response_ms", "ms", 40},
	} {
		t.Run(tc.metric, func(t *testing.T) {
			address, _ := tcpBackend(t, func(conn net.Conn) error {
				if _, err := io.ReadAll(conn); err != nil {
					return err
				}
				if tc.unit == "ms" {
					// The bridge will close the connection while waiting for a reply.
					time.Sleep(150 * time.Millisecond)
				}
				_, err := conn.Write([]byte("cd"))
				return err
			})
			b := ddos.NewEngine().Bind(ddos.Spec{ID: "tcp", Kind: ddos.HTTPTCP, Policy: &ddos.Policy{
				EnforceLimits: true,
				Limits:        []ddos.Limit{{ID: "limit", Metric: tc.metric, Unit: tc.unit, Value: tc.value, Scope: "endpoint", Action: ddos.Reject}},
			}})
			w := httptest.NewRecorder()
			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("ab"))
			if err := Handle(w, r, Config{"tcp", address}, b, clientIP); !errors.Is(err, ErrQuota) || w.Body.Len() != 0 {
				t.Fatalf("expected quota error before sending backend reply, got %v", err)
			}
		})
	}
}

func TestBackendCancellation(t *testing.T) {
	received := make(chan struct{})
	release := make(chan struct{})
	defer close(release)
	address, _ := tcpBackend(t, func(conn net.Conn) error {
		if _, err := io.ReadAll(conn); err != nil {
			return err
		}
		close(received)
		<-release
		return nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString("ab")).WithContext(ctx)
	done := make(chan error, 1)
	go func() { done <- Handle(httptest.NewRecorder(), r, Config{"tcp", address}, nil, clientIP) }()
	select {
	case <-received:
	case <-time.After(2 * time.Second):
		t.Fatal("backend did not receive request")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v, want context cancellation", err)
		}
	case <-time.After(time.Second):
		t.Fatal("backend read did not stop on cancellation")
	}
}

func tcpBackend(t *testing.T, serve func(net.Conn) error) (string, <-chan error) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			defer conn.Close()
			if err = conn.SetDeadline(time.Now().Add(2 * time.Second)); err == nil {
				err = serve(conn)
			}
		}
		done <- err
	}()
	return listener.Addr().String(), done
}
