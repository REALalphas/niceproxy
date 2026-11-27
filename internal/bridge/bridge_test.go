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

func TestHandleHTTPForwardsRequestAndResponse(t *testing.T) {
	const requestBody = "hello bridge"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read upstream body: %v", err)
		}
		if string(body) != requestBody {
			t.Errorf("upstream body = %q, want %q", body, requestBody)
		}
		if got := r.Header.Get("X-Niceproxy-Bridge-Route"); got != "" {
			t.Errorf("bridge route header leaked to upstream: %q", got)
		}
		if got := r.Header.Get("X-Test"); got != "kept" {
			t.Errorf("ordinary request header = %q, want kept", got)
		}
		if r.URL.Path != "/echo" || r.URL.RawQuery != "x=1" {
			t.Errorf("upstream URL = %s, want /echo?x=1", r.URL.RequestURI())
		}
		w.Header().Set("X-Upstream", "yes")
		_, _ = io.WriteString(w, "reply")
	}))
	defer upstream.Close()

	req := httptest.NewRequest(http.MethodPost, "/echo?x=1", bytes.NewBufferString(requestBody))
	req.Header.Set("X-Niceproxy-Bridge-Route", "should-be-removed")
	req.Header.Set("X-Test", "kept")
	w := httptest.NewRecorder()
	if err := HandleHTTP(w, req, upstream.URL, nil, nil, clientIP); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusOK || w.Header().Get("X-Upstream") != "yes" || w.Body.String() != "reply" {
		t.Fatalf("unexpected bridge response: status=%d headers=%v body=%q", w.Code, w.Header(), w.Body.String())
	}
}

func TestHandleHTTPRejectsInvalidTargets(t *testing.T) {
	for _, target := range []string{
		"",
		"ftp://127.0.0.1:8080",
		"http://user:pass@127.0.0.1:8080",
		"http://127.0.0.1:8080/path",
		"http://127.0.0.1:8080?secret=1",
		"http://127.0.0.1:8080#fragment",
		"http://:8080",
	} {
		t.Run(target, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			w := httptest.NewRecorder()
			if err := HandleHTTP(w, r, target, nil, nil, clientIP); err == nil {
				t.Fatalf("accepted invalid target %q", target)
			}
			if w.Code != http.StatusOK || w.Body.Len() != 0 {
				t.Fatalf("invalid target wrote HTTP response: %d %q", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleHTTPRequestBodyLimit(t *testing.T) {
	for _, tc := range []struct {
		name    string
		chunked bool
	}{
		{name: "content-length", chunked: false},
		{name: "chunked", chunked: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(make([]byte, httpMaxBytes+1)))
			if tc.chunked {
				r.ContentLength = -1
			}
			w := httptest.NewRecorder()
			if err := HandleHTTP(w, r, "http://127.0.0.1:1", nil, nil, clientIP); !errors.Is(err, ErrBodyTooLarge) {
				t.Fatalf("got %v, want body limit error", err)
			}
			if w.Code != http.StatusOK || w.Body.Len() != 0 {
				t.Fatalf("body limit wrote HTTP response: %d %q", w.Code, w.Body.String())
			}
		})
	}
}
