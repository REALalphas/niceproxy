// Package bridge translates an HTTP request into one exchange with a fixed
// TCP or UDP route target.
package bridge

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strconv"
	"time"

	"niceproxy/internal/ddos"
)

const (
	tcpMaxBytes  = 1 << 20
	httpMaxBytes = 8 << 20
	// Use the IPv4 payload limit for both address families.
	udpMaxBytes    = 65507
	bodyTimeout    = 5 * time.Second
	backendTimeout = 5 * time.Second
)

var (
	ErrBodyTooLarge  = errors.New("bridge request body exceeds hard limit")
	ErrReplyTooLarge = errors.New("bridge backend reply exceeds hard limit")
	ErrQuota         = errors.New("bridge backend admission denied")
)

// Config specifies the fixed, validated host:port target of an HTTP route.
// Network must be "tcp" or "udp". TCP allows 1 MiB each for the request
// and reply, and UDP allows one datagram of at most 65,507 bytes each way.
// Reading the HTTP body and exchanging data with the backend each get at
// most five seconds. An enforced backend response limit can shorten the exchange.
type Config struct {
	Network string
	Address string
}

// Handle sends the request body to cfg and writes a binary response or a 204.
// Errors before the HTTP response is written are returned for the caller to map
// to an HTTP status. The caller owns HTTP admission and outcome telemetry.
func Handle(w http.ResponseWriter, r *http.Request, cfg Config, b *ddos.Binding, ip netip.Addr) error {
	return HandleWithListener(w, r, cfg, nil, b, ip)
}

func HandleWithListener(w http.ResponseWriter, r *http.Request, cfg Config, listener, b *ddos.Binding, ip netip.Addr) error {
	if cfg.Network != "tcp" && cfg.Network != "udp" {
		return fmt.Errorf("unsupported bridge network %q", cfg.Network)
	}
	host, port, err := net.SplitHostPort(cfg.Address)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if err != nil || host == "" || portErr != nil || portNumber == 0 {
		return errors.New("bridge target must be a host and numeric port")
	}

	ctx := r.Context()
	maxBytes := tcpMaxBytes
	if cfg.Network == "udp" {
		maxBytes = udpMaxBytes
	}
	body, err := readBody(w, r, maxBytes)
	if err != nil {
		return err
	}
	for _, binding := range []*ddos.Binding{listener, b} {
		binding.Count(ddos.PreFilter, 1)
		binding.Count("requests", 1)
		binding.Source(ip, "caddy · client address")
		binding.Observe("requests", ip, 1)
	}

	amounts := []ddos.Amount{{Metric: "backend_active", Value: 1}}
	if cfg.Network == "tcp" {
		amounts = append(amounts,
			ddos.Amount{Metric: "backend_tcp_new", Value: 1},
			ddos.Amount{Metric: "backend_tcp_bytes", Value: float64(len(body))},
			ddos.Amount{Metric: "backend_bytes", Value: float64(len(body))})
	} else {
		amounts = append(amounts,
			ddos.Amount{Metric: "backend_datagrams", Value: 1},
			ddos.Amount{Metric: "backend_request_bytes", Value: float64(len(body))},
			ddos.Amount{Metric: "backend_udp_packets", Value: 1},
			ddos.Amount{Metric: "backend_udp_bytes", Value: float64(len(body))})
	}
	admission := b.Check(ip, amounts...)
	defer admission.Release()
	if err := admit(ctx, &admission); err != nil {
		return err
	}
	for _, binding := range []*ddos.Binding{listener, b} {
		binding.Count(ddos.Accepted, 1)
		binding.Count(ddos.Routed, 1)
		binding.InFlight(1)
		defer binding.InFlight(-1)
	}

	expectReply := cfg.Network == "tcp" || b.ExpectsUDPResponse()
	started := time.Now()
	deadline := started.Add(backendTimeout)
	// Maximum includes source-scoped rules. Without a source, defer to the
	// scope-aware operation check below.
	if ms := b.Maximum("backend_response_ms"); ip.IsValid() && ms > 0 && ms < backendTimeout.Milliseconds() {
		deadline = started.Add(time.Duration(ms)*time.Millisecond + time.Nanosecond)
	}
	backendCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	reply, backendErr := exchange(backendCtx, cfg, b, body, expectReply)
	elapsed := time.Since(started)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	b.Backend(ip, started, backendErr)
	listener.Backend(ip, started, backendErr)
	if backendErr == nil {
		b.Count(ddos.Forwarded, 1)
		listener.Count(ddos.Forwarded, 1)
	}

	amounts = []ddos.Amount{{Metric: "backend_response_ms", Value: float64(elapsed) / float64(time.Millisecond)}}
	if cfg.Network == "tcp" && len(reply) > 0 {
		amounts = append(amounts,
			ddos.Amount{Metric: "backend_tcp_bytes", Value: float64(len(body) + len(reply))},
			ddos.Amount{Metric: "backend_bytes", Value: float64(len(reply))})
	}
	result := b.CheckOperation(ip, amounts...)
	defer result.Release()
	if err := admit(ctx, &result); err != nil {
		return err
	}
	if backendErr != nil {
		return backendErr
	}
	if !expectReply {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, err = w.Write(reply)
	return err
}

// HandleHTTP forwards a fixed HTTP(S) route through the same endpoint
// admission gate. The route target is supplied by persisted configuration.
func HandleHTTP(w http.ResponseWriter, r *http.Request, target string, listener, b *ddos.Binding, ip netip.Addr) error {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("invalid HTTP bridge target")
	}
	for _, binding := range []*ddos.Binding{listener, b} {
		binding.Count(ddos.PreFilter, 1)
		binding.Count("requests", 1)
		binding.Observe("requests", ip, 1)
		binding.Source(ip, "caddy · client address")
	}
	body, err := readBody(w, r, httpMaxBytes)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	r.ContentLength = int64(len(body))
	bodyBytes := int64(len(body))
	var headerBytes int
	for key, values := range r.Header {
		headerBytes += len(key)
		for _, value := range values {
			headerBytes += len(value)
		}
	}
	amounts := []ddos.Amount{{Metric: "http_requests", Value: 1}, {Metric: "http_active", Value: 1}, {Metric: "backend_active", Value: 1}, {Metric: "header_bytes", Value: float64(headerBytes)}, {Metric: "body_bytes", Value: float64(bodyBytes)}}
	d := listener.Check(ip, amounts...)
	d.Combine(b.Check(ip, amounts...))
	defer d.Release()
	if err := admit(r.Context(), &d); err != nil {
		return err
	}
	for _, binding := range []*ddos.Binding{listener, b} {
		binding.Count(ddos.Accepted, 1)
		binding.Count(ddos.Routed, 1)
		binding.InFlight(1)
		defer binding.InFlight(-1)
	}
	started := time.Now()
	proxy := httputil.NewSingleHostReverseProxy(u)
	director := proxy.Director
	proxy.Director = func(req *http.Request) { director(req); req.Header.Del("X-Niceproxy-Bridge-Route") }
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, e error) {
		b.Backend(ip, started, e)
		listener.Backend(ip, started, e)
	}
	proxy.ModifyResponse = func(res *http.Response) error {
		if res.ContentLength > httpMaxBytes {
			return ErrReplyTooLarge
		}
		res.Body = http.MaxBytesReader(w, res.Body, httpMaxBytes)
		elapsed := time.Since(started)
		b.Backend(ip, started, nil)
		listener.Backend(ip, started, nil)
		responseBytes := res.ContentLength
		if responseBytes < 0 {
			responseBytes = 0
		}
		responseAmounts := []ddos.Amount{{Metric: "response_ms", Value: float64(elapsed) / float64(time.Millisecond)}, {Metric: "body_bytes", Value: float64(responseBytes)}}
		a := listener.CheckOperation(ip, responseAmounts...)
		a.Combine(b.CheckOperation(ip, responseAmounts...))
		a.Record()
		if a.Rejected() {
			a.Release()
			return ErrQuota
		}
		a.Release()
		b.Count(ddos.Forwarded, 1)
		listener.Count(ddos.Forwarded, 1)
		return nil
	}
	proxy.ServeHTTP(w, r)
	return nil
}

func admit(ctx context.Context, decision *ddos.Decision) error {
	decision.Record()
	if err := ctx.Err(); err != nil {
		return err
	}
	if !decision.Wait(ctx) {
		if err := ctx.Err(); err != nil {
			return err
		}
		return ErrQuota
	}
	return ctx.Err()
}

func readBody(w http.ResponseWriter, r *http.Request, limit int) ([]byte, error) {
	if r.ContentLength > int64(limit) {
		return nil, ErrBodyTooLarge
	}
	if r.Body == nil {
		return nil, r.Context().Err()
	}

	ctx, cancel := context.WithTimeout(r.Context(), bodyTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	controller := http.NewResponseController(w)
	deadline, _ := ctx.Deadline()
	deadlineErr := controller.SetReadDeadline(deadline)
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		defer close(done)
		if deadlineErr == nil {
			_ = controller.SetReadDeadline(time.Now())
		} else {
			_ = r.Body.Close()
		}
	})
	body, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if !stop() {
		<-done
	}
	if deadlineErr == nil {
		_ = controller.SetReadDeadline(time.Time{})
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if len(body) > limit {
		return nil, ErrBodyTooLarge
	}
	return body, err
}

func exchange(ctx context.Context, cfg Config, b *ddos.Binding, body []byte, expectReply bool) ([]byte, error) {
	conn, err := (&net.Dialer{}).DialContext(ctx, cfg.Network, cfg.Address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}

	n, err := conn.Write(body)
	if err != nil {
		return nil, err
	}
	if n != len(body) {
		return nil, io.ErrShortWrite
	}
	b.Count(ddos.Forwarded, 1)
	if cfg.Network == "tcp" {
		if err := conn.(*net.TCPConn).CloseWrite(); err != nil {
			return nil, err
		}
		reply, err := io.ReadAll(io.LimitReader(conn, tcpMaxBytes+1))
		if len(reply) > tcpMaxBytes {
			return reply, ErrReplyTooLarge
		}
		return reply, err
	}
	if !expectReply {
		return nil, nil
	}
	reply := make([]byte, udpMaxBytes+1)
	n, err = conn.Read(reply)
	if n > udpMaxBytes {
		return nil, ErrReplyTooLarge
	}
	return reply[:n], err
}
