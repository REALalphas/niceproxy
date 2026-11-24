package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

const maxBody = 16 << 20

type config struct {
	protocol, target, host, path, ca, connections, source, expect string
	duration, timeout                                             time.Duration
	concurrency, payload                                          int
	allowErrors                                                   bool
	roots                                                         *x509.CertPool
}

func parseLoad(args []string) (c config, err error) {
	fs := flag.NewFlagSet("load", flag.ContinueOnError)
	fs.StringVar(&c.protocol, "protocol", "http", "http|https|tcp|udp")
	fs.StringVar(&c.target, "target", "", "IP:port or hostname:port")
	fs.StringVar(&c.host, "host", "", "HTTP Host and TLS server name (defaults to target host)")
	fs.StringVar(&c.path, "path", "/", "HTTP request URI")
	fs.StringVar(&c.ca, "ca", "", "PEM CA bundle (otherwise OS trust)")
	fs.StringVar(&c.connections, "connections", "reused", "reused|new")
	fs.StringVar(&c.source, "source-host", "", "source IP")
	fs.StringVar(&c.expect, "expect-prefix", "", "required HTTP response body prefix")
	fs.DurationVar(&c.duration, "duration", 5*time.Second, "time to start requests")
	fs.DurationVar(&c.timeout, "timeout", 5*time.Second, "per-request deadline including dial and complete response")
	fs.IntVar(&c.concurrency, "concurrency", 32, "workers (1..1024)")
	fs.IntVar(&c.payload, "payload-size", 256, "TCP/UDP request bytes; ignored for HTTP")
	fs.BoolVar(&c.allowErrors, "allow-errors", false, "exit successfully even if requests fail")
	if err = fs.Parse(args); err != nil {
		return
	}
	bad := func(s string) (config, error) { return c, errors.New(s) }
	if fs.NArg() != 0 {
		return bad("unexpected arguments")
	}
	if c.protocol != "http" && c.protocol != "https" && c.protocol != "tcp" && c.protocol != "udp" {
		return bad("invalid protocol")
	}
	th, port, e := net.SplitHostPort(c.target)
	if e != nil || th == "" || port == "" {
		return bad("target must be host:port")
	}
	pn, e := net.LookupPort("tcp", port)
	if e != nil || pn < 1 || pn > 65535 {
		return bad("invalid target port")
	}
	if c.host == "" {
		c.host = th
	}
	if c.duration <= 0 || c.timeout <= 0 {
		return bad("duration and timeout must be positive")
	}
	if c.concurrency < 1 || c.concurrency > 1024 {
		return bad("concurrency must be 1..1024")
	}
	if c.payload < 1 || c.payload > maxBody {
		return bad("payload-size must be 1..16777216")
	}
	if c.protocol == "udp" && c.payload > 65507 {
		return bad("UDP payload-size exceeds 65507")
	}
	if c.connections != "new" && c.connections != "reused" {
		return bad("connections must be reused|new")
	}
	if c.source != "" && net.ParseIP(c.source) == nil {
		return bad("source-host must be an IP")
	}
	u, e := url.ParseRequestURI(c.path)
	if e != nil || !strings.HasPrefix(c.path, "/") || u.IsAbs() {
		return bad("path must be an origin-form request URI")
	}
	if strings.ContainsAny(c.host, "/\r\n ") {
		return bad("invalid host")
	}
	if c.ca != "" {
		pem, e := os.ReadFile(c.ca)
		if e != nil {
			return c, e
		}
		c.roots = x509.NewCertPool()
		if !c.roots.AppendCertsFromPEM(pem) {
			return bad("CA file contains no certificates")
		}
	}
	return c, nil
}

type latencyReport struct {
	P50 float64 `json:"p50"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
	Max float64 `json:"max"`
}
type report struct {
	Protocol                 string        `json:"protocol"`
	Target                   string        `json:"target"`
	Host                     string        `json:"host"`
	DurationSeconds          float64       `json:"durationSeconds"`
	RequestedDurationSeconds float64       `json:"requestedDurationSeconds"`
	Concurrency              int           `json:"concurrency"`
	PayloadBytes             int           `json:"payloadBytes"`
	Connections              string        `json:"connections"`
	Attempted                uint64        `json:"attempted"`
	Succeeded                uint64        `json:"succeeded"`
	Errors                   uint64        `json:"errors"`
	RequestsPerSecond        float64       `json:"requestsPerSecond"`
	Bytes                    uint64        `json:"bytes"`
	SentBytes                uint64        `json:"sentBytes"`
	ReceivedBytes            uint64        `json:"receivedBytes"`
	Latency                  latencyReport `json:"latencyMs"`
	ErrorSamples             []string      `json:"errorSamples"`
	LatencyMethod            string        `json:"latencyMethod"`
	ByteSemantics            string        `json:"byteSemantics"`
}

// Fixed log histogram: 1 microsecond base, 1% bucket spacing; overflow at ~700s.
type stats struct {
	attempted, succeeded, failed, sent, received uint64
	hist                                         [2048]uint64
	max                                          time.Duration
	samples                                      []string
}

func (s *stats) record(d time.Duration, err error) {
	s.attempted++
	if err != nil {
		s.failed++
		if len(s.samples) < 5 {
			s.samples = append(s.samples, err.Error())
		}
	} else {
		s.succeeded++
	}
	i := int(math.Ceil(math.Log1p(float64(d)/float64(time.Microsecond)) / math.Log(1.01)))
	if i >= len(s.hist) {
		i = len(s.hist) - 1
	}
	s.hist[i]++
	if d > s.max {
		s.max = d
	}
}
func (s *stats) percentile(q float64) float64 {
	want := uint64(math.Ceil(float64(s.attempted) * q))
	if want == 0 {
		return 0
	}
	var n uint64
	for i, v := range s.hist {
		n += v
		if n >= want {
			return math.Min(math.Expm1(float64(i)*math.Log(1.01))/1000, float64(s.max)/float64(time.Millisecond))
		}
	}
	return 0
}
func load(c config) report {
	start := time.Now()
	end := start.Add(c.duration)
	workers := make([]stats, c.concurrency)
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(i int) { defer wg.Done(); worker(c, i, end, &workers[i]) }(i)
	}
	wg.Wait()
	var all stats
	for i := range workers {
		s := &workers[i]
		all.attempted += s.attempted
		all.succeeded += s.succeeded
		all.failed += s.failed
		all.sent += s.sent
		all.received += s.received
		if s.max > all.max {
			all.max = s.max
		}
		for j, v := range s.hist {
			all.hist[j] += v
		}
		for _, v := range s.samples {
			if len(all.samples) < 5 {
				all.samples = append(all.samples, v)
			}
		}
	}
	elapsed := time.Since(start).Seconds()
	payload := c.payload
	if c.protocol == "http" || c.protocol == "https" {
		payload = 0
	}
	return report{Protocol: c.protocol, Target: c.target, Host: c.host, DurationSeconds: elapsed, RequestedDurationSeconds: c.duration.Seconds(), Concurrency: c.concurrency, PayloadBytes: payload, Connections: c.connections, Attempted: all.attempted, Succeeded: all.succeeded, Errors: all.failed, RequestsPerSecond: float64(all.succeeded) / elapsed, Bytes: all.sent + all.received, SentBytes: all.sent, ReceivedBytes: all.received, Latency: latencyReport{all.percentile(.5), all.percentile(.95), all.percentile(.99), float64(all.max) / float64(time.Millisecond)}, ErrorSamples: all.samples, LatencyMethod: "all attempts, fixed 2048-bucket log histogram; 1us base, 1% spacing, last bucket overflow; max exact", ByteSemantics: "application payload only, including partial failed I/O; bytes = sentBytes + receivedBytes; HTTP GET sentBytes=0, response body only, headers/TLS/IP excluded"}
}
func dialer(c config) *net.Dialer {
	d := &net.Dialer{Timeout: c.timeout}
	if c.source != "" {
		if c.protocol == "udp" {
			d.LocalAddr = &net.UDPAddr{IP: net.ParseIP(c.source)}
		} else {
			d.LocalAddr = &net.TCPAddr{IP: net.ParseIP(c.source)}
			bindSourceIPOnly(d)
		}
	}
	return d
}
func httpClient(c config) *http.Client {
	d := dialer(c)
	name := c.host
	if h, _, e := net.SplitHostPort(name); e == nil {
		name = h
	}
	name = strings.Trim(name, "[]")
	tr := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: c.connections == "new", MaxIdleConns: 1, MaxIdleConnsPerHost: 1, TLSClientConfig: &tls.Config{RootCAs: c.roots, ServerName: name, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return d.DialContext(ctx, network, c.target)
	}}
	return &http.Client{Transport: tr, Timeout: c.timeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}
func worker(c config, id int, end time.Time, s *stats) {
	isHTTP := c.protocol == "http" || c.protocol == "https"
	var client *http.Client
	var conn net.Conn
	if isHTTP {
		client = httpClient(c)
		defer client.CloseIdleConnections()
	}
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	var payload, reply []byte
	var httpBuf []byte
	if isHTTP {
		httpBuf = make([]byte, 32*1024)
	}
	if !isHTTP {
		payload = make([]byte, c.payload)
		reply = make([]byte, c.payload)
		if c.protocol == "udp" {
			reply = make([]byte, c.payload+1)
		}
	}
	for seq := uint64(1); time.Now().Before(end); seq++ {
		began := time.Now()
		deadline := began.Add(c.timeout)
		var err error
		if isHTTP {
			err = httpAttempt(client, c, s, httpBuf)
		} else {
			fillPayload(payload, uint64(id+1), seq)
			if conn == nil {
				ctx, cancel := context.WithDeadline(context.Background(), deadline)
				conn, err = dialer(c).DialContext(ctx, c.protocol, c.target)
				cancel()
			}
			if err == nil {
				err = conn.SetDeadline(deadline)
			}
			if err == nil {
				var sent, received int
				if c.protocol == "tcp" {
					sent, received, err = exchangeTCP(conn, payload, reply)
				} else {
					sent, err = conn.Write(payload)
					if err == nil && sent != len(payload) {
						err = io.ErrShortWrite
					}
					if err == nil {
						received, err = conn.Read(reply)
					}
				}
				s.sent += uint64(sent)
				s.received += uint64(received)
				if err == nil && !bytes.Equal(payload, reply[:received]) {
					err = errors.New("echo payload mismatch")
				}
			}
			if conn != nil && (err != nil || c.connections == "new") {
				conn.Close()
				conn = nil
			}
		}
		s.record(time.Since(began), err)
	}
}

// Echoes can exceed both peers' socket buffers. Drain the response while sending.
// Join the writer before returning, including on failures, so buffers can be reused.
func exchangeTCP(conn net.Conn, payload, reply []byte) (int, int, error) {
	type result struct {
		n   int
		err error
	}
	written := make(chan result, 1)
	go func() {
		n, err := writeFull(conn, payload)
		if err != nil {
			conn.Close()
		}
		written <- result{n, err}
	}()
	received, readErr := io.ReadFull(conn, reply)
	if readErr != nil {
		conn.Close()
	}
	w := <-written
	if w.err != nil {
		return w.n, received, w.err
	}
	return w.n, received, readErr
}
func fillPayload(b []byte, worker, seq uint64) {
	x := seq ^ (worker * 0x9e3779b97f4a7c15)
	for i := range b {
		x ^= x << 13
		x ^= x >> 7
		x ^= x << 17
		b[i] = byte(x)
	}
}
func writeFull(w io.Writer, b []byte) (int, error) {
	total := 0
	for len(b) > 0 {
		n, e := w.Write(b)
		total += n
		b = b[n:]
		if e != nil {
			return total, e
		}
		if n == 0 {
			return total, io.ErrShortWrite
		}
	}
	return total, nil
}
func httpAttempt(client *http.Client, c config, s *stats, buf []byte) error {
	host := c.host
	if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	u := &url.URL{Scheme: c.protocol, Host: host}
	parsed, _ := url.ParseRequestURI(c.path)
	u.Path = parsed.Path
	u.RawPath = parsed.RawPath
	u.RawQuery = parsed.RawQuery
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}
	req.Host = c.host
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Streaming verification keeps response memory bounded even for large bodies.
	var prefix bytes.Buffer
	var total int64
	for {
		n, e := resp.Body.Read(buf)
		total += int64(n)
		s.received += uint64(n)
		if prefix.Len() < len(c.expect) {
			take := len(c.expect) - prefix.Len()
			if take > n {
				take = n
			}
			prefix.Write(buf[:take])
		}
		if total > maxBody {
			return fmt.Errorf("HTTP body exceeds %d bytes", maxBody)
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	if !strings.HasPrefix(prefix.String(), c.expect) {
		return errors.New("HTTP body prefix mismatch")
	}
	return nil
}
