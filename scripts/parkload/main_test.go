package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--protocol", "sctp"}, {"--concurrency", "1025"}, {"--concurrency", "0"}, {"--duration", "0s"}, {"--timeout", "-1s"}, {"--payload-size", "16777217"}, {"--protocol", "udp", "--payload-size", "65508"}, {"--connections", "forever"}, {"--source-host", "bogus"}, {"--path", "https://example.org/"}, {"--target", "noport"}, {"--ca", "missing.pem"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			if _, e := parseLoad(append([]string{"--target", "127.0.0.1:80"}, args...)); e == nil {
				t.Fatal("accepted invalid arguments")
			}
		})
	}
	for _, p := range []string{"http", "https", "tcp", "udp"} {
		if _, e := parseLoad([]string{"--protocol", p, "--target", "127.0.0.1:80"}); e != nil {
			t.Fatal(e)
		}
	}
}
func testConfig(protocol, target string) config {
	return config{protocol: protocol, target: target, host: "example.com", path: "/hello?nonce=42", connections: "reused", duration: 20 * time.Millisecond, timeout: time.Second, concurrency: 2, payload: 256}
}
func assertReport(t *testing.T, r report) {
	t.Helper()
	if r.Attempted == 0 || r.Attempted != r.Succeeded+r.Errors {
		t.Fatalf("inconsistent report: %+v", r)
	}
	if r.Latency.P50 > r.Latency.P95 || r.Latency.P95 > r.Latency.P99 || r.Latency.P99 > r.Latency.Max {
		t.Fatalf("invalid quantiles: %+v", r.Latency)
	}
}
func TestTLSVerifiedTargetOverride(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "example.com" || r.TLS.ServerName != "example.com" {
			t.Errorf("host/SNI: %q/%q", r.Host, r.TLS.ServerName)
		}
		io.WriteString(w, "backend-a "+r.RequestURI)
	}))
	defer srv.Close()
	c := testConfig("https", srv.Listener.Addr().String())
	c.expect = "backend-a /hello?nonce=42"
	r := load(c)
	assertReport(t, r)
	if r.Errors == 0 || r.Succeeded != 0 {
		t.Fatal("untrusted certificate accepted")
	}
	c.roots = x509.NewCertPool()
	c.roots.AddCert(srv.Certificate())
	r = load(c)
	assertReport(t, r)
	if r.Errors != 0 {
		t.Fatalf("trusted TLS failed: %+v", r)
	}
	if r.PayloadBytes != 0 || r.SentBytes != 0 || r.ReceivedBytes == 0 {
		t.Fatal("incorrect HTTP byte semantics")
	}
	c.host = "wrong.test"
	r = load(c)
	if r.Errors == 0 || r.Succeeded != 0 {
		t.Fatal("wrong TLS hostname accepted")
	}
}
func TestHTTPVerificationAndDeadline(t *testing.T) {
	for _, mode := range []string{"prefix", "status", "truncated", "deadline", "oversize"} {
		t.Run(mode, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "status":
					w.WriteHeader(503)
				case "truncated":
					w.Header().Set("Content-Length", "100")
					io.WriteString(w, "short")
				case "deadline":
					w.WriteHeader(200)
					w.(http.Flusher).Flush()
					<-r.Context().Done()
				case "oversize":
					chunk := make([]byte, 32*1024)
					for i := 0; i < maxBody/len(chunk)+1; i++ {
						if _, e := w.Write(chunk); e != nil {
							return
						}
					}
				default:
					io.WriteString(w, "wrong backend")
				}
			}))
			defer srv.Close()
			c := testConfig("http", srv.Listener.Addr().String())
			c.concurrency = 1
			c.duration = time.Millisecond
			c.timeout = 40 * time.Millisecond
			if mode == "prefix" {
				c.expect = "backend-a"
			}
			r := load(c)
			assertReport(t, r)
			if r.Errors == 0 || r.Succeeded != 0 {
				t.Fatalf("invalid response passed: %+v", r)
			}
			if mode == "deadline" && r.DurationSeconds < .03 {
				t.Fatal("reported configured instead of actual elapsed time")
			}
		})
	}
}
func TestEchoIntegrity(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		for _, corrupt := range []bool{false, true} {
			t.Run(protocol+map[bool]string{false: "-valid", true: "-corrupt"}[corrupt], func(t *testing.T) {
				var target string
				var closeServer func()
				if protocol == "tcp" {
					ln, e := net.Listen("tcp", "127.0.0.1:0")
					if e != nil {
						t.Fatal(e)
					}
					target = ln.Addr().String()
					closeServer = func() { ln.Close() }
					go func() {
						for {
							c, e := ln.Accept()
							if e != nil {
								return
							}
							go func() {
								defer c.Close()
								b := make([]byte, 256)
								for {
									_, e := io.ReadFull(c, b)
									if e != nil {
										return
									}
									if corrupt {
										b[100] ^= 1
									}
									for i := 0; i < len(b); i += 7 {
										end := i + 7
										if end > len(b) {
											end = len(b)
										}
										if _, e = c.Write(b[i:end]); e != nil {
											return
										}
									}
								}
							}()
						}
					}()
				} else {
					pc, e := net.ListenPacket("udp", "127.0.0.1:0")
					if e != nil {
						t.Fatal(e)
					}
					target = pc.LocalAddr().String()
					closeServer = func() { pc.Close() }
					go func() {
						b := make([]byte, 65535)
						for {
							n, a, e := pc.ReadFrom(b)
							if e != nil {
								return
							}
							if corrupt {
								b[0] ^= 1
							}
							pc.WriteTo(b[:n], a)
						}
					}()
				}
				defer closeServer()
				for _, connections := range []string{"new", "reused"} {
					c := testConfig(protocol, target)
					c.connections = connections
					r := load(c)
					assertReport(t, r)
					if corrupt {
						if r.Errors == 0 || r.Succeeded != 0 {
							t.Fatal("corruption accepted")
						}
					} else if r.Errors != 0 || r.SentBytes != r.Succeeded*256 || r.ReceivedBytes != r.SentBytes {
						t.Fatalf("bad echo report: %+v", r)
					}
				}
			})
		}
	}
}
func TestBoundedStats(t *testing.T) {
	var s stats
	for i := 0; i < 100000; i++ {
		s.record(time.Duration(i+1)*time.Microsecond, io.ErrUnexpectedEOF)
	}
	if len(s.samples) != 5 || len(s.hist) != 2048 {
		t.Fatal("unbounded stats")
	}
	if s.percentile(.99) < 99000*.001 || s.percentile(.99) > 100 {
		t.Fatal("incorrect percentile")
	}
}
func TestServeReadinessAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pr, pw := io.Pipe()
	defer pr.Close()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, pw, "127.0.0.1", 0, 0, 0, "backend-a"); pw.Close() }()
	var ready map[string]string
	if err := json.NewDecoder(pr).Decode(&ready); err != nil {
		t.Fatal(err)
	}
	raw, e := net.Dial("tcp", ready["tcp"])
	if e != nil {
		t.Fatal(e)
	}
	defer raw.Close()
	for _, p := range []string{"http", "tcp", "udp"} {
		c := testConfig(p, ready[p])
		c.expect = "backend-a /hello?nonce=42"
		r := load(c)
		if r.Errors != 0 {
			t.Fatalf("%s: %+v", p, r)
		}
	}
	cancel()
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked on idle TCP")
	}
	raw.SetReadDeadline(time.Now().Add(time.Second))
	if _, e = raw.Read(make([]byte, 1)); e == nil {
		t.Fatal("active stream left open")
	}
}
func TestCLIErrorExitAndJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer srv.Close()
	args := []string{"load", "--target", srv.Listener.Addr().String(), "--duration", "1ms", "--concurrency", "1"}
	for _, allow := range []bool{false, true} {
		var out bytes.Buffer
		a := append([]string{}, args...)
		if allow {
			a = append(a, "--allow-errors")
		}
		err := run(a, &out)
		if (err == nil) != allow {
			t.Fatalf("allow=%v err=%v", allow, err)
		}
		var r report
		dec := json.NewDecoder(&out)
		if e := dec.Decode(&r); e != nil {
			t.Fatal(e)
		}
		if e := dec.Decode(&r); e != io.EOF {
			t.Fatal("extra stdout")
		}
		assertReport(t, r)
	}
}

// net.Pipe has no socket buffering: a write-then-read client deadlocks here.
func TestLargeDuplexEcho(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer server.Close()
		buf := make([]byte, 4096)
		for {
			n, err := server.Read(buf)
			if n > 0 {
				if _, e := writeFull(server, buf[:n]); e != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	payload := make([]byte, maxBody)
	reply := make([]byte, len(payload))
	fillPayload(payload, 1, 17)
	client.SetDeadline(time.Now().Add(3 * time.Second))
	sent, received, err := exchangeTCP(client, payload, reply)
	if err != nil || sent != len(payload) || received != len(payload) || !bytes.Equal(payload, reply) {
		t.Fatalf("duplex echo: sent=%d received=%d err=%v", sent, received, err)
	}
	client.Close()
	<-done
}
