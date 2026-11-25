package caddy

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"niceproxy/internal/model"
)

func TestCertificateStatusReportsStorageAndResolverIndependently(t *testing.T) {
	manager := New(options(t))
	if got := manager.CertificateStatus(context.Background(), ""); got.Configured || got.State != "not_configured" ||
		got.DNSState != "" || got.StoredState != "" || got.TLSState != "" {
		t.Fatalf("unexpected status with no domain: %+v", got)
	}

	// A numeric loopback host resolves without consulting DNS.
	got := manager.CertificateStatus(context.Background(), "127.0.0.1")
	if !got.Configured || got.Domain != "127.0.0.1" || got.DNSState != "resolved" ||
		len(got.Addresses) != 1 || got.Addresses[0] != "127.0.0.1" ||
		got.StoredState != "missing" || got.State != "pending" || got.TLSState != "caddy_stopped" {
		t.Fatalf("unexpected status without a certificate: %+v", got)
	}

	got = manager.CertificateStatus(context.Background(), "invalid hostname")
	if got.DNSState != "error" || got.DNSError == "" || len(got.Addresses) != 0 ||
		got.StoredState != "missing" || got.State != "pending" || got.TLSState != "caddy_stopped" {
		t.Fatalf("resolver failure masked other diagnostics: %+v", got)
	}

	const domain = "localhost"
	now := time.Now()
	for _, tt := range []struct {
		name, san, state, stored, problem string
		expires                           time.Time
		emptyKey                          bool
	}{
		{"issued", domain, "issued", "valid", "", now.Add(time.Hour), false},
		{"expired", domain, "expired", "expired", "expired", now.Add(-time.Hour), false},
		{"wrong hostname", "other.test", "error", "wrong_host", "does not contain", now.Add(time.Hour), false},
		{"empty key", domain, "error", "invalid", "private key is empty", now.Add(time.Hour), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			opts := options(t)
			manager := New(opts)
			root := filepath.Join(opts.DataDir, "caddy", "certificates", "test-issuer", domain)
			if err := os.MkdirAll(root, 0700); err != nil {
				t.Fatal(err)
			}
			cert, key := testCertificatePair(t, []string{tt.san}, now.Add(-2*time.Hour), tt.expires)
			if tt.emptyKey {
				key = nil
			}
			if err := os.WriteFile(filepath.Join(root, domain+".crt"), cert, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, domain+".key"), key, 0600); err != nil {
				t.Fatal(err)
			}

			got := manager.CertificateStatus(context.Background(), domain)
			if got.State != tt.state || got.StoredState != tt.stored || got.TLSState != "caddy_stopped" {
				t.Fatalf("state = %s, stored = %s, TLS = %s, want %s, %s, caddy_stopped", got.State, got.StoredState, got.TLSState, tt.state, tt.stored)
			}
			if tt.problem == "" && got.Error != "" || tt.problem != "" && !strings.Contains(got.Error, tt.problem) {
				t.Fatalf("storage error = %q, want %q", got.Error, tt.problem)
			}
		})
	}
}

func TestCertificateStatusTracksListenerOwnershipAndBusyManager(t *testing.T) {
	// The fake child handles only admin requests. A local plaintext HTTP server
	// on the HTTPS port makes the TLS handshake failure deterministic.
	plain := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(plain.Close)
	port := plain.Listener.Addr().(*net.TCPAddr).Port

	runtimeDir, err := os.MkdirTemp("/tmp", "np-caddy-status-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	opts := options(t)
	opts.RuntimeDir, opts.HTTPSPort = runtimeDir, port
	manager, _ := fakeManagerWithOptions(t, "", opts)
	ctx := context.Background()
	if err := manager.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	check := func(state string, wantError bool) {
		t.Helper()
		got := manager.CertificateStatus(ctx, "127.0.0.1")
		if got.TLSState != state || (got.TLSError != "") != wantError ||
			got.State != "pending" || got.StoredState != "missing" || got.DNSState != "resolved" || got.ExpiresAt != nil {
			t.Fatalf("certificate status = %+v, want TLS state %s, TLS error %t", got, state, wantError)
		}
	}
	check("handshake_failed", true)
	if err := manager.ApplyConfig(ctx, model.Config{PortOwners: model.PortOwners{HTTPS: "direct"}}); err != nil {
		t.Fatal(err)
	}
	check("no_caddy_tcp_listener", false)

	manager.mu.Lock()
	defer manager.mu.Unlock()
	check("busy", false)
}

func TestTLSProbeChecksValidityAndTrust(t *testing.T) {
	const domain = "panel.test"
	now := time.Now().Truncate(time.Second)
	for _, tt := range []struct {
		name          string
		names         []string
		before, after time.Time
		wantError     bool
	}{
		{"not_yet_valid", []string{domain}, now.Add(time.Hour), now.Add(2 * time.Hour), false},
		{"expired", []string{domain}, now.Add(-2 * time.Hour), now.Add(-time.Hour), false},
		{"bootstrap", []string{"Caddy Local Authority test", domain}, now.Add(-time.Hour), now.Add(time.Hour), true},
		{"untrusted", []string{domain}, now.Add(-time.Hour), now.Add(time.Hour), true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cert, key := testCertificatePair(t, tt.names, tt.before, tt.after)
			pair, err := tls.X509KeyPair(cert, key)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.NotFoundHandler())
			server.TLS = &tls.Config{Certificates: []tls.Certificate{pair}}
			server.StartTLS()
			t.Cleanup(server.Close)
			status := model.CertificateStatus{Domain: domain}
			probeCertificate(context.Background(), server.Listener.Addr().String(), &status)
			if status.TLSState != tt.name || (status.TLSError != "") != tt.wantError ||
				status.ExpiresAt == nil || !status.ExpiresAt.Equal(tt.after) {
				t.Fatalf("TLS status = %+v, want %s, TLS error %t, expiry %v", status, tt.name, tt.wantError, tt.after)
			}
		})
	}
}

func TestTLSProbeReportsUnavailableListener(t *testing.T) {
	status := model.CertificateStatus{Domain: "panel.test"}
	// Port zero cannot be the bound port of a listening TCP socket.
	probeCertificate(context.Background(), "127.0.0.1:0", &status)
	if status.TLSState != "unreachable" || status.TLSError == "" || status.ExpiresAt != nil {
		t.Fatalf("unexpected TLS status: %+v", status)
	}
}
