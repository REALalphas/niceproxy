package caddy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"niceproxy/internal/model"
)

func testCertificate(t *testing.T, names []string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	cert, _ := testCertificatePair(t, names, notBefore, notAfter)
	return cert
}

func testCertificatePair(t *testing.T, names []string, notBefore, notAfter time.Time) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

func TestStoredCertificateCandidates(t *testing.T) {
	const host = "panel.example"
	data := t.TempDir()
	m := New(Options{DataDir: data, RuntimeDir: filepath.Join(data, "run"), PanelDomainProxied: true})
	now := time.Now()
	writePair := func(issuer, name, san string, expires time.Time) {
		t.Helper()
		path := filepath.Join(data, "caddy", "certificates", issuer, name, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		cert, key := testCertificatePair(t, []string{san}, now.Add(-time.Hour), expires)
		if err := os.WriteFile(path+".crt", cert, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".key", key, 0600); err != nil {
			t.Fatal(err)
		}
	}
	check := func(want string, wantErr bool) {
		t.Helper()
		state, err := m.CertificateState(context.Background(), host)
		if state != want || (err != nil) != wantErr {
			t.Fatalf("state=%s err=%v, want %s, error=%v", state, err, want, wantErr)
		}
	}
	writePair("acme.example", "other.example", "other.example", now.Add(time.Hour))
	check("missing", false)
	writePair("local", host, host, now.Add(time.Hour))
	check("bootstrap", false)
	writePair("local", host, host, now.Add(-time.Hour))
	m.panelDNS.Store(uint32(panelDNSOnly))
	check("missing", false)
	writePair("local", host, host, now.Add(time.Hour))
	m.panelDNS.Store(uint32(panelDNSProxied))
	writePair("acme.example", host, host, now.Add(-time.Minute))
	check("expired", true)
	writePair("acme.example", host, "other.example", now.Add(time.Hour))
	check("wrong_host", true)
	writePair("another.example", "wildcard_.example", "*.example", now.Add(time.Hour))
	check("valid", false)
}

func TestTLSProbePreservesStoredIssuanceState(t *testing.T) {
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	status := model.CertificateStatus{Domain: "other.example", State: "issued", StoredState: "valid"}
	probeCertificate(ctx, server.Listener.Addr().String(), &status)
	if status.TLSState != "wrong_host" || status.TLSError == "" || status.State != "issued" || status.StoredState != "valid" {
		t.Fatalf("expected separate storage and local TLS status: %+v", status)
	}
}

func TestOriginTrustIsSeparateFromSystemTrust(t *testing.T) {
	const host = "panel.example"
	now := time.Now()
	certPEM := testCertificate(t, []string{host}, now.Add(-time.Minute), now.Add(time.Hour))
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if trust, err := verifyOriginChain([]*x509.Certificate{cert}, host, cloudflareOriginRoots()); trust != "untrusted" || err == nil {
		t.Fatalf("unrelated authority accepted: %s %v", trust, err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	if trust, err := verifyOriginChain([]*x509.Certificate{cert}, host, roots); trust != "cloudflare_origin" || err != nil {
		t.Fatalf("origin-specific trust anchor rejected: %s %v", trust, err)
	}
}

func TestValidateCertificateStates(t *testing.T) {
	now := time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, want    string
		before, after time.Time
		host          string
	}{
		{"valid", "valid", now.Add(-time.Hour), now.Add(time.Hour), "panel.example"},
		{"missing-host", "wrong_host", now.Add(-time.Hour), now.Add(time.Hour), "other.example"},
		{"expired", "expired", now.Add(-2 * time.Hour), now.Add(-time.Hour), "panel.example"},
		{"future", "not_yet_issued", now.Add(time.Hour), now.Add(2 * time.Hour), "panel.example"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, _ := ValidateCertificate(testCertificate(t, []string{"panel.example"}, tc.before, tc.after), nil, tc.host, now)
			if state != tc.want {
				t.Fatalf("state=%s want %s", state, tc.want)
			}
		})
	}
}
