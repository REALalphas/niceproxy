package caddy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"niceproxy/internal/model"
)

func TestManagedPanelOriginLifecycle(t *testing.T) {
	binary := os.Getenv("NICEPROXY_CADDY_TEST_BINARY")
	if binary == "" {
		t.Skip("set NICEPROXY_CADDY_TEST_BINARY for integration")
	}
	o := options(t)
	o.Binary = binary
	o.PanelDomain, o.PanelDomainProxied = "panel.example.test", true
	o.HTTPPort, o.HTTPSPort = freePort(t), freePort(t)
	o.PanelListen = net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Origin CA"},
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(400 * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	originalRoots := cloudflareOriginRoots
	cloudflareOriginRoots = func() *x509.CertPool { return pool }
	t.Cleanup(func() { cloudflareOriginRoots = originalRoots })

	backend, err := net.Listen("unix", o.BackendSocket)
	if err != nil {
		t.Fatal(err)
	}
	panel := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Host+r.URL.RequestURI())
	})}
	go panel.Serve(backend)
	defer panel.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	m := New(o)
	defer m.Close(context.Background())
	if err := m.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	issueCount := 0
	validity := 10 * 24 * time.Hour
	issue := func(_ context.Context, host, csr string) (string, error) {
		issueCount++
		block, _ := pem.Decode([]byte(csr))
		if block == nil {
			t.Fatal("missing certificate request PEM")
		}
		req, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil || req.CheckSignature() != nil || len(req.DNSNames) != 1 || req.DNSNames[0] != o.PanelDomain || host != o.PanelDomain {
			t.Fatalf("invalid host-scoped CSR: %v", err)
		}
		leaf := &x509.Certificate{
			SerialNumber: big.NewInt(int64(issueCount + 1)), DNSNames: req.DNSNames,
			NotBefore: now.Add(-time.Minute), NotAfter: now.Add(validity), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, leaf, ca, req.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, net.JoinHostPort("127.0.0.1", strconv.Itoa(o.HTTPSPort)))
		},
		DisableKeepAlives: true,
	}
	client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
	checkCallbackRoute := func() {
		t.Helper()
		const callback = "/api/cloudflare/callback?state=example"
		response, err := client.Get("https://" + o.PanelDomain + callback)
		if err != nil {
			t.Fatalf("panel OAuth callback TLS/route: %v", err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil || response.StatusCode != http.StatusOK || string(body) != o.PanelDomain+callback {
			t.Fatalf("panel OAuth callback host or path changed: %d %q (%v)", response.StatusCode, body, err)
		}
	}
	cfg := model.Config{PanelDomain: o.PanelDomain, PanelDomainProxied: true, PanelDNSObserved: true}
	for range 2 {
		if changed, err := m.PreparePanelOrigin(ctx, o.PanelDomain, issue); !changed || err != nil {
			t.Fatalf("issue or renew panel certificate: changed=%t error=%v", changed, err)
		}
		if err := m.ApplyConfig(ctx, cfg); err != nil {
			t.Fatal(err)
		}
		presented := model.CertificateStatus{Domain: o.PanelDomain}
		probeCertificate(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(o.HTTPSPort)), &presented)
		if presented.TLSState != "cloudflare_origin" || presented.ExpiresAt == nil || !presented.ExpiresAt.Equal(now.Add(validity).Truncate(time.Second)) {
			t.Fatalf("Origin CA certificate not presented for correct SNI: %+v", presented)
		}
		checkCallbackRoute()
		validity = 365 * 24 * time.Hour
	}
	path := managedPanelPEM(o.DataDir, o.PanelDomain)
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("private persisted certificate pair: %v %v", info, err)
	}
	if err := m.Close(ctx); err != nil {
		t.Fatal(err)
	}
	restarted := New(o)
	defer restarted.Close(context.Background())
	if err := restarted.Start(ctx, nil); err != nil {
		t.Fatal(err)
	}
	if changed, err := restarted.PreparePanelOrigin(ctx, o.PanelDomain, issue); changed || err != nil || issueCount != 2 {
		t.Fatalf("restart unnecessarily renewed certificate: changed=%t count=%d err=%v", changed, issueCount, err)
	}
	presented := model.CertificateStatus{Domain: o.PanelDomain}
	probeCertificate(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(o.HTTPSPort)), &presented)
	if presented.TLSState != "cloudflare_origin" {
		t.Fatalf("persisted Origin CA certificate lost across restart: %+v", presented)
	}

	checkCallbackRoute()

	o.PanelDomainProxied = false
	o.PanelCertFile, o.PanelKeyFile = path, path
	manual, err := BuildConfig(o, nil)
	if err != nil || !strings.Contains(string(manual), "load_files") {
		t.Fatalf("the manually mounted Origin CA pair must work before DNS discovery: %v %s", err, manual)
	}
	o.PanelDNSObserved = true
	direct, err := BuildConfig(o, nil)
	if err != nil || strings.Contains(string(direct), "load_files") || !strings.Contains(string(direct), `"module":"acme"`) {
		t.Fatalf("DNS Only must use public ACME: %v %s", err, direct)
	}
	invalid := o
	invalid.PanelKeyFile = path + ".missing"
	if cert, err := New(invalid).CertificateState(ctx, o.PanelDomain); err != nil || cert != "missing" {
		t.Fatalf("unusable import masked the public ACME state: %q %v", cert, err)
	}
	cfg.PanelDomainProxied = false
	if err := restarted.ApplyConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	presented = model.CertificateStatus{Domain: o.PanelDomain}
	probeCertificate(ctx, net.JoinHostPort("127.0.0.1", strconv.Itoa(o.HTTPSPort)), &presented)
	if presented.TLSState == "cloudflare_origin" || presented.TLSState == "bootstrap" {
		t.Fatalf("Caddy retained a private certificate after switching to DNS Only: %+v", presented)
	}
}
