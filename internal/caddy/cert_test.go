package caddy

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func testCertificate(t *testing.T, names []string, notBefore, notAfter time.Time) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names, NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
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
