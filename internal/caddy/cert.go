package caddy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ValidateCertificate classifies an origin certificate without changing any
// persisted Caddy or user data. It is used for actionable panel diagnostics
// and is intentionally independent of Caddy's issuance loop.
func ValidateCertificate(certPEM, keyPEM []byte, host string, now time.Time) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return "invalid", errors.New("certificate PEM is missing")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "invalid", fmt.Errorf("parse certificate: %w", err)
	}
	if len(keyPEM) > 0 {
		if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
			return "invalid", fmt.Errorf("certificate key mismatch: %w", err)
		}
	}
	if now.IsZero() {
		now = time.Now()
	}
	if now.Before(cert.NotBefore) {
		return "not_yet_issued", fmt.Errorf("certificate is valid from %s", cert.NotBefore.UTC().Format(time.RFC3339))
	}
	if !now.Before(cert.NotAfter) {
		return "expired", fmt.Errorf("certificate expired at %s", cert.NotAfter.UTC().Format(time.RFC3339))
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if err := cert.VerifyHostname(host); err != nil {
		return "wrong_host", fmt.Errorf("certificate does not contain %s", host)
	}
	return "valid", nil
}
