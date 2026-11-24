package caddy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
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
	return certificateValidity(cert, host, now)
}

func certificateValidity(cert *x509.Certificate, host string, now time.Time) (string, error) {
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

// importedPanelCertificate checks the pair before Caddy loads it. Requiring a
// single SAN keeps an origin-only certificate from matching other routes.
func importedPanelCertificate(certFile, keyFile, host string) ([]*x509.Certificate, string, error) {
	if !validPath(certFile) || !validPath(keyFile) {
		return nil, "invalid", errors.New("set both panel certificate and private key to absolute PEM file paths")
	}
	cert, err := os.ReadFile(certFile)
	if err != nil {
		return nil, "invalid", fmt.Errorf("read panel certificate: %w", err)
	}
	key, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, "invalid", fmt.Errorf("read panel private key: %w", err)
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, "invalid", fmt.Errorf("invalid panel certificate/private key pair: %w", err)
	}
	chain := make([]*x509.Certificate, 0, len(pair.Certificate))
	for _, der := range pair.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, "invalid", fmt.Errorf("parse panel certificate chain: %w", err)
		}
		chain = append(chain, cert)
	}
	leaf := chain[0]
	if state, err := certificateValidity(leaf, host, time.Now()); err != nil {
		return nil, state, err
	}
	if len(leaf.DNSNames) != 1 || !strings.EqualFold(leaf.DNSNames[0], host) || len(leaf.IPAddresses) != 0 {
		return nil, "invalid", fmt.Errorf("panel certificate must cover only %q. Issue a dedicated certificate for this hostname", host)
	}
	return chain, "valid", nil
}
