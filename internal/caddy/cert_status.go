package caddy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"niceproxy/internal/model"
)

// Public trust anchors from Cloudflare's Origin CA installation guide.
// https://developers.cloudflare.com/ssl/origin-configuration/origin-ca/#cloudflare-origin-ca-root-certificate
//
//go:embed cloudflare_origin_ecc.pem
var cloudflareOriginECC []byte

//go:embed cloudflare_origin_rsa.pem
var cloudflareOriginRSA []byte

var cloudflareOriginRoots = sync.OnceValue(func() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(cloudflareOriginECC)
	pool.AppendCertsFromPEM(cloudflareOriginRSA)
	return pool
})

func verifyOriginChain(chain []*x509.Certificate, host string, originRoots *x509.CertPool) (string, error) {
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	options := x509.VerifyOptions{DNSName: host, Intermediates: intermediates, Roots: originRoots}
	if _, err := chain[0].Verify(options); err == nil {
		return "cloudflare_origin", nil
	}
	options.Roots = nil
	if _, err := chain[0].Verify(options); err != nil {
		return "untrusted", err
	}
	return "served", nil
}

// CertificateState examines the matching SNI entries across Caddy's issuers.
func (m *Manager) CertificateState(ctx context.Context, host string) (string, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	mode := panelDNSMode(m.panelDNS.Load())
	_, _, chain, importedState, certErr := panelCertificateFiles(m.options.DataDir, m.options.PanelCertFile, m.options.PanelKeyFile, host, mode)
	if certErr != nil {
		return importedState, certErr
	}
	if len(chain) != 0 {
		if _, err := verifyOriginChain(chain, host, cloudflareOriginRoots()); err != nil {
			return "invalid", fmt.Errorf("panel certificate is not trusted by the system or Cloudflare Origin CA: %w", err)
		}
		return "valid", nil
	}
	wildcard := ""
	if _, suffix, ok := strings.Cut(host, "."); ok {
		wildcard = "wildcard_." + suffix
	}
	root := filepath.Join(m.options.DataDir, "caddy", "certificates")
	state := "missing"
	var stateErr error
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".crt" {
			return nil
		}
		name := strings.TrimSuffix(entry.Name(), ".crt")
		if name != host && name != wildcard {
			return nil
		}
		issuerDir := filepath.Base(filepath.Dir(filepath.Dir(path)))
		if issuerDir == "local" && mode != panelDNSProxied {
			return nil
		}
		cert, certErr := os.ReadFile(path)
		key, keyErr := os.ReadFile(strings.TrimSuffix(path, ".crt") + ".key")
		candidate, candidateErr := "invalid", errors.Join(certErr, keyErr)
		if candidateErr == nil && len(key) == 0 {
			candidateErr = errors.New("certificate private key is empty")
		}
		if candidateErr == nil {
			candidate, candidateErr = ValidateCertificate(cert, key, host, time.Now())
		}
		if candidate == "valid" && issuerDir == "local" {
			if state == "missing" {
				state = "bootstrap"
			}
			return nil
		}
		if candidate == "valid" {
			state, stateErr = candidate, nil
			return filepath.SkipAll
		}
		if stateErr == nil {
			state, stateErr = candidate, candidateErr
		}
		return nil
	})
	if walkErr != nil {
		return "invalid", fmt.Errorf("inspect Caddy certificate storage: %w", walkErr)
	}
	return state, stateErr
}

// CertificateStatus distinguishes the system resolver, on-disk certificates and
// the certificate Caddy actually presents on the local HTTPS listener.
func (m *Manager) CertificateStatus(ctx context.Context, domain string) model.CertificateStatus {
	status := model.CertificateStatus{Configured: domain != "", Domain: domain, State: "not_configured"}
	if domain == "" {
		return status
	}
	lookup, cancel := context.WithTimeout(ctx, 2*time.Second)
	addresses, err := net.DefaultResolver.LookupHost(lookup, domain)
	cancel()
	if err != nil {
		status.DNSState = "error"
		status.DNSError = err.Error()
	} else {
		status.DNSState = "resolved"
		status.Addresses = addresses
	}

	state, err := m.CertificateState(ctx, domain)
	status.StoredState = state
	status.State = "pending"
	switch state {
	case "valid":
		status.State = "issued"
	case "expired":
		status.State = "expired"
	case "invalid", "wrong_host":
		status.State = "error"
	}
	if err != nil {
		status.Error = err.Error()
	}
	if !m.mu.TryLock() {
		status.TLSState = "busy"
		return status
	}
	running, port := !m.closed && m.running(), m.options.HTTPSPort
	tcpOwned := m.options.PortOwners.Defaults().HTTPS == "caddy"
	m.mu.Unlock()
	switch {
	case !running:
		status.TLSState = "caddy_stopped"
	case !tcpOwned:
		status.TLSState = "no_caddy_tcp_listener"
	default:
		probe, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		probeCertificate(probe, net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), &status)
	}
	return status
}

func probeCertificate(ctx context.Context, address string, status *model.CertificateStatus) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		status.TLSState, status.TLSError = "unreachable", err.Error()
		return
	}
	defer raw.Close()
	// Complete the local handshake to inspect the presented chain. Report
	// readiness only after verifying the leaf against system roots below.
	conn := tls.Client(raw, &tls.Config{ServerName: status.Domain, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err := conn.HandshakeContext(ctx); err != nil {
		status.TLSState, status.TLSError = "handshake_failed", err.Error()
		return
	}
	chain := conn.ConnectionState().PeerCertificates
	if len(chain) == 0 {
		status.TLSState = "missing"
		return
	}
	leaf := chain[0]
	status.ExpiresAt = &leaf.NotAfter
	now := time.Now()
	switch {
	case leaf.VerifyHostname(status.Domain) != nil:
		status.TLSState = "wrong_host"
		status.TLSError = "The origin certificate does not cover the requested hostname"
	case now.Before(leaf.NotBefore):
		status.TLSState = "not_yet_valid"
	case !now.Before(leaf.NotAfter):
		status.TLSState = "expired"
	case strings.HasPrefix(leaf.Issuer.CommonName, "Caddy Local Authority"):
		status.TLSState = "bootstrap"
		status.TLSError = "Caddy serves a local certificate. Cloudflare Full (strict) needs a trusted origin certificate"
	default:
		trust, err := verifyOriginChain(chain, status.Domain, cloudflareOriginRoots())
		status.TLSState = trust
		if err != nil {
			status.TLSError = fmt.Sprintf("Certificate chain failed verification against the system and Cloudflare Origin CA: %v", err)
		}
	}
}
