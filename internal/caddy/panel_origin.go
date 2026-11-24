package caddy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func managedPanelPEM(dataDir, host string) string {
	return filepath.Join(dataDir, "panel-origin", host+".pem")
}

// PreparePanelOrigin renews the dedicated Cloudflare Origin CA certificate when
// necessary. A successful replacement is published as one certificate/key file.
func (m *Manager) PreparePanelOrigin(ctx context.Context, host string, issue func(context.Context, string, string) (string, error)) (bool, error) {
	if !hostname(host) || !strings.Contains(host, ".") {
		return false, errors.New("panel Origin CA requires a fully qualified hostname")
	}
	if chain, _, err := importedPanelCertificate(m.options.PanelCertFile, m.options.PanelKeyFile, host); err == nil {
		if _, err := verifyOriginChain(chain, host, cloudflareOriginRoots()); err == nil {
			return false, nil
		}
	}
	path := managedPanelPEM(m.options.DataDir, host)
	if chain, _, err := importedPanelCertificate(path, path, host); err == nil && time.Until(chain[0].NotAfter) > 30*24*time.Hour {
		if trust, err := verifyOriginChain(chain, host, cloudflareOriginRoots()); err == nil && trust == "cloudflare_origin" {
			return false, nil
		}
	}
	if _, _, chain := storedPublicPanelCertificate(m.options.DataDir, host); len(chain) > 0 && time.Until(chain[0].NotAfter) > 30*24*time.Hour {
		return false, nil
	}
	dir := filepath.Dir(path)
	if err := privateDir(dir); err != nil {
		return false, fmt.Errorf("prepare panel certificate directory: %w", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return false, err
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: []string{host}}, key)
	if err != nil {
		return false, err
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return false, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := issue(ctx, host, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request})))
	if err != nil {
		return false, err
	}
	chain, _, err := panelCertificateChain([]byte(cert), keyPEM, host)
	if err != nil {
		return false, fmt.Errorf("Cloudflare returned an invalid panel certificate: %w", err)
	}
	if trust, err := verifyOriginChain(chain, host, cloudflareOriginRoots()); err != nil || trust != "cloudflare_origin" {
		return false, errors.New("issued panel certificate failed Cloudflare Origin CA verification")
	}
	f, err := os.CreateTemp(dir, ".origin-*.pem")
	if err != nil {
		return false, err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.WriteString(strings.TrimSpace(cert) + "\n" + string(keyPEM))
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return false, err
	}
	if err := os.Rename(f.Name(), path); err != nil {
		return false, err
	}
	storage, err := os.Open(dir)
	if err != nil {
		return false, err
	}
	return true, errors.Join(storage.Sync(), storage.Close())
}

type panelDNSMode uint32

const (
	panelDNSUnknown panelDNSMode = iota
	panelDNSOnly
	panelDNSProxied
)

func (o Options) panelDNSMode() panelDNSMode {
	if o.PanelDomainProxied {
		return panelDNSProxied
	}
	if o.PanelDNSObserved {
		return panelDNSOnly
	}
	return panelDNSUnknown
}

func panelCertificateFiles(dataDir, certFile, keyFile, host string, mode panelDNSMode) (string, string, []*x509.Certificate, string, error) {
	var imported []*x509.Certificate
	var state string
	var err error
	if certFile != "" || keyFile != "" {
		imported, state, err = importedPanelCertificate(certFile, keyFile, host)
		if err == nil {
			if trust, err := verifyOriginChain(imported, host, cloudflareOriginRoots()); err == nil {
				if trust == "cloudflare_origin" && mode == panelDNSOnly {
					// Cloudflare's edge trusts Origin CA. Direct browsers need public ACME.
					return "", "", nil, "", nil
				}
				return certFile, keyFile, imported, state, nil
			}
		}
	}
	if mode == panelDNSOnly {
		// Unusable imports should not mask the public ACME certificate state.
		return "", "", nil, "", nil
	}
	if mode == panelDNSProxied {
		path := managedPanelPEM(dataDir, host)
		if chain, _, err := importedPanelCertificate(path, path, host); err == nil {
			if trust, err := verifyOriginChain(chain, host, cloudflareOriginRoots()); err == nil && trust == "cloudflare_origin" {
				return path, path, chain, "valid", nil
			}
		}
		if publicCert, publicKey, chain := storedPublicPanelCertificate(dataDir, host); len(chain) > 0 {
			return publicCert, publicKey, chain, "valid", nil
		}
	}
	return certFile, keyFile, imported, state, err
}

// A certificate issued before switching to Proxied can still secure the origin.
func storedPublicPanelCertificate(dataDir, host string) (string, string, []*x509.Certificate) {
	root := filepath.Join(dataDir, "caddy", "certificates")
	issuers, _ := os.ReadDir(root)
	var certFile, keyFile string
	var best []*x509.Certificate
	for _, issuer := range issuers {
		if !issuer.IsDir() || issuer.Name() == "local" {
			continue
		}
		base := filepath.Join(root, issuer.Name(), host, host)
		chain, _, err := importedPanelCertificate(base+".crt", base+".key", host)
		if err != nil || len(best) != 0 && !chain[0].NotAfter.After(best[0].NotAfter) {
			continue
		}
		if trust, err := verifyOriginChain(chain, host, cloudflareOriginRoots()); err == nil && trust == "served" {
			best, certFile, keyFile = chain, base+".crt", base+".key"
		}
	}
	return certFile, keyFile, best
}
