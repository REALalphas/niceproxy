package cloudflare

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

func panelHostname(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// PanelRecord identifies the most specific accessible zone and checks the
// proxy status of all address records for the exact panel hostname.
func (m *Manager) PanelRecord(ctx context.Context, host string) (string, bool, error) {
	host = panelHostname(host)
	if !hostname(host) {
		return "", false, errors.New("invalid panel hostname")
	}
	zones, err := m.Zones(ctx)
	if err != nil {
		return "", false, fmt.Errorf("list Cloudflare zones for the panel (Zone Read): %w", err)
	}
	zone := panelZone(zones, host)
	if !validHex(zone.ID) {
		return "", false, errors.New("no accessible Cloudflare zone for the panel hostname")
	}
	if zone.Status != "" && zone.Status != "active" {
		return "", false, fmt.Errorf("Cloudflare zone for the panel is %s. Check domain delegation and zone activation", zone.Status)
	}
	current, currentZone := host, zone
	visited := make(map[string]bool)
	for range 16 {
		if visited[current] {
			return "", false, errors.New("loop in the panel's Cloudflare CNAME chain")
		}
		visited[current] = true
		found, proxied, target, err := m.panelDNSRecord(ctx, currentZone.ID, current)
		if err != nil {
			return "", false, err
		}
		if !found && current == host {
			return "", false, errors.New("panel hostname has no exact Cloudflare A, AAAA or CNAME record")
		}
		if proxied || target == "" {
			return zone.ID, proxied, nil
		}
		current, currentZone = target, panelZone(zones, target)
		if !validHex(currentZone.ID) {
			// The panel record is DNS Only. Its external target is outside this grant.
			return zone.ID, false, nil
		}
	}
	return "", false, errors.New("panel's Cloudflare CNAME chain exceeds 16 records")
}

func panelZone(zones []Zone, host string) Zone {
	var best Zone
	for _, zone := range zones {
		name := panelHostname(zone.Name)
		if len(name) > len(panelHostname(best.Name)) && (name == host || strings.HasSuffix(host, "."+name)) {
			best = zone
		}
	}
	return best
}

func (m *Manager) panelDNSRecord(ctx context.Context, zoneID, host string) (found, proxied bool, target string, err error) {
	for page := 1; page <= 100; page++ {
		var records []Record
		path := fmt.Sprintf("/zones/%s/dns_records?name.exact=%s&page=%d&per_page=50", zoneID, url.QueryEscape(host), page)
		pages, err := m.api(ctx, http.MethodGet, path, nil, &records)
		if err != nil {
			return false, false, "", fmt.Errorf("read Cloudflare DNS records for the panel (DNS Read): %w", err)
		}
		for _, record := range records {
			if panelHostname(record.Name) != host {
				continue
			}
			switch record.Type {
			case "CNAME":
				target = panelHostname(record.Content)
			case "A", "AAAA":
			default:
				continue
			}
			// Cloudflare proxies the whole address set if any A/AAAA is proxied.
			found, proxied = true, proxied || record.Proxied
		}
		if pages > 0 && page >= pages || pages == 0 && len(records) < 50 {
			return found, proxied, target, nil
		}
	}
	return false, false, "", errors.New("Cloudflare panel DNS record pagination limit exceeded")
}

// PanelSSLMode reads the zone's current SSL mode and whether Cloudflare manages
// it automatically. Older zones may not expose the automatic selection setting.
func (m *Manager) PanelSSLMode(ctx context.Context, zoneID string) (mode, selection string, err error) {
	if !validHex(zoneID) {
		return "", "", errors.New("invalid zone id")
	}
	var result struct {
		Value string `json:"value"`
	}
	if _, err := m.api(ctx, http.MethodGet, "/zones/"+zoneID+"/settings/ssl", nil, &result); err != nil {
		return "", "", fmt.Errorf("read Cloudflare zone SSL mode (Zone Settings Read): %w", err)
	}
	if result.Value == "" {
		return "", "", errors.New("Cloudflare returned an empty zone SSL mode")
	}
	mode = result.Value
	result.Value = ""
	if _, err := m.api(ctx, http.MethodGet, "/zones/"+zoneID+"/settings/ssl_automatic_mode", nil, &result); err == nil {
		switch result.Value {
		case "auto", "automatic":
			selection = "automatic"
		case "custom":
			selection = "custom"
		}
	}
	return mode, selection, nil
}

// IssuePanelOrigin requests an Origin CA certificate using a signed
// ECDSA CSR for the exact panel hostname.
func (m *Manager) IssuePanelOrigin(ctx context.Context, host, csr string) (string, error) {
	host = panelHostname(host)
	if !hostname(host) {
		return "", errors.New("invalid panel hostname")
	}
	block, rest := pem.Decode([]byte(csr))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(strings.TrimSpace(string(rest))) != 0 {
		return "", errors.New("invalid panel certificate request PEM")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || request.CheckSignature() != nil {
		return "", errors.New("invalid panel certificate request signature")
	}
	if _, ok := request.PublicKey.(*ecdsa.PublicKey); !ok {
		return "", errors.New("panel certificate request must use an ECDSA key")
	}
	if len(request.DNSNames) != 1 || panelHostname(request.DNSNames[0]) != host ||
		len(request.IPAddresses)+len(request.EmailAddresses)+len(request.URIs) != 0 ||
		(request.Subject.CommonName != "" && panelHostname(request.Subject.CommonName) != host) {
		return "", errors.New("panel certificate request must identify only the panel hostname")
	}
	body := struct {
		CSR               string   `json:"csr"`
		Hostnames         []string `json:"hostnames"`
		RequestType       string   `json:"request_type"`
		RequestedValidity int      `json:"requested_validity"`
	}{csr, []string{host}, "origin-ecc", 365}
	var result struct {
		Certificate string `json:"certificate"`
	}
	if _, err := m.api(ctx, http.MethodPost, "/certificates", body, &result); err != nil {
		return "", fmt.Errorf("issue Cloudflare Origin CA certificate (SSL and Certificates Edit): %w", err)
	}
	if strings.TrimSpace(result.Certificate) == "" {
		return "", errors.New("Cloudflare returned an empty Origin CA certificate")
	}
	return result.Certificate, nil
}

const panelConfigPhase = "http_config_settings"

type panelConfigRule struct {
	Ref         string            `json:"ref"`
	Description string            `json:"description"`
	Expression  string            `json:"expression"`
	Action      string            `json:"action"`
	Parameters  map[string]any    `json:"action_parameters"`
	Enabled     bool              `json:"enabled"`
	Position    map[string]string `json:"position,omitempty"`
}

type panelConfigRuleset struct {
	ID    string `json:"id"`
	Rules []struct {
		ID string `json:"id"`
		panelConfigRule
	} `json:"rules"`
}

func desiredPanelRule(host string) panelConfigRule {
	digest := sha256.Sum256([]byte(host))
	return panelConfigRule{
		Ref:         fmt.Sprintf("niceproxy_panel_tls_%x", digest[:16]),
		Description: "niceproxy panel Full (strict)",
		Expression:  fmt.Sprintf("http.host eq %q", host),
		Action:      "set_config",
		Parameters:  map[string]any{"ssl": "strict"},
		Enabled:     true,
	}
}

func (r panelConfigRule) isStrictFor(expected panelConfigRule) bool {
	return r.Action == expected.Action && r.Expression == expected.Expression &&
		len(r.Parameters) == 1 && r.Parameters["ssl"] == "strict"
}

func (rs panelConfigRuleset) ownedIndex(ref string) (int, error) {
	index := -1
	for i, candidate := range rs.Rules {
		if candidate.Ref != ref {
			continue
		}
		if index >= 0 {
			return -1, errors.New("Cloudflare returned duplicate owned panel configuration rules")
		}
		if !validHex(candidate.ID) {
			return -1, errors.New("invalid Cloudflare panel configuration rule id")
		}
		index = i
	}
	return index, nil
}

func (m *Manager) panelRuleset(ctx context.Context, path string) (panelConfigRuleset, error) {
	var ruleset panelConfigRuleset
	_, err := m.api(ctx, http.MethodGet, path+"/phases/"+panelConfigPhase+"/entrypoint", nil, &ruleset)
	if err != nil {
		return panelConfigRuleset{}, err
	}
	if !validHex(ruleset.ID) {
		return panelConfigRuleset{}, errors.New("invalid Cloudflare Configuration Rules ruleset id")
	}
	return ruleset, nil
}

func cloudflareNotFound(err error) bool {
	// api reports non-2xx statuses as this error. Cloudflare returns 404
	// when a phase entrypoint or rule no longer exists.
	return err != nil && err.Error() == "Cloudflare API request failed (HTTP 404)"
}

// PanelStrictOverrideNeeded checks whether a zone set to strict has a
// Configuration Rule that can weaken the panel's origin TLS.
func (m *Manager) PanelStrictOverrideNeeded(ctx context.Context, zoneID, host string) (bool, error) {
	host = panelHostname(host)
	if !validHex(zoneID) || !hostname(host) {
		return false, errors.New("invalid zone id or panel hostname")
	}
	ruleset, err := m.panelRuleset(ctx, "/zones/"+zoneID+"/rulesets")
	if cloudflareNotFound(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("verify Cloudflare Configuration Rules (Config Settings Read or Write): %w", err)
	}
	exactHost := desiredPanelRule(host).Expression
	for i := len(ruleset.Rules) - 1; i >= 0; i-- {
		rule := ruleset.Rules[i]
		ssl, setsSSL := rule.Parameters["ssl"]
		if !rule.Enabled || rule.Action != "set_config" || !setsSSL {
			continue
		}
		expr := strings.TrimSpace(rule.Expression)
		switch {
		case expr == exactHost || expr == "true":
			return ssl != "strict" && ssl != "origin_pull", nil
		case ssl != "strict" && ssl != "origin_pull":
			// Ignore a simple exact-host rule for a different hostname.
			if rhs, ok := strings.CutPrefix(expr, "http.host eq "); ok {
				if name, err := strconv.Unquote(rhs); err == nil && hostname(name) {
					continue
				}
			}
			// A more general expression could match the panel.
			return true, nil
		}
	}
	return false, nil
}

// EnsurePanelStrict creates or updates the hostname's owned configuration
// rule for Full (strict) SSL mode.
func (m *Manager) EnsurePanelStrict(ctx context.Context, zoneID, host string) error {
	host = panelHostname(host)
	if !validHex(zoneID) || !hostname(host) {
		return errors.New("invalid zone id or panel hostname")
	}
	m.op.Lock()
	defer m.op.Unlock()

	rule := desiredPanelRule(host)
	path := "/zones/" + zoneID + "/rulesets"
	ruleset, err := m.panelRuleset(ctx, path)
	if cloudflareNotFound(err) {
		body := struct {
			Name  string            `json:"name"`
			Kind  string            `json:"kind"`
			Phase string            `json:"phase"`
			Rules []panelConfigRule `json:"rules"`
		}{"Configuration Rules", "zone", panelConfigPhase, []panelConfigRule{rule}}
		if _, err := m.api(ctx, http.MethodPost, path, body, nil); err != nil {
			return fmt.Errorf("create Cloudflare Configuration Rules (Config Settings Write): %w", err)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Cloudflare Configuration Rules (Config Settings Read or Write): %w", err)
	}
	ownedIndex, err := ruleset.ownedIndex(rule.Ref)
	if err != nil {
		return err
	}
	path += "/" + ruleset.ID + "/rules"
	if ownedIndex < 0 {
		if _, err := m.api(ctx, http.MethodPost, path, rule, nil); err != nil {
			return fmt.Errorf("add Cloudflare panel Configuration Rule (Config Settings Write): %w", err)
		}
		return nil
	}
	owned := ruleset.Rules[ownedIndex]
	if !owned.isStrictFor(rule) {
		return errors.New("Cloudflare panel Configuration Rule was edited. Restore or remove that rule to resume automatic setup")
	}
	for _, later := range ruleset.Rules[ownedIndex+1:] {
		if ssl, setsSSL := later.Parameters["ssl"]; setsSSL && ssl != "strict" && later.Action == "set_config" && later.Enabled {
			// The last matching SSL setting takes precedence.
			rule.Position = map[string]string{"after": ""}
			break
		}
	}
	if rule.Position == nil && owned.Enabled {
		return nil
	}
	if _, err := m.api(ctx, http.MethodPatch, path+"/"+owned.ID, rule, nil); err != nil {
		return fmt.Errorf("update Cloudflare panel Configuration Rule (Config Settings Write): %w", err)
	}
	return nil
}

// RemovePanelStrict deletes the exact hostname's owned Full (strict) SSL rule.
func (m *Manager) RemovePanelStrict(ctx context.Context, zoneID, host string) error {
	host = panelHostname(host)
	if !validHex(zoneID) || !hostname(host) {
		return errors.New("invalid zone id or panel hostname")
	}
	m.op.Lock()
	defer m.op.Unlock()

	path := "/zones/" + zoneID + "/rulesets"
	ruleset, err := m.panelRuleset(ctx, path)
	if cloudflareNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read Cloudflare Configuration Rules (Config Settings Read or Write): %w", err)
	}
	rule := desiredPanelRule(host)
	ownedIndex, err := ruleset.ownedIndex(rule.Ref)
	if err != nil || ownedIndex < 0 {
		return err
	}
	owned := ruleset.Rules[ownedIndex]
	if !owned.isStrictFor(rule) {
		return errors.New("Cloudflare panel Configuration Rule was edited and could not be removed safely")
	}
	_, err = m.api(ctx, http.MethodDelete, path+"/"+ruleset.ID+"/rules/"+owned.ID, nil, nil)
	if err != nil && !cloudflareNotFound(err) {
		return fmt.Errorf("remove Cloudflare panel Configuration Rule (Config Settings Write): %w", err)
	}
	return nil
}
