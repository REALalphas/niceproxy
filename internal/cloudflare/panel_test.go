package cloudflare

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// These fixtures use reserved example names, fictional IDs and local HTTP stubs.
const (
	panelTestHost = "panel.branch.example.com"
	panelTestZone = "11111111111111111111111111111111"
	panelTestSet  = "22222222222222222222222222222222"
	panelTestRule = "33333333333333333333333333333333"
)

func panelTestManager(t *testing.T, handler http.HandlerFunc) *Manager {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			token(w)
			return
		}
		if r.Header.Get("Authorization") != "Bearer secret-access" {
			t.Error("expected test bearer credential")
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	m := manager(t, opts(t, server), nil)
	login(t, m)
	return m
}

func TestPanelRecord(t *testing.T) {
	for _, tc := range []struct {
		name, records, wantError string
		proxied                  bool
	}{
		{"proxied", `{"type":"A","name":"panel.branch.example.com","proxied":true}`, "", true},
		{"DNS only", `{"type":"CNAME","name":"panel.branch.example.com","proxied":false}`, "", false},
		{"mixed", `{"type":"A","name":"panel.branch.example.com","proxied":true},{"type":"AAAA","name":"panel.branch.example.com","proxied":false}`, "", true},
		{"absent", `{"type":"TXT","name":"panel.branch.example.com","proxied":true},{"type":"A","name":"another.branch.example.com","proxied":true}`, "no exact", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := panelTestManager(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.Method + " " + r.URL.Path {
				case "GET /zones":
					fmt.Fprintf(w, `{"success":true,"result":[{"name":"example.com","id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},{"name":"branch.example.com","id":%q},{"name":"anel.branch.example.com","id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]}`, panelTestZone)
				case "GET /zones/" + panelTestZone + "/dns_records":
					if r.URL.Query().Get("name.exact") != panelTestHost {
						t.Errorf("wrong DNS query %s", r.URL)
					}
					if r.URL.Query().Get("page") == "1" {
						fmt.Fprint(w, `{"success":true,"result":[],"result_info":{"total_pages":2}}`)
					} else {
						fmt.Fprintf(w, `{"success":true,"result":[%s],"result_info":{"total_pages":2}}`, tc.records)
					}
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
					http.NotFound(w, r)
				}
			})
			zone, proxied, err := m.PanelRecord(context.Background(), "Panel.Branch.Example.com.")
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("expected %q, got %v", tc.wantError, err)
				}
			} else if err != nil || zone != panelTestZone || proxied != tc.proxied {
				t.Fatalf("got (%q, %t, %v)", zone, proxied, err)
			}
		})
	}
}

func TestPanelSSLModeAndOriginCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	makeCSR := func(hosts ...string) string {
		t.Helper()
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{DNSNames: hosts}, key)
		if err != nil {
			t.Fatal(err)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
	}
	csr := makeCSR(panelTestHost)
	m := panelTestManager(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method + " " + r.URL.Path {
		case "GET /zones/" + panelTestZone + "/settings/ssl":
			fmt.Fprint(w, `{"success":true,"result":{"id":"ssl","value":"full"}}`)
		case "GET /zones/" + panelTestZone + "/settings/ssl_automatic_mode":
			fmt.Fprint(w, `{"success":true,"result":{"id":"ssl_automatic_mode","value":"auto"}}`)
		case "POST /certificates":
			var body struct {
				CSR      string   `json:"csr"`
				Hosts    []string `json:"hostnames"`
				Type     string   `json:"request_type"`
				Validity int      `json:"requested_validity"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.CSR != csr ||
				len(body.Hosts) != 1 || body.Hosts[0] != panelTestHost || body.Type != "origin-ecc" || body.Validity != 365 {
				t.Errorf("wrong certificate request: %+v, %v", body, err)
			}
			fmt.Fprint(w, `{"success":true,"result":{"certificate":"mock-issued-certificate"}}`)
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	})
	ctx := context.Background()
	if mode, selection, err := m.PanelSSLMode(ctx, panelTestZone); err != nil || mode != "full" || selection != "automatic" {
		t.Fatalf("got (%q, %q, %v)", mode, selection, err)
	}
	if _, err := m.IssuePanelOrigin(ctx, panelTestHost, makeCSR(panelTestHost, "another.example.com")); err == nil {
		t.Fatal("unexpected acceptance of a CSR for multiple names")
	}
	if cert, err := m.IssuePanelOrigin(ctx, panelTestHost, csr); err != nil || cert != "mock-issued-certificate" {
		t.Fatalf("got (%q, %v)", cert, err)
	}
}

func TestPanelStrictOwnedRules(t *testing.T) {
	const base = "/zones/" + panelTestZone + "/rulesets"
	for _, initial := range []string{"no ruleset", "existing ruleset", "later SSL rule", "permission denied"} {
		t.Run(initial, func(t *testing.T) {
			var mu sync.Mutex
			var owned map[string]any
			var mutations []string
			unrelated := map[string]any{"id": "44444444444444444444444444444444", "ref": "third_party_ssl", "expression": "true", "action": "set_config", "action_parameters": map[string]any{"ssl": "full"}, "enabled": true}
			gets := 0
			wantMove := initial == "later SSL rule"
			m := panelTestManager(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				var rule map[string]any
				switch r.Method + " " + r.URL.Path {
				case "GET " + base + "/phases/" + panelConfigPhase + "/entrypoint":
					gets++
					if initial == "permission denied" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					if owned == nil && initial == "no ruleset" {
						http.NotFound(w, r)
						return
					}
					rules := []map[string]any{}
					if initial != "no ruleset" {
						rules = append(rules, unrelated)
					}
					if owned != nil {
						if wantMove && gets == 2 {
							rules = []map[string]any{owned, unrelated}
						} else {
							rules = append(rules, owned)
						}
					}
					json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": panelTestSet, "rules": rules}})
					return
				case "POST " + base:
					var body struct {
						Kind, Phase string
						Rules       []map[string]any
					}
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Kind != "zone" || body.Phase != panelConfigPhase || len(body.Rules) != 1 {
						t.Errorf("invalid ruleset body: %+v, %v", body, err)
						http.Error(w, "wrong body", http.StatusBadRequest)
						return
					}
					rule = body.Rules[0]
				case "POST " + base + "/" + panelTestSet + "/rules",
					"PATCH " + base + "/" + panelTestSet + "/rules/" + panelTestRule:
					if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
						t.Errorf("invalid rule body: %v", err)
						http.Error(w, "wrong body", http.StatusBadRequest)
						return
					}
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
					http.NotFound(w, r)
					return
				}
				params, _ := rule["action_parameters"].(map[string]any)
				ref, _ := rule["ref"].(string)
				if !strings.HasPrefix(ref, "niceproxy_panel_tls_") || rule["expression"] != "http.host eq \""+panelTestHost+"\"" ||
					rule["action"] != "set_config" || len(params) != 1 || params["ssl"] != "strict" || rule["enabled"] != true || rule["rules"] != nil {
					t.Errorf("unexpected rule %+v", rule)
				}
				if r.Method == "PATCH" {
					position, _ := rule["position"].(map[string]any)
					if position["after"] != "" {
						t.Errorf("owned SSL rule should move to the end, got %+v", position)
					}
					delete(rule, "position")
				}
				mutations = append(mutations, r.Method+" "+r.URL.Path)
				rule["id"] = panelTestRule
				owned = rule
				fmt.Fprint(w, `{"success":true,"result":{}}`)
			})
			ctx := context.Background()
			for i := 0; i < 3; i++ {
				err := m.EnsurePanelStrict(ctx, panelTestZone, panelTestHost)
				if initial == "permission denied" {
					if err == nil || !strings.Contains(err.Error(), "Config Settings Read or Write") {
						t.Fatalf("permission error missing context: %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			expected := []string{"POST " + base + "/" + panelTestSet + "/rules"}
			switch initial {
			case "no ruleset":
				expected = []string{"POST " + base}
			case "later SSL rule":
				expected = append(expected, "PATCH "+base+"/"+panelTestSet+"/rules/"+panelTestRule)
			case "permission denied":
				expected = nil
			}
			mu.Lock()
			defer mu.Unlock()
			if strings.Join(mutations, "\n") != strings.Join(expected, "\n") {
				t.Fatalf("mutations %v, want %v", mutations, expected)
			}
		})
	}
}

func TestRemovePanelStrict(t *testing.T) {
	const base = "/zones/" + panelTestZone + "/rulesets"
	for _, initial := range []string{"owned", "edited", "no owned ref", "no ruleset"} {
		t.Run(initial, func(t *testing.T) {
			var mu sync.Mutex
			deletes := 0
			m := panelTestManager(t, func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				switch r.Method + " " + r.URL.Path {
				case "GET " + base + "/phases/" + panelConfigPhase + "/entrypoint":
					if initial == "no ruleset" {
						http.NotFound(w, r)
						return
					}
					rule := desiredPanelRule(panelTestHost)
					switch initial {
					case "edited":
						rule.Expression = "true"
					case "no owned ref":
						rule.Ref = "third_party_rule_with_exact_host_expression"
					}
					rules := []any{map[string]any{
						"id":         "44444444444444444444444444444444",
						"ref":        "third_party_rule",
						"expression": rule.Expression,
					}}
					if deletes == 0 {
						rules = append(rules, struct {
							ID string `json:"id"`
							panelConfigRule
						}{panelTestRule, rule})
					}
					json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": panelTestSet, "rules": rules}})
				case "DELETE " + base + "/" + panelTestSet + "/rules/" + panelTestRule:
					deletes++
					fmt.Fprint(w, `{"success":true,"result":{}}`)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
					http.NotFound(w, r)
				}
			})
			for i := 0; i < 2; i++ {
				err := m.RemovePanelStrict(context.Background(), panelTestZone, panelTestHost)
				if initial == "edited" {
					if err == nil || !strings.Contains(err.Error(), "was edited") {
						t.Fatalf("expected edit conflict, got %v", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			wantDeletes := 0
			if initial == "owned" {
				wantDeletes = 1
			}
			mu.Lock()
			defer mu.Unlock()
			if deletes != wantDeletes {
				t.Fatalf("got %d rule deletes, want %d", deletes, wantDeletes)
			}
		})
	}
}

func TestPanelStrictOverrideNeeded(t *testing.T) {
	const base = "/zones/" + panelTestZone + "/rulesets/phases/" + panelConfigPhase + "/entrypoint"
	for _, tc := range []struct {
		name, expr, ssl string
		want            bool
	}{
		{"strict default", "", "", false},
		{"panel Flexible", desiredPanelRule(panelTestHost).Expression, "flexible", true},
		{"other hostname Flexible", `http.host eq "other.example.com"`, "flexible", false},
		{"path-based Full can weaken panel TLS", `starts_with(http.request.uri.path, "/api/")`, "full", true},
		{"panel Full strict", desiredPanelRule(panelTestHost).Expression, "strict", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := panelTestManager(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != base {
					t.Errorf("unexpected request %s %s", r.Method, r.URL)
					http.NotFound(w, r)
					return
				}
				rules := []panelConfigRule{}
				if tc.expr != "" {
					rules = append(rules, panelConfigRule{Expression: tc.expr, Action: "set_config", Parameters: map[string]any{"ssl": tc.ssl}, Enabled: true})
				}
				json.NewEncoder(w).Encode(map[string]any{"success": true, "result": map[string]any{"id": panelTestSet, "rules": rules}})
			})
			if got, err := m.PanelStrictOverrideNeeded(context.Background(), panelTestZone, panelTestHost); err != nil || got != tc.want {
				t.Fatalf("override needed = %t, want %t, err=%v", got, tc.want, err)
			}
		})
	}
}

func TestPanelRecordDetectsProxiedCNAMETarget(t *testing.T) {
	m := panelTestManager(t, func(w http.ResponseWriter, r *http.Request) {
		const target = "origin.branch.example.com"
		switch r.URL.Path {
		case "/zones":
			fmt.Fprintf(w, `{"success":true,"result":[{"name":"branch.example.com","id":%q,"status":"active"}]}`, panelTestZone)
		case "/zones/" + panelTestZone + "/dns_records":
			switch r.URL.Query().Get("name.exact") {
			case panelTestHost:
				fmt.Fprintf(w, `{"success":true,"result":[{"type":"CNAME","name":%q,"content":%q,"proxied":false}]}`, panelTestHost, target)
			case target:
				fmt.Fprintf(w, `{"success":true,"result":[{"type":"A","name":%q,"content":"192.0.2.10","proxied":true}]}`, target)
			default:
				t.Errorf("unexpected DNS lookup %s", r.URL)
			}
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL)
			http.NotFound(w, r)
		}
	})
	if zone, proxied, err := m.PanelRecord(context.Background(), panelTestHost); err != nil || zone != panelTestZone || !proxied {
		t.Fatalf("CNAME target proxy mode missed: %q %v %v", zone, proxied, err)
	}
}
