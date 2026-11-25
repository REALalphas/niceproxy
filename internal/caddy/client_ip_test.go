package caddy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPublicPanelCloudflareRangesAreAutomatic(t *testing.T) {
	for _, tc := range []struct {
		name, override string
		want           []string
	}{
		{"defaults", "", strings.Fields(cloudflarePanelCIDRs)},
		{"replacement", "192.0.2.0/24, 2001:db8:1::/48", []string{"192.0.2.0/24", "2001:db8:1::/48"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := options(t)
			o.PanelDomain = "panel.example.test"
			o.PanelCloudflareCIDRs = tc.override
			raw, err := BuildConfig(o, nil)
			if err != nil {
				t.Fatal(err)
			}
			var cfg object
			if err := json.Unmarshal(raw, &cfg); err != nil {
				t.Fatal(err)
			}
			apps := cfg["apps"].(map[string]any)
			servers := apps["http"].(map[string]any)["servers"].(map[string]any)
			publicRoutes := servers["public_https"].(map[string]any)["routes"].([]any)
			panelRoute := publicRoutes[0].(map[string]any)
			hostMatch := panelRoute["match"].([]any)[0].(map[string]any)
			if len(hostMatch) != 1 || !reflect.DeepEqual(hostMatch["host"], []any{o.PanelDomain}) {
				t.Fatalf("expected the panel hostname to be matched first, got %v", hostMatch)
			}
			handler := panelRoute["handle"].([]any)[0].(map[string]any)
			edgeRoute := handler["routes"].([]any)[0].(map[string]any)
			match := edgeRoute["match"].([]any)[0].(map[string]any)
			got := match["remote_ip"].(map[string]any)["ranges"].([]any)
			want := make([]any, len(tc.want))
			for i, cidr := range tc.want {
				want[i] = cidr
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("remote ranges = %v, want %v", got, want)
			}
			localRoute := servers["panel"].(map[string]any)["routes"].([]any)[0].(map[string]any)
			if _, ok := localRoute["match"]; ok {
				t.Fatal("local panel has a Cloudflare route")
			}
		})
	}
}

func TestPanelCloudflareRejectsInvalidCIDRs(t *testing.T) {
	for _, value := range []string{"not-a-cidr", "127.0.0.3", "0.0.0.0/0", "::/0", "::ffff:192.0.2.0/120"} {
		o := options(t)
		o.PanelCloudflareCIDRs = value
		if _, err := BuildConfig(o, nil); err != nil {
			t.Errorf("local panel cannot recover with override %q: %v", value, err)
		}
		o.PanelDomain = "panel.example.test"
		if _, err := BuildConfig(o, nil); err == nil {
			t.Errorf("accepted proxy range %q", value)
		}
	}
}

func TestRealPanelClientIPHeaders(t *testing.T) {
	binary := os.Getenv("NICEPROXY_CADDY_TEST_BINARY")
	if binary == "" {
		t.Skip("set NICEPROXY_CADDY_TEST_BINARY for integration")
	}
	o := options(t)
	o.HTTPPort, o.HTTPSPort = freePort(t), freePort(t)
	o.PanelListen = net.JoinHostPort("127.0.0.1", strconv.Itoa(freePort(t)))
	o.PanelDomain = "panel.example.test"
	o.PanelCloudflareCIDRs = "127.0.0.3/32, 2001:db8:1::/48"
	backend, err := net.Listen("unix", o.BackendSocket)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(r.Header)
	})}
	go srv.Serve(backend)
	defer srv.Close()

	raw, err := BuildConfig(o, nil)
	if err != nil {
		t.Fatal(err)
	}
	var cfg object
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	// Use a private test certificate and loopback listeners for the generated routes.
	apps := cfg["apps"].(map[string]any)
	servers := apps["http"].(map[string]any)["servers"].(map[string]any)
	delete(servers, "public_http")
	httpsAddress := net.JoinHostPort("127.0.0.1", strconv.Itoa(o.HTTPSPort))
	servers["public_https"].(map[string]any)["listen"] = []string{httpsAddress}
	apps["tls"] = object{"automation": object{"policies": []object{{
		"subjects": []string{o.PanelDomain},
		"issuers":  []object{{"module": "internal"}},
	}}}}
	apps["pki"] = object{"certificate_authorities": object{"local": object{"install_trust": false}}}
	cfg["admin"] = object{"disabled": true}
	raw, err = json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "caddy.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, "run", "--config", path)
	cmd.Env = append(os.Environ(), "XDG_DATA_HOME="+o.DataDir, "XDG_CONFIG_HOME="+o.RuntimeDir)
	logPath := filepath.Join(t.TempDir(), "caddy.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	cmd.Stdout, cmd.Stderr = logFile, logFile
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			log, _ := os.ReadFile(logPath)
			t.Log(string(log))
		}
	}()
	rootPath := filepath.Join(o.DataDir, "caddy", "pki", "authorities", "local", "root.crt")
	roots := x509.NewCertPool()
	for {
		if pem, err := os.ReadFile(rootPath); err == nil && roots.AppendCertsFromPEM(pem) {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("Caddy did not create the test CA")
		case <-time.After(20 * time.Millisecond):
		}
	}

	for _, tc := range []struct {
		name, source, cfIP string
		public             bool
		visitor            []string
	}{
		{"edge IPv4 reports visitor IPv6", "127.0.0.3", "2001:db8::1", true, []string{"2001:db8::1"}},
		{"direct ignores both forged headers", "127.0.0.2", "", true, []string{"198.51.100.1"}},
		{"local panel ignores edge headers", "127.0.0.3", "", false, []string{"198.51.100.1"}},
		{"edge with absent visitor cannot inject internal header", "127.0.0.3", "", true, nil},
		{"repeated visitor values reach Go as a list", "127.0.0.3", "198.51.100.1,203.0.113.1", true, []string{"198.51.100.1", "203.0.113.1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialer := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(tc.source)}}
			tr := &http.Transport{DialContext: dialer.DialContext,
				TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: o.PanelDomain}}
			defer tr.CloseIdleConnections()
			client := &http.Client{Transport: tr, Timeout: time.Second}
			url := "http://" + o.PanelListen
			if tc.public {
				url = "https://" + httpsAddress
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Host = o.PanelDomain
			for _, value := range tc.visitor {
				req.Header.Add("CF-Connecting-IP", value)
			}
			req.Header.Set(PanelPeerIPHeader, "203.0.113.1")
			req.Header.Set(PanelCloudflareIPHeader, "203.0.113.2")
			req.Header.Set("X-Forwarded-For", "203.0.113.3")
			var res *http.Response
			for {
				res, err = client.Do(req)
				if err == nil {
					break
				}
				select {
				case <-ctx.Done():
					t.Fatal(err)
				case <-time.After(20 * time.Millisecond):
				}
			}
			defer res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("unexpected response: %s", res.Status)
			}
			var got http.Header
			if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
				t.Fatal(err)
			}
			if peer, visitor := got.Get(PanelPeerIPHeader), got.Get(PanelCloudflareIPHeader); peer != tc.source || visitor != tc.cfIP {
				t.Fatalf("peer and visitor = (%q, %q), want (%q, %q)", peer, visitor, tc.source, tc.cfIP)
			}
		})
	}
}
