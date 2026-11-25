package trust

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
)

func TestClient(t *testing.T) {
	r, err := New(Config{Enabled: true, TrustedProxies: []string{"192.0.2.0/24", "2001:db8:1::1"}})
	if err != nil {
		t.Fatal(err)
	}
	s := r.Snapshot()
	s.IPv4 = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	r.current.Store(&s)

	for _, tc := range []struct {
		name, peer, address, reason string
		header                      http.Header
		cf                          bool
	}{
		{"untrusted spoof", "198.51.100.1", "198.51.100.1", "untrusted_peer", http.Header{"X-Forwarded-For": {"203.0.113.1"}, "CF-Connecting-IP": {"198.51.100.2"}}, false},
		{"direct Cloudflare", "::ffff:203.0.113.1", "198.51.100.2", "cf_connecting_ip", http.Header{"CF-Connecting-IP": {"198.51.100.2"}}, true},
		{"direct Cloudflare missing", "203.0.113.1", "203.0.113.1", "cf_connecting_ip_missing", http.Header{"X-Forwarded-For": {"198.51.100.2"}}, true},
		{"direct Cloudflare malformed", "203.0.113.1", "203.0.113.1", "cf_connecting_ip_invalid", http.Header{"CF-Connecting-IP": {"198.51.100.2, 198.51.100.3"}}, true},
		{"duplicate Cloudflare header", "203.0.113.1", "203.0.113.1", "cf_connecting_ip_invalid", http.Header{"CF-Connecting-IP": {"198.51.100.2"}, "Cf-Connecting-Ip": {"198.51.100.3"}}, true},
		{"trusted chain to Cloudflare", "192.0.2.1", "198.51.100.2", "cf_connecting_ip", http.Header{"X-Forwarded-For": {"198.51.100.2, 203.0.113.1, 2001:db8:1::1"}, "CF-Connecting-IP": {"198.51.100.2"}}, true},
		{"trusted chain missing Cloudflare client", "192.0.2.1", "192.0.2.1", "cf_connecting_ip_missing", http.Header{"X-Forwarded-For": {"203.0.113.1"}}, true},
		{"spoof beyond untrusted hop", "192.0.2.1", "198.51.100.1", "xff", http.Header{"X-Forwarded-For": {"203.0.113.1, 198.51.100.1, 192.0.2.2"}, "CF-Connecting-IP": {"198.51.100.2"}}, false},
		{"duplicate XFF", "192.0.2.1", "192.0.2.1", "xff_invalid", http.Header{"X-Forwarded-For": {"203.0.113.1", "198.51.100.1"}}, false},
		{"malformed XFF", "192.0.2.1", "192.0.2.1", "xff_invalid", http.Header{"X-Forwarded-For": {"garbage, 203.0.113.1"}}, false},
		{"oversize XFF", "192.0.2.1", "192.0.2.1", "xff_invalid", http.Header{"X-Forwarded-For": {strings.Repeat(" ", maxXFFBytes) + "203.0.113.1"}}, false},
		{"too many hops", "192.0.2.1", "192.0.2.1", "xff_invalid", http.Header{"X-Forwarded-For": {strings.Repeat("192.0.2.2, ", maxXFFHops) + "203.0.113.1"}}, false},
		{"trusted hops only", "192.0.2.1", "192.0.2.1", "xff_no_untrusted_hop", http.Header{"X-Forwarded-For": {"192.0.2.2"}}, false},
		{"missing XFF", "192.0.2.1", "192.0.2.1", "xff_missing", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := r.Client(netip.MustParseAddr(tc.peer), tc.header)
			want := Identity{Address: netip.MustParseAddr(tc.address), Reason: tc.reason, Cloudflare: tc.cf}
			if got != want {
				t.Fatalf("Client = %+v, want %+v", got, want)
			}
		})
	}
}

func TestRefreshRetainsCompletePair(t *testing.T) {
	var phase atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/v4":
			if phase.Load() == 0 {
				w.Write([]byte("203.0.113.0/24\n"))
			} else {
				w.Write([]byte("198.51.100.0/24\n"))
			}
		case "/v6":
			switch phase.Load() {
			case 1:
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
			case 2:
				w.Write([]byte("203.0.113.0/24\n"))
			case 3:
				w.Write([]byte(strings.Repeat(" ", maxListBytes+1)))
			case 4:
				w.Write([]byte(strings.Repeat("2001:db8::/32\n", maxNetworks+1)))
			case 5:
				http.Redirect(w, req, "http://example.invalid/list", http.StatusFound)
			default:
				w.Write([]byte("2001:db8::/32\n"))
			}
		}
	}))
	defer srv.Close()
	cfg := Config{Enabled: true, IPv4URL: srv.URL + "/v4", IPv6URL: srv.URL + "/v6"}
	r, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.client.Transport = srv.Client().Transport
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	first := r.Snapshot()
	if len(first.IPv4) != 1 || len(first.IPv6) != 1 || first.UpdatedAt.IsZero() || first.ConfiguredIPv4URL != cfg.IPv4URL || first.EffectiveIPv6URL != cfg.IPv6URL {
		t.Fatalf("unexpected initial snapshot: %+v", first)
	}
	for i := int32(1); i <= 5; i++ {
		phase.Store(i)
		if err := r.Refresh(context.Background()); err == nil {
			t.Fatalf("phase %d unexpectedly succeeded", i)
		}
		got := r.Snapshot()
		if got.Error == "" {
			t.Fatalf("phase %d failed to expose error", i)
		}
		got.Error = ""
		if !reflect.DeepEqual(first, got) {
			t.Fatalf("phase %d changed last complete snapshot: %+v", i, got)
		}
	}
	phase.Store(6)
	if err := r.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := r.Snapshot()
	if got.Error != "" || got.IPv4[0] != netip.MustParsePrefix("198.51.100.0/24") {
		t.Fatalf("unexpected recovered snapshot: %+v", got)
	}
	got.IPv4[0] = netip.Prefix{}
	if !r.Snapshot().IPv4[0].IsValid() {
		t.Fatal("snapshot exposes mutable resolver data")
	}
}

func TestConfig(t *testing.T) {
	r, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	s := r.Snapshot()
	if s.ConfiguredIPv4URL != "" || s.ConfiguredIPv6URL != "" || s.EffectiveIPv4URL != defaultIPv4URL || s.EffectiveIPv6URL != defaultIPv6URL {
		t.Fatalf("unexpected default URLs: %+v", s)
	}
	for _, cfg := range []Config{
		{IPv4URL: "http://example.com/list"},
		{IPv6URL: "https:///list"},
		{TrustedProxies: []string{"localhost"}},
	} {
		if cfg.Validate() == nil {
			t.Errorf("accepted invalid config %+v", cfg)
		}
	}
}
