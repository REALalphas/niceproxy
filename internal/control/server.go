package control

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/bcrypt"
	"niceproxy/internal/bridge"
	"niceproxy/internal/caddy"
	"niceproxy/internal/cloudflare"
	"niceproxy/internal/ddos"
	"niceproxy/internal/ddos/trust"
	"niceproxy/internal/model"
	"niceproxy/internal/proxy"
	"niceproxy/internal/store"
)

type Caddy interface {
	Apply(context.Context, []model.HTTPRoute) error
	Healthy(context.Context) bool
}

type certificateReporter interface {
	CertificateStatus(context.Context, string) model.CertificateStatus
}

type App struct {
	mu                     sync.Mutex
	db                     *store.Store
	caddy                  Caddy
	proxy                  *proxy.Manager
	config                 model.Config
	applied                int64
	active                 map[string]model.DirectRule
	httpActive             []model.HTTPRoute
	activeProtection       ddos.Config
	httpOwners             model.PortOwners
	activePanelDomain      string
	activePanelProxied     bool
	activePanelDNSObserved bool
	panelEdge              panelEdgeStatus
	panelEdgeWake          chan struct{}
	caddyUnconfirmed       bool
	httpPort, httpsPort    int
	ruleErrors             map[string]string
	httpError, applyError  string
	state                  string
	startupError           string
	reserved               map[int]bool
	authMu                 sync.Mutex
	authWindow             time.Time
	authAttempts           int
	authByClient           map[string]authBucket
	cfMu                   sync.Mutex
	cf                     *cloudflare.Manager
	cfOptions              cloudflare.Options
	cfDefaultRedirect      string
	cfInitError            string
	cfCallbackHost         atomic.Value // explicit trusted callback host; never learned from a request
	cfHTTPSCallback        atomic.Bool
	trustResolver          *trust.Resolver
	bridgeToken            string
}

const systemPanelRouteID = "system-panel-domain"

type authBucket struct {
	window   time.Time
	attempts int
}

func New(db *store.Store, c Caddy, p *proxy.Manager, reserved map[int]bool) (*App, error) {
	cfg, persistedApplied, err := db.Load()
	if err != nil {
		return nil, err
	}
	if cfg.HTTPRoutes == nil {
		cfg.HTTPRoutes = []model.HTTPRoute{}
	}
	if cfg.DirectRules == nil {
		cfg.DirectRules = []model.DirectRule{}
	}
	cfg.ApplyDefaults()
	if err := validateAntiDDoS(cfg); err != nil {
		return nil, err
	}
	reservedCopy := map[int]bool{}
	for port, value := range reserved {
		reservedCopy[port] = value
	}
	hp, sp := 80, 443
	if ports, ok := c.(interface{ PublicPorts() (int, int) }); ok {
		hp, sp = ports.PublicPorts()
	}
	delete(reservedCopy, hp)
	delete(reservedCopy, sp)
	resolver, resolverErr := newTrustResolver(cfg.AntiDDoS)
	if resolverErr != nil {
		return nil, resolverErr
	}
	a := &App{httpPort: hp, httpsPort: sp, db: db, caddy: c, proxy: p, config: cfg, applied: persistedApplied, active: map[string]model.DirectRule{}, ruleErrors: map[string]string{}, reserved: reservedCopy, authByClient: map[string]authBucket{}, state: "ready", panelEdgeWake: make(chan struct{}, 1), trustResolver: resolver}
	if err := a.panelDomainConflict(cfg); err != nil {
		a.startupError = err.Error()
		a.state = "unrecoverable_corruption"
		a.applied = -1
	}
	good, err := db.LastGood()
	if err != nil {
		return nil, err
	}
	a.setCaddyActive(good)
	if cfg.PanelDomain != "" && cfg.PanelDomain == good.PanelDomain && good.PanelDNSObserved {
		mode := "dns_only"
		if good.PanelDomainProxied {
			mode = "proxied"
		}
		a.panelEdge = panelEdgeStatus{Domain: cfg.PanelDomain, DNSMode: mode, State: "checking_tls"}
	}
	for _, r := range good.DirectRules {
		if !r.Enabled {
			continue
		}
		_, e := p.AddProtected(r.ID, proxy.Rule{Protocol: r.Protocol, ListenAddress: r.ListenHost, ListenPort: r.ListenPort, TargetAddress: r.TargetHost, TargetPort: r.TargetPort}, &proxy.ProtectionConfig{Version: good.Revision, Listener: good.AntiDDoS.Listener, Endpoint: good.AntiDDoS.Endpoints[r.ID]})
		if e == nil {
			a.active[r.ID] = r
		}
	}
	return a, nil
}

func (a *App) SetBridgeToken(token string) { a.mu.Lock(); a.bridgeToken = token; a.mu.Unlock() }

func (a *App) RunProtection(ctx context.Context) {
	go a.proxy.Defense().Run(ctx)
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		a.mu.Lock()
		resolver := a.trustResolver
		a.mu.Unlock()
		if resolver != nil {
			_ = resolver.Refresh(ctx) // the resolver retains its last complete pair
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func validateAntiDDoS(c model.Config) error {
	if err := c.AntiDDoS.Listener.Validate(ddos.Listener); err != nil {
		return fmt.Errorf("listener protection: %w", err)
	}
	known := make(map[string]string, len(c.HTTPRoutes)+len(c.DirectRules))
	for _, r := range c.DirectRules {
		if r.Protocol == "tcp" {
			known[r.ID] = ddos.TCP
		} else if r.Protocol == "udp" {
			known[r.ID] = ddos.UDP
		}
	}
	for _, r := range c.HTTPRoutes {
		kind := ddos.HTTP
		if strings.HasPrefix(strings.ToLower(r.Target), "tcp://") {
			kind = ddos.HTTPTCP
		}
		if strings.HasPrefix(strings.ToLower(r.Target), "udp://") {
			kind = ddos.HTTPUDP
		}
		known[r.ID] = kind
	}
	for id, p := range c.AntiDDoS.Endpoints {
		kind, ok := known[id]
		if !ok {
			return fmt.Errorf("anti-DDoS endpoint %q is not configured", id)
		}
		if err := p.Validate(kind); err != nil {
			return fmt.Errorf("endpoint %s protection: %w", id, err)
		}
		for _, route := range c.HTTPRoutes {
			if route.ID == id && p.CloudflareOnly && route.TLS == "off" {
				return fmt.Errorf("endpoint %s Cloudflare-only protection requires TLS", id)
			}
		}
		if p.CloudflareOnly && (c.AntiDDoS.Cloudflare == nil || !c.AntiDDoS.Cloudflare.Enabled) {
			return fmt.Errorf("endpoint %s Cloudflare-only protection requires enabled Cloudflare network refresh", id)
		}
	}
	if c.AntiDDoS.Cloudflare != nil {
		if err := c.AntiDDoS.Cloudflare.Validate(); err != nil {
			return fmt.Errorf("Cloudflare trust: %w", err)
		}
	}
	cloudflareHosts := map[string]bool{}
	cloudflareCAs := map[string]string{}
	for _, route := range c.HTTPRoutes {
		policy := c.AntiDDoS.Endpoints[route.ID]
		if policy == nil || !policy.CloudflareOnly {
			continue
		}
		host := strings.ToLower(strings.TrimSuffix(route.Host, "."))
		if previous, ok := cloudflareHosts[host]; ok && !previous {
			return fmt.Errorf("Cloudflare-only protection must cover every path of host %s", host)
		}
		cloudflareHosts[host] = true
		if ca, ok := cloudflareCAs[host]; ok && ca != policy.OriginPullCA {
			return fmt.Errorf("Cloudflare Origin Pull CA must be identical for every path of host %s", host)
		}
		cloudflareCAs[host] = policy.OriginPullCA
		for _, other := range c.HTTPRoutes {
			if other.ID == route.ID || !strings.EqualFold(strings.TrimSuffix(other.Host, "."), host) {
				continue
			}
			otherPolicy := c.AntiDDoS.Endpoints[other.ID]
			if otherPolicy == nil || !otherPolicy.CloudflareOnly {
				return fmt.Errorf("Cloudflare-only protection must cover every path of host %s", host)
			}
		}
	}
	return nil
}

func newTrustResolver(cfg ddos.Config) (*trust.Resolver, error) {
	trustConfig := trust.Config{TrustedProxies: []string{"127.0.0.1/32", "::1/128"}}
	if cfg.Cloudflare != nil {
		trustConfig = *cfg.Cloudflare
		trustConfig.TrustedProxies = append(trustConfig.TrustedProxies, "127.0.0.1/32", "::1/128")
	}
	return trust.New(trustConfig)
}

func (a *App) Reconcile(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.reconcile(ctx)
}

func (a *App) antiDDoSStatus() map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	status := map[string]any{"revision": a.config.Revision, "appliedRevision": a.applied, "status": "active", "instances": []any{}}
	if a.applied < 0 || a.applied != a.config.Revision {
		status["status"] = "partial"
	}
	if a.applied >= 0 && a.applied != a.config.Revision {
		status["status"] = "applying"
	}
	targets := make([]any, 0)
	for _, s := range a.proxy.Defense().Snapshots() {
		targets = append(targets, s)
	}
	instance := map[string]any{"id": "local", "version": a.applied, "targets": targets}
	if a.trustResolver != nil {
		s := a.trustResolver.Snapshot()
		networks := make([]string, 0, len(s.IPv4)+len(s.IPv6))
		for _, n := range append(s.IPv4, s.IPv6...) {
			networks = append(networks, n.String())
		}
		cloudflareStatus := map[string]any{"networks": networks, "ipv4URL": s.EffectiveIPv4URL, "ipv6URL": s.EffectiveIPv6URL}
		if !s.UpdatedAt.IsZero() {
			cloudflareStatus["updatedAt"] = s.UpdatedAt
		}
		if s.Error != "" {
			cloudflareStatus["error"] = s.Error
		}
		instance["cloudflare"] = cloudflareStatus
	}
	status["instances"] = []any{instance}
	return status
}

// SetCaddyActive records the public configuration loaded during startup.
func (a *App) SetCaddyActive(cfg model.Config) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.setCaddyActive(cfg)
}

func (a *App) setCaddyActive(cfg model.Config) {
	a.httpActive = append([]model.HTTPRoute{}, cfg.HTTPRoutes...)
	a.activeProtection = cfg.AntiDDoS
	a.httpOwners = cfg.PortOwners
	a.activePanelDomain = cfg.PanelDomain
	a.activePanelProxied = cfg.PanelDomainProxied
	a.activePanelDNSObserved = cfg.PanelDNSObserved
}

// ConfigurePanelDomain applies the deployment-provided initial domain only
// when no domain has been persisted yet. Subsequent changes go through the
// authenticated /api/panel-domain endpoint so every path uses one reconciler.
func (a *App) ConfigurePanelDomain(domain string) error {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if domain == "" {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.config.PanelDomain != "" {
		return nil
	}
	if err := validatePanelDomain(domain); err != nil {
		return err
	}
	c := a.config
	c.PanelDomain = domain
	if err := a.commit(context.Background(), c); err != nil {
		a.startupError = err.Error()
		a.state = "unrecoverable_corruption"
		a.applyError = err.Error()
		return err
	}
	return nil
}
func (a *App) reconcile(ctx context.Context) error {
	caddyConfig := a.effectiveCaddyConfig()
	var errs []error
	a.ruleErrors = map[string]string{}
	if a.startupError != "" {
		a.applyError = a.startupError
		a.state = "unrecoverable_corruption"
		a.applied = -1
		return errors.New(a.startupError)
	}
	if v, ok := a.caddy.(interface{ ValidateConfig(model.Config) error }); ok {
		if err := v.ValidateConfig(caddyConfig); err != nil {
			a.httpError = err.Error()
			a.applyError = err.Error()
			a.applied = -1
			a.state = classifyState(err.Error())
			return err
		}
	}
	wanted := map[string]bool{}
	for _, r := range a.config.DirectRules {
		if r.Enabled {
			wanted[r.ID] = true
		}
	}
	for id, old := range a.active {
		if !a.proxy.HasListener(id) {
			delete(a.active, id)
			continue
		}
		if !wanted[id] || a.ownershipConflict(model.Config{PortOwners: a.config.PortOwners, DirectRules: []model.DirectRule{old}}) != nil {
			if err := a.retire(id); err != nil {
				a.ruleErrors[id] = err.Error()
				errs = append(errs, err)
			} else {
				delete(a.active, id)
			}
		}
	}
	a.httpError = ""
	caddyApplied := true
	if a.caddyUnconfirmed || a.httpOwners != a.config.PortOwners ||
		a.activePanelDomain != caddyConfig.PanelDomain || a.activePanelProxied != caddyConfig.PanelDomainProxied ||
		a.activePanelDNSObserved != caddyConfig.PanelDNSObserved ||
		!reflect.DeepEqual(a.httpActive, a.config.HTTPRoutes) || !reflect.DeepEqual(a.activeProtection, caddyConfig.AntiDDoS) || !a.caddy.Healthy(ctx) {
		if err := a.applyCaddy(ctx, caddyConfig); err != nil {
			caddyApplied = false
			// An admin request can fail after Caddy changed its listeners.
			// Even reverting to the prior desired config needs a confirmed load.
			a.caddyUnconfirmed = true
			a.httpError = err.Error()
			errs = append(errs, fmt.Errorf("Caddy: %w", err))
		} else {
			a.caddyUnconfirmed = false
			a.setCaddyActive(caddyConfig)
			a.activeProtection = caddyConfig.AntiDDoS
		}
	}
	for _, r := range a.config.DirectRules {
		if !r.Enabled {
			continue
		}
		pr := proxy.Rule{Protocol: r.Protocol, ListenAddress: r.ListenHost, ListenPort: r.ListenPort, TargetAddress: r.TargetHost, TargetPort: r.TargetPort}
		protection := &proxy.ProtectionConfig{Version: a.config.Revision, Listener: a.config.AntiDDoS.Listener, Endpoint: a.config.AntiDDoS.Endpoints[r.ID]}
		previous, exists := a.active[r.ID]
		if exists && !a.proxy.HasListener(r.ID) {
			// A replacement and its rollback may both fail to bind.
			delete(a.active, r.ID)
			exists = false
		}
		if exists && reflect.DeepEqual(previous, r) && a.applied == a.config.Revision {
			continue
		}
		var err error
		if exists {
			drain, cancel := context.WithTimeout(ctx, time.Second)
			_, e := a.proxy.UpdateProtected(drain, r.ID, pr, protection)
			cancel()
			err = e
		} else {
			_, err = a.proxy.AddProtected(r.ID, pr, protection)
		}
		if err != nil {
			if !a.proxy.HasListener(r.ID) {
				delete(a.active, r.ID)
			}
			a.ruleErrors[r.ID] = err.Error()
			errs = append(errs, fmt.Errorf("%s: %w", r.ID, err))
		} else {
			a.active[r.ID] = r
		}
	}
	httpProtection := make([]proxy.HTTPProtectionConfig, 0, len(a.config.HTTPRoutes))
	for _, r := range a.config.HTTPRoutes {
		if !r.Enabled {
			continue
		}
		network := ddos.HTTP
		switch strings.ToLower(strings.SplitN(r.Target, "://", 2)[0]) {
		case "tcp":
			network = ddos.HTTPTCP
		case "udp":
			network = ddos.HTTPUDP
		}
		httpProtection = append(httpProtection, proxy.HTTPProtectionConfig{ID: r.ID, Label: r.Host + r.Path, Network: network, Version: a.config.Revision, Listener: a.config.AntiDDoS.Listener, Endpoint: a.config.AntiDDoS.Endpoints[r.ID]})
	}
	a.proxy.SetGlobalProtection(a.config.AntiDDoS.Listener, a.config.Revision)
	if caddyApplied {
		a.proxy.SetHTTPProtection(httpProtection)
	} else {
		a.proxy.SetHTTPProtection(nil)
	}
	a.proxy.PublishProtection()
	if len(errs) == 0 {
		if err := a.db.MarkApplied(caddyConfig); err != nil {
			errs = append(errs, err)
		} else {
			a.applied = a.config.Revision
			a.state = "ready"
		}
	}
	err := errors.Join(errs...)
	a.applyError = ""
	if err != nil {
		// Several subsystems may already have changed. No single revision can
		// truthfully describe a mixed runtime state.
		a.applied = -1
		a.applyError = err.Error()
		a.state = classifyState(err.Error())
	}
	return err
}

func (a *App) snapshot() model.Config {
	c := a.config
	c.HTTPRoutes = append([]model.HTTPRoute{}, c.HTTPRoutes...)
	c.DirectRules = append([]model.DirectRule{}, c.DirectRules...)
	for i := range c.HTTPRoutes {
		r := &c.HTTPRoutes[i]
		r.Status = "unknown"
		if r.Enabled {
			if a.httpError != "" {
				r.Status = "error"
				r.Error = a.httpError
			} else {
				r.Status = "healthy"
			}
		}
	}
	for i := range c.DirectRules {
		r := &c.DirectRules[i]
		r.Stats = nil
		if stats, ok := a.proxy.Stats(r.ID); ok {
			r.Stats = &model.ConnectionStats{Accepted: stats.Accepted, Active: stats.Active, Closed: stats.Closed, Errors: stats.Errors, Rejects: stats.Rejects, StartedAt: stats.StartedAt.UTC().Format(time.RFC3339Nano)}
		}
		r.Status = "unknown"
		if msg := a.ruleErrors[r.ID]; msg != "" {
			r.Status = "error"
			r.Error = msg
			continue
		}
		if r.Enabled {
			if _, ok := a.active[r.ID]; ok {
				r.Status = "healthy"
			}
		}
	}
	if c.PanelDomain != "" {
		certificate := a.certificateState()
		route := model.HTTPRoute{
			ID:            systemPanelRouteID,
			Host:          c.PanelDomain,
			Path:          "/",
			Target:        "management panel",
			TLS:           "auto",
			Enabled:       true,
			SystemManaged: true,
			Status:        "healthy",
		}
		if certificate != "valid" && certificate != "unknown" {
			route.Status = panelCertificateLifecycle(certificate)
			route.Error = panelCertificateDiagnostic(c.PanelDomain, certificate, a.effectiveCaddyConfig().PanelDomainProxied)
		}
		if a.panelEdge.Domain == c.PanelDomain {
			switch a.panelEdge.State {
			case "waiting_dns":
				route.Status, route.Error = "waiting_dns", a.panelEdge.Detail
			case "waiting_origin", "waiting_access", "waiting_edge":
				if a.panelEdge.DNSMode == "proxied" {
					route.Error = a.panelEdge.Detail
					if route.Status == "healthy" {
						route.Status = "error"
					}
				}
			}
		}
		c.HTTPRoutes = append([]model.HTTPRoute{route}, c.HTTPRoutes...)
	}
	return c
}

func panelCertificateLifecycle(certificate string) string {
	switch certificate {
	case "bootstrap", "missing", "not_yet_issued":
		return "waiting_acme"
	default:
		return "invalid_certificate"
	}
}

func panelCertificateDiagnostic(domain, certificate string, proxied bool) string {
	if certificate == "valid" {
		return ""
	}
	if certificate == "expired" || certificate == "wrong_host" || certificate == "invalid" {
		return fmt.Sprintf("Origin certificate for %q is %s. Check the hostname, expiry, private key and issuer. Apply the corrected certificate and restart niceproxy.", domain, certificate)
	}
	if certificate == "bootstrap" {
		return fmt.Sprintf("Caddy has a local TLS certificate for %q. Configure Cloudflare API access for managed Origin CA issuance, or mount a trusted certificate for Full (strict). For DNS Only, verify public TCP 80 or 443 forwarding for ACME.", domain)
	}
	if proxied {
		return fmt.Sprintf("Trusted origin certificate for %q is pending. Configure Cloudflare API access for Origin CA issuance, or mount a certificate that Cloudflare trusts.", domain)
	}
	return fmt.Sprintf("Public certificate for %q is pending. Verify that public DNS points to this origin, that TCP 80 reaches Caddy for HTTP-01 or TCP 443 for TLS-ALPN-01, and that the proxy is DNS-only during ACME validation.", domain)
}

func (a *App) Handler(static http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		a.mu.Lock()
		state := a.state
		applyError := a.applyError
		a.mu.Unlock()
		if !a.caddy.Healthy(ctx) || applyError != "" || state != "ready" {
			message := applyError
			if message == "" {
				message = "niceproxy state: " + state
			}
			fail(w, 503, message)
			return
		}
		write(w, 200, map[string]any{"ok": true, "state": state})
	})
	mux.HandleFunc("/api/", a.api)
	mux.Handle("/", static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		// Alpha UI sets icon URLs and motion variables on style attributes.
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; style-src-attr 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
		a.mu.Lock()
		bridgeToken := a.bridgeToken
		a.mu.Unlock()
		if routeID := r.Header.Get("X-Niceproxy-Bridge-Route"); routeID != "" && bridgeToken != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Niceproxy-Bridge-Token")), []byte(bridgeToken)) == 1 && r.Header.Get("X-Niceproxy-Forwarded-By") == "niceproxy-caddy" {
			a.mu.Lock()
			var route *model.HTTPRoute
			for i := range a.httpActive {
				if a.httpActive[i].ID == routeID && a.httpActive[i].Enabled {
					route = &a.httpActive[i]
					break
				}
			}
			var target string
			if route != nil {
				target = route.Target
			}
			a.mu.Unlock()
			if route == nil {
				fail(w, 404, "bridge route not found")
				return
			}
			u, err := url.Parse(target)
			if err != nil {
				fail(w, 502, "invalid bridge target")
				return
			}
			p := a.proxy.HTTPProtection(routeID)
			peer := netip.Addr{}
			if marker := strings.TrimSpace(r.Header.Get("X-Niceproxy-Client-IP")); marker != "" {
				peer, _ = netip.ParseAddr(marker)
			}
			if !peer.IsValid() {
				fail(w, http.StatusBadGateway, "Caddy did not provide a valid client address")
				return
			}
			cloudflarePeer := false
			a.mu.Lock()
			resolver := a.trustResolver
			a.mu.Unlock()
			if resolver != nil && peer.IsValid() {
				identity := resolver.Client(peer, r.Header)
				peer, cloudflarePeer = identity.Address, identity.Cloudflare
			}
			if p.Endpoint.CloudflareOnly() && !cloudflarePeer {
				fail(w, http.StatusForbidden, "route requires a verified Cloudflare source")
				return
			}
			var bridgeErr error
			if u.Scheme == "http" || u.Scheme == "https" {
				bridgeErr = bridge.HandleHTTP(w, r, target, p.Listener, p.Endpoint, peer)
			} else {
				bridgeErr = bridge.HandleWithListener(w, r, bridge.Config{Network: u.Scheme, Address: u.Host}, p.Listener, p.Endpoint, peer)
			}
			if err := bridgeErr; err != nil {
				status := http.StatusBadGateway
				if errors.Is(err, bridge.ErrBodyTooLarge) {
					status = http.StatusRequestEntityTooLarge
				}
				if errors.Is(err, bridge.ErrQuota) {
					status = http.StatusTooManyRequests
				}
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					status = http.StatusGatewayTimeout
				}
				fail(w, status, err.Error())
			}
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		mux.ServeHTTP(w, r)
	})
}

func (a *App) authenticated(r *http.Request) bool {
	c, err := r.Cookie("niceproxy_session")
	return err == nil && a.db.Authenticated(hash(c.Value))
}
func hash(s string) string { d := sha256.Sum256([]byte(s)); return hex.EncodeToString(d[:]) }

func (a *App) certificateStatus(ctx context.Context) model.CertificateStatus {
	a.mu.Lock()
	domain := a.config.PanelDomain
	a.mu.Unlock()
	if domain == "" {
		a.cfMu.Lock()
		u, err := url.Parse(a.cfOptions.RedirectURL)
		a.cfMu.Unlock()
		if err != nil || u.Scheme != "https" || u.Hostname() == "" {
			return model.CertificateStatus{State: "not_configured", Error: "HTTPS domain is not configured"}
		}
		domain = u.Hostname()
	}
	if reader, ok := a.caddy.(certificateReporter); ok {
		return reader.CertificateStatus(ctx, domain)
	}
	return model.CertificateStatus{Configured: true, Domain: domain, State: "unknown", Error: "Caddy certificate status is unavailable"}
}

func randomID() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func (a *App) api(w http.ResponseWriter, r *http.Request) {
	// The panel is configured on an IP listener. Reject arbitrary DNS Host
	// headers so a browser cannot rebind an attacker's domain onto loopback.
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	a.mu.Lock()
	panelDomain := a.config.PanelDomain
	a.mu.Unlock()
	callbackHost := ""
	if value := a.cfCallbackHost.Load(); value != nil {
		callbackHost, _ = value.(string)
	}
	if net.ParseIP(host) == nil && host != "localhost" && !strings.EqualFold(host, panelDomain) && !strings.EqualFold(r.Host, callbackHost) {
		fail(w, 403, "management API requires an IP address or localhost host")
		return
	}
	if r.Method != "GET" {
		if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			fail(w, 403, "cross-site request rejected")
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			u, err := url.Parse(origin)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host != r.Host {
				fail(w, 403, "origin mismatch")
				return
			}
		}
	}
	if r.URL.Path == "/api/auth" && r.Method == "GET" {
		password, err := a.db.Password()
		if err != nil {
			fail(w, 500, "cannot read authentication state")
			return
		}
		write(w, 200, map[string]bool{"configured": len(password) > 0, "authenticated": a.authenticated(r)})
		return
	}
	if r.URL.Path == "/api/setup" || r.URL.Path == "/api/login" {
		a.login(w, r)
		return
	}
	// Cross-site OAuth GET returns without our SameSite=Strict admin cookie.
	// The callback instead validates a one-time Lax cookie and the session
	// that started the flow; it never creates an app login session.
	if r.URL.Path == "/api/cloudflare/callback" {
		a.cloudflareCallback(w, r)
		return
	}
	if !a.authenticated(r) {
		fail(w, 401, "authentication required")
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/cloudflare") {
		a.cloudflareAPI(w, r)
		return
	}
	if r.URL.Path == "/api/logout" && r.Method == "POST" {
		c, _ := r.Cookie("niceproxy_session")
		_ = a.db.Logout(hash(c.Value))
		http.SetCookie(w, &http.Cookie{Name: "niceproxy_session", Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		write(w, 200, map[string]bool{"ok": true})
		return
	}
	if r.URL.Path == "/api/certificate" && r.Method == "GET" {
		write(w, 200, a.certificateStatus(r.Context()))
		return
	}
	if (r.URL.Path == "/api/anti-ddos" || r.URL.Path == "/api/metrics") && r.Method == "GET" {
		write(w, 200, a.antiDDoSStatus())
		return
	}
	if r.URL.Path == "/api/anti-ddos" && r.Method == "PATCH" {
		var request struct {
			Listener   *ddos.Policy            `json:"listener"`
			Endpoints  map[string]*ddos.Policy `json:"endpoints"`
			Cloudflare *trust.Config           `json:"cloudflare"`
			Revision   int64                   `json:"revision"`
		}
		if err := decode(w, r, &request); err != nil {
			fail(w, 400, err.Error())
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if request.Revision != 0 && request.Revision != a.config.Revision {
			fail(w, 409, "configuration revision changed")
			return
		}
		c := a.config
		c.AntiDDoS = ddos.Config{Listener: request.Listener, Endpoints: request.Endpoints, Cloudflare: request.Cloudflare}
		if err := a.commit(r.Context(), c); err != nil {
			mutationFail(w, err)
			return
		}
		write(w, 200, a.snapshot())
		return
	}
	if r.URL.Path == "/api/anti-ddos/clear" && r.Method == "POST" {
		var request struct {
			Instance, Target, Rule, Subject string
			TTLSeconds                      int `json:"ttlSeconds"`
		}
		if err := decode(w, r, &request); err != nil {
			fail(w, 400, err.Error())
			return
		}
		if request.Instance != "" && request.Instance != "local" {
			fail(w, 400, "unknown instance")
			return
		}
		if request.TTLSeconds < 1 || request.TTLSeconds > 86400 {
			fail(w, 400, "ttlSeconds must be between 1 and 86400")
			return
		}
		b := a.proxy.Defense().Binding(request.Target)
		if b == nil {
			fail(w, 404, "protection target not found")
			return
		}
		_ = b.Clear(request.Rule, request.Subject, "admin", time.Duration(request.TTLSeconds)*time.Second)
		write(w, 200, map[string]bool{"ok": true})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if r.URL.Path == "/api/port-owners" {
		a.portOwners(w, r)
		return
	}
	if r.URL.Path == "/api/config" && r.Method == "GET" {
		write(w, 200, a.snapshot())
		return
	}
	if r.URL.Path == "/api/health" && r.Method == "GET" {
		ctx, cancel := context.WithTimeout(r.Context(), time.Second)
		defer cancel()
		ok := a.caddy.Healthy(ctx)
		state := a.state
		certificate := a.certificateState()
		healthError := a.applyError
		if a.config.PanelDomain != "" && certificate != "valid" && certificate != "unknown" && a.applyError == "" {
			state = panelCertificateLifecycle(certificate)
			healthError = panelCertificateDiagnostic(a.config.PanelDomain, certificate, a.effectiveCaddyConfig().PanelDomainProxied)
		}
		status := "healthy"
		if !ok || a.applyError != "" || state != "ready" {
			status = "error"
		}
		if state == "" {
			state = "ready"
		}
		write(w, 200, model.Health{Status: status, State: state, Caddy: ok, Revision: a.config.Revision, AppliedRevision: a.applied, Error: healthError, PanelDomain: a.config.PanelDomain, Certificate: certificate})
		return
	}
	if r.URL.Path == "/api/panel-domain" {
		a.panelDomainAPI(w, r)
		return
	}
	if r.URL.Path == "/api/reconcile" && r.Method == "POST" {
		_ = a.reconcile(r.Context())
		a.queuePanelAutomation()
		write(w, 200, a.snapshot())
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/direct-rules") {
		a.direct(w, r)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/api/http-routes") {
		a.httpRoute(w, r)
		return
	}
	fail(w, 404, "endpoint not found")
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		fail(w, 405, "POST required")
		return
	}
	a.authMu.Lock()
	defer a.authMu.Unlock()
	if time.Since(a.authWindow) > time.Minute {
		a.authWindow = time.Now()
		a.authAttempts = 0
		for key, bucket := range a.authByClient {
			if time.Since(bucket.window) > time.Minute {
				delete(a.authByClient, key)
			}
		}
	}
	password, err := a.db.Password()
	if err != nil {
		fail(w, 500, "cannot read password")
		return
	}
	if r.URL.Path == "/api/setup" && len(password) > 0 {
		fail(w, 409, "already configured")
		return
	}
	key := loginClientKey(r)
	if len(a.authByClient) >= 4096 {
		if _, ok := a.authByClient[key]; !ok {
			fail(w, 429, "authentication client limit reached")
			return
		}
	}
	bucket := a.authByClient[key]
	if time.Since(bucket.window) > time.Minute {
		bucket = authBucket{window: time.Now()}
	}
	if bucket.attempts >= 10 || a.authAttempts >= 1000 {
		w.Header().Set("Retry-After", "60")
		fail(w, 429, "too many authentication attempts; retry in one minute")
		return
	}
	bucket.attempts++
	a.authByClient[key] = bucket
	a.authAttempts++
	var body struct {
		Password string `json:"password"`
	}
	if err := decode(w, r, &body); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if r.URL.Path == "/api/setup" {
		if len(body.Password) < 12 || len(body.Password) > 72 {
			fail(w, 400, "password must contain 12 to 72 bytes")
			return
		}
		password, err = bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
		if err == nil {
			err = a.db.Setup(password)
		}
		if err != nil {
			fail(w, 500, "cannot save password")
			return
		}
	} else if len(password) == 0 || bcrypt.CompareHashAndPassword(password, []byte(body.Password)) != nil {
		fail(w, 401, "invalid credentials")
		return
	}
	token := randomID()
	if err := a.db.Session(hash(token), time.Now().Add(12*time.Hour)); err != nil {
		fail(w, 500, "cannot create session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "niceproxy_session", Value: token, Path: "/", MaxAge: 43200, HttpOnly: true, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" || (a.cfHTTPSCallback.Load() && a.cfCallbackHost.Load() == r.Host), SameSite: http.SameSiteStrictMode})
	a.authAttempts = 0
	delete(a.authByClient, key)
	write(w, 200, map[string]bool{"configured": true, "authenticated": true})
}

func loginClientKey(r *http.Request) string {
	// The private control listener is reached through the bundled Caddy,
	// which overwrites these headers and gates the Cloudflare value by CIDR.
	if _, ok := r.Context().Value(http.LocalAddrContextKey).(*net.UnixAddr); ok {
		for _, header := range []string{caddy.PanelCloudflareIPHeader, caddy.PanelPeerIPHeader} {
			values := r.Header.Values(header)
			if len(values) != 1 {
				continue
			}
			ip, err := netip.ParseAddr(strings.TrimSpace(values[0]))
			if err == nil && (header == caddy.PanelPeerIPHeader || ip.Zone() == "") {
				return ip.WithZone("").Unmap().String()
			}
		}
	}
	if ip, err := netip.ParseAddrPort(r.RemoteAddr); err == nil {
		return ip.Addr().WithZone("").Unmap().String()
	}
	return r.RemoteAddr
}

func decode(w http.ResponseWriter, r *http.Request, dst any) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return fmt.Errorf("Content-Type application/json required")
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384))
	d.DisallowUnknownFields()
	if err := d.Decode(dst); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("request must contain one JSON object")
	}
	return nil
}
func write(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, message string) {
	write(w, status, map[string]string{"error": message})
}

func resourceID(path, base string) (string, bool) {
	if path == base {
		return "", true
	}
	if !strings.HasPrefix(path, base+"/") {
		return "", false
	}
	id := strings.TrimPrefix(path, base+"/")
	return id, id != "" && !strings.Contains(id, "/")
}
func (a *App) commit(ctx context.Context, c model.Config) error {
	if err := a.ownershipConflict(c); err != nil {
		return err
	}
	if err := validateAntiDDoS(c); err != nil {
		return err
	}
	resolver, err := newTrustResolver(c.AntiDDoS)
	if err != nil {
		return err
	}
	// A valid authenticated edit is the recovery path for a legacy or
	// interrupted state that was discovered during startup.
	a.startupError = ""
	c.Revision = a.config.Revision + 1
	if err := a.db.Save(c); err != nil {
		return err
	}
	retained := make(map[string]bool, len(c.DirectRules))
	for _, rule := range c.DirectRules {
		retained[rule.ID] = true
	}
	for _, previous := range a.config.DirectRules {
		if !retained[previous.ID] {
			// Accepted streams keep their counters until their last generation
			// finishes; deleted IDs then release their statistics completely.
			a.proxy.ForgetStats(previous.ID)
		}
	}
	a.config = c
	a.trustResolver = resolver
	_ = a.reconcile(ctx)
	return nil
}

func (a *App) direct(w http.ResponseWriter, r *http.Request) {
	id, ok := resourceID(r.URL.Path, "/api/direct-rules")
	if !ok {
		fail(w, 404, "rule not found")
		return
	}
	c := a.config
	c.DirectRules = append([]model.DirectRule{}, c.DirectRules...)
	index := -1
	for i, v := range c.DirectRules {
		if v.ID == id {
			index = i
			break
		}
	}
	if id != "" && index < 0 {
		fail(w, 404, "rule not found")
		return
	}
	if r.Method == "DELETE" && index >= 0 {
		c.DirectRules = append(c.DirectRules[:index], c.DirectRules[index+1:]...)
		if err := a.commit(r.Context(), c); err != nil {
			fail(w, 500, err.Error())
			return
		}
		write(w, 200, map[string]bool{"ok": true})
		return
	}
	var item model.DirectRule
	if r.Method == "PATCH" && index >= 0 {
		item = c.DirectRules[index]
	} else if r.Method != "POST" || id != "" {
		fail(w, 405, "method not allowed")
		return
	}
	if err := decode(w, r, &item); err != nil {
		fail(w, 400, err.Error())
		return
	}
	item.ID = id
	if id == "" {
		item.ID = randomID()
	}
	item.Stats = nil
	item.Status = ""
	item.Error = ""
	if err := validateDirect(&item, nil); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if len(c.DirectRules) >= 1024 && index < 0 {
		fail(w, 400, "maximum 1024 direct rules")
		return
	}
	if a.reserved[item.ListenPort] {
		fail(w, 409, "port is reserved for the management panel")
		return
	}
	if index < 0 {
		c.DirectRules = append(c.DirectRules, item)
	} else {
		c.DirectRules[index] = item
	}
	if err := a.commit(r.Context(), c); err != nil {
		mutationFail(w, err)
		return
	}
	for _, saved := range a.snapshot().DirectRules {
		if saved.ID == item.ID {
			write(w, 200, saved)
			return
		}
	}
}

func (a *App) httpRoute(w http.ResponseWriter, r *http.Request) {
	id, ok := resourceID(r.URL.Path, "/api/http-routes")
	if !ok {
		fail(w, 404, "route not found")
		return
	}
	if id == systemPanelRouteID {
		fail(w, 409, "the panel domain route is system-managed and follows panel-domain settings")
		return
	}
	c := a.config
	c.HTTPRoutes = append([]model.HTTPRoute{}, c.HTTPRoutes...)
	index := -1
	for i, v := range c.HTTPRoutes {
		if v.ID == id {
			index = i
			break
		}
	}
	if id != "" && index < 0 {
		fail(w, 404, "route not found")
		return
	}
	if r.Method == "DELETE" && index >= 0 {
		c.HTTPRoutes = append(c.HTTPRoutes[:index], c.HTTPRoutes[index+1:]...)
		if err := a.commit(r.Context(), c); err != nil {
			fail(w, 500, err.Error())
			return
		}
		write(w, 200, map[string]bool{"ok": true})
		return
	}
	var item model.HTTPRoute
	if r.Method == "PATCH" && index >= 0 {
		item = c.HTTPRoutes[index]
	} else if r.Method != "POST" || id != "" {
		fail(w, 405, "method not allowed")
		return
	}
	if err := decode(w, r, &item); err != nil {
		fail(w, 400, err.Error())
		return
	}
	item.ID = id
	if id == "" {
		item.ID = randomID()
	}
	item.Status = ""
	item.Error = ""
	if err := validateHTTP(&item); err != nil {
		fail(w, 400, err.Error())
		return
	}
	if len(c.HTTPRoutes) >= 1024 && index < 0 {
		fail(w, 400, "maximum 1024 HTTP routes")
		return
	}
	for _, other := range c.HTTPRoutes {
		if other.ID != item.ID && strings.EqualFold(strings.TrimSuffix(other.Host, "."), strings.TrimSuffix(item.Host, ".")) {
			otherPath, _ := model.NormalizeRoutePath(other.Path)
			if otherPath == item.Path {
				fail(w, 409, "domain and path already configured")
				return
			}
			if other.TLS != item.TLS {
				fail(w, 409, "all paths of a domain must use the same TLS mode")
				return
			}
		}
	}
	if index < 0 {
		c.HTTPRoutes = append(c.HTTPRoutes, item)
	} else {
		c.HTTPRoutes[index] = item
	}
	if err := a.commit(r.Context(), c); err != nil {
		mutationFail(w, err)
		return
	}
	for _, saved := range a.snapshot().HTTPRoutes {
		if saved.ID == item.ID {
			write(w, 200, saved)
			return
		}
	}
}
