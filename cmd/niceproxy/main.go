package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"niceproxy/internal/caddy"
	"niceproxy/internal/cloudflare"
	"niceproxy/internal/control"
	"niceproxy/internal/proxy"
	"niceproxy/internal/store"
)

func env(key, fallback string) string {
	if s := os.Getenv(key); s != "" {
		return s
	}
	return fallback
}
func envInt(key string, fallback int) int {
	s := os.Getenv(key)
	if s == "" {
		return fallback
	}
	n, e := strconv.Atoi(s)
	if e != nil {
		log.Fatalf("%s must be an integer", key)
	}
	return n
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		if err := healthcheck(); err != nil {
			log.Print(err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func healthcheck() error {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	socket := filepath.Join(env("NICEPROXY_RUNTIME_DIR", "./data/run"), "control.sock")
	client := http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}, Timeout: 3 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://niceproxy/healthz", nil)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("healthcheck: HTTP %d", resp.StatusCode)
	}
	return nil
}
func run() error {
	syscall.Umask(0077)
	dataDir := flag.String("data", env("NICEPROXY_DATA_DIR", "./data"), "persistent data directory")
	runtimeDir := flag.String("runtime", env("NICEPROXY_RUNTIME_DIR", "./data/run"), "private runtime directory")
	ui := flag.String("ui", env("NICEPROXY_UI_DIR", "web/dist"), "built web UI directory")
	caddyBin := flag.String("caddy", env("NICEPROXY_CADDY_BIN", "caddy"), "bundled Caddy executable")
	panel := flag.String("panel", env("NICEPROXY_PANEL_LISTEN", "127.0.0.1:9080"), "management panel listener")
	httpPort := flag.Int("http-port", envInt("NICEPROXY_HTTP_PORT", 80), "Caddy HTTP port")
	httpsPort := flag.Int("https-port", envInt("NICEPROXY_HTTPS_PORT", 443), "Caddy HTTPS port")
	maxTCP := flag.Int("max-tcp", envInt("NICEPROXY_MAX_TCP_CONNECTIONS", 16384), "maximum TCP connections per rule")
	maxUDP := flag.Int("max-udp", envInt("NICEPROXY_MAX_UDP_ASSOCIATIONS", 1024), "maximum UDP associations per rule")
	flag.Parse()
	for _, path := range []*string{dataDir, runtimeDir, ui} {
		absolute, e := filepath.Abs(*path)
		if e != nil {
			return e
		}
		*path = absolute
	}
	if *httpPort < 1 || *httpPort > 65535 || *httpsPort < 1 || *httpsPort > 65535 || *httpPort == *httpsPort || *maxTCP < 1 || *maxUDP < 1 {
		return fmt.Errorf("invalid ports or connection limits")
	}
	_, panelPort, err := net.SplitHostPort(*panel)
	if err != nil {
		return fmt.Errorf("panel address: %w", err)
	}
	pp, err := strconv.Atoi(panelPort)
	if err != nil || pp < 1 || pp > 65535 || pp == *httpPort || pp == *httpsPort {
		return fmt.Errorf("invalid or conflicting panel port")
	}
	if _, err := os.Stat(filepath.Join(*ui, "index.html")); err != nil {
		return fmt.Errorf("UI is not built: npm --prefix web ci && npm --prefix web run build: %w", err)
	}
	for _, dir := range []string{*dataDir, *runtimeDir} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return err
		}
		if err := os.Chmod(dir, 0700); err != nil {
			return err
		}
	}
	lock, err := os.OpenFile(filepath.Join(*dataDir, "niceproxy.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("another niceproxy uses this data directory: %w", err)
	}
	db, err := store.Open(filepath.Join(*dataDir, "niceproxy.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	cfg, _, err := db.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	socket := filepath.Join(*runtimeDir, "control.sock")
	if stat, err := os.Lstat(socket); err == nil {
		if stat.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("refusing to remove non-socket %s", socket)
		}
		if err := os.Remove(socket); err != nil {
			return err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	defer listener.Close()
	defer os.Remove(socket)
	if err := os.Chmod(socket, 0600); err != nil {
		return err
	}
	good, err := db.LastGood()
	if err != nil {
		return err
	}
	panelDomain := cfg.PanelDomain
	if good.PanelDomain != "" {
		panelDomain = good.PanelDomain
	}
	if panelDomain == "" {
		panelDomain = os.Getenv("NICEPROXY_DOMAIN")
	}
	caddyOptions := caddy.Options{Binary: *caddyBin, RuntimeDir: *runtimeDir, DataDir: *dataDir, PanelListen: *panel, BackendSocket: socket, HTTPPort: *httpPort, HTTPSPort: *httpsPort, PanelDomain: panelDomain, PanelDomainProxied: good.PanelDomainProxied || cfg.PanelDomainProxied}
	cm := caddy.New(caddyOptions)
	startedRoutes := good.HTTPRoutes
	if err := cm.Start(ctx, startedRoutes, good.PortOwners); err != nil {
		log.Printf("last-good Caddy startup failed; starting management panel only: %v", err)
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 3*time.Second)
		_ = cm.Close(closeCtx)
		closeCancel()
		cm = caddy.New(caddyOptions)
		startedRoutes = nil
		if err := cm.Start(ctx, startedRoutes, good.PortOwners); err != nil {
			return fmt.Errorf("start Caddy management panel: %w", err)
		}
	}
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = cm.Close(c)
	}()
	pm := proxy.NewManager(proxy.Options{MaxTCPConnections: *maxTCP, MaxUDPAssociations: *maxUDP})
	defer func() {
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = pm.Close(c)
	}()
	app, err := control.New(db, cm, pm, map[int]bool{*httpPort: true, *httpsPort: true, pp: true})
	if err != nil {
		return err
	}
	app.SetHTTPActive(startedRoutes)
	initialDomain := cfg.PanelDomain
	if initialDomain == "" {
		initialDomain = os.Getenv("NICEPROXY_DOMAIN")
	}
	if err := app.ConfigurePanelDomain(initialDomain); err != nil {
		log.Printf("panel domain configuration unavailable: %v", err)
	}
	cfRedirect := os.Getenv("NICEPROXY_CF_REDIRECT_URL")
	if initialDomain != "" {
		cfRedirect = "https://" + initialDomain + "/api/cloudflare/callback"
	}
	if cfRedirect == "" {
		host, _, _ := net.SplitHostPort(*panel)
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
			cfRedirect = "http://" + *panel + "/api/cloudflare/callback"
		}
	}
	if err := app.ConfigureCloudflare(cloudflare.Options{DataDir: *dataDir, RedirectURL: cfRedirect}); err != nil {
		log.Print("Cloudflare integration unavailable; management panel remains available")
	}
	applyCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	err = app.Reconcile(applyCtx)
	cancel()
	if err != nil {
		log.Printf("configuration partially applied: %v", err)
	}
	static := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			http.Error(w, "method not allowed", 405)
			return
		}
		if r.URL.Path != "/" {
			file, err := os.Stat(filepath.Join(*ui, filepath.Clean("/"+r.URL.Path)))
			if err != nil || file.IsDir() {
				http.NotFound(w, r)
				return
			}
		}
		http.FileServer(http.Dir(*ui)).ServeHTTP(w, r)
	})
	server := &http.Server{Handler: app.Handler(static), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Minute, MaxHeaderBytes: 16384}
	serveErr := make(chan error, 1)
	go func() { serveErr <- server.Serve(listener) }()
	log.Printf("niceproxy ready: panel http://%s; TCP HTTP %d / HTTPS %d; config revision %d", *panel, *httpPort, *httpsPort, cfg.Revision)
	var runErr error
	select {
	case <-ctx.Done():
	case runErr = <-cm.Done():
		if runErr == nil {
			runErr = errors.New("Caddy stopped unexpectedly")
		}
	case runErr = <-serveErr:
		if errors.Is(runErr, http.ErrServerClosed) {
			runErr = nil
		}
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(shutdown)
	return runErr
}
