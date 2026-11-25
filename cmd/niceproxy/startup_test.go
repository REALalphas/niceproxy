package main

import (
	"bytes"
	"context"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"niceproxy/internal/model"
	"niceproxy/internal/store"
)

func TestStartupRejectsInvalidInputs(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"HTTP port below range", []string{"--http-port=0"}, "invalid ports or connection limits"},
		{"HTTPS port above range", []string{"--https-port=65536"}, "invalid ports or connection limits"},
		{"overlapping public ports", []string{"--https-port=25180"}, "invalid ports or connection limits"},
		{"invalid TCP limit", []string{"--max-tcp=0"}, "invalid ports or connection limits"},
		{"invalid UDP limit", []string{"--max-udp=-1"}, "invalid ports or connection limits"},
		{"panel without port", []string{"--panel=127.0.0.1"}, "panel address"},
		{"panel with service name", []string{"--panel=127.0.0.1:https"}, "invalid or conflicting panel port"},
		{"panel on public port", []string{"--panel=127.0.0.1:25180"}, "invalid or conflicting panel port"},
		{"missing UI build", []string{"--ui=missing-ui"}, "UI is not built"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			data := filepath.Join(t.TempDir(), "data")
			useStartupFlags(t, data, filepath.Join(t.TempDir(), "run"), t.TempDir(), tt.args...)
			if err := run(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("run() = %v, want %q", err, tt.want)
			}
			if _, err := os.Stat(data); !os.IsNotExist(err) {
				t.Fatalf("invalid startup touched persistent data: %v", err)
			}
		})
	}
}

func TestStartupPreservesExistingDataAndRuntimePaths(t *testing.T) {
	for _, tt := range []struct {
		name, file, contents, want string
		lock                       bool
	}{
		{"data directory already locked", "data/niceproxy.lock", "held by another instance", "another niceproxy uses this data directory", true},
		{"control socket path is a regular file", "run/control.sock", "keep this file", "refusing to remove non-socket", false},
		{"database is corrupt", "data/niceproxy.db", "not a sqlite database", "file is not a database", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			root := t.TempDir()
			data, runtime, ui := filepath.Join(root, "data"), filepath.Join(root, "run"), filepath.Join(root, "ui")
			path := filepath.Join(root, tt.file)
			for _, dir := range []string{filepath.Dir(path), ui} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			for path, contents := range map[string]string{path: tt.contents, filepath.Join(ui, "index.html"): "test UI"} {
				if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tt.lock {
				file, err := os.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				defer file.Close()
				if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
					t.Fatal(err)
				}
			}

			useStartupFlags(t, data, runtime, ui)
			if err := run(); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("run() = %v, want %q", err, tt.want)
			}
			if got, err := os.ReadFile(path); err != nil || string(got) != tt.contents {
				t.Fatalf("startup changed %s: %q, %v", path, got, err)
			}
		})
	}
}

func TestEnvironmentIntegerDefaultAndOverride(t *testing.T) {
	const key = "NICEPROXY_TEST_INTEGER"
	t.Setenv(key, "")
	if got := envInt(key, 1024); got != 1024 {
		t.Fatalf("envInt default = %d, want 1024", got)
	}
	t.Setenv(key, "4096")
	if got := envInt(key, 1024); got != 4096 {
		t.Fatalf("envInt override = %d, want 4096", got)
	}
}

func TestStartupRecoversFromRejectedLastGood(t *testing.T) {
	binary := os.Getenv("NICEPROXY_CADDY_TEST_BINARY")
	if binary == "" {
		t.Skip("set NICEPROXY_CADDY_TEST_BINARY for integration")
	}
	binary, err := filepath.Abs(binary)
	if err != nil {
		t.Fatal(err)
	}
	// The child also binds a Unix socket in this directory.
	root, err := os.MkdirTemp("/tmp", "np-startup-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	data, runtime, ui := filepath.Join(root, "data"), filepath.Join(root, "run"), filepath.Join(root, "ui")
	if err := os.Mkdir(ui, 0700); err != nil {
		t.Fatal(err)
	}
	const page = "<!doctype html><title>test panel</title>"
	if err := os.WriteFile(filepath.Join(ui, "index.html"), []byte(page), 0600); err != nil {
		t.Fatal(err)
	}
	if err := seedRejectedLastGood(data); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	panel := listener.Addr().String()
	panelPort := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	// The public ports are owned by direct proxy rules, so Caddy never binds them.
	httpPort, httpsPort := 25180, 25443
	if panelPort == httpPort || panelPort == httpsPort {
		httpPort, httpsPort = 25181, 25444
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	args := []string{"-test.run=^TestStartupChild$"}
	if coverage := flag.Lookup("test.gocoverdir"); coverage != nil && coverage.Value.String() != "" {
		args = append(args, "-test.gocoverdir="+coverage.Value.String())
	}
	args = append(args, "--", "--caddy="+binary, "--data="+data, "--runtime="+runtime, "--ui="+ui,
		"--panel="+panel, "--http-port="+strconv.Itoa(httpPort), "--https-port="+strconv.Itoa(httpsPort))
	cmd := exec.CommandContext(ctx, os.Args[0], args...)
	keys := []string{"NICEPROXY_HTTP_PORT", "NICEPROXY_HTTPS_PORT", "NICEPROXY_MAX_TCP_CONNECTIONS",
		"NICEPROXY_MAX_UDP_ASSOCIATIONS", "NICEPROXY_DOMAIN", "NICEPROXY_CF_REDIRECT_URL",
		"NICEPROXY_PANEL_CERT_FILE", "NICEPROXY_PANEL_KEY_FILE"}
	cmd.Env = append(os.Environ(), "NICEPROXY_STARTUP_CHILD=1")
	for _, key := range keys {
		cmd.Env = append(cmd.Env, key+"=")
	}
	var logs bytes.Buffer
	cmd.Stdout, cmd.Stderr = &logs, &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			<-done
		}
		if t.Failed() {
			t.Log(logs.String())
		}
	}()
	client := &http.Client{Timeout: time.Second}
	defer client.CloseIdleConnections()
	ticker := time.NewTicker(30 * time.Millisecond)
	defer ticker.Stop()
ready:
	for {
		resp, err := client.Get("http://" + panel + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				break ready
			}
		}
		select {
		case err := <-done:
			waited = true
			t.Fatalf("niceproxy exited before readiness: %v", err)
		case <-ctx.Done():
			t.Fatalf("panel never became ready: %v", ctx.Err())
		case <-ticker.C:
		}
	}
	resp, err := client.Get("http://" + panel + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != 200 || string(body) != page {
		t.Fatalf("panel page = %d %q, read error=%v", resp.StatusCode, body, err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	err = <-done
	waited = true
	if err != nil || !strings.Contains(logs.String(), "last-good Caddy startup failed; starting management panel only") {
		t.Fatalf("fallback startup or shutdown failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(runtime, "control.sock")); !os.IsNotExist(err) {
		t.Fatalf("control socket remained after SIGTERM: %v", err)
	}

	db, err := store.Open(filepath.Join(data, "niceproxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	desired, applied, err := db.Load()
	if err != nil {
		t.Fatal(err)
	}
	good, err := db.LastGood()
	if err != nil || desired.Revision != 2 || applied != 2 || good.Revision != 2 || len(good.HTTPRoutes) != 0 {
		t.Fatalf("persisted recovery: desired=%+v applied=%d last-good=%+v err=%v", desired, applied, good, err)
	}
}

func seedRejectedLastGood(data string) error {
	db, err := store.Open(filepath.Join(data, "niceproxy.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	owners := model.PortOwners{HTTP: "direct", HTTPS: "direct", HTTP3: "direct"}
	legacy := model.Config{
		Revision: 1, PortOwners: owners,
		HTTPRoutes: []model.HTTPRoute{{ID: "legacy", Host: "app.test", Target: "broken", Enabled: true}},
	}
	if err := db.Save(legacy); err != nil {
		return err
	}
	if err := db.MarkApplied(legacy); err != nil {
		return err
	}
	return db.Save(model.Config{Revision: 2, PortOwners: owners})
}

func TestStartupChild(t *testing.T) {
	if os.Getenv("NICEPROXY_STARTUP_CHILD") != "1" {
		return
	}
	os.Args = append([]string{"niceproxy"}, flag.Args()...)
	flag.CommandLine = flag.NewFlagSet("niceproxy", flag.ContinueOnError)
	if err := run(); err != nil {
		t.Fatal(err)
	}
}

// run sets process-global flags and the umask during startup.
func useStartupFlags(t *testing.T, data, runtime, ui string, overrides ...string) {
	t.Helper()
	for _, key := range []string{"NICEPROXY_HTTP_PORT", "NICEPROXY_HTTPS_PORT", "NICEPROXY_MAX_TCP_CONNECTIONS", "NICEPROXY_MAX_UDP_ASSOCIATIONS"} {
		t.Setenv(key, "")
	}
	args, flags := os.Args, flag.CommandLine
	umask := syscall.Umask(0077)
	t.Cleanup(func() {
		os.Args, flag.CommandLine = args, flags
		syscall.Umask(umask)
	})
	flag.CommandLine = flag.NewFlagSet("niceproxy", flag.ContinueOnError)
	flag.CommandLine.SetOutput(io.Discard)
	os.Args = append([]string{"niceproxy", "--data=" + data, "--runtime=" + runtime, "--ui=" + ui,
		"--http-port=25180", "--https-port=25443", "--panel=127.0.0.1:25080", "--caddy=" + filepath.Join(t.TempDir(), "unused")}, overrides...)
}
