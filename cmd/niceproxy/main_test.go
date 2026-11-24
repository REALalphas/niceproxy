package main

import (
	"net"
	"net/http"
	"path/filepath"
	"sync/atomic"
	"testing"
)

func TestHealthcheckUsesPrivateUnixSocket(t *testing.T) {
	runtimeDir := t.TempDir()
	t.Setenv("NICEPROXY_RUNTIME_DIR", runtimeDir)
	if err := healthcheck(); err == nil {
		t.Fatal("healthcheck succeeded without the control socket")
	}

	listener, err := net.Listen("unix", filepath.Join(runtimeDir, "control.sock"))
	if err != nil {
		t.Fatal(err)
	}
	var status atomic.Int32
	status.Store(http.StatusOK)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(int(status.Load()))
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })

	if err := healthcheck(); err != nil {
		t.Fatal(err)
	}
	status.Store(http.StatusServiceUnavailable)
	if err := healthcheck(); err == nil || err.Error() != "healthcheck: HTTP 503" {
		t.Fatalf("healthcheck returned %v, want HTTP 503 error", err)
	}
}
