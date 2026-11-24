package proxy

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// Opt-in integration smoke using the benchmark's actual generator and backend:
// go build -o bin/parkload ./scripts/parkload
// NICEPROXY_PARKLOAD="$PWD/bin/parkload" go test ./internal/proxy -run TestUDPColdStartParkload -v -count=1
func TestUDPColdStartParkload(t *testing.T) {
	binary := os.Getenv("NICEPROXY_PARKLOAD")
	if binary == "" {
		t.Skip("set NICEPROXY_PARKLOAD to the built scripts/parkload helper")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	backend := exec.CommandContext(ctx, binary, "serve", "--listen-host", "127.88.0.10")
	stdout, err := backend.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	backend.Stderr = os.Stderr
	if err = backend.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { backend.Process.Signal(syscall.SIGTERM); backend.Wait() }()
	var endpoints map[string]string
	if err = json.NewDecoder(stdout).Decode(&endpoints); err != nil {
		t.Fatal(err)
	}
	host, p, err := net.SplitHostPort(endpoints["udp"])
	if err != nil {
		t.Fatal(err)
	}
	targetPort, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	var total uint64
	for repeat := 1; repeat <= 10; repeat++ {
		m := NewManager(Options{MaxUDPAssociations: 1024})
		addr, err := m.Add("cold", Rule{"udp", "127.88.0.2", 0, host, targetPort})
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, binary, "load", "--protocol", "udp", "--target", addr.String(),
			"--source-host", "127.89.0."+strconv.Itoa(repeat), "--connections", "reused",
			"--concurrency", "64", "--payload-size", "256", "--duration", "1s", "--timeout", "5s")
		output, loadErr := cmd.Output()
		closeErr := m.Close(context.Background())
		var r struct{ Attempted, Succeeded, Errors uint64 }
		if err = json.Unmarshal(output, &r); err != nil {
			t.Fatalf("repeat %d: %v; output=%s; load=%v", repeat, err, output, loadErr)
		}
		s, _ := m.Stats("cold")
		t.Logf("repeat=%d attempted=%d succeeded=%d errors=%d stats=%+v", repeat, r.Attempted, r.Succeeded, r.Errors, s)
		if loadErr != nil || closeErr != nil || r.Errors != 0 || r.Attempted != r.Succeeded || r.Succeeded == 0 || s.Accepted != 64 || s.Active != 0 || s.Closed != 64 || s.Rejects != 0 || s.Errors != 0 {
			t.Fatalf("repeat %d failed: load=%v close=%v report=%s stats=%+v", repeat, loadErr, closeErr, output, s)
		}
		total += r.Succeeded
	}
	t.Logf("10 cold starts, 64 clients each: %d verified UDP round trips, zero errors", total)
}
