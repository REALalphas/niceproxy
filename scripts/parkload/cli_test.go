package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRunRejectsInvalidArguments(t *testing.T) {
	for _, tt := range []struct {
		name string
		args []string
		want string
	}{
		{"missing command", nil, "usage:"},
		{"unknown command", []string{"bench"}, "usage:"},
		{"unknown serve flag", []string{"serve", "--unknown"}, "flag provided but not defined"},
		{"unexpected serve argument", []string{"serve", "extra"}, "unexpected arguments"},
		{"non-IP listen host", []string{"serve", "--listen-host=example.test"}, "listen-host must be an IP"},
		{"invalid HTTP port", []string{"serve", "--http-port=-1"}, "port must be 0..65535"},
		{"invalid UDP port", []string{"serve", "--udp-port=65536"}, "port must be 0..65535"},
		{"missing load target", []string{"load"}, "target must be host:port"},
		{"invalid load port", []string{"load", "--target=127.0.0.1:65536"}, "invalid target port"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := run(tt.args, &out); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("run(%v) = %v, want %q", tt.args, err, tt.want)
			}
			if out.Len() != 0 {
				t.Fatalf("invalid CLI invocation wrote a report: %s", out.Bytes())
			}
		})
	}
}

func TestLoadCLIReportsFailuresEvenWhenAllowed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
	}))
	defer upstream.Close()

	for _, tt := range []struct {
		name      string
		flag      string
		wantError bool
	}{
		{"strict", "--allow-errors=false", true},
		{"allow failures", "--allow-errors=true", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			err := run([]string{"load", "--target=" + upstream.Listener.Addr().String(), "--duration=50ms",
				"--concurrency=1", "--timeout=1s", tt.flag}, &out)
			if (err != nil) != tt.wantError || err != nil && !strings.Contains(err.Error(), "requests failed") {
				t.Fatalf("load error = %v, want failure=%v", err, tt.wantError)
			}
			var got report
			if err := json.Unmarshal(out.Bytes(), &got); err != nil {
				t.Fatal(err)
			}
			assertReport(t, got)
			if got.Errors != got.Attempted || got.Succeeded != 0 || got.RequestsPerSecond != 0 || len(got.ErrorSamples) == 0 {
				t.Fatalf("failed requests were misreported: %+v", got)
			}
		})
	}
}

func TestLoadCLIPropagatesOutputError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "backend reply")
	}))
	defer upstream.Close()
	err := run([]string{"load", "--target=" + upstream.Listener.Addr().String(), "--duration=20ms", "--concurrency=1"}, unavailableOutput{})
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("run() = %v, want closed output pipe", err)
	}
}

type unavailableOutput struct{}

func (unavailableOutput) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
