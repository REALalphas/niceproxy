// parkload is a test-only, closed-loop traffic generator and echo backend.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(args []string, out io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: parkload serve|load [flags]")
	}
	switch args[0] {
	case "serve":
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		host := fs.String("listen-host", "127.0.0.1", "listen IP")
		hp := fs.Int("http-port", 0, "HTTP port")
		tp := fs.Int("tcp-port", 0, "TCP port")
		up := fs.Int("udp-port", 0, "UDP port")
		id := fs.String("id", "backend-a", "backend ID")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		if net.ParseIP(*host) == nil {
			return errors.New("listen-host must be an IP")
		}
		for _, p := range []int{*hp, *tp, *up} {
			if p < 0 || p > 65535 {
				return errors.New("port must be 0..65535")
			}
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		return serve(ctx, out, *host, *hp, *tp, *up, *id)
	case "load":
		cfg, err := parseLoad(args[1:])
		if err != nil {
			return err
		}
		report := load(cfg)
		if err = json.NewEncoder(out).Encode(report); err != nil {
			return err
		}
		if report.Errors > 0 && !cfg.allowErrors {
			return fmt.Errorf("%d requests failed", report.Errors)
		}
		return nil
	default:
		return errors.New("usage: parkload serve|load [flags]")
	}
}
