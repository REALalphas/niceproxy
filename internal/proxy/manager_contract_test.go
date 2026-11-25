package proxy

import (
	"context"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestCheckBindDoesNotReserveAListener(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		t.Run(protocol, func(t *testing.T) {
			manager := NewManager(Options{})
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				if err := manager.Close(ctx); err != nil {
					t.Error(err)
				}
			})

			rule := Rule{Protocol: protocol, ListenAddress: "127.0.0.1", TargetAddress: "127.0.0.1", TargetPort: 1}
			addr, err := manager.Add("active", rule)
			if err != nil {
				t.Fatal(err)
			}
			if !manager.HasListener("active") {
				t.Fatal("manager did not report the active listener")
			}
			switch addr := addr.(type) {
			case *net.TCPAddr:
				rule.ListenPort = addr.Port
			case *net.UDPAddr:
				rule.ListenPort = addr.Port
			default:
				t.Fatalf("unexpected address type %T", addr)
			}
			if err := CheckBind(rule); !errors.Is(err, syscall.EADDRINUSE) {
				t.Fatalf("CheckBind on an occupied port = %v", err)
			}

			if err := manager.Retire("active"); err != nil {
				t.Fatal(err)
			}
			if manager.HasListener("active") {
				t.Fatal("retired rule still owns its listener")
			}
			if _, ok := manager.Stats("active"); !ok {
				t.Fatal("retirement removed the rule's retained statistics")
			}
			if err := CheckBind(rule); err != nil {
				t.Fatalf("retired listener was not released: %v", err)
			}
			if _, err := manager.Add("replacement", rule); err != nil {
				t.Fatalf("CheckBind left the socket reserved: %v", err)
			}
		})
	}
}

func TestInvalidRuleCannotChangeActiveListener(t *testing.T) {
	manager := NewManager(Options{})
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = manager.Close(ctx)
	})
	valid := Rule{Protocol: "tcp", ListenAddress: "127.0.0.1", TargetAddress: "127.0.0.1", TargetPort: 1}
	if _, err := manager.Add("", valid); err == nil {
		t.Fatal("Add accepted an empty ID")
	}
	if _, err := manager.Add("active", valid); err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name   string
		change func(*Rule)
	}{
		{"bad protocol", func(r *Rule) { r.Protocol = "http" }},
		{"negative listen port", func(r *Rule) { r.ListenPort = -1 }},
		{"listen port above range", func(r *Rule) { r.ListenPort = 65536 }},
		{"zero target port", func(r *Rule) { r.TargetPort = 0 }},
		{"target port above range", func(r *Rule) { r.TargetPort = 65536 }},
		{"missing target address", func(r *Rule) { r.TargetAddress = "" }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			rule := valid
			tt.change(&rule)
			if err := CheckBind(rule); err == nil {
				t.Fatal("CheckBind accepted an invalid rule")
			}
			if _, err := manager.Add("invalid", rule); err == nil {
				t.Fatal("Add accepted an invalid rule")
			}
			if _, err := manager.Update(context.Background(), "active", rule); err == nil {
				t.Fatal("Update accepted an invalid rule")
			}
			if !manager.HasListener("active") || manager.HasListener("invalid") {
				t.Fatal("an invalid rule changed listener ownership")
			}
			if _, ok := manager.Stats("invalid"); ok {
				t.Fatal("invalid rule allocated runtime statistics")
			}
		})
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Add("new", valid); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Add after Close = %v, want net.ErrClosed", err)
	}
	if _, err := manager.Update(context.Background(), "active", valid); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("Update after Close = %v, want net.ErrClosed", err)
	}
}
