package ddos

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestPolicyValidationRejectsAmbiguousBudgets(t *testing.T) {
	p := &Policy{EnforceLimits: true, Limits: []Limit{{ID: "r", Metric: "tcp_new", Value: 10, Unit: "count", Scope: "ip", Action: Reject}}}
	if err := p.Validate(TCP); err == nil {
		t.Fatal("rate limit without a window was accepted")
	}
	p.Limits[0].WindowSeconds = 1
	if err := p.Validate(TCP); err != nil {
		t.Fatal(err)
	}
	p.Limits[0].Unit = "bytes"
	if err := p.Validate(TCP); err == nil {
		t.Fatal("mismatched rate unit was accepted")
	}
	udp := &Policy{ExpectUDPResponse: true}
	if err := udp.Validate(TCP); err == nil {
		t.Fatal("UDP response mode was accepted for TCP")
	}
}

func TestAdmissionBlockIsBoundedAndAttributed(t *testing.T) {
	e := NewEngine()
	p := &Policy{EnforceLimits: true, Limits: []Limit{{ID: "one", Metric: "tcp_new", Value: 1, Unit: "count", WindowSeconds: 1, Scope: "ip", Action: Block, TTLSeconds: 30}}}
	if err := p.Validate(TCP); err != nil {
		t.Fatal(err)
	}
	b := e.Bind(Spec{ID: "endpoint", Kind: TCP, Protocol: "tcp", Policy: p, PreFilter: "socket"})
	e.Publish([]*Binding{b})
	ip := netip.MustParseAddr("192.0.2.10")
	d := b.Check(ip, Amount{Metric: "tcp_new", Value: 1})
	if d.Rejected() {
		t.Fatal("first connection was rejected")
	}
	d.Record()
	d.Release()
	d = b.Check(ip, Amount{Metric: "tcp_new", Value: 1})
	if !d.Rejected() || d.Action() != Block {
		t.Fatalf("second connection decision=%s rejected=%v", d.Action(), d.Rejected())
	}
	d.Record()
	d.Release()
	s := e.Snapshots()
	if len(s) != 1 || len(s[0].Restrictions) != 1 || s[0].Restrictions[0].Target != ip.String() {
		t.Fatalf("unexpected restrictions: %+v", s)
	}
	if s[0].Metrics["dropped"].Value == nil {
		t.Fatal("known proxy drop counter was omitted")
	}
}

func TestManualClearSuppressesAutomaticRule(t *testing.T) {
	e := NewEngine()
	p := &Policy{Detect: true, AutoFilter: true, StableWindows: 1, Rules: []Rule{{ID: "errors", Signal: "protocol_errors", Scope: "ip", Threshold: 1, ClearThreshold: 0, WindowSeconds: 1, MinSamples: 1, Action: Block, CooldownSeconds: 30}}}
	b := e.Bind(Spec{ID: "endpoint", Kind: TCP, Protocol: "tcp", Policy: p, PreFilter: "socket"})
	e.Publish([]*Binding{b})
	ip := netip.MustParseAddr("192.0.2.11")
	b.Observe("protocol_errors", ip, 1)
	// A manual clear is a durable override in the target state. It does not
	// remove unrelated source restrictions.
	if got := b.Clear("errors", ip.String(), "operator", time.Minute); got != nil {
		t.Fatalf("expected no automatic restriction before a detector window: %+v", got)
	}
	d := b.CheckOperation(ip, Amount{Metric: "tcp_new", Value: 1})
	if !d.Wait(context.Background()) {
		t.Fatal("operation should remain admitted")
	}
}
