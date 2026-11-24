//go:build linux

package main

import (
	"context"
	"net"
	"syscall"
	"testing"
	"time"
)

func TestExplicitTCPSourcePreservesConnectTimePortAllocation(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := dialer(config{protocol: "tcp", source: "127.0.0.2", timeout: time.Second}).DialContext(ctx, "tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !conn.LocalAddr().(*net.TCPAddr).IP.Equal(net.ParseIP("127.0.0.2")) {
		t.Fatal("source IP was not preserved")
	}
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var value int
	var optionErr error
	if err = raw.Control(func(fd uintptr) {
		value, optionErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBindAddressNoPort)
	}); err != nil || optionErr != nil || value != 1 {
		t.Fatalf("source port reserved before connect: option=%d control=%v socket=%v", value, err, optionErr)
	}
}
