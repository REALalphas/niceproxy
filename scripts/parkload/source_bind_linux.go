//go:build linux

package main

import (
	"net"
	"syscall"
)

// IP_BIND_ADDRESS_NO_PORT (Linux UAPI linux/in.h = 24) keeps an explicit
// source IP without reserving a source port before connect. Plain bind(IP, 0)
// unnecessarily consumes bind buckets across destinations in a local test park.
const ipBindAddressNoPort = 24

func bindSourceIPOnly(d *net.Dialer) {
	d.Control = func(_, _ string, conn syscall.RawConn) error {
		var optionErr error
		err := conn.Control(func(fd uintptr) {
			optionErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBindAddressNoPort, 1)
		})
		if err != nil {
			return err
		}
		return optionErr
	}
}
