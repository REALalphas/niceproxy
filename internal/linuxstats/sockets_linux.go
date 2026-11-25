package linuxstats

import (
	"bufio"
	"strconv"
	"strings"
	"syscall"
)

// SocketQueue reports the TCP listener's queued connections or the UDP
// socket's receive queue in bytes. Drops is the cumulative UDP socket drop
// count. Unavailable fields, including TCP Drops, are nil.
type SocketQueue struct {
	Receive, Drops *float64
}

// SocketQueues returns TCP listeners and UDP sockets visible in the current
// network namespace, keyed by inode. Unreadable tables are skipped. At most
// 8 MiB of complete rows per table are sampled, so large tables can be partial.
func SocketQueues() map[uint64]SocketQueue {
	queues := make(map[uint64]SocketQueue)
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		scanFile("/proc/net/"+table, 8<<20, func(scanner *bufio.Scanner) {
			parseSockets(scanner, strings.HasPrefix(table, "udp"), queues)
		})
	}
	return queues
}

func parseSockets(scanner *bufio.Scanner, udp bool, queues map[uint64]SocketQueue) {
	if !scanner.Scan() {
		return
	}
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 10 || (!udp && fields[3] != "0A") {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		var queue SocketQueue
		if tx, rx, ok := strings.Cut(fields[4], ":"); ok {
			if _, err := strconv.ParseUint(tx, 16, 32); err == nil {
				queue.Receive = counter(rx, 16)
			}
		}
		if udp && len(fields) >= 13 {
			queue.Drops = counter(fields[12], 10)
		}
		if queue.Receive != nil || queue.Drops != nil {
			queues[inode] = queue
		}
	}
}

// SocketInode returns the inode of an open socket, or zero if unavailable.
// The caller can pass a TCP listener or UDP connection directly.
func SocketInode(conn syscall.Conn) uint64 {
	if conn == nil {
		return 0
	}
	raw, err := conn.SyscallConn()
	if err != nil {
		return 0
	}
	var inode uint64
	if err := raw.Control(func(fd uintptr) {
		var stat syscall.Stat_t
		if syscall.Fstat(int(fd), &stat) == nil && stat.Mode&syscall.S_IFMT == syscall.S_IFSOCK {
			inode = stat.Ino
		}
	}); err != nil {
		return 0
	}
	return inode
}
