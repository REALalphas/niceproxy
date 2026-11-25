package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
	"niceproxy/internal/ddos"
)

type Protection struct {
	Listener, Endpoint *ddos.Binding
}

func (p Protection) socket(inode uint64) { p.Listener.Socket(inode) }

func (p Protection) bytes(phase string, n int64) {
	if n > 0 {
		p.Endpoint.Count(phase, uint64(n))
		p.Listener.Count(phase, uint64(n))
	}
}

func firstByte(c *net.TCPConn, deadline time.Time) error {
	if err := c.SetReadDeadline(deadline); err != nil {
		return err
	}
	_, err := readable(c)
	_ = c.SetReadDeadline(time.Time{})
	return err
}

// readable waits for application data without consuming it, leaving the source
// connection available to net.TCPConn.ReadFrom and Linux splice.
func readable(c *net.TCPConn) (int64, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var readErr error
	var n int
	err = raw.Read(func(fd uintptr) bool {
		var data [1]byte
		for {
			n, _, readErr = unix.Recvfrom(int(fd), data[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
			if readErr != unix.EINTR {
				break
			}
		}
		if readErr == unix.EAGAIN {
			return false
		}
		if readErr == nil && n > 0 {
			n, readErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ)
		}
		return true
	})
	if err == nil {
		err = readErr
	}
	return int64(n), err
}

const transferChunk = 256 << 10

var errTrafficLimit = errors.New("TCP traffic limit")

type tcpFlow struct {
	mu        sync.Mutex
	cond      *sync.Cond
	remaining int64
	reserved  int64
	byteLimit int64
	startedAt time.Time
	last      atomic.Int64
	total     atomic.Int64
	limited   sync.Once
}

func newTCPFlow(byteLimit int64) *tcpFlow {
	f := &tcpFlow{byteLimit: byteLimit, remaining: byteLimit, startedAt: time.Now()}
	f.cond = sync.NewCond(&f.mu)
	return f
}

func (f *tcpFlow) reserve(n int64) int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.remaining <= 0 {
		return 0
	}
	n = min(n, f.remaining)
	f.remaining -= n
	f.reserved += n
	return n
}

func (f *tcpFlow) finish(reserved, actual int64) {
	f.mu.Lock()
	f.reserved -= reserved
	f.remaining += reserved - actual
	f.cond.Broadcast()
	f.mu.Unlock()
}

func (f *tcpFlow) copy(dst, src *net.TCPConn, onBytes func(int64), done chan<- error, frequent bool) {
	var err error
	for err == nil {
		n := int64(transferChunk)
		if f.byteLimit != 0 || frequent {
			n, err = readable(src)
			if err != nil || n == 0 {
				break
			}
			n = min(n, transferChunk)
		}
		if f.byteLimit != 0 {
			n = f.reserve(n)
			if n == 0 {
				err = errTrafficLimit
				break
			}
		}
		// TCPConn.ReadFrom unwraps io.LimitedReader and can splice even
		// when a byte cap is configured.
		var moved int64
		moved, err = io.CopyN(dst, src, n)
		if f.byteLimit != 0 {
			f.finish(n, moved)
		}
		if moved > 0 {
			f.total.Add(moved)
			f.last.Store(int64(time.Since(f.startedAt)))
			onBytes(moved)
		}
	}
	if errors.Is(err, io.EOF) {
		err = nil
	}
	if err != nil {
		_ = dst.Close()
		_ = src.Close()
	}
	_ = dst.CloseWrite()
	_ = src.CloseRead()
	done <- err
}

func (f *tcpFlow) watchIdle(ctx context.Context, idle time.Duration, client, upstream *net.TCPConn, exceeded func(time.Duration)) {
	timer := time.NewTimer(idle)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			elapsed := time.Since(f.startedAt) - time.Duration(f.last.Load())
			if elapsed >= idle {
				if ctx.Err() == nil {
					exceeded(elapsed)
					_ = client.Close()
					_ = upstream.Close()
				}
				return
			}
			timer.Reset(idle - elapsed)
		}
	}
}

func isTimeout(err error) bool {
	var e net.Error
	return errors.As(err, &e) && e.Timeout()
}
