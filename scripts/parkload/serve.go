package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

func serve(ctx context.Context, out io.Writer, host string, hp, tp, up int, id string) error {
	addr := func(p int) string { return net.JoinHostPort(host, strconv.Itoa(p)) }
	hl, err := net.Listen("tcp", addr(hp))
	if err != nil {
		return err
	}
	defer hl.Close()
	tl, err := net.Listen("tcp", addr(tp))
	if err != nil {
		return err
	}
	defer tl.Close()
	ul, err := net.ListenPacket("udp", addr(up))
	if err != nil {
		return err
	}
	defer ul.Close()
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Park-Backend", id)
		fmt.Fprint(w, id+" "+r.RequestURI)
	}), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second}
	var mu sync.Mutex
	active := map[net.Conn]struct{}{}
	closing := false
	var wg sync.WaitGroup
	// HTTP Close also closes active HTTP connections; raw streams are tracked below.
	defer srv.Close()
	done := make(chan error, 3)
	go func() { done <- srv.Serve(hl) }()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, e := tl.Accept()
			if e != nil {
				done <- e
				return
			}
			mu.Lock()
			if closing {
				mu.Unlock()
				c.Close()
				return
			}
			active[c] = struct{}{}
			wg.Add(1)
			mu.Unlock()
			go func() {
				defer wg.Done()
				defer c.Close()
				defer func() { mu.Lock(); delete(active, c); mu.Unlock() }()
				io.Copy(c, c)
			}()
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 65535)
		for {
			n, a, e := ul.ReadFrom(buf)
			if e != nil {
				done <- e
				return
			}
			if _, e = ul.WriteTo(buf[:n], a); e != nil {
				done <- e
				return
			}
		}
	}()
	shutdown := func() {
		tl.Close()
		ul.Close()
		srv.Close()
		mu.Lock()
		closing = true
		for c := range active {
			c.Close()
		}
		mu.Unlock()
		wg.Wait()
	}
	if err = json.NewEncoder(out).Encode(map[string]string{"http": hl.Addr().String(), "tcp": tl.Addr().String(), "udp": ul.LocalAddr().String(), "id": id}); err != nil {
		shutdown()
		return err
	}
	select {
	case <-ctx.Done():
		shutdown()
		return nil
	case err = <-done:
		shutdown()
		return fmt.Errorf("backend stopped: %w", err)
	}
}
