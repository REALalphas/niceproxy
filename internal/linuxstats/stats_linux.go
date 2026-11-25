// Package linuxstats samples Linux process and network statistics.
package linuxstats

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Sample describes the process and its current network namespace. Network
// counters are cumulative across the namespace, including other processes.
// A nil field means the measurement is unavailable.
type Sample struct {
	CPUPercent, MemoryBytes, ListenOverflows, ListenDrops, UDPInErrors, UDPReceiveBufferErrors *float64
}

// Sampler retains the previous process CPU measurement. Its zero value is ready
// to use. A Sampler must not be copied after first use.
type Sampler struct {
	mu   sync.Mutex
	wall time.Time
	cpu  time.Duration
}

// Read samples current RSS in bytes and namespace counters. CPUPercent is the
// change in process user plus system CPU time divided by elapsed monotonic wall
// time and by GOMAXPROCS at this read, multiplied by 100. It is nil until two
// successful CPU measurements are available.
func (s *Sampler) Read() Sample {
	s.mu.Lock()
	defer s.mu.Unlock()

	var sample Sample
	var usage syscall.Rusage
	if syscall.Getrusage(syscall.RUSAGE_SELF, &usage) == nil {
		now := time.Now()
		cpu := time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
		if elapsed := now.Sub(s.wall); !s.wall.IsZero() && elapsed > 0 && cpu >= s.cpu {
			percent := 100 * float64(cpu-s.cpu) / float64(elapsed) / float64(runtime.GOMAXPROCS(0))
			sample.CPUPercent = &percent
		}
		s.wall, s.cpu = now, cpu
	}
	scanFile("/proc/self/statm", 4096, func(scanner *bufio.Scanner) {
		if scanner.Scan() {
			sample.MemoryBytes = parseRSS(scanner.Text(), os.Getpagesize())
		}
	})
	scanFile("/proc/net/netstat", 256<<10, func(scanner *bufio.Scanner) {
		fields := parseCounters(scanner, "TcpExt:", "ListenOverflows", "ListenDrops")
		sample.ListenOverflows, sample.ListenDrops = fields["ListenOverflows"], fields["ListenDrops"]
	})
	scanFile("/proc/net/snmp", 256<<10, func(scanner *bufio.Scanner) {
		fields := parseCounters(scanner, "Udp:", "InErrors", "RcvbufErrors")
		sample.UDPInErrors, sample.UDPReceiveBufferErrors = fields["InErrors"], fields["RcvbufErrors"]
	})
	return sample
}

// Limit the bytes delivered to the parser. Use a sentinel at the limit so the
// scanner never interprets a truncated final row as a complete row.
func scanFile(path string, limit int64, parse func(*bufio.Scanner)) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(&boundedReader{io.LimitedReader{R: file, N: limit}})
	scanner.Split(completeLines)
	parse(scanner)
}

func completeLines(data []byte, atEOF bool) (int, []byte, error) {
	if atEOF && bytes.IndexByte(data, '\n') < 0 {
		return 0, nil, nil
	}
	return bufio.ScanLines(data, atEOF)
}

type boundedReader struct{ io.LimitedReader }

func (r *boundedReader) Read(p []byte) (int, error) {
	if r.N == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	return r.LimitedReader.Read(p)
}

func parseRSS(line string, pageSize int) *float64 {
	fields := strings.Fields(line)
	if len(fields) != 7 {
		return nil
	}
	pages := counter(fields[1], 10)
	if pages != nil {
		*pages *= float64(pageSize)
	}
	return pages
}

func parseCounters(scanner *bufio.Scanner, section string, wanted ...string) map[string]*float64 {
	for scanner.Scan() {
		header := strings.Fields(scanner.Text())
		if len(header) == 0 || header[0] != section {
			continue
		}
		if !scanner.Scan() {
			return nil
		}
		values := strings.Fields(scanner.Text())
		if len(values) != len(header) || values[0] != section {
			return nil
		}
		result := make(map[string]*float64, len(wanted))
		for _, name := range wanted {
			for i := 1; i < len(header); i++ {
				if header[i] == name {
					result[name] = counter(values[i], 10)
					break
				}
			}
		}
		return result
	}
	return nil
}

func counter(value string, base int) *float64 {
	n, err := strconv.ParseUint(value, base, 64)
	if err != nil {
		return nil
	}
	v := float64(n)
	return &v
}
