package linuxstats

import (
	"bufio"
	"io"
	"net"
	"strings"
	"testing"
)

func TestParseRSS(t *testing.T) {
	got := parseRSS("100 25 0 0 0 0 0", 4096)
	if got == nil || *got != 102400 {
		t.Fatalf("RSS = %v", got)
	}
	for _, line := range []string{"100 25", "100 -1 0 0 0 0 0", "100 NaN 0 0 0 0 0"} {
		if got := parseRSS(line, 4096); got != nil {
			t.Errorf("accepted invalid statm row %q", line)
		}
	}
}

func TestParseCounters(t *testing.T) {
	input := "Ignore: Name\nIgnore: 10\nUdp: InErrors Other RcvbufErrors\nUdp: 12 99 -1\n"
	got := parseCounters(bufio.NewScanner(strings.NewReader(input)), "Udp:", "InErrors", "RcvbufErrors", "Missing")
	if got["InErrors"] == nil || *got["InErrors"] != 12 || got["RcvbufErrors"] != nil || got["Missing"] != nil {
		t.Fatalf("unexpected counters: %v", got)
	}
	for _, line := range []string{"Udp: 12\n", "Tcp: 12 13\n", "Udp: 12 13 14\n"} {
		got := parseCounters(bufio.NewScanner(strings.NewReader("Udp: InErrors RcvbufErrors\n"+line)), "Udp:", "InErrors")
		if got != nil {
			t.Errorf("accepted mismatched counter row %q", line)
		}
	}
}

func TestBoundedReader(t *testing.T) {
	scanner := bufio.NewScanner(&boundedReader{io.LimitedReader{R: strings.NewReader("first\nsecond\n"), N: 9}})
	scanner.Split(completeLines)
	if !scanner.Scan() || scanner.Text() != "first" || scanner.Scan() || scanner.Err() != io.ErrUnexpectedEOF {
		t.Fatal("expected only the complete row followed by a limit error")
	}
}

func TestParseSockets(t *testing.T) {
	const input = "header\n" +
		"0: local remote 0A 00000000:00000003 timer retrans uid timeout 42 2 ptr\n" +
		"1: local remote 01 00000000:00000004 timer retrans uid timeout 43 2 ptr\n" +
		"2: local remote 07 00000000:000000FF timer retrans uid timeout 44 2 ptr 19\n" +
		"3: local remote 07 invalid timer retrans uid timeout 45 2 ptr 7\n" +
		"4: local remote 07 00000000:00000003 timer retrans uid timeout 0 2 ptr 0\n"
	tcp := make(map[uint64]SocketQueue)
	parseSockets(bufio.NewScanner(strings.NewReader(input)), false, tcp)
	if q := tcp[42]; len(tcp) != 1 || q.Receive == nil || *q.Receive != 3 || q.Drops != nil {
		t.Fatalf("unexpected TCP queues: %v", tcp)
	}
	udp := make(map[uint64]SocketQueue)
	parseSockets(bufio.NewScanner(strings.NewReader(input)), true, udp)
	if q := udp[44]; len(udp) != 4 || q.Receive == nil || *q.Receive != 255 || q.Drops == nil || *q.Drops != 19 {
		t.Fatalf("unexpected UDP queues: %v", udp)
	}
	if q := udp[45]; q.Receive != nil || q.Drops == nil || *q.Drops != 7 {
		t.Fatalf("unexpected partially available UDP queue: %v", q)
	}
}

func TestSamplerRead(t *testing.T) {
	var sampler Sampler
	first, second := sampler.Read(), sampler.Read()
	if first.CPUPercent != nil || second.CPUPercent == nil || *second.CPUPercent < 0 {
		t.Fatal("expected CPU percentage only on the second read")
	}
	if second.MemoryBytes == nil || *second.MemoryBytes <= 0 {
		t.Fatal("expected positive process RSS")
	}
}

func TestSocketQueues(t *testing.T) {
	tcp, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	client, err := net.DialTCP("tcp4", nil, tcp.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	queues := SocketQueues()
	if q := queues[SocketInode(tcp)]; q.Receive == nil || *q.Receive != 1 || q.Drops != nil {
		t.Fatalf("expected one pending TCP connection, got %v", q)
	}
	if q := queues[SocketInode(udp)]; q.Receive == nil || *q.Receive != 0 || q.Drops == nil || *q.Drops != 0 {
		t.Fatalf("expected empty UDP queue with zero drops, got %v", q)
	}
}
