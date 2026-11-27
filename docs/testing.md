# Testing niceproxy

All test harnesses create separate processes, data directories, and high ports. They do not use
the production niceproxy or NAS configuration. Run commands from the repository root.
The park uses Linux loopback IPs; this is not a VM and does not model WAN/CGNAT.

## Preparation

```sh
go build -o bin/niceproxy ./cmd/niceproxy
go build -o bin/parkload ./scripts/parkload
npm --prefix web ci
npm --prefix web run typecheck
npm --prefix web run build
```

A verified Caddy 2.10.2 binary is required. Its path is passed explicitly in all commands. Downloading it
and verifying its checksum are performed separately; the harness does not install trusted CAs in the OS.

## Regressions and Park

```sh
NICEPROXY_CADDY_TEST_BINARY=/path/to/caddy go test -race -count=1 ./...
go vet ./...
npm --prefix web test
python3 scripts/smoke.py --caddy /path/to/caddy
python3 scripts/ownership-smoke.py --caddy /path/to/caddy
python3 scripts/virtual-park.py --caddy /path/to/caddy --instances 6 --clients 128 --cycles 50 --output test-results/park/fleet.json
```

The park keeps all 768 TCP clients open simultaneously across six instances.
It verifies nonce/payload and backend isolation, HTTP and TLS, foreign Host headers, target
changes, limits, process and backend crashes, session and rule persistence,
termination of TCP/UDP associations, and FD/RSS/threads. Details and limitations —
[virtual-park.md](virtual-park.md).

Observing new connections during owner handover involves several separate
API operations: disable, assign, and enable. Between them, the port may be closed;
these failures are recorded rather than excluded from the measurement. A held accepted TCP stream
is verified separately. These are distinct properties, so passing the stream-preservation test
does not imply zero failures for new connections.

Quick run for routing and concurrent clients only:

```sh
python3 scripts/virtual-park.py --caddy /path/to/caddy --instances 6 --clients 128 --functional-only
```

Real HTTP/3 (requires curl with HTTP3 support):

```sh
python3 scripts/http3-smoke.py --caddy /path/to/caddy
```

It tests QUIC with a trusted CA when TCP on the same port is occupied by direct forwarding;
then HTTPS over TCP with direct UDP, plus a foreign Host in HTTP/3 with verified SNI.

For Linux splice:

```sh
go test -c -o /tmp/niceproxy-proxy.test ./internal/proxy
strace -f -e trace=splice -o test-results/splice-bulk.trace /tmp/niceproxy-proxy.test -test.run '^TestTCPBulkSplice$' -test.count=1
```

## Local Load Testing

```sh
python3 scripts/benchmark-park.py --caddy /path/to/caddy --seconds 3 --repeats 2 --concurrency 1,16,64 --output test-results/park/benchmark.json
```

Go budgets are configured separately: `--backend-gomaxprocs 4`, `--client-gomaxprocs 4`,
`--app-gomaxprocs 4` (niceproxy and its inherited Caddy). All default to 4,
as in the baseline methodology. They change the environment only for temporary child processes;
the harness does not modify the production environment, affinity, or OS settings. The JSON stores
exact budgets, actual CPU affinity, and for each run CPU seconds,
measurement wall seconds, and mean cores: deltas of `/proc/PID/stat` for niceproxy/backend/Caddy,
and for the client, its own user+system CPU via `wait4`. For persistent processes,
the interval is determined by the midpoints of `/proc/PID/stat` reads; for the client, it includes its startup
and exit. These are approximate metrics, especially for short runs:
they do not match the generator's internal RPS interval. Mean cores is CPU seconds /
wall seconds, not CPU percentage. The JSON also records CPU tick resolution, CPU quota,
cpuset, and throttling across all accessible cgroup v2 ancestors before/after the run, inherited
GOGC/GOMEMLIMIT/GODEBUG/GOEXPERIMENT, and SHA-256 hashes of the three binaries.

`--proxy-only` excludes direct baselines. Explicit RPS targets can be checked as follows:

```sh
python3 scripts/benchmark-park.py --caddy /path/to/caddy --cases http_keepalive,tcp_256_reused,https_keepalive --seconds 15 --repeats 3 --concurrency 64 --proxy-only --backend-gomaxprocs 4 --client-gomaxprocs 4 --app-gomaxprocs 8 --targets 'tcp_256_reused=70000,http_keepalive=80000,https_keepalive=40000'
```

`passed` indicates functional success; `targetPassed` is the separate target outcome
(`null` if no targets were specified). Each target requires at least one concurrency level
where **all** expected proxy repeats completed with zero errors and each reached the target;
the average and maximum do not replace this check. `targetAssessment` contains the result
for each level. A missing case, or incomplete or repeated repeat numbers, fails the check.
Direct variants are not counted. An unmet explicit target produces a non-zero exit code,
even if the functional check passed. HTTP/HTTPS require the full expected
`bench-backend /` prefix and exact received bytes = succeeded × full body length;
HTTPS retains CA verification. Validator checks: `python3 -m unittest discover -s scripts/tests`.

To test TCP on a port assigned to public HTTP, there is a separate mode:

```sh
python3 scripts/benchmark-park.py --caddy /path/to/caddy --cases tcp_256_reused --tcp-on-http-port --seconds 15 --repeats 3 --concurrency 64 --proxy-only --app-gomaxprocs 8 --targets tcp_256_reused=70000
```

It explicitly sets the HTTP port owner to `direct` before creating the TCP rule; HTTP
is absent on that socket. For the unprivileged local harness, a random high port
from the range 20000–29999 is passed as `--http-port`.
This tests the same owner selection as public 80, rather than literally binding
to :80 or benchmarking a router. The exact port and owner are recorded in `listeners`.
Regular TCP forwarding and this mode use the same `internal/proxy` path, without a protocol detector.

The UDP creation queue is tested by separate regressions: 64/128 clients with a single first packet, delayed DNS, limits of 32 workers/128 requests/1 MiB, cancellation, and generation changes.

The generator validates response contents, does not retry lost UDP packets, and reports
failure on any error. It measures HTTP/1.1 and verified HTTPS, new TCP connections,
TCP/UDP request-reply with connection reuse, and 64 KiB TCP payload.
By default, new TCP connections are measured in short 1-second windows (`--new-connection-seconds`, max 1) to limit load on the shared conntrack table. Other modes use `--seconds`. Before runs, the harness reads conntrack and reserves headroom for new connections; under high usage, it waits for entries to expire naturally. It does not modify sysctl or flush unrelated entries. The pre-check does not protect against independent load from other programs.

For each mode, actual duration, successes/errors, payload bytes,
RPS, and approximate p50/p95/p99 are recorded. The unproxied backend is measured separately where
the protocol is identical; HTTPS has no spurious direct HTTP baseline. Generator details —
[parkload.md](parkload.md).

The `--cases udp_256_reused` parameter lets you run a single mode without repeating
the entire matrix. Example of cold UDP starts:

```sh
python3 scripts/benchmark-park.py --caddy /path/to/caddy --cases udp_256_reused --seconds 1 --repeats 5 --concurrency 64 --output test-results/park/udp-cold.json
```

niceproxy, Caddy, the backend, and the generator share the same machine. The load is
closed-loop: a client's next request is sent after receiving a response rather than on an independent
schedule. Therefore, this RPS does not prove sustaining a given external arrival rate
or WAN throughput. For TCP with a specified source IP, the generator uses Linux IP_BIND_ADDRESS_NO_PORT; without it, bind-before-connect distorts the shared local port pool. No comparison with nginx is performed. SQLite DB/WAL
are compared before and after pure traffic without administrative mutations during the interval.

## Rootless Container

Standard build:

```sh
podman build -t localhost/niceproxy:test .
```

If the registry is unreachable, there is a separate diagnostic image built from local
static Go/Caddy, prebuilt UI, and the system CA bundle:

```sh
python3 scripts/park-container.py --build --caddy /path/to/caddy
python3 scripts/smoke.py --binary scripts/park-container.py --caddy /path/to/caddy
python3 scripts/ownership-smoke.py --binary scripts/park-container.py --caddy /path/to/caddy
```

The container is rootless, with host networking, `cap_drop ALL`, `no-new-privileges`, PID/memory/FD
limits, and mounts only the temporary root of the specific test. Neither the Docker
socket, `privileged`, nor `NET_ADMIN` is required. It verifies Go/Caddy in the container,
but does **not** verify Node/bootstrap or the build stages of the standard Dockerfile. This is a separate
result that must not be presented as a passing standard build.

Results and logs are saved in `test-results/`. Keep failed runs
separate from re-runs after fixes — especially on UDP losses or bind failures.
