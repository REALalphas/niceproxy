# parkload test traffic helper

`parkload` is a Linux test-only backend and closed-loop load client, implemented
with the Go standard library. It does not configure interfaces, routes, firewall
rules, proxies, or host services. Build from the repository root:

```sh
go build -o bin/parkload ./scripts/parkload
```

Start a backend (the default listen IP is `127.0.0.1`, all ports default to zero):

```sh
bin/parkload serve --listen-host 127.40.0.10 --http-port 0 --tcp-port 0 --udp-port 0 --id backend-a
```

After binding **all three** listeners, stdout receives exactly one JSON line:

```json
{"http":"127.40.0.10:41001","tcp":"127.40.0.10:41002","udp":"127.40.0.10:41003","id":"backend-a"}
```

Use the actual allocated ports from readiness. The process stays running until
SIGINT/SIGTERM. Shutdown closes listeners, active HTTP connections, and active
raw TCP streams, including idle streams. A listener failure also shuts down the
other listeners. HTTP supports HTTP/1.1 keepalive, returns `ID requestURI` without
a trailing newline, and sets `X-Park-Backend: ID`. TCP echoes the exact stream;
UDP echoes each datagram. The backend has no TLS listener; use the proxy/Caddy
HTTPS endpoint to measure TLS.

```sh
bin/parkload load --protocol http --target 127.40.0.10:41001 --host fleet.test --path '/probe?nonce=123' --duration 5s --concurrency 32 --expect-prefix 'backend-a /probe?nonce=123'
bin/parkload load --protocol tcp --target 127.40.0.10:41002 --duration 5s --concurrency 32 --payload-size 256 --connections reused
bin/parkload load --protocol udp --target 127.40.0.10:41003 --duration 5s --concurrency 32 --payload-size 256 --connections new --source-host 127.40.0.20
bin/parkload load --protocol https --target 127.0.0.1:443 --host fleet.test --ca /path/root.crt --path / --expect-prefix 'backend-a ' --duration 5s --concurrency 32
```

HTTPS always verifies the certificate chain and hostname. `--ca` supplies a PEM
trust bundle; omitting it uses OS trust. `--host` controls HTTP Host and TLS SNI
(default: target hostname). The actual connection always goes to `--target`,
regardless of the Host/SNI name; environment proxy variables are ignored.
Redirects are not followed. HTTP responses must be 2xx, fully read, and no larger
than 16 MiB; optional `--expect-prefix` verifies the response body prefix, not the
header. Compression negotiation is disabled so byte counts represent body bytes
read from the connection, without transparent decompression. HTTP is GET only:
`--payload-size` applies exclusively to TCP/UDP, and HTTP `payloadBytes` is zero.

`--source-host` binds the client socket to the given existing local IP. It does
not add addresses. For TCP (including HTTP/TLS), Linux `IP_BIND_ADDRESS_NO_PORT`
defers port allocation until connect while preserving the requested source IP.
This prevents bind-before-connect from unnecessarily consuming local bind buckets
in a shared-host process park. It does not alter the proxy or kernel settings. `--connections reused` (default) keeps one connection per
worker, reconnecting after failures. `new` creates a connection for each request
(and a new UDP socket for each datagram). TCP stream requests are sequential:
one payload followed by its complete echo. Payload contents vary deterministically
with worker and request sequence; every response byte and length is checked.
This detects corruption and stale UDP responses; payloads of only a few bytes
naturally have limited nonce space. TCP reads/writes handle partial I/O.

Each worker starts requests until `--duration` expires. In-flight requests finish
or fail within `--timeout` (default 5s); they are never silently discarded or
cancelled merely because the run duration expired. For TCP/UDP, a single absolute
deadline covers dialing, complete write, and complete echo read together, rather
than resetting the timeout after every partial operation. HTTP uses a total
client deadline including dialing, TLS, headers, and body. Actual elapsed run
time can exceed configured duration by roughly one timeout plus scheduling and
cleanup overhead. Load mode prints one JSON report after all workers finish.
Failures produce a nonzero exit status **after** the report; use `--allow-errors`
for intentional failure loads. Diagnostics go to stderr.

Metrics and limits:

- `attempted = succeeded + errors`, including failed dials and in-flight failures.
  `requestsPerSecond` is successful requests divided by **actual**
  `durationSeconds`; `requestedDurationSeconds` records the configured duration.
- `sentBytes` and `receivedBytes` count application payload I/O, including partial
  failed operations. `bytes` is their sum: an echoed 256-byte payload counts 512
  bytes. HTTP counts response body bytes only; HTTP headers, TCP/IP, TLS, and
  other transport overhead are excluded. These are not wire bandwidth metrics.
- `latencyMs` covers all attempts, including failures, from request start through
  completion. Quantiles use a fixed 2,048-bucket logarithmic histogram per worker,
  with 1 microsecond base and 1% bucket spacing. Reported quantiles are bucket
  upper bounds (clamped to the exact observed maximum). The final overflow bucket
  starts around 700 seconds and loses precision for unusually long timeouts.
  `max` is exact. No per-request latency slice is retained.
- At most five error samples are retained per worker and five emitted. Samples
  are the first errors within each worker, merged in worker order, rather than
  the globally earliest errors. `errorSamples` is null when there are none.
- Concurrency must be 1..1024. Payloads must be 1..16 MiB; UDP is capped at 65,507
  bytes. Buffers and histograms are bounded per worker, but high concurrency with
  large payloads can still consume substantial memory: TCP/UDP use approximately
  twice payload size per worker, plus histogram and transport overhead. HTTP
  uses a 32 KiB streaming read buffer per worker and retains only the requested
  verification prefix, not the entire response body.
- This is a closed-loop workload: workers wait for responses before issuing more
  requests. Client CPU, payload generation, scheduling, network behavior, and
  connection setup can limit throughput. No throughput level is guaranteed.
  Compare direct versus proxy paths using the same host, payload, connection
  mode, and concurrency (for example 1, 16, and 64); retain the JSON reports.

Scoped verification:

```sh
go test -race ./scripts/parkload
go vet ./scripts/parkload
```

Tests cover CLI validation and exit behavior, trusted/untrusted/wrong-host TLS,
Host/SNI with target override, corrupt TCP/UDP echoes, TCP partial reads, HTTP
prefix/status/truncation/size/deadline failures, statistics bounds, readiness,
and shutdown with an idle TCP stream. For a brief manual self-test, start a
backend and run each of HTTP/TCP/UDP with `--duration 1s --concurrency 1` against
its readiness addresses, then send SIGTERM and wait for it to exit.

Recorded direct self-test on 2026-11-08 (temporary executable removed afterward):

```sh
go build -o /tmp/parkload-selftest-rx4yqwx6/parkload ./scripts/parkload
/tmp/parkload-selftest-rx4yqwx6/parkload serve --listen-host 127.40.0.10 --http-port 0 --tcp-port 0 --udp-port 0 --id backend-a
/tmp/parkload-selftest-rx4yqwx6/parkload load --protocol tcp --target 127.40.0.10:46539 --duration 1s --concurrency 1 --payload-size 256 --connections reused --source-host 127.40.0.20
/tmp/parkload-selftest-rx4yqwx6/parkload load --protocol udp --target 127.40.0.10:55708 --duration 1s --concurrency 1 --payload-size 256 --connections reused --source-host 127.40.0.20
/tmp/parkload-selftest-rx4yqwx6/parkload load --protocol http --target 127.40.0.10:38957 --duration 1s --concurrency 1 --payload-size 256 --connections reused --source-host 127.40.0.20 --host fleet.test --path '/probe?nonce=123' --expect-prefix 'backend-a /probe?nonce=123'
```

All three one-second runs returned zero errors with consistent counts. The backend
received SIGTERM afterward and exited with status zero and no additional stdout
or stderr. These were correctness smoke tests, not a throughput claim.
