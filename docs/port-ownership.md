# Port Ownership

niceproxy does not detect protocols by inspecting connection payloads. A single listener runs on each address and port for a given transport. HTTP(S), paths, WebSocket, certificates, and ACME stay with the bundled Caddy; direct TCP/UDP is served by Go. There is no domain field in the raw forwarding form.

The `portOwners` configuration contains three independent assignments: `http`, `https`, and `http3`, each set to `caddy` or `direct`. For legacy configurations, missing assignments default to `caddy`. No new SQL migration is required for this. The setting applies to the actual port numbers from `NICEPROXY_HTTP_PORT` and `NICEPROXY_HTTPS_PORT`, not necessarily 80/443.

In the standard UI, there is no separate port-assignment screen. When creating or editing a route, niceproxy automatically selects the appropriate handler and updates public port owners in a single operation. If a port is already required by another enabled route, the error is displayed on that route with the address and port. The legacy `GET/PATCH /api/port-owners` API is kept for compatibility and emergency recovery.

## Conflicts

- The control panel port is always reserved.
- An enabled direct rule on a port assigned to Caddy for that transport returns 409.
- Overlapping enabled direct listeners on the same transport, including wildcards and equivalent IPs, return 409.
- HTTP without TLS requires HTTP to be assigned to Caddy. A TLS route requires at least HTTPS or HTTP/3 on Caddy.
- When transferring 443/UDP to a direct rule, Caddy disables HTTP/3 while keeping HTTPS over TCP.
- When transferring HTTPS/TCP to a direct rule, Caddy can only serve HTTP/3 over UDP. No HTTP redirect to TCP HTTPS is created in this mode. This does not mean a standard browser will automatically reach HTTP/3 without TCP: the client needs a way to discover the QUIC endpoint.
- For `auto` ACME, at least one TCP challenge port must remain with Caddy. The generator disables HTTP-01/TLS-ALPN-01 for ports transferred to direct rules. External challenge reachability also depends on DNS and the router.

A logical conflict does not write a new revision. The OS bind check remains authoritative: another process may occupy a previously free port. In that case, the desired configuration is saved with an apply error, `appliedRevision=-1`, and the panel remains available for recovery.

## Switching

Caddy configuration is validated before releasing active direct listeners. When disabling or deleting a direct rule, the listener is released immediately; already-accepted TCP connections continue using the previous target. Their completion does not delay applying the new owner. Prepared changes are applied serialized. This is verified with a real TCP stream during port handover to Caddy.

At the OS level, the listener is still released and rebound by the next owner; measuring the control request duration does not guarantee zero failures for all new connections at that moment. Claims of outperforming nginx or reaching 100k/s require dedicated load testing.

A shared connection limit across old and new generations applies per rule ID. At most 1024 listener generations may remain in drain; reaching the limit keeps the previous listener and displays an error. Stopping the entire application drains remaining streams up to the shutdown deadline.

## Statistics

`GET /api/config` adds a runtime `stats` field to direct rules: `accepted`, `active`, `closed`, `errors`, `rejects`, `startedAt`. It is not persisted in the DB. Values are atomic, though individual fields in a snapshot may come from adjacent moments in time.

TCP `accepted` counts accepted sockets, including those subsequently rejected by the limit; `active` includes admitted connections with a pending dial; `closed` counts completed accepted connections. UDP counts association attempts, including the creation queue and pending dials; `rejects` records admission denials without storing history of rejected clients. Idle expiry and administrative stop are not counted as network errors. Errors are counted at the lifecycle level without wrapping TCPConn and without a counter on each transferred chunk.

Counters are scoped to a rule ID and reset on process restart. The inactive ID table is bounded; deleted rules may free their statistics once their streams finish. Closed ports and traffic blocked by the router never reach the application.

## API

```text
GET /api/port-owners
→ {httpPort, httpsPort, owners: {http, https, http3}}

PATCH /api/port-owners
{ "https": "direct", "http3": "direct" }
→ updated configuration with revision
```

All changes require an existing administrative session and pass through the shared mutation queue.

Checks: `go test -race ./...`, `go vet ./...`, frontend typecheck/build/tests, legacy `scripts/smoke.py`, new `scripts/ownership-smoke.py`, and `strace -f -e splice` on the TCP bulk test. The previous-version NAS installation is not modified by this work.
