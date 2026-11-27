# niceproxy

Linux host with a web panel for publishing HTTP/HTTPS and individual TCP/UDP ports. A single container includes niceproxy and a bundled Caddy instance. External tunnels and intermediate VPS servers are not required.

## Startup

```sh
docker compose up -d --build
```

Panel: `http://127.0.0.1:9080`. On first sign-in, set a password of 12–72 bytes. The password is stored as a bcrypt hash, and sessions are stored in SQLite. Complete initial setup locally first, then expose the panel on your LAN if needed.

To access from another machine, set `NICEPROXY_PANEL_LISTEN=<LAN-IP>:9080` in `.env` and recreate the container. Do not expose the HTTP panel to the public internet: use a protected administrative network. Port 9080 and management sockets are separated from published services.

`network_mode: host` allows adding ports from the interface without recreating the container. The container only requires permission to bind low ports (`NET_BIND_SERVICE`); the Docker socket, `privileged`, and `NET_ADMIN` are not used. On rootless Docker/Podman, access to ports below 1024 additionally depends on Linux host policy.

On TrueNAS SCALE, use host networking and a separate dataset for `/data`. If ports 80/443 are occupied by the NAS UI, assign free high ports to Caddy and configure corresponding port forwarding on your router if needed. A tested deployment setup is described in [docs/truenas.md](docs/truenas.md). TrueNAS CORE (FreeBSD) is not supported.

## Routes

- **HTTP/HTTPS:** domain, path prefix, and target application address such as `http://192.168.1.20:3000`, with TLS set to `auto`, `internal`, or `off`. On a single domain, you can route `/api` to an API service, `/files` to a file service, and `/` to the main application. `/api` matches `/api` and `/api/...`, but not `/apix`; the longest matching path is selected first. Paths are case-sensitive: `/API` and `/api` are distinct. Unmatched paths return 404. Path and query string are preserved; the "Strip path prefix" option turns, for example, `/api/users?q=1` into `/users?q=1`. All paths on the same domain share the same TLS setting. Legacy entries automatically receive `/`. Caddy terminates HTTPS and supports WebSocket. For a public certificate, the domain must point to a public IP address and domain validation must reach Caddy. In local `internal` mode, Caddy's root certificate must be installed on client devices.
- **TCP/UDP:** protocol, bind IP, incoming port, target IP/hostname, and a separate target port. For example, `TCP 0.0.0.0:1234` forwards to `192.168.1.20:3300`. TCP can pass TLS through unchanged; in that case, the target service handles the certificate.

In the "Routes" section, when creating or editing a route, niceproxy automatically selects web access or direct forwarding and claims the required public port. A conflict with another enabled route returns HTTP 409 with a clear address and port, without writing the new configuration. The control panel remains on a separate reserved port. The legacy port-ownership API is kept for compatibility. See [docs/port-ownership.md](docs/port-ownership.md) for details. In HTTP mode, the client address is passed via proxy headers. With direct TCP/UDP forwarding, the target service sees the niceproxy address. FTP active mode and other protocols with embedded addresses may require separate configuration.

In the "Routes" section, both rule types appear in a single list. Each row shows the incoming domain and path or TCP/UDP port → target, status, and actions. A filter lets you display only the desired type.

## Cloudflare

The Cloudflare section connects your account via official OAuth PKCE without manually entering an API token. Your deployment requires one-time registration of a public OAuth client ID and permissions; afterwards, you can sign in with a localhost callback from the LAN panel and automatically configure TLS via OAuth. Domain selection and creating/updating A, AAAA, and CNAME records with explicit confirmation are supported. Client setup and constraints are described in [docs/cloudflare.md](docs/cloudflare.md).

Your router forwards the required external ports to the niceproxy host. When forwarding an entire port range, the Linux firewall must also block unrelated host services: host networking does not hide SSH, the NAS UI, or other already listening ports. niceproxy itself listens only on explicitly enabled rules.

## State and Data

The `/data` volume stores SQLite, settings, the last successfully applied configuration, Caddy certificates, and prebuilt UI bundles. Saving creates a desired revision, then triggers apply. An occupied port or Caddy error is shown on the rule; a successful save does not guarantee a successful apply. On partial apply, there is no single active revision (`appliedRevision: -1`). On restart, saved rules are restored. If a public port is occupied, the panel starts separately and allows fixing the routes. Caddy receives its configuration via a private Unix admin socket. Diagnostics are available via `docker compose logs`. `GET /api/health` additionally reports lifecycle `state` and certificate status. Possible states include `ready`, `waiting_dns`, `waiting_acme`, `invalid_certificate`, `partially_applied`, and `unrecoverable_corruption`. Diagnostics are available at `/healthz`. The public panel hostname is configured via `NICEPROXY_DOMAIN` on first startup or via `PATCH /api/panel-domain` with `{ "panelDomain": "panel.example.com" }`. This hostname is reserved against user routes, served by Caddy with the same SNI, and used in the Cloudflare callback URL. A Cloudflare-proxied record requires an origin certificate or DNS-01; otherwise, health reports the exact recovery condition.

Changing a TCP target applies to new connections; existing ones continue using the previous target. Disabling or deleting a direct rule immediately releases the listener while keeping accepted TCP streams active until they finish. When changing a listener address via edit, a bounded drain period applies; when the entire process stops, remaining streams are forcefully terminated after the shutdown deadline. UDP associations are reset when the target changes. Connection/association counts are limited per rule, including still-running generations; the number of released listeners with unfinished streams is bounded separately. There is no forced lifetime limit on TCP streams. Direct rule rows display active/accepted connections and errors; values are updated with the "Refresh" button. Counters live in process memory and reset on restart. For UDP, associations are counted rather than packets. `rejects` reflects only application-rejected attempts, not connections to a closed port or one not forwarded by the router.

## Performance

Direct TCP uses `io.Copy` between concrete `*net.TCPConn` instances, preserving Linux `splice` support. SQLite and the HTTP API are not on the traffic path. UDP preserves datagram boundaries, has an idle timeout, and enforces resource limits. Initial packets from new clients are accepted into a bounded queue: up to 128 pending associations and up to 1 MiB of data per rule, with 32 concurrent workers. Repeated packets from a client before its association is ready may be dropped; queue overflows are counted in rejects. Batched `recvmmsg/sendmmsg` is not yet implemented.

A 100k/s threshold is not claimed without load testing on target hardware. HTTP requests/s, new TCP connections/s, concurrent open connections, and UDP packets/s are distinct metrics. Environment limits are documented in `.env.example`.

## Development and Testing

The virtual park, load tests, HTTP/3, and rootless checks are described in [docs/testing.md](docs/testing.md).

```sh
npm --prefix web ci
npm --prefix web run typecheck
npm --prefix web run build
npm --prefix web test
go test -race ./...
go vet ./...
go build -o bin/niceproxy ./cmd/niceproxy
python3 scripts/smoke.py --caddy /path/to/caddy
python3 scripts/ownership-smoke.py --binary bin/niceproxy --caddy /path/to/caddy
```

Install Caddy 2.10.2 or specify the path with `--caddy /path/to/caddy`. Running without low ports:

```sh
./bin/niceproxy --http-port 8080 --https-port 8443
```

To verify TCP splice:

```sh
go test -c -o /tmp/niceproxy-proxy.test ./internal/proxy
strace -f -e splice /tmp/niceproxy-proxy.test -test.run '^TestTCPMapping$'
```

Verified suite: Go tests with race detector and vet, Caddy 2.10.2, end-to-end HTTP/HTTPS with local CA verification, TCP/UDP with separate ports, recovery after restart and occupied port, and browser interactions at 1440 and 320 px. Public ACME requires verification with a real domain. The image was built and run on TrueNAS SCALE 25.10.4: Docker healthcheck, HTTP/HTTPS, paths, TCP/UDP with separate ports, and recovery after restart were confirmed.

Alpha UI 0.4.11 is bundled as local archives inside the repository. Startup updates use a configurable trusted `NICEPROXY_ALPHA_RELEASE_URL`; without the URL or on error, the latest prebuilt local build is used. See `web/README.md` for details.
