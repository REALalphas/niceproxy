# niceproxy

Linux self-hosted proxy with a web panel for HTTP/HTTPS and direct TCP/UDP forwarding. One container runs niceproxy and bundled Caddy. No tunnel or relay VPS is required.

## Run

```sh
docker compose up -d --build
```

A push to `master` builds and publishes a multi-arch image to GHCR. Tags use `0.1.N`, where `N` is the GitHub Actions run number. GHCR keeps the numbered tag and moving `latest`; commit SHA tags are not published.

```sh
export NICEPROXY_IMAGE=ghcr.io/realalphas/niceproxy:latest
docker compose pull
docker compose up -d --no-build
```

Open `http://127.0.0.1:9080`. On first login, set a 12–72 byte password. Passwords use bcrypt and sessions use SQLite. Complete setup locally before exposing the panel on a LAN.

Set `NICEPROXY_PANEL_LISTEN=<LAN-IP>:9080` in `.env` to use another machine, then recreate the container. Keep the panel on a trusted admin network. Port 9080 and control sockets are separate from published services.

`network_mode: host` lets the panel add listeners without recreating the container. Only `NET_BIND_SERVICE` is needed for low ports. Docker socket, `privileged`, and `NET_ADMIN` are not used. Rootless Docker/Podman still follows the host policy for ports below 1024.

For TrueNAS SCALE, use host networking and a dedicated `/data` dataset. If the NAS panel owns 80/443, assign free high ports to Caddy and forward them on the router. See [docs/truenas.md](docs/truenas.md). TrueNAS CORE is unsupported.

## Routes

- **HTTP/HTTPS** accepts a domain, path prefix, target such as `http://192.168.1.20:3000`, and TLS mode `auto`, `internal`, or `off`. `/api` matches `/api` and `/api/...`, but not `/apix`. The longest matching path wins and matching is case-sensitive. Paths and queries are preserved unless **Strip path prefix** is enabled. All paths on one domain share TLS. Old records default to `/`. Caddy terminates HTTPS and supports WebSocket. Public certificates require DNS and ACME checks to reach Caddy. Install Caddy's root certificate on clients when using `internal` TLS.
- **TCP/UDP** accepts a protocol, listen address and port, target address, and target port. Example `TCP 0.0.0.0:1234` forwards to `192.168.1.20:3300`. TCP can pass TLS through to the target.

TCP 80/443 and UDP 443 are reserved for Caddy HTTP/3. Environment variables can change those ports. Caddy forwards the client address in HTTP headers. Direct TCP/UDP targets see the niceproxy address, not the original client address. Protocols that embed addresses, such as FTP active mode, need separate handling.

HTTP and direct rules share one list. Each row shows the incoming endpoint, target, status, and actions. Filter by HTTP, TCP, or UDP.

## Cloudflare

Cloudflare uses official OAuth PKCE. No API token is entered in the panel. Register one public OAuth client for the installation, then connect the account. The panel can list zones and create or edit A, AAAA, and CNAME records after explicit confirmation. See [docs/cloudflare.md](docs/cloudflare.md).

Set `NICEPROXY_DOMAIN=cf.example.com` when the Cloudflare callback should use a public hostname. Caddy then serves that hostname, obtains its HTTPS certificate, and proxies the panel and `/api/cloudflare/callback`. Leave it empty for a fully local HTTP callback.

Forward required external ports from the router to the niceproxy host. If forwarding a full range, the host firewall must protect unrelated services because host networking exposes existing listeners. niceproxy listens only on enabled rules.

## State and data

`/data` stores SQLite, settings, the last applied configuration, Caddy certificates, and built UI assets. Saving creates a desired revision and then applies it. Port conflicts and Caddy errors are shown on the rule. A successful save does not prove that the revision was applied. Partial apply reports `appliedRevision: -1`. Rules recover after restart. If a public port is busy, the panel stays available on its separate listener. Caddy uses a private Unix admin socket. Use `docker compose logs` for diagnostics.

Changing a TCP target affects new connections. Existing connections keep their current target. Removing or changing a listener uses a short drain period, then closes connections. Changing a UDP target resets associations. Connection and association limits are per rule. TCP streams have no forced lifetime limit.

## Performance

Direct TCP uses `io.Copy` between concrete `*net.TCPConn` values so Linux `splice` remains available. SQLite and the HTTP API are not on the traffic path. UDP preserves datagram boundaries, uses an idle timeout, and applies resource limits. `recvmmsg/sendmmsg` batching is not implemented.

No 100k/s claim is made without target hardware measurements. HTTP requests/s, new TCP connections/s, open connections, and UDP packets/s are separate metrics. Environment limits are listed in `.env.example`.

## Development and checks

GitHub Actions runs these checks on Linux for pull requests and pushes to `master`. The smoke test uses Caddy 2.10.2. `strace` verifies `splice` on the TCP path.

```sh
npm --prefix web ci
npm --prefix web run typecheck
npm --prefix web run build
npm --prefix web test
go test -race ./...
go vet ./...
go build -o bin/niceproxy ./cmd/niceproxy
python3 scripts/smoke.py --caddy /path/to/caddy
```

Install Caddy 2.10.2 or pass `--caddy /path/to/caddy`. Run without low ports:

```sh
./bin/niceproxy --http-port 8080 --https-port 8443
```

Check TCP splice:

```sh
go test -c -o /tmp/niceproxy-proxy.test ./internal/proxy
strace -f -e splice /tmp/niceproxy-proxy.test -test.run '^TestTCPMapping$'
```

The verified set covers Go race tests and vet, Caddy 2.10.2, end-to-end HTTP/HTTPS with a local CA, TCP/UDP on separate ports, restart and port-conflict recovery, and browser checks at 1440 and 320 px. Public ACME needs a real domain. A TrueNAS SCALE 25.10.4 deployment confirmed Docker health checks, HTTP/HTTPS, path routing, TCP/UDP, and restart recovery.

Alpha UI 0.4.9 is bundled as local archives. Startup updates use the trusted `NICEPROXY_ALPHA_RELEASE_URL`; without it or after an update error, the last working local build is used. See `web/README.md`.
