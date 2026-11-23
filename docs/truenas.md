# TrueNAS SCALE

niceproxy was verified as a Custom App on SCALE 25.10.4 with the original Dockerfile, host networking, and a NAS-local bind mount for `/data`. Docker socket and privileged mode are not required.

Create a dedicated dataset and data directory owned by UID/GID 1000 with mode 0700. Copy source to the NAS without `.git`, data, `.env`, `node_modules`, or local binaries. Use an absolute NAS path for `build.context`.

```yaml
services:
  niceproxy:
    build:
      context: /mnt/POOL/apps/niceproxy/source
    image: niceproxy:truenas-local
    pull_policy: build
    user: "1000:1000"
    network_mode: host
    restart: unless-stopped
    cap_drop: [ALL]
    security_opt: ["no-new-privileges:true"]
    environment:
      HOME: /data
      NICEPROXY_ALPHA_STATE_DIR: /tmp/niceproxy-ui
      NICEPROXY_PANEL_LISTEN: "YOUR_LAN_IP:19080"
      NICEPROXY_DOMAIN: "cf.example.com" # optional public panel and Cloudflare callback hostname
      NICEPROXY_HTTP_PORT: "18080"
      NICEPROXY_HTTPS_PORT: "18443"
    volumes:
      - type: bind
        source: /mnt/POOL/apps/niceproxy/data
        target: /data
        bind:
          create_host_path: false
    tmpfs:
      - /run/niceproxy:uid=1000,gid=1000,mode=0700
      - /tmp:mode=1777
    ulimits:
      nofile:
        soft: 262144
        hard: 262144
    stop_grace_period: 20s
```

Replace `POOL`, paths, and `YOUR_LAN_IP`. Keep a separate build compose file for updates. Remove `build` and set `pull_policy: never` in the runtime compose so normal starts use the existing image. Future builds need NAS access to base images, Go/npm, and Debian repositories.

Without capabilities, listeners from port 1024 are supported. For standard public ports, forward external 80/TCP to NAS:18080, 443/TCP to NAS:18443, and 443/UDP to NAS:18443 for HTTP/3. HTTP(S) listeners appear when routes are added or `NICEPROXY_DOMAIN` is set. Public ACME also needs correct DNS and a reachable challenge path. Keep the NAS and niceproxy panels on their separate trusted networks.

Host networking shares ports with every NAS service. Check conflicts when creating rules. A container can be healthy while one route fails, so check desired/applied revisions and UI errors. Back up all of `/data`, including SQLite WAL, certificates, and the Cloudflare key, before updates. Use a new release tag and keep the previous image until verification.

The upstream Caddy image has file capabilities. Dockerfile copies the binary as a new file so `cap_drop: ALL` does not fail with `operation not permitted`. Keep this step and verify startup after image changes.
