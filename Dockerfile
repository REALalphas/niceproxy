FROM docker.io/library/caddy:2.10.2 AS caddy

FROM docker.io/library/golang:1.26.0-bookworm AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /niceproxy ./cmd/niceproxy

FROM docker.io/library/node:22.16.0-bookworm-slim AS frontend
WORKDIR /app
COPY assets/alpha ./assets/alpha
COPY web/package*.json ./web/
WORKDIR /app/web
RUN npm ci
COPY web ./
RUN npm run typecheck && npm run build

FROM docker.io/library/node:22.16.0-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tini && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Install a fresh file so Caddy's upstream file capabilities are not inherited.
# File capabilities outside cap_drop: ALL make exec fail with EPERM on Linux.
COPY --from=caddy /usr/bin/caddy /tmp/caddy-bundled
COPY --from=backend /niceproxy /usr/local/bin/niceproxy
COPY --from=frontend /app/web /app/web
COPY --from=frontend /app/assets /app/assets
COPY scripts/container-start.sh /usr/local/bin/niceproxy-start
RUN install -m 0755 /tmp/caddy-bundled /usr/local/bin/caddy \
    && rm /tmp/caddy-bundled \
    && chmod +x /usr/local/bin/niceproxy-start
ENV NICEPROXY_DATA_DIR=/data NICEPROXY_RUNTIME_DIR=/run/niceproxy NICEPROXY_PANEL_LISTEN=127.0.0.1:9080 NICEPROXY_CADDY_BIN=/usr/local/bin/caddy
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["niceproxy", "healthcheck"]
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/niceproxy-start"]
