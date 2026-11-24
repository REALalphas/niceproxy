ARG APP_VERSION=0.1.0

FROM docker.io/library/caddy:2.10.2 AS caddy

FROM docker.io/library/golang:1.26.0-bookworm AS backend
ARG APP_VERSION
ARG GOARCH
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN target_arch="${GOARCH:-${TARGETARCH:-amd64}}" \
    && CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" go build -trimpath -ldflags="-s -w -X main.version=${APP_VERSION}" -o /niceproxy ./cmd/niceproxy

FROM scratch AS backend-artifact
COPY --from=backend /niceproxy /niceproxy

FROM docker.io/library/node:22.16.0-bookworm-slim AS frontend
ARG APP_VERSION
WORKDIR /app
COPY assets/alpha ./assets/alpha
COPY web/package*.json ./web/
WORKDIR /app/web
RUN npm ci
COPY web ./
RUN npm run typecheck && npm run build

FROM scratch AS frontend-artifact
COPY --from=frontend /app/web /web
COPY --from=frontend /app/assets /assets

FROM docker.io/library/node:22.16.0-bookworm-slim AS runtime-base
ARG APP_VERSION
LABEL org.opencontainers.image.version="${APP_VERSION}"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tini && rm -rf /var/lib/apt/lists/*
WORKDIR /app
# Install a fresh file so Caddy's upstream file capabilities are not inherited.
# File capabilities outside cap_drop: ALL make exec fail with EPERM on Linux.
COPY --from=caddy /usr/bin/caddy /tmp/caddy-bundled
COPY scripts/container-start.sh /usr/local/bin/niceproxy-start
RUN install -m 0755 /tmp/caddy-bundled /usr/local/bin/caddy \
    && rm /tmp/caddy-bundled \
    && chmod +x /usr/local/bin/niceproxy-start
ENV NICEPROXY_DATA_DIR=/data NICEPROXY_RUNTIME_DIR=/run/niceproxy NICEPROXY_PANEL_LISTEN=127.0.0.1:9080 NICEPROXY_CADDY_BIN=/usr/local/bin/caddy
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD ["niceproxy", "healthcheck"]

# The release workflow supplies this context with the already-built backend and
# frontend artifacts. Keeping the regular image as the default target preserves
# local `docker compose build` usage.
FROM runtime-base AS release
ARG APP_VERSION
ARG TARGETARCH
COPY --chmod=755 --from=release-artifacts /niceproxy-${TARGETARCH} /usr/local/bin/niceproxy
COPY --from=release-artifacts /web /app/web
COPY --from=release-artifacts /assets /app/assets
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/niceproxy-start"]

FROM runtime-base
COPY --from=backend /niceproxy /usr/local/bin/niceproxy
COPY --from=frontend /app/web /app/web
COPY --from=frontend /app/assets /app/assets
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/niceproxy-start"]
