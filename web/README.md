# Niceproxy web

Niceproxy web panel built with React + TypeScript and Alpha UI 0.4.12-niceproxy.4 (a local extension from 0.4.11 sources). English UI: initial setup and password sign-in, CRUD for HTTP/HTTPS routes and TCP/UDP rules, and saved vs. applied revision status.

Screen structure and emphasis hierarchy: [UI design](../docs/ui-design.md).

```sh
cd web
npm ci
npm run typecheck
npm run build
npm start
```

For a dev server accessed via a public hostname, set `NICEPROXY_DOMAIN` in the
repository `.env` or set a list of hostnames via `VITE_ALLOWED_HOSTS`, e.g.
`VITE_ALLOWED_HOSTS=cf.toxl.fun npm run dev -- --host 0.0.0.0`. Vite is for
development only. Public TCP 80 and 443 must reach Caddy for ACME validation.

`npm start` runs `scripts/alpha-bootstrap.mjs`. When `NICEPROXY_ALPHA_RELEASE_URL` is set, the script verifies `latest.json`, the manifest, and SHA-512 checksums of the core/react/project-server archives, builds in staging within a 20-second total timeout, and activates only a completed build. Without the URL, the local version is used explicitly; errors and timeouts fall back to the last working build. `node scripts/alpha-bootstrap.mjs --prepare` prints the active build path without starting the server.

API: `GET /api/auth`; `POST /api/setup` and `/api/login` `{password}`; `POST /api/logout`; `GET /api/config` `{revision,panelDomain,httpRoutes,directRules}`; `GET/PATCH /api/panel-domain`; CRUD `/api/http-routes/:id` and `/api/direct-rules/:id`; `GET /api/health` `{status,state,caddy,revision,appliedRevision,panelDomain,certificate,error?}`. Non-2xx responses contain JSON `error`, and 401 returns the sign-in screen. UI builds are selected from `/data/ui` only after atomic marker, version and digest validation.
