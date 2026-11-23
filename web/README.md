# Niceproxy web

React + TypeScript panel using Alpha UI 0.4.9. It provides password setup and login, CRUD for HTTP/HTTPS and TCP/UDP routes, and saved/applied revision status.

```sh
cd web
npm ci
npm run typecheck
npm run build
npm start
```

`npm start` runs `scripts/alpha-bootstrap.mjs`. With `NICEPROXY_ALPHA_RELEASE_URL`, it verifies `latest.json`, the manifest, and SHA-512 archives for core/react/project-server, builds in staging within one 20-second deadline, and activates only a ready build. Without a URL, the local version is used. Errors and timeouts fall back to the last working build. `node scripts/alpha-bootstrap.mjs --prepare` prints the active build path.

API endpoints include `GET /api/auth`, `POST /api/setup` and `/api/login` with `{password}`, `POST /api/logout`, `GET /api/config` with `{revision,httpRoutes,directRules}`, CRUD for `/api/http-routes/:id` and `/api/direct-rules/:id`, and `GET /api/health` with `{status,caddy,revision,appliedRevision,error?}`. Non-2xx responses return JSON `error`; 401 returns the login screen.
