export type Health = "healthy" | "unknown" | "error";
export type LifecycleState =
  | "ready"
  | "migrating"
  | "waiting_dns"
  | "waiting_acme"
  | "invalid_certificate"
  | "partially_applied"
  | "unrecoverable_corruption";
export type Auth = { configured: boolean; authenticated: boolean };
export type HttpRoute = {
  id: string;
  host: string;
  path: string;
  stripPrefix: boolean;
  target: string;
  tls: "auto" | "internal" | "off";
  enabled: boolean;
  status: Health;
  error?: string;
};
export type PortOwners = Record<"http" | "https" | "http3", "caddy" | "direct">;
export type PortOwnerSettings = {
  httpPort: number;
  httpsPort: number;
  owners: PortOwners;
};
export type DirectStats = {
  accepted: number;
  active: number;
  closed: number;
  errors: number;
  rejects: number;
  startedAt: string;
};
export type DirectRule = {
  id: string;
  protocol: "tcp" | "udp";
  listenHost: string;
  listenPort: number;
  targetHost: string;
  targetPort: number;
  enabled: boolean;
  status: Health;
  error?: string;
  stats?: DirectStats;
};
export type NewHttpRoute = Omit<HttpRoute, "id" | "status" | "error">;
export type NewDirectRule = Omit<
  DirectRule,
  "id" | "status" | "error" | "stats"
>;
export type ProxyConfig = {
  revision: number;
  panelDomain?: string;
  portOwners: PortOwners;
  httpRoutes: HttpRoute[];
  directRules: DirectRule[];
};
export type ServiceHealth = {
  status: string;
  caddy: string | boolean;
  revision: number;
  appliedRevision: number;
  state?: LifecycleState | string;
  panelDomain?: string;
  certificate?: string;
  error?: string;
};
const record = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null;
const port = (v: unknown) =>
  Number.isInteger(v) && Number(v) >= 1 && Number(v) <= 65535;
const base = (v: unknown): v is Record<string, unknown> =>
  record(v) &&
  typeof v.id === "string" &&
  typeof v.enabled === "boolean" &&
  ["healthy", "unknown", "error"].includes(String(v.status)) &&
  (v.error == null || typeof v.error === "string");
type StoredHttpRoute = Omit<HttpRoute, "path" | "stripPrefix"> &
  Partial<Pick<HttpRoute, "path" | "stripPrefix">>;
type StoredConfig = Omit<ProxyConfig, "httpRoutes" | "portOwners"> & {
  portOwners?: PortOwners;
  panelDomain?: string;
  httpRoutes: StoredHttpRoute[];
};
const normalizeHttp = (route: StoredHttpRoute): HttpRoute => ({
  ...route,
  path: route.path ?? "/",
  stripPrefix: route.stripPrefix ?? false,
});
const normalizeConfig = (config: StoredConfig): ProxyConfig => ({
  ...config,
  httpRoutes: config.httpRoutes.map(normalizeHttp),
  portOwners: config.portOwners ?? {
    http: "caddy",
    https: "caddy",
    http3: "caddy",
  },
});
const http = (v: unknown): v is StoredHttpRoute =>
  base(v) &&
  typeof v.host === "string" &&
  (v.path === undefined || typeof v.path === "string") &&
  (v.stripPrefix === undefined || typeof v.stripPrefix === "boolean") &&
  typeof v.target === "string" &&
  ["auto", "internal", "off"].includes(String(v.tls));
const owners = (v: unknown): v is PortOwners =>
  record(v) &&
  [v.http, v.https, v.http3].every(
    (owner) => owner === "caddy" || owner === "direct",
  );
const count = (v: unknown) =>
  typeof v === "number" && Number.isSafeInteger(v) && v >= 0;
const stats = (v: unknown): v is DirectStats =>
  record(v) &&
  [v.accepted, v.active, v.closed, v.errors, v.rejects].every(count) &&
  typeof v.startedAt === "string" &&
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(
    v.startedAt,
  ) &&
  Number.isFinite(Date.parse(v.startedAt));
const direct = (v: unknown): v is DirectRule =>
  base(v) &&
  ["tcp", "udp"].includes(String(v.protocol)) &&
  typeof v.listenHost === "string" &&
  typeof v.targetHost === "string" &&
  port(v.listenPort) &&
  port(v.targetPort) &&
  (v.stats === undefined || stats(v.stats));
const config = (v: unknown): v is StoredConfig =>
  record(v) &&
  Number.isInteger(v.revision) &&
  (v.panelDomain == null || typeof v.panelDomain === "string") &&
  (v.portOwners === undefined || owners(v.portOwners)) &&
  Array.isArray(v.httpRoutes) &&
  v.httpRoutes.every(http) &&
  Array.isArray(v.directRules) &&
  v.directRules.every(direct);
const auth = (v: unknown): v is Auth =>
  record(v) &&
  typeof v.configured === "boolean" &&
  typeof v.authenticated === "boolean";
const ok = (v: unknown): v is { ok: true } => record(v) && v.ok === true;
export class Unauthorized extends Error {}
let sessionVersion = 0;
function requireSession(version: number) {
  if (version !== sessionVersion)
    throw new Unauthorized("Сессия изменилась. Ответ устарел.");
}
async function performRequest<T>(
  path: string,
  valid: (v: unknown) => v is T,
  method: string,
  data: unknown,
  version: number,
): Promise<T> {
  requireSession(version);
  let response: Response;
  try {
    response = await fetch(`/api${path}`, {
      method,
      credentials: "same-origin",
      headers: {
        Accept: "application/json",
        ...(data === undefined ? {} : { "Content-Type": "application/json" }),
      },
      body: data === undefined ? undefined : JSON.stringify(data),
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    requireSession(version);
    throw new Error(
      "The server is unavailable or the request timed out. Try again.",
    );
  }
  const body: unknown = await response.json().catch(() => null);
  requireSession(version);
  if (response.status === 401) {
    if (path === "/login" || path === "/setup") {
      throw new Error("Incorrect password. Try again.");
    }
    ++sessionVersion;
    window.dispatchEvent(new Event("niceproxy:unauthorized"));
    throw new Unauthorized("Your session has expired. Sign in again.");
  }
  if (!response.ok)
    throw new Error(
      record(body) && typeof body.error === "string"
        ? body.error
        : `Server error: HTTP ${response.status}`,
    );
  if (!valid(body))
    throw new Error("The server returned an invalid response.");
  return body;
}
// All mutations share one queue, including actions from different cards.
let mutationQueue: Promise<unknown> = Promise.resolve();
export function request<T>(
  path: string,
  valid: (v: unknown) => v is T,
  method = "GET",
  data?: unknown,
): Promise<T> {
  const version = sessionVersion;
  if (method === "GET")
    return performRequest(path, valid, method, data, version);
  const result = mutationQueue.then(() =>
    performRequest(path, valid, method, data, version),
  );
  mutationQueue = result.catch(() => undefined);
  return result.then((value) => {
    requireSession(version);
    if (path === "/login" || path === "/setup" || path === "/logout")
      ++sessionVersion;
    window.dispatchEvent(
      new CustomEvent("niceproxy:changed", { detail: { path } }),
    );
    return value;
  });
}
const itemPath = (collection: string, id: string) =>
  `/${collection}/${encodeURIComponent(id)}`;
export const api = {
  panelDomain: () =>
    request(
      "/panel-domain",
      (v): v is { panelDomain: string } =>
        record(v) && typeof v.panelDomain === "string",
    ),
  savePanelDomain: (panelDomain: string) =>
    request("/panel-domain", config, "PATCH", { panelDomain }).then(normalizeConfig),
  portOwners: () =>
    request(
      "/port-owners",
      (v): v is PortOwnerSettings =>
        record(v) && port(v.httpPort) && port(v.httpsPort) && owners(v.owners),
    ),
  savePortOwners: (data: Partial<PortOwners>) =>
    request("/port-owners", config, "PATCH", data).then(normalizeConfig),
  reconcile: () => request("/reconcile", config, "POST").then(normalizeConfig),
  auth: () => request("/auth", auth),
  login: (password: string, setup: boolean) =>
    request(setup ? "/setup" : "/login", auth, "POST", { password }),
  logout: () => request("/logout", ok, "POST"),
  config: () => request("/config", config).then(normalizeConfig),
  health: () =>
    request(
      "/health",
      (v): v is ServiceHealth =>
        record(v) &&
        typeof v.status === "string" &&
        (typeof v.caddy === "string" || typeof v.caddy === "boolean") &&
        Number.isInteger(v.revision) &&
        Number.isInteger(v.appliedRevision) &&
        (v.state == null || typeof v.state === "string") &&
        (v.panelDomain == null || typeof v.panelDomain === "string") &&
        (v.certificate == null || typeof v.certificate === "string") &&
        (v.error == null || typeof v.error === "string"),
    ),
  saveHttp: (data: NewHttpRoute, id?: string) =>
    request(
      id ? itemPath("http-routes", id) : "/http-routes",
      http,
      id ? "PATCH" : "POST",
      data,
    ).then(normalizeHttp),
  saveDirect: (data: NewDirectRule, id?: string) =>
    request(
      id ? itemPath("direct-rules", id) : "/direct-rules",
      direct,
      id ? "PATCH" : "POST",
      data,
    ),
  toggle: (
    kind: "http-routes" | "direct-rules",
    id: string,
    enabled: boolean,
  ) =>
    request(
      itemPath(kind, id),
      kind === "http-routes"
        ? (v): v is StoredHttpRoute | DirectRule => http(v)
        : (v): v is StoredHttpRoute | DirectRule => direct(v),
      "PATCH",
      { enabled },
    ).then((route) => ("host" in route ? normalizeHttp(route) : route)),
  remove: (kind: "http-routes" | "direct-rules", id: string) =>
    request(itemPath(kind, id), ok, "DELETE"),
};
