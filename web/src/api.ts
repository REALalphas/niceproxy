export type Health = "healthy" | "unknown" | "error";
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
};
export type NewHttpRoute = Omit<HttpRoute, "id" | "status" | "error">;
export type NewDirectRule = Omit<DirectRule, "id" | "status" | "error">;
export type ProxyConfig = {
  revision: number;
  httpRoutes: HttpRoute[];
  directRules: DirectRule[];
};
export type ServiceHealth = {
  status: string;
  caddy: string | boolean;
  revision: number;
  appliedRevision: number;
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
type StoredConfig = Omit<ProxyConfig, "httpRoutes"> & {
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
});
const http = (v: unknown): v is StoredHttpRoute =>
  base(v) &&
  typeof v.host === "string" &&
  (v.path === undefined || typeof v.path === "string") &&
  (v.stripPrefix === undefined || typeof v.stripPrefix === "boolean") &&
  typeof v.target === "string" &&
  ["auto", "internal", "off"].includes(String(v.tls));
const direct = (v: unknown): v is DirectRule =>
  base(v) &&
  ["tcp", "udp"].includes(String(v.protocol)) &&
  typeof v.listenHost === "string" &&
  typeof v.targetHost === "string" &&
  port(v.listenPort) &&
  port(v.targetPort);
const config = (v: unknown): v is StoredConfig =>
  record(v) &&
  Number.isInteger(v.revision) &&
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
async function performRequest<T>(
  path: string,
  valid: (v: unknown) => v is T,
  method = "GET",
  data?: unknown,
): Promise<T> {
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
    throw new Error(
      "Сервер недоступен или время ожидания истекло. Повторите попытку.",
    );
  }
  const body: unknown = await response.json().catch(() => null);
  if (response.status === 401) {
    if (path === "/login" || path === "/setup") {
      throw new Error("Неверный пароль. Повторите попытку.");
    }
    window.dispatchEvent(new Event("niceproxy:unauthorized"));
    throw new Unauthorized("Сессия завершена. Войдите снова.");
  }
  if (!response.ok)
    throw new Error(
      record(body) && typeof body.error === "string"
        ? body.error
        : `Ошибка сервера: HTTP ${response.status}`,
    );
  if (!valid(body))
    throw new Error("Сервер вернул данные в неизвестном формате.");
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
  if (method === "GET") return performRequest(path, valid, method, data);
  const result = mutationQueue.then(() =>
    performRequest(path, valid, method, data),
  );
  mutationQueue = result.catch(() => undefined);
  return result.then((value) => {
    window.dispatchEvent(new Event("niceproxy:changed"));
    return value;
  });
}
const itemPath = (collection: string, id: string) =>
  `/${collection}/${encodeURIComponent(id)}`;
export const api = {
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
