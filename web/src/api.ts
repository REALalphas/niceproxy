export type Health =
  | "healthy"
  | "unknown"
  | "error"
  | "waiting_acme"
  | "waiting_dns"
  | "invalid_certificate";
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
  autoSetup?: boolean;
  status: Health;
  error?: string;
  systemManaged?: boolean;
};
export type PortOwners = Record<"http" | "https" | "http3", "caddy" | "direct">;
export type PortOwnerSettings = {
  httpPort: number;
  httpsPort: number;
  owners: PortOwners;
};
export type PanelDomainSettings = {
  panelDomain: string;
  proxied: boolean;
  proxyWarning?: string;
  automation?: {
    domain?: string;
    dnsMode?: string;
    zoneSSL?: string;
    sslSelection?: string;
    state: string;
    detail?: string;
  };
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
  autoSetup?: boolean;
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
  antiDDoS?: AntiDDoSConfig;
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
  typeof v === "object" && v !== null && !Array.isArray(v);
const port = (v: unknown) =>
  Number.isInteger(v) && Number(v) >= 1 && Number(v) <= 65535;
const base = (v: unknown): v is Record<string, unknown> =>
  record(v) &&
  typeof v.id === "string" &&
  typeof v.enabled === "boolean" &&
  [
    "healthy",
    "unknown",
    "error",
    "waiting_acme",
    "waiting_dns",
    "invalid_certificate",
  ].includes(String(v.status)) &&
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
  (v.autoSetup === undefined || typeof v.autoSetup === "boolean") &&
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
export const scopes = [
  "ip",
  "subnet",
  "listener",
  "endpoint",
  "group",
  "all_instances",
] as const;
export const actions = ["pass", "slow", "reject", "block"] as const;
export const units = ["count", "bytes", "ms", "percent"] as const;
export const signals = [
  "tcp_new",
  "tls_new",
  "requests",
  "udp_packets",
  "udp_bytes",
  "protocol_errors",
  "timeouts",
  "short_connections",
  "backend_errors",
  "backend_latency_ms",
  "pressure",
  "distinct_sources",
  "distinct_subnets",
  "kernel_drops",
  "udp_unanswered",
] as const;
export type Limit = {
  id: string;
  metric: string;
  value: number;
  unit: (typeof units)[number];
  windowSeconds?: number;
  burst?: number;
  scope: (typeof scopes)[number];
  action: (typeof actions)[number];
  ttlSeconds?: number;
};
export type DetectionRule = {
  id: string;
  signal: (typeof signals)[number];
  scope: (typeof scopes)[number];
  threshold: number;
  clearThreshold: number;
  windowSeconds: number;
  burst: number;
  minSamples: number;
  action: (typeof actions)[number];
  cooldownSeconds: number;
};
export type Policy = {
  detect: boolean;
  autoFilter: boolean;
  enforceLimits: boolean;
  stableWindows?: number;
  group?: string;
  limits?: Limit[];
  rules?: DetectionRule[];
  expectUDPResponse?: boolean;
  cloudflareOnly?: boolean;
  originPullCA?: string;
};
export type AntiDDoSConfig = {
  listener?: Policy;
  endpoints?: Record<string, Policy>;
  cloudflare?: {
    enabled: boolean;
    ipv4URL?: string;
    ipv6URL?: string;
    trustedProxies?: string[];
  };
};
type ClearRestriction = {
  instance: string;
  target: string;
  rule?: string;
  subject?: string;
  ttlSeconds: number;
};
type Restriction = {
  rule: string;
  scope: (typeof scopes)[number];
  target: string;
  action: (typeof actions)[number];
  expiresAt: string;
  automatic: boolean;
};
type DetectorTarget = {
  id: string;
  label: string;
  kind: string;
  policy: Policy;
  state: string;
  score: number;
  reason: string;
  observability: string;
  metrics: Record<string, { value: number | null; source: string }>;
  restrictions?: Restriction[];
  events?: {
    at: string;
    reason: string;
    action: (typeof actions)[number];
    rules: string[] | null;
  }[];
  history?: {
    at: string;
    load: number;
    normalLow?: number;
    normalHigh?: number;
  }[];
  sources?: {
    address: string;
    subnet: string;
    count: number;
    reason?: string;
  }[];
};
export type DDoSStatus = {
  revision: number;
  appliedRevision: number;
  status: "active" | "applying" | "partial";
  instances: {
    id: string;
    version: string | number;
    error?: string;
    targets: DetectorTarget[];
    cloudflare?: {
      networks?: string[] | number;
      updatedAt?: string;
      ipv4URL?: string;
      ipv6URL?: string;
      error?: string;
    };
  }[];
};

const string = (v: unknown) => typeof v === "string";
const boolean = (v: unknown) => typeof v === "boolean";
const nonnegative = (v: unknown) =>
  typeof v === "number" && Number.isFinite(v) && v >= 0;
const optional = (v: unknown, valid: (value: unknown) => boolean) =>
  v === undefined || valid(v);
const arrayOf = (v: unknown, valid: (value: unknown) => boolean) =>
  Array.isArray(v) && v.every(valid);
const oneOf = (v: unknown, values: readonly string[]) =>
  typeof v === "string" && values.includes(v);
const limit = (v: unknown): v is Limit =>
  record(v) &&
  string(v.id) &&
  string(v.metric) &&
  nonnegative(v.value) &&
  oneOf(v.unit, units) &&
  oneOf(v.scope, scopes) &&
  oneOf(v.action, actions) &&
  optional(v.windowSeconds, count) &&
  optional(v.burst, nonnegative) &&
  optional(v.ttlSeconds, count);
const detectionRule = (v: unknown): v is DetectionRule =>
  record(v) &&
  string(v.id) &&
  oneOf(v.signal, signals) &&
  oneOf(v.scope, scopes) &&
  oneOf(v.action, actions) &&
  [v.threshold, v.clearThreshold, v.burst].every(nonnegative) &&
  [v.windowSeconds, v.minSamples, v.cooldownSeconds].every(count);
export const validPolicy = (v: unknown): v is Policy =>
  record(v) &&
  boolean(v.detect) &&
  boolean(v.autoFilter) &&
  boolean(v.enforceLimits) &&
  optional(v.stableWindows, count) &&
  optional(v.group, string) &&
  optional(v.originPullCA, string) &&
  optional(v.cloudflareOnly, boolean) &&
  optional(v.expectUDPResponse, boolean) &&
  optional(v.limits, (items) => arrayOf(items, limit)) &&
  optional(v.rules, (items) => arrayOf(items, detectionRule));
const antiDDoSConfig = (v: unknown): v is AntiDDoSConfig =>
  record(v) &&
  optional(v.listener, validPolicy) &&
  optional(
    v.endpoints,
    (items) => record(items) && Object.values(items).every(validPolicy),
  ) &&
  optional(
    v.cloudflare,
    (cf) =>
      record(cf) &&
      boolean(cf.enabled) &&
      optional(cf.ipv4URL, string) &&
      optional(cf.ipv6URL, string) &&
      optional(cf.trustedProxies, (items) => arrayOf(items, string)),
  );
const timestamp = (v: unknown) =>
  typeof v === "string" && Number.isFinite(Date.parse(v));
const restriction = (v: unknown): v is Restriction =>
  record(v) &&
  string(v.rule) &&
  oneOf(v.scope, scopes) &&
  string(v.target) &&
  oneOf(v.action, actions) &&
  timestamp(v.expiresAt) &&
  boolean(v.automatic);
const detectorTarget = (v: unknown): v is DetectorTarget =>
  record(v) &&
  [v.id, v.label, v.kind, v.state, v.reason, v.observability].every(string) &&
  validPolicy(v.policy) &&
  nonnegative(v.score) &&
  record(v.metrics) &&
  Object.values(v.metrics).every(
    (metric) =>
      record(metric) &&
      (metric.value === null || nonnegative(metric.value)) &&
      string(metric.source),
  ) &&
  optional(v.restrictions, (items) => arrayOf(items, restriction)) &&
  optional(v.events, (items) =>
    arrayOf(
      items,
      (item) =>
        record(item) &&
        timestamp(item.at) &&
        string(item.reason) &&
        oneOf(item.action, actions) &&
        (item.rules === null || arrayOf(item.rules, string)),
    ),
  ) &&
  optional(v.history, (items) =>
    arrayOf(
      items,
      (item) =>
        record(item) &&
        timestamp(item.at) &&
        nonnegative(item.load) &&
        optional(item.normalLow, nonnegative) &&
        optional(item.normalHigh, nonnegative),
    ),
  ) &&
  optional(v.sources, (items) =>
    arrayOf(
      items,
      (item) =>
        record(item) &&
        string(item.address) &&
        string(item.subnet) &&
        count(item.count) &&
        optional(item.reason, string),
    ),
  );
const ddosStatus = (v: unknown): v is DDoSStatus =>
  record(v) &&
  count(v.revision) &&
  typeof v.appliedRevision === "number" && Number.isSafeInteger(v.appliedRevision) && v.appliedRevision >= -1 &&
  oneOf(v.status, ["active", "applying", "partial"]) &&
  arrayOf(
    v.instances,
    (instance) =>
      record(instance) &&
      string(instance.id) &&
      (string(instance.version) || (typeof instance.version === "number" && Number.isSafeInteger(instance.version) && instance.version >= -1)) &&
      optional(instance.error, string) &&
      arrayOf(instance.targets, detectorTarget) &&
      optional(
        instance.cloudflare,
        (cf) =>
          record(cf) &&
          optional(
            cf.networks,
            (items) => count(items) || arrayOf(items, string),
          ) &&
          optional(cf.updatedAt, timestamp) &&
          optional(cf.ipv4URL, string) &&
          optional(cf.ipv6URL, string) &&
          optional(cf.error, string),
      ),
  );

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
  (v.autoSetup === undefined || typeof v.autoSetup === "boolean") &&
  typeof v.listenHost === "string" &&
  typeof v.targetHost === "string" &&
  port(v.listenPort) &&
  port(v.targetPort) &&
  (v.stats === undefined || stats(v.stats));
const config = (v: unknown): v is StoredConfig =>
  record(v) &&
  Number.isInteger(v.revision) &&
  (v.antiDDoS === undefined || antiDDoSConfig(v.antiDDoS)) &&
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
    throw new Unauthorized("Сессия завершена. Войдите снова.");
  }
  if (!response.ok)
    throw new Error(
      record(body) && typeof body.message === "string"
        ? body.message
        : record(body) && typeof body.error === "string"
          ? body.error
          : `Ошибка сервера (HTTP ${response.status})`,
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
  antiDDoS: () => request("/anti-ddos", ddosStatus),
  saveAntiDDoS: (data: AntiDDoSConfig & { revision?: number }) =>
    request("/anti-ddos", config, "PATCH", data).then(normalizeConfig),
  clearAntiDDoS: (data: ClearRestriction) =>
    request("/anti-ddos/clear", ok, "POST", data),
  panelDomain: () =>
    request(
      "/panel-domain",
      (v): v is PanelDomainSettings =>
        record(v) &&
        typeof v.panelDomain === "string" &&
        typeof v.proxied === "boolean" &&
        (v.proxyWarning == null || typeof v.proxyWarning === "string") &&
        (v.automation == null ||
          (record(v.automation) &&
            typeof v.automation.state === "string" &&
            [
              v.automation.domain,
              v.automation.dnsMode,
              v.automation.zoneSSL,
              v.automation.sslSelection,
              v.automation.detail,
            ].every((value) => value == null || typeof value === "string"))),
    ),
  savePanelDomain: (panelDomain: string) =>
    request("/panel-domain", config, "PATCH", { panelDomain }).then(
      normalizeConfig,
    ),
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
      { ...data, autoSetup: true },
    ).then(normalizeHttp),
  saveDirect: (data: NewDirectRule, id?: string) =>
    request(
      id ? itemPath("direct-rules", id) : "/direct-rules",
      direct,
      id ? "PATCH" : "POST",
      { ...data, autoSetup: true },
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
      { enabled, autoSetup: true },
    ).then((route) => ("host" in route ? normalizeHttp(route) : route)),
  remove: (kind: "http-routes" | "direct-rules", id: string) =>
    request(itemPath(kind, id), ok, "DELETE"),
};
