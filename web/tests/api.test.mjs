import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const source = await readFile(new URL("../src/api.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
});
const { api, validPolicy } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);
const snapshot = { revision: 1, httpRoutes: [], directRules: [] };
const owners = { http: "caddy", https: "direct", http3: "direct" };
const rule = {
  id: "one", protocol: "udp", listenHost: "0.0.0.0", listenPort: 8443,
  targetHost: "127.0.0.1", targetPort: 9000, enabled: true, status: "healthy",
};
const stats = { accepted: 0, active: 0, closed: 0, errors: 0, rejects: 0, startedAt: "2026-11-08T12:00:00Z" };
function reply(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
function setup(t, fetcher) {
  const originalFetch = globalThis.fetch;
  const originalWindow = globalThis.window;
  globalThis.fetch = fetcher;
  globalThis.window = new EventTarget();
  t.after(() => { globalThis.fetch = originalFetch; globalThis.window = originalWindow; });
}

test("normalizes legacy owner absence and preserves explicit ownership", async (t) => {
  setup(t, async () => reply(snapshot));
  assert.deepEqual((await api.config()).portOwners, { http: "caddy", https: "caddy", http3: "caddy" });
  globalThis.fetch = async () => reply({ ...snapshot, portOwners: owners });
  assert.deepEqual((await api.config()).portOwners, owners);
  globalThis.fetch = async () => reply({ ...snapshot, portOwners: { ...owners, http: "other" } });
  await assert.rejects(api.config(), /unknown format/);
});

test("distinguishes missing statistics from real zero and rejects malformed counters", async (t) => {
  setup(t, async () => reply({ ...snapshot, directRules: [rule] }));
  assert.equal((await api.config()).directRules[0].stats, undefined);
  globalThis.fetch = async () => reply({ ...snapshot, directRules: [{ ...rule, stats }] });
  assert.deepEqual((await api.config()).directRules[0].stats, stats);
  const malformed = [null, {}, { ...stats, startedAt: "yesterday" }];
  for (const key of ["accepted", "active", "closed", "errors", "rejects"]) {
    for (const invalid of [-1, 0.5, "0", Number.MAX_SAFE_INTEGER + 1]) {
      malformed.push({ ...stats, [key]: invalid });
    }
  }
  for (const badStats of malformed) {
    globalThis.fetch = async () => reply({ ...snapshot, directRules: [{ ...rule, stats: badStats }] });
    await assert.rejects(api.config(), /unknown format/);
  }
});

test("validates anti-DDoS policy primitives and nested optional values", () => {
  const policy = {
    detect: true,
    autoFilter: true,
    enforceLimits: false,
    stableWindows: 2,
    group: "edge",
    expectUDPResponse: true,
    cloudflareOnly: false,
    limits: [{
      id: "udp-rate",
      metric: "udp_packets",
      value: 100,
      unit: "count",
      windowSeconds: 10,
      burst: 20,
      scope: "listener",
      action: "slow",
      ttlSeconds: 60,
    }],
    rules: [{
      id: "packet-loss",
      signal: "udp_unanswered",
      scope: "endpoint",
      threshold: 4,
      clearThreshold: 2,
      windowSeconds: 30,
      burst: 1,
      minSamples: 5,
      action: "block",
      cooldownSeconds: 120,
    }],
  };
  assert.equal(validPolicy(policy), true);
  for (const [field, value] of [
    ["stableWindows", -1],
    ["limits", [{ ...policy.limits[0], unit: "packets" }]],
    ["rules", [{ ...policy.rules[0], minSamples: 1.5 }]],
    ["expectUDPResponse", "yes"],
  ]) {
    assert.equal(validPolicy({ ...policy, [field]: value }), false, field);
  }
  assert.equal(validPolicy({ detect: true, autoFilter: false, enforceLimits: false }), true);
});

test("anti-DDoS status and mutations validate nested data and normalize config", async (t) => {
  const status = {
    revision: 4,
    appliedRevision: 4,
    status: "active",
    instances: [{
      id: "node-1",
      version: "v1",
      targets: [{
        id: "listener",
        label: "Public listener",
        kind: "listener",
        policy: { detect: false, autoFilter: false, enforceLimits: false },
        state: "normal",
        score: 0,
        reason: "none",
        observability: "full",
        metrics: { udp_packets: { value: null, source: "kernel" } },
      }],
      cloudflare: { networks: ["192.0.2.0/24"], updatedAt: "2026-11-08T12:00:00Z" },
    }],
  };
  const responseConfig = { ...snapshot, httpRoutes: [{
    id: "legacy", host: "example.test", target: "http://127.0.0.1:9000",
    tls: "off", enabled: true, status: "healthy",
  }] };
  const calls = [];
  setup(t, async (url, options) => {
    calls.push([url, options.method, options.body === undefined ? undefined : JSON.parse(options.body)]);
    if (url === "/api/anti-ddos" && options.method === "GET") return reply(status);
    if (url === "/api/anti-ddos") return reply(responseConfig);
    return reply({ ok: true });
  });
  assert.deepEqual(await api.antiDDoS(), status);
  assert.equal((await api.saveAntiDDoS({ listener: { detect: false, autoFilter: false, enforceLimits: false } })).httpRoutes[0].path, "/");
  await api.clearAntiDDoS({ instance: "node-1", target: "listener", ttlSeconds: 60 });
  assert.deepEqual(calls.map(([url, method, body]) => [url, method, body]), [
    ["/api/anti-ddos", "GET", undefined],
    ["/api/anti-ddos", "PATCH", { listener: { detect: false, autoFilter: false, enforceLimits: false } }],
    ["/api/anti-ddos/clear", "POST", { instance: "node-1", target: "listener", ttlSeconds: 60 }],
  ]);
  setup(t, async () => reply({ ...status, instances: [{ ...status.instances[0], targets: [{ ...status.instances[0].targets[0], score: -1 }] }] }));
  await assert.rejects(api.antiDDoS(), /unknown format/);
});

test("route conflicts show the user message and the mutation queue recovers", async (t) => {
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  const calls = [];
  let changed = 0;
  setup(t, async (url, options) => {
    calls.push({ url, options });
    if (options.method === "PATCH") {
      await blocked;
      return reply({ error: "ownership conflict", message: "Choose another incoming port" }, 409);
    }
    return reply({ ok: true });
  });
  window.addEventListener("niceproxy:changed", () => { changed++; });
  const save = api.toggle("direct-rules", "one", true);
  const rejection = assert.rejects(save, /Choose another incoming port/);
  const remove = api.remove("direct-rules", "one");
  await Promise.resolve();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.method, "PATCH");
  assert.deepEqual(JSON.parse(calls[0].options.body), { enabled: true, autoSetup: true });
  release();
  await rejection;
  await remove;
  assert.equal(calls.length, 2);
  assert.equal(calls[1].url, "/api/direct-rules/one");
  assert.equal(changed, 1);
});

test("route forms request automatic setup on create and edit", async (t) => {
  const { id, status, ...direct } = rule;
  const web = { host: "example.test", target: "http://127.0.0.1:9000", tls: "off", enabled: true };
  const draft = { ...web, path: "/", stripPrefix: false };
  const calls = [];
  setup(t, async (url, options) => {
    calls.push([url, options.method, JSON.parse(options.body)]);
    return reply(url.startsWith("/api/direct-rules") ? rule : { ...web, id, status });
  });
  let changed = 0;
  window.addEventListener("niceproxy:changed", () => { changed++; });
  assert.deepEqual(await api.saveHttp(draft), { ...draft, id, status });
  assert.deepEqual(await api.saveDirect(direct, id), rule);
  assert.deepEqual(calls, [
    ["/api/http-routes", "POST", { ...draft, autoSetup: true }],
    ["/api/direct-rules/one", "PATCH", { ...direct, autoSetup: true }],
  ]);
  assert.equal(changed, 2);
});

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return { promise, resolve };
}

test("late unauthorized responses from the old session cannot end a new login", async t => {
  const configResponse = deferred();
  const healthResponse = deferred();
  let expired = 0;
  setup(t, async url => {
    if (url === "/api/config") return configResponse.promise;
    if (url === "/api/health") return healthResponse.promise;
    if (url === "/api/login") return reply({ configured: true, authenticated: true });
    throw new Error(`Unexpected ${url}`);
  });
  window.addEventListener("niceproxy:unauthorized", () => expired++);
  const oldConfig = assert.rejects(api.config(), /Session/);
  const oldHealth = assert.rejects(api.health(), /Session/);
  configResponse.resolve(reply({ error: "expired" }, 401));
  await oldConfig;
  assert.equal(expired, 1);
  await api.login("test-session-password", false);
  healthResponse.resolve(reply({ error: "expired" }, 401));
  await oldHealth;
  assert.equal(expired, 1, "a delayed 401 must not log out the new session");
  globalThis.fetch = async () => reply(snapshot);
  assert.equal((await api.config()).revision, snapshot.revision);
});

test("expired-session mutations cannot publish stale state or send queued writes", async t => {
  const saveResponse = deferred();
  const saveStarted = deferred();
  let writes = 0;
  let changed = 0;
  setup(t, async (url, options) => {
    if (options.method !== "GET") {
      writes++;
      saveStarted.resolve();
      return saveResponse.promise;
    }
    assert.equal(url, "/api/health");
    return reply({ error: "expired" }, 401);
  });
  window.addEventListener("niceproxy:changed", () => changed++);
  const saving = assert.rejects(api.toggle("direct-rules", "one", true), /Session/);
  await saveStarted.promise;
  const queued = assert.rejects(api.remove("direct-rules", "one"), /Session/);
  await assert.rejects(api.health(), /Session/);
  saveResponse.resolve(reply({ ...snapshot, portOwners: owners }));
  await Promise.all([saving, queued]);
  assert.equal(writes, 1, "a queued mutation must not run in a different session");
  assert.equal(changed, 0, "stale success must not publish a mutation event");
});

test("reports transport, HTTP and malformed JSON failures through the shared client", async t => {
  setup(t, async () => { throw new TypeError("network failure"); });
  await assert.rejects(api.config(), /server is unavailable or the request timed out/);
  globalThis.fetch = async () => new Response("Bad gateway", { status: 502 });
  await assert.rejects(api.health(), /HTTP 502/);
  globalThis.fetch = async () => new Response("invalid JSON");
  await assert.rejects(api.auth(), /unknown format/);
  let expired = 0;
  window.addEventListener("niceproxy:unauthorized", () => expired++);
  globalThis.fetch = async () => reply({ error: "invalid credentials" }, 401);
  await assert.rejects(api.login("wrong-password", false), /Incorrect password/);
  assert.equal(expired, 0);
});

test("HTTP and direct route CRUD use encoded IDs and normalize legacy HTTP paths", async t => {
  const stored = { id: "route/a", host: "app.example", target: "http://127.0.0.1:3001", tls: "off", enabled: true, status: "healthy" };
  const httpInput = { host: stored.host, target: stored.target, tls: stored.tls, enabled: true, path: "/", stripPrefix: false };
  const directInput = { protocol: rule.protocol, listenHost: rule.listenHost, listenPort: rule.listenPort, targetHost: rule.targetHost, targetPort: rule.targetPort, enabled: true };
  const calls = [];
  setup(t, async (url, options) => {
    calls.push([url, options.method, options.body === undefined ? undefined : JSON.parse(options.body)]);
    if (options.method === "DELETE") return reply({ ok: true });
    if (url.includes("direct-rules")) return reply(rule);
    return reply(stored);
  });
  assert.deepEqual(await api.saveHttp(httpInput), { ...stored, path: "/", stripPrefix: false });
  await api.saveHttp(httpInput, stored.id);
  assert.equal((await api.toggle("http-routes", stored.id, true)).path, "/");
  assert.deepEqual(await api.saveDirect(directInput), rule);
  await api.saveDirect(directInput, "direct/a");
  assert.deepEqual(await api.toggle("direct-rules", "direct/a", true), rule);
  await api.remove("direct-rules", "direct/a");
  assert.deepEqual(calls, [
    ["/api/http-routes", "POST", { ...httpInput, autoSetup: true }],
    ["/api/http-routes/route%2Fa", "PATCH", { ...httpInput, autoSetup: true }],
    ["/api/http-routes/route%2Fa", "PATCH", { enabled: true, autoSetup: true }],
    ["/api/direct-rules", "POST", { ...directInput, autoSetup: true }],
    ["/api/direct-rules/direct%2Fa", "PATCH", { ...directInput, autoSetup: true }],
    ["/api/direct-rules/direct%2Fa", "PATCH", { enabled: true, autoSetup: true }],
    ["/api/direct-rules/direct%2Fa", "DELETE", undefined],
  ]);
});
