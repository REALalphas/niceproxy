import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";

const source = await readFile(new URL("../src/api.ts", import.meta.url), "utf8");
const { outputText } = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
});
const { api } = await import(`data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`);
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
  await assert.rejects(api.config(), /неизвестном формате/);
});

test("uses configured ports and validates owner settings", async (t) => {
  const settings = { httpPort: 8081, httpsPort: 8443, owners };
  setup(t, async (url) => { assert.equal(url, "/api/port-owners"); return reply(settings); });
  assert.deepEqual(await api.portOwners(), settings);
  for (const httpPort of ["8081", 0, 65536, 1.5]) {
    globalThis.fetch = async () => reply({ ...settings, httpPort });
    await assert.rejects(api.portOwners(), /неизвестном формате/);
  }
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
    await assert.rejects(api.config(), /неизвестном формате/);
  }
});

test("ownership conflicts are surfaced and the shared mutation queue recovers", async (t) => {
  let release;
  const blocked = new Promise((resolve) => { release = resolve; });
  const calls = [];
  let changed = 0;
  setup(t, async (url, options) => {
    calls.push({ url, options });
    if (url === "/api/port-owners") {
      await blocked;
      return reply({ error: "Отключите конфликтующие правила" }, 409);
    }
    return reply({ ok: true });
  });
  window.addEventListener("niceproxy:changed", () => { changed++; });
  const save = api.savePortOwners({ http: "direct" });
  const rejection = assert.rejects(save, /Отключите конфликтующие правила/);
  const remove = api.remove("direct-rules", "one");
  await Promise.resolve();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.method, "PATCH");
  assert.deepEqual(JSON.parse(calls[0].options.body), { http: "direct" });
  release();
  await rejection;
  await remove;
  assert.equal(calls.length, 2);
  assert.equal(changed, 1);
});

test("saving owners returns the updated normalized snapshot and emits a change", async (t) => {
  setup(t, async () => reply({ ...snapshot, revision: 2, portOwners: owners }));
  let changed = 0;
  window.addEventListener("niceproxy:changed", () => { changed++; });
  const result = await api.savePortOwners(owners);
  assert.deepEqual(result.portOwners, owners);
  assert.equal(result.revision, 2);
  assert.equal(changed, 1);
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
  const oldConfig = assert.rejects(api.config(), /Сессия/);
  const oldHealth = assert.rejects(api.health(), /Сессия/);
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
  const saving = assert.rejects(api.savePortOwners({ http: "direct" }), /Сессия/);
  await saveStarted.promise;
  const queued = assert.rejects(api.savePortOwners({ https: "direct" }), /Сессия/);
  await assert.rejects(api.health(), /Сессия/);
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
  await assert.rejects(api.auth(), /неизвестном формате/);
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
    ["/api/http-routes", "POST", httpInput],
    ["/api/http-routes/route%2Fa", "PATCH", httpInput],
    ["/api/http-routes/route%2Fa", "PATCH", { enabled: true }],
    ["/api/direct-rules", "POST", directInput],
    ["/api/direct-rules/direct%2Fa", "PATCH", directInput],
    ["/api/direct-rules/direct%2Fa", "PATCH", { enabled: true }],
    ["/api/direct-rules/direct%2Fa", "DELETE", undefined],
  ]);
});
