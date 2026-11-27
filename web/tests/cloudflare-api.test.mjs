import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";

async function moduleURL(path, replacements = {}) {
  let source = await readFile(new URL(path, import.meta.url), "utf8");
  for (const [from, to] of Object.entries(replacements)) source = source.replaceAll(from, to);
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  });
  return `data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`;
}
const apiURL = await moduleURL("../src/api.ts");
const cloudflareURL = await moduleURL("../src/cloudflare-api.ts", { '"./api"': `"${apiURL}"` });
const { cloudflareApi, parseScopes, supportedRecord, authorizationURL } = await import(cloudflareURL);

function setup(t, fetcher) {
  const originalFetch = globalThis.fetch;
  const originalWindow = globalThis.window;
  globalThis.fetch = fetcher;
  globalThis.window = new EventTarget();
  t.after(() => { globalThis.fetch = originalFetch; globalThis.window = originalWindow; });
}
const reply = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
const status = { configured: true, connected: false, clientId: "client", redirectUrl: "https://panel.example/callback", scopes: ["dns:read"] };
const record = { id: "r1", type: "A", name: "app.example", content: "192.0.2.1", proxied: true, ttl: 120 };

test("scope and authorization helpers normalize and reject unsafe values", () => {
  assert.deepEqual(parseScopes("dns:read, dns:write\ndns:read"), ["dns:read", "dns:write"]);
  assert.equal(supportedRecord("A"), true);
  assert.equal(supportedRecord("TXT"), false);
  assert.equal(authorizationURL("https://dash.cloudflare.com/oauth/authorize?state=x"), "https://dash.cloudflare.com/oauth/authorize?state=x");
  for (const value of ["http://dash.cloudflare.com/x", "https://evil.example/", "https://user:pass@dash.cloudflare.com/x"]) {
    assert.throws(() => authorizationURL(value), /invalid Cloudflare authorization URL/);
  }
});

test("Cloudflare status, zones and records validate responses and encode IDs", async t => {
  const calls = [];
  const zones = { zones: [{ id: "zone/id", name: "example", status: "active", account: { id: "a", name: "Acme" } }] };
  const records = { records: [record] };
  setup(t, async (url, options) => {
    calls.push([url, options.method]);
    if (url === "/api/cloudflare") return reply(status);
    if (url === "/api/cloudflare/zones") return reply(zones);
    if (url === "/api/cloudflare/zones/zone%2Fid/records") return reply(records);
    return reply({ error: "unknown request" }, 404);
  });
  assert.deepEqual(await cloudflareApi.status(), status);
  assert.deepEqual(await cloudflareApi.zones(), zones);
  assert.deepEqual(await cloudflareApi.records("zone/id"), records);
  assert.deepEqual(calls, [
    ["/api/cloudflare", "GET"],
    ["/api/cloudflare/zones", "GET"],
    ["/api/cloudflare/zones/zone%2Fid/records", "GET"],
  ]);
});

test("record mutations serialize payload and use PATCH for an existing ID", async t => {
  const calls = [];
  setup(t, async (url, options) => {
    calls.push([url, options.method, options.body === undefined ? undefined : JSON.parse(options.body)]);
    return reply(record);
  });
  const input = { name: "app.example", type: "A", content: "192.0.2.1", proxied: true, ttl: 120 };
  assert.deepEqual(await cloudflareApi.saveRecord("zone/id", input), record);
  assert.deepEqual(await cloudflareApi.saveRecord("zone/id", input, "record/1"), record);
  assert.deepEqual(calls, [
    ["/api/cloudflare/zones/zone%2Fid/records", "POST", input],
    ["/api/cloudflare/zones/zone%2Fid/records/record%2F1", "PATCH", input],
  ]);
});

test("connect modes and malformed server data fail loudly", async t => {
  const calls = [];
  setup(t, async (url, options) => {
    calls.push({ url, options });
    if (url.includes("mode=localhost")) return reply({ url: "https://dash.cloudflare.com/connect" });
    return reply({ zones: [{ id: 1 }] });
  });
  assert.equal((await cloudflareApi.connect(true)).url, "https://dash.cloudflare.com/connect");
  await assert.rejects(cloudflareApi.zones(), /unknown format/);
  assert.equal(calls[0].url, "/api/cloudflare/connect?mode=localhost");
  assert.equal(calls[0].options.method, "POST");
});

test("OAuth mutations and certificate diagnostics preserve the API contract", async t => {
  const calls = [];
  const connected = { ...status, connected: true, expiresAt: "2026-11-25T00:00:00Z" };
  const certificate = { configured: true, domain: "panel.example", state: "pending", addresses: ["192.0.2.1"], tlsError: "certificate unavailable" };
  const callbackUrl = "http://localhost:9080/api/cloudflare/callback?code=test&state=test";
  const expected = [
    ["/api/cloudflare/settings", "POST", { clientId: "client", scopes: status.scopes }, status],
    ["/api/cloudflare/connect", "POST", undefined, { url: "https://dash.cloudflare.com/oauth/authorize" }],
    ["/api/cloudflare/complete", "POST", { callbackUrl }, connected],
    ["/api/certificate", "GET", undefined, certificate],
    ["/api/cloudflare/disconnect", "POST", undefined, { ok: true, warning: "cleanup deferred" }],
  ];
  setup(t, async (url, options) => {
    const index = calls.length;
    calls.push([url, options.method, options.body === undefined ? undefined : JSON.parse(options.body)]);
    return reply(expected[index][3]);
  });
  assert.deepEqual(await cloudflareApi.settings("client", status.scopes), status);
  assert.deepEqual(await cloudflareApi.connect(), expected[1][3]);
  assert.deepEqual(await cloudflareApi.complete(callbackUrl), connected);
  assert.deepEqual(await cloudflareApi.certificate(), certificate);
  assert.deepEqual(await cloudflareApi.disconnect(), expected[4][3]);
  assert.deepEqual(calls, expected.map(row => row.slice(0, 3)));
});

test("Cloudflare rejects invalid status fields, certificates, records and mutation replies", async t => {
  let payload;
  setup(t, async () => reply(payload));
  for (const [invoke, body] of [
    [cloudflareApi.status, { ...status, scopes: ["dns:read", 1] }],
    [cloudflareApi.status, { ...status, loopbackRedirectUrl: 1 }],
    [cloudflareApi.certificate, { configured: true, domain: "panel.example", state: "other" }],
    [cloudflareApi.certificate, { configured: true, domain: "panel.example", state: "issued", addresses: [1] }],
    [() => cloudflareApi.records("zone"), { records: [{ ...record, ttl: "120" }] }],
    [cloudflareApi.connect, { url: 1 }],
    [cloudflareApi.disconnect, { ok: true, warning: [] }],
  ]) {
    payload = body;
    await assert.rejects(invoke(), /unknown format/);
  }
});
