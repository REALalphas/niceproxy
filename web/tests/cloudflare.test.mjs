import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import ts from "typescript";

async function moduleURL(file, imports = {}) {
  let source = await readFile(new URL(`../src/${file}.ts`, import.meta.url), "utf8");
  for (const [specifier, url] of Object.entries(imports))
    source = source.replace(JSON.stringify(specifier), JSON.stringify(url));
  const { outputText } = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  });
  return `data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`;
}
const { cloudflareApi, domainSuggestions, zoneForDomain } = await import(
  await moduleURL("cloudflare-api", { "./api": await moduleURL("api") })
);

test("suggests normalized panel and route names only inside the selected zone", () => {
  assert.deepEqual(domainSuggestions("EXAMPLE.test.", [
    "Panel.Example.Test.", "app.example.test", "APP.example.test.",
    "example.test", "anotherexample.test", "*.example.test",
    "https://panel.example.test", "app.example.test/path", "-bad.example.test",
  ]), ["panel.example.test", "app.example.test", "example.test"]);
  const root = { id: "root", name: "example.test" };
  const child = { id: "child", name: "ops.example.test" };
  assert.equal(zoneForDomain([root, child], "Panel.OPS.example.test."), child);
  assert.equal(zoneForDomain([child], "panel.devops.example.test"), undefined);
});

test("reads and explicitly patches one setting in the selected zone", async (t) => {
  const originalFetch = globalThis.fetch;
  const originalWindow = globalThis.window;
  globalThis.window = new EventTarget();
  t.after(() => { globalThis.window = originalWindow; globalThis.fetch = originalFetch; });

  const path = "/api/cloudflare/zones/fictional-zone/settings/ssl";
  const setting = { id: "ssl", value: "full", editable: true };
  let calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push([url, options.method, options.body]);
    return Response.json({ ...setting, value: options.method === "PATCH" ? "strict" : "full" });
  };
  assert.deepEqual(await cloudflareApi.zoneSetting("fictional-zone", "ssl"), setting);
  assert.deepEqual(calls, [[path, "GET", undefined]]);
  assert.deepEqual(await cloudflareApi.saveZoneSetting("fictional-zone", "ssl", "strict"), {
    ...setting, value: "strict",
  });
  assert.deepEqual(calls[1], [path, "PATCH", '{"value":"strict"}']);

  globalThis.fetch = async () => Response.json({ ...setting, id: "always_use_https" });
  await assert.rejects(cloudflareApi.zoneSetting("fictional-zone", "ssl"), /неизвестном формате/);
  globalThis.fetch = async () => Response.json({
    error: "Check Zone Settings Write and reconnect Cloudflare",
  }, { status: 502 });
  await assert.rejects(cloudflareApi.saveZoneSetting("fictional-zone", "ssl", "strict"), /Zone Settings Write/);
});
