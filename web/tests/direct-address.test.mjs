import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";
const source = await readFile(
  new URL("../src/direct-address.ts", import.meta.url),
  "utf8",
);
const { outputText } = ts.transpileModule(source, {
  compilerOptions: {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
  },
});
const { isDirectIP, isDirectTarget } = await import(
  `data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`
);
test("direct fields accept bare IPs and target hostnames, never URL or host:port syntax", () => {
  for (const ip of [
    "0.0.0.0",
    "127.0.0.1",
    "192.168.1.10",
    "::",
    "::1",
    "2001:db8::1",
    "::ffff:192.0.2.1",
  ]) {
    assert.ok(isDirectIP(ip), ip);
    assert.ok(isDirectTarget(ip), ip);
  }
  for (const host of ["example.test", "localhost", "my-service.lan"]) {
    assert.equal(isDirectIP(host), false);
    assert.equal(isDirectTarget(host), true);
  }
  for (const invalid of [
    "",
    "example.test:8080",
    "http://localhost",
    "localhost/path",
    "[::1]",
    "::1]/path",
    "::1]#fragment",
    "::1]?query",
    "::1]",
    "fe80::1%eth0",
    "-host",
    "host_1",
    "a..b",
    " a",
  ]) {
    assert.equal(isDirectIP(invalid), false, invalid);
    assert.equal(isDirectTarget(invalid), false, invalid);
  }
});
