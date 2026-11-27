import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import ts from "typescript";
const source = await readFile(
  new URL("../src/http-path.ts", import.meta.url),
  "utf8",
);
const { outputText } = ts.transpileModule(source, {
  compilerOptions: {
    target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.ESNext,
  },
});
const { validHttpPath } = await import(
  `data:text/javascript;base64,${Buffer.from(outputText).toString("base64")}`
);
test("literal route path accepts root/default and rejects server-invalid prefixes", () => {
  for (const path of ["", "/", "/api", "/api/", "/API/v1", "/data", "/a\uFEFFb"])
    assert.equal(validHttpPath(path), true, path);
  for (const path of [
    "api",
    "/api//v1",
    "/api/*",
    "/api/%20",
    "/api/../v1",
    "/./api",
    "/api?x",
    "/api#x",
    "/api\\x",
    "/{path}",
    "/[x]",
    "/a\tb",
    "/a\u0000b",
    "/a\u0085b",
    "/a b",
    "/" + "é".repeat(1024),
  ])
    assert.equal(validHttpPath(path), false, path);
  assert.equal(validHttpPath("/" + "a".repeat(2047)), true);
  assert.equal(validHttpPath("/" + "a".repeat(2048)), false);
});
