import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, cp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import http from "node:http";
import { createHash } from "node:crypto";
async function fixture(t, local = true) {
  const root = await mkdtemp(join(tmpdir(), "niceproxy-alpha-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "scripts"));
  await cp(
    "scripts/alpha-bootstrap.mjs",
    join(root, "scripts/alpha-bootstrap.mjs"),
  );
  if (local) {
    await mkdir(join(root, "dist/assets"), { recursive: true });
    await writeFile(join(root, "dist/index.html"), "working");
  }
  for (const p of ["src"]) await mkdir(join(root, p));
  for (const p of ["index.html", "tsconfig.json", "vite.config.ts"])
    await writeFile(join(root, p), "");
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({ dependencies: {}, scripts: {} }),
  );
  const m = await import(
    pathToFileURL(join(root, "scripts/alpha-bootstrap.mjs"))
  );
  return { root, prepare: m.prepare };
}
async function server(t, handler) {
  const s = http.createServer(handler);
  await new Promise((r) => s.listen(0, "127.0.0.1", r));
  t.after(() => {
    s.closeAllConnections();
    s.close();
  });
  return `http://127.0.0.1:${s.address().port}`;
}
test("no URL registers completed bundled build and keeps it offline", async (t) => {
  const { root, prepare } = await fixture(t);
  const path = await prepare({ releaseRoot: "" });
  assert.equal(await readFile(join(path, "index.html"), "utf8"), "working");
  await rm(join(root, "dist"), { recursive: true });
  assert.equal(await prepare({ releaseRoot: "http://127.0.0.1:1" }), path);
});
test("no local build fails with manual installation command", async (t) => {
  const { prepare } = await fixture(t, false);
  await assert.rejects(prepare({ releaseRoot: "" }), /install.mjs/);
});
test("network timeout falls back within overall deadline and aborts requests", async (t) => {
  const { prepare } = await fixture(t);
  const url = await server(t, () => {});
  const started = Date.now();
  const path = await prepare({ releaseRoot: url, deadline: 100 });
  assert.ok(Date.now() - started < 1500);
  assert.equal(await readFile(join(path, "index.html"), "utf8"), "working");
});
const bytes = Buffer.from("not an archive");
const integrity =
  "sha512-" + createHash("sha512").update(bytes).digest("base64");
async function releaseServer(t, corrupt = false) {
  return server(t, (req, res) => {
    res.setHeader("Content-Type", "application/json");
    if (req.url === "/latest.json")
      res.end(JSON.stringify({ version: "0.5.0" }));
    else if (req.url.endsWith("manifest.json"))
      res.end(
        JSON.stringify({
          schema: 1,
          version: "0.5.0",
          packages: Object.fromEntries(
            ["core", "react", "project-server"].map((n) => [
              "@alpha/" + n,
              {
                file: n + ".tgz",
                integrity: corrupt ? "sha512-AAAA" : integrity,
              },
            ]),
          ),
        }),
      );
    else res.end(bytes);
  });
}
test("corrupt archive preserves active marker and local assets", async (t) => {
  const { root, prepare } = await fixture(t);
  const original = await prepare({ releaseRoot: "" });
  const marker = await readFile(join(root, ".alpha-state/active.json"), "utf8");
  assert.equal(
    await prepare({ releaseRoot: await releaseServer(t, true) }),
    original,
  );
  assert.equal(
    await readFile(join(root, ".alpha-state/active.json"), "utf8"),
    marker,
  );
});
test("installation failure falls back and cleans staging", async (t) => {
  const { prepare } = await fixture(t);
  const original = await prepare({ releaseRoot: "" });
  assert.equal(
    await prepare({ releaseRoot: await releaseServer(t), deadline: 3000 }),
    original,
  );
});
import { execFile } from "node:child_process";
import { promisify } from "node:util";
const exec = promisify(execFile);
async function validRelease(t, version = "0.5.0") {
  const temp = await mkdtemp(join(tmpdir(), "alpha-release-"));
  t.after(() => rm(temp, { recursive: true, force: true }));
  const packages = {};
  const archives = {};
  for (const n of ["core", "react", "project-server"]) {
    const p = join(temp, n, "package");
    await mkdir(p, { recursive: true });
    await writeFile(
      join(p, "package.json"),
      JSON.stringify({ name: "@alpha/" + n, version }),
    );
    const archive = join(temp, n + ".tgz");
    await exec("tar", ["-czf", archive, "-C", join(temp, n), "package"]);
    const b = await readFile(archive);
    archives["/" + version + "/" + n + ".tgz"] = b;
    packages["@alpha/" + n] = {
      file: n + ".tgz",
      integrity: "sha512-" + createHash("sha512").update(b).digest("base64"),
    };
  }
  return server(t, (req, res) => {
    if (req.url === "/latest.json") res.end(JSON.stringify({ version }));
    else if (req.url.endsWith("manifest.json"))
      res.end(JSON.stringify({ schema: 1, version, packages }));
    else res.end(archives[req.url]);
  });
}
test("staging build failure leaves marker unchanged", async (t) => {
  const { root, prepare } = await fixture(t);
  const original = await prepare({ releaseRoot: "" });
  await writeFile(
    join(root, "package.json"),
    JSON.stringify({
      dependencies: {},
      scripts: { typecheck: 'node -e "process.exit(0)"' },
    }),
  );
  assert.equal(await prepare({ releaseRoot: await validRelease(t) }), original);
});
test("available trusted release builds staged packages and activates completed dist", async (t) => {
  const { root, prepare } = await fixture(t);
  await prepare({ releaseRoot: "" });
  const marker = join(root, ".alpha-state/active.json");
  const a = JSON.parse(await readFile(marker, "utf8"));
  a.version = "0.4.8";
  await writeFile(marker, JSON.stringify(a));
  for (const f of ["src", "index.html", "vite.config.ts", "tsconfig.json"])
    await cp(resolve(f), join(root, f), { recursive: true, force: true });
  const pkg = JSON.parse(await readFile("package.json", "utf8"));
  await writeFile(join(root, "package.json"), JSON.stringify(pkg));
  const release = resolve("../assets/alpha/0.4.11");
  const url = await server(t, async (req, res) => {
    try {
      res.end(
        req.url === "/latest.json"
          ? JSON.stringify({ version: "0.4.11" })
          : await readFile(join(release, req.url.split("/").at(-1))),
      );
    } catch {
      res.statusCode = 404;
      res.end();
    }
  });
  const path = await prepare({ releaseRoot: url });
  const selected = JSON.parse(await readFile(marker, "utf8"));
  assert.equal(selected.version, "0.4.11");
  assert.match(selected.directory, /release-0.4.11/);
  assert.ok(
    (await readFile(join(path, "index.html"), "utf8")).includes("assets/"),
  );
});

test("production 20 second deadline cancels a slow server", async (t) => {
  const { prepare } = await fixture(t);
  const url = await server(t, () => {});
  const started = Date.now();
  const path = await prepare({ releaseRoot: url });
  assert.ok(Date.now() - started >= 19000);
  assert.ok(Date.now() - started < 23000);
  assert.equal(await readFile(join(path, "index.html"), "utf8"), "working");
});

test("a new bundled app build replaces persisted UI even at the same Alpha version", async (t) => {
  const {root,prepare}=await fixture(t);
  await writeFile(join(root,"dist/.app-build.json"),JSON.stringify({digest:"first",version:"0.4.11"}));
  const first=await prepare({releaseRoot:""});
  await writeFile(join(root,"dist/index.html"),"new application build");
  await writeFile(join(root,"dist/.app-build.json"),JSON.stringify({digest:"second",version:"0.4.11"}));
  const second=await prepare({releaseRoot:""});
  assert.notEqual(first,second);
  assert.equal(await readFile(join(second,"index.html"),"utf8"),"new application build");
});
