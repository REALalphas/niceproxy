#!/usr/bin/env node
import { promises as fs } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const state = resolve(process.env.NICEPROXY_ALPHA_STATE_DIR || join(root, ".alpha-state")),
  builds = join(state, "builds"),
  marker = join(state, "active.json"),
  migration = join(state, "migration.json"),
  lockPath = join(state, "migration.lock");
const LOCK_MAX_AGE = 10 * 60 * 1000;
const log = (m) => console.error(`[alpha-bootstrap] ${m}`);
const exists = async (p) => {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
};
async function validDist(p) {
  return (
    (await exists(join(p, "index.html"))) && (await exists(join(p, "assets")))
  );
}
async function readJSON(path) {
  try { return JSON.parse(await fs.readFile(path, "utf8")); } catch { return null; }
}
async function writeJSONAtomic(path, value) {
  const tmp = `${path}.${process.pid}.${Date.now()}.tmp`;
  const handle = await fs.open(tmp, "w", 0o600);
  try {
    await handle.writeFile(JSON.stringify(value));
    await handle.sync();
  } finally {
    await handle.close();
  }
  await fs.rename(tmp, path);
}
function validVersion(version) {
  return typeof version === "string" && version.length > 0 && version.length < 128 && /^[0-9A-Za-z][0-9A-Za-z.+-]*$/.test(version);
}
function validDigest(digest) {
  return typeof digest === "string" && digest.length > 0 && digest.length < 256 && /^[A-Za-z0-9._:+/=~-]+$/.test(digest);
}
function contentDigestValue(digest) {
  return typeof digest === "string" && /^[a-f0-9]{64}$/.test(digest);
}
async function contentDigest(path) {
  const hash = createHash("sha256");
  async function visit(p, relative) {
    const stat = await fs.stat(p);
    if (stat.isDirectory()) for (const name of (await fs.readdir(p)).sort()) await visit(join(p, name), join(relative, name));
    else if (relative !== ".app-build.json") { hash.update(relative); hash.update(await fs.readFile(p)); }
  }
  await visit(path, "");
  return hash.digest("hex");
}
async function buildManifest(p) {
  if (!(await validDist(p))) return null;
  const m = await readJSON(join(p, ".app-build.json"));
  if (!m || (m.schema !== undefined && m.schema !== 1) || !validVersion(m.version) || !validDigest(m.digest)) return null;
  if (contentDigestValue(m.digest) && await contentDigest(p) !== m.digest) return null;
  return { schema: 1, version: m.version, digest: m.digest };
}
async function markerBuild() {
  const a = await readJSON(marker);
  if (!a || !/^[\w.-]+$/.test(a.directory) || !validVersion(a.version)) return null;
  const p = join(builds, a.directory, "dist");
  const manifest = await buildManifest(p);
  const digest = a.digest || a.appDigest;
  if (!manifest || !validDigest(digest) || manifest.digest !== digest || manifest.version !== a.version) return null;
  return { ...a, digest, appDigest: digest, manifest, path: p };
}
async function acquireLock() {
  await fs.mkdir(state, { recursive: true });
  const token = `${process.pid}:${Date.now()}:${Math.random().toString(16).slice(2)}`;
  for (;;) {
    try {
      const handle = await fs.open(lockPath, "wx", 0o600);
      await handle.writeFile(JSON.stringify({ pid: process.pid, startedAt: Date.now(), token }));
      await handle.sync();
      await handle.close();
      return async () => {
        const current = await readJSON(lockPath);
        if (current?.token === token) await fs.rm(lockPath, { force: true });
      };
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
      const current = await readJSON(lockPath);
      let stale = !current || !Number.isInteger(current.pid) || !Number.isFinite(current.startedAt);
      if (!stale) {
        try { process.kill(current.pid, 0); } catch (probe) { stale = probe.code === "ESRCH"; }
        stale ||= Date.now() - current.startedAt > LOCK_MAX_AGE;
      }
      if (!stale) throw Error("UI migration already in progress");
      await fs.rm(lockPath, { force: true });
    }
  }
}
async function recoverMigration() {
  const p = await readJSON(migration);
  if (!p) {
    await fs.rm(migration, { force: true });
    return;
  }
  const directory = typeof p.directory === "string" && /^[\w.-]+$/.test(p.directory) ? p.directory : "";
  const target = directory ? join(builds, directory, "dist") : "";
  if (directory) await fs.rm(join(builds, `.staging-${directory}`), { recursive: true, force: true });
  if (p.phase === "ready" && target) {
    const manifest = await buildManifest(target);
    if (manifest && manifest.version === p.version && manifest.digest === p.digest) {
      await activate(directory, manifest.version, manifest.digest);
    } else if (directory) {
      await fs.rm(join(builds, directory), { recursive: true, force: true });
    }
  } else if (directory) {
    await fs.rm(join(builds, directory), { recursive: true, force: true });
  }
  await fs.rm(migration, { force: true });
}
async function appDigest() {
  const hash = createHash("sha256");
  async function visit(path) {
    const stat = await fs.stat(path);
    if (stat.isDirectory()) {
      for (const name of (await fs.readdir(path)).sort()) await visit(join(path,name));
    } else { hash.update(path.slice(root.length)); hash.update(await fs.readFile(path)); }
  }
  for (const name of ["src","index.html","package.json","tsconfig.json","vite.config.ts"]) await visit(join(root,name));
  return hash.digest("hex");
}
async function active() { return markerBuild(); }
async function sourceVersion() {
  try {
    const p = JSON.parse(await fs.readFile(join(root, "node_modules/@alpha/core/package.json"), "utf8"));
    if (validVersion(p.version)) return p.version;
  } catch {}
  try {
    const p = JSON.parse(await fs.readFile(join(root, "package.json"), "utf8"));
    if (validVersion(p.version)) return p.version;
  } catch {}
  return "0.0.0";
}
async function bundledBuild() {
  const p = join(root, "dist");
  const manifest = await buildManifest(p);
  if (manifest) return { manifest, path: p, legacy: false };
  if (!(await validDist(p))) return null;
  // Older images did not ship a manifest. Derive a stable identity for one
  // migration and persist it only in the derived state copy under /data/ui.
  return { legacy: true, manifest: { schema: 1, version: await sourceVersion(), digest: await contentDigest(p) }, path: p };
}
function versionParts(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?/.exec(v || "");
  return m ? [Number(m[1]), Number(m[2]), Number(m[3]), m[4] || ""] : null;
}
function compareVersions(a, b) {
  const x = versionParts(a), y = versionParts(b);
  if (!x || !y) return 0;
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] - y[i];
  if (!x[3] && y[3]) return 1;
  if (x[3] && !y[3]) return -1;
  return x[3].localeCompare(y[3]);
}
async function stageBuild(source, manifest, prefix) {
  const directory = `${prefix}-${Date.now()}-${process.pid}`;
  const temp = join(builds, `.staging-${directory}`);
  await writeJSONAtomic(migration, { schema: 1, phase: "staging", directory, version: manifest.version, digest: manifest.digest });
  await fs.rm(temp, { recursive: true, force: true });
  await fs.mkdir(temp, { recursive: true });
  await fs.cp(source, join(temp, "dist"), { recursive: true });
  if (!(await buildManifest(join(temp, "dist")))) {
    await fs.writeFile(join(temp, "dist/.app-build.json"), JSON.stringify(manifest));
  }
  const checked = await buildManifest(join(temp, "dist"));
  if (!checked || checked.version !== manifest.version || checked.digest !== manifest.digest) throw Error("staged UI manifest mismatch");
  await fs.rename(temp, join(builds, directory));
  await writeJSONAtomic(migration, { schema: 1, phase: "ready", directory, version: manifest.version, digest: manifest.digest });
  await activate(directory, manifest.version, manifest.digest);
  await fs.rm(migration, { force: true });
  return { directory, version: manifest.version, digest: manifest.digest, path: join(builds, directory, "dist"), manifest: checked };
}
export async function recordLocal() {
  if (!(await validDist(join(root, "dist"))))
    throw Error("local dist is incomplete");
  await fs.mkdir(builds, { recursive: true });
  const release = await acquireLock();
  try {
    const version = await sourceVersion();
    const digest = await contentDigest(join(root, "dist"));
    await fs.writeFile(join(root,"dist/.app-build.json"),JSON.stringify({schema:1,digest,version}));
    await stageBuild(join(root, "dist"), { schema: 1, version, digest }, "bundled");
    log(`local build recorded ${version}`);
  } finally { await release(); }
}
async function activate(directory, version, digest, signal) {
  signal?.throwIfAborted();
  const tmp = `${marker}.${process.pid}.${Date.now()}.tmp`;
  await writeJSONAtomic(tmp, { directory, version, digest, appDigest: digest });
  signal?.throwIfAborted();
  await fs.rename(tmp, marker);
}
function run(cmd, args, { cwd, signal } = {}) {
  return new Promise((ok, bad) => {
    if (signal?.aborted) {
      bad(signal.reason);
      return;
    }
    const c = spawn(cmd, args, {
      cwd,
      stdio: ["ignore", 2, 2],
      detached: true,
    });
    const stop = () => {
      try {
        process.kill(-c.pid, "SIGKILL");
      } catch {}
    };
    signal?.addEventListener("abort", stop, { once: true });
    c.once("error", bad);
    c.once("close", (n) => {
      signal?.removeEventListener("abort", stop);
      n === 0 && !signal?.aborted
        ? ok()
        : bad(
            Error(signal?.aborted ? "deadline exceeded" : `${cmd} exited ${n}`),
          );
    });
  });
}
async function fetchBytes(url, signal) {
  const r = await fetch(url, { signal });
  if (!r.ok) throw Error(`HTTP ${r.status}: ${url}`);
  const b = Buffer.from(await r.arrayBuffer());
  signal.throwIfAborted();
  return b;
}
export async function prepare({
  releaseRoot = process.env.NICEPROXY_ALPHA_RELEASE_URL,
  deadline = 20000,
} = {}) {
  await fs.mkdir(builds, { recursive: true });
  const releaseLock = await acquireLock();
  try {
    await recoverMigration();
    let previous = await active();
    const bundled = await bundledBuild();
    // A completed local Vite build is the bundled fallback. Never register a partial tree.
    // The image's bundled UI wins whenever it has a different identity or a newer version.
    const bundledVersionComparison = previous && bundled ? compareVersions(bundled.manifest.version, previous.version) : 1;
    if (bundled && (!previous || (bundled.legacy && bundled.manifest.digest !== previous.digest) || bundledVersionComparison > 0 || (bundledVersionComparison === 0 && bundled.manifest.digest !== previous.digest))) {
      previous = await stageBuild(bundled.path, bundled.manifest, "bundled");
    }
  let selected = previous;
  const ctl = new AbortController(),
    timer = setTimeout(
      () => ctl.abort(Error("20-second update deadline exceeded")),
      deadline,
    );
  const tmp = join(state, `staging-${process.pid}-${Date.now()}`);
  try {
    if (!releaseRoot) {
      log(
        "NICEPROXY_ALPHA_RELEASE_URL is not set: local bundled version " +
          (previous?.version ?? "0.4.11"),
      );
    } else {
      const base = new URL(
        releaseRoot.endsWith("/") ? releaseRoot : releaseRoot + "/",
      );
      if (!["http:", "https:"].includes(base.protocol))
        throw Error("release URL must use HTTP(S)");
      const latest = JSON.parse(
        (await fetchBytes(new URL("latest.json", base), ctl.signal)).toString(),
      );
      const v = latest.version;
      const versionParts = typeof v === "string"
        ? /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(v)
        : null;
      if (!versionParts || versionParts[4]?.split(".").some((part) => /^\d+$/.test(part) && part.length > 1 && part.startsWith("0")))
        throw Error("invalid release version");
      if (v === previous?.version) {
        log(`version ${v}: up to date`);
      } else {
        const release = new URL(v + "/", base),
          man = JSON.parse(
            (
              await fetchBytes(new URL("manifest.json", release), ctl.signal)
            ).toString(),
          );
        if (man.version !== v || man.schema !== 1)
          throw Error("invalid manifest");
        await fs.mkdir(tmp, { recursive: true });
        const pkg = JSON.parse(
          await fs.readFile(join(root, "package.json"), "utf8"),
        );
        for (const n of [
          "@alpha/core",
          "@alpha/react",
          "@alpha/project-server",
        ]) {
          const e = man.packages?.[n];
          if (
            !e ||
            typeof e.file !== "string" ||
            !/^[\w.-]+\.tgz$/.test(e.file) ||
            !/^sha512-[A-Za-z0-9+/]+={0,2}$/.test(e.integrity)
          )
            throw Error(`invalid manifest entry ${n}`);
          const b = await fetchBytes(new URL(e.file, release), ctl.signal);
          if (
            "sha512-" + createHash("sha512").update(b).digest("base64") !==
            e.integrity
          )
            throw Error(`checksum mismatch ${n}`);
          await fs.writeFile(join(tmp, e.file), b);
          pkg.dependencies[n] = "file:./" + e.file;
        }
        // Source and build configuration live in staging: module resolution must use staged packages.
        for (const f of [
          "src",
          "index.html",
          "tsconfig.json",
          "vite.config.ts",
        ])
          await fs.cp(join(root, f), join(tmp, f), { recursive: true });
        pkg.scripts.build = "vite build";
        await fs.writeFile(join(tmp, "package.json"), JSON.stringify(pkg));
        await run(
          "npm",
          ["install", "--ignore-scripts", "--no-audit", "--no-fund"],
          { cwd: tmp, signal: ctl.signal },
        );
        for (const n of ["core", "react", "project-server"]) {
          const p = JSON.parse(
            await fs.readFile(
              join(tmp, "node_modules", "@alpha", n, "package.json"),
              "utf8",
            ),
          );
          if (p.version !== v) throw Error(`package version mismatch ${n}`);
        }
        await run("npm", ["run", "typecheck"], {
          cwd: tmp,
          signal: ctl.signal,
        });
        await run("npm", ["run", "build"], { cwd: tmp, signal: ctl.signal });
        ctl.signal.throwIfAborted();
        if (!(await validDist(join(tmp, "dist"))))
          throw Error("build missing assets");
        const directory = `release-${v}-${Date.now()}-${process.pid}`;
        const releaseDigest = await contentDigest(join(tmp, "dist"));
        await fs.writeFile(join(tmp, "dist/.app-build.json"), JSON.stringify({ schema: 1, version: v, digest: releaseDigest }));
        await fs.rename(tmp, join(builds, directory));
        const built = await buildManifest(join(builds, directory, "dist"));
        if (!built) throw Error("release build missing manifest");
        ctl.signal.throwIfAborted();
        await writeJSONAtomic(migration, { schema: 1, phase: "ready", directory, version: built.version, digest: built.digest });
        await activate(directory, built.version, built.digest, ctl.signal);
        await fs.rm(migration, { force: true });
        selected = { directory, version: built.version, digest: built.digest, path: join(builds, directory, "dist"), manifest: built };
        log(`version ${v}: updated`);
      }
    }
  } catch (e) {
    log(`starting local build after error/timeout: ${e.message}`);
  } finally {
    clearTimeout(timer);
    ctl.abort();
    await fs.rm(tmp, { recursive: true, force: true });
  }
  if (!selected) {
    throw Error(
      "No ready local build is available. Manual installation is required: node /path/to/release/install.mjs --project . --framework react; then npm run build",
    );
  }
  const path = selected.path || join(builds, selected.directory, "dist");
  log(`selected version ${selected.version}: ${path}`);
  return path;
  } finally { await releaseLock(); }
}
async function main() {
  if (process.argv.includes("--record-local")) {
    await recordLocal();
    return;
  }
  const path = await prepare();
  if (process.argv.includes("--prepare")) {
    console.log(path);
    return;
  }
  const ctl = new AbortController();
  for (const s of ["SIGINT", "SIGTERM"]) process.once(s, () => ctl.abort());
  await run(
    process.execPath,
    [
      join(root, "node_modules/vite/bin/vite.js"),
      "preview",
      "--outDir",
      path,
      "--host",
      "127.0.0.1",
    ],
    { cwd: root, signal: ctl.signal },
  );
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
)
  main().catch((e) => {
    log(e.message);
    process.exitCode = 1;
  });
