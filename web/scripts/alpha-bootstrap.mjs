#!/usr/bin/env node
import { promises as fs } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const state = resolve(process.env.NICEPROXY_ALPHA_STATE_DIR || join(root, ".alpha-state")),
  builds = join(state, "builds"),
  marker = join(state, "active.json");
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
async function active() {
  try {
    const a = JSON.parse(await fs.readFile(marker, "utf8"));
    return /^[\w.-]+$/.test(a.directory) &&
      (await validDist(join(builds, a.directory, "dist")))
      ? a
      : null;
  } catch {
    return null;
  }
}
export async function recordLocal() {
  if (!(await validDist(join(root, "dist"))))
    throw Error("local dist is incomplete");
  await fs.mkdir(builds, { recursive: true });
  const directory = `bundled-${Date.now()}`;
  await fs.cp(join(root, "dist"), join(builds, directory, "dist"), {
    recursive: true,
  });
  const pkg = JSON.parse(
    await fs.readFile(
      join(root, "node_modules/@alpha/core/package.json"),
      "utf8",
    ),
  );
  const digest = await appDigest();
  await fs.writeFile(join(root,"dist/.app-build.json"),JSON.stringify({digest,version:pkg.version}));
  await activate(directory, pkg.version, digest);
  log(`зафиксирована локальная сборка ${pkg.version}`);
}
async function activate(directory, version, digest, signal) {
  signal?.throwIfAborted();
  const tmp = marker + ".tmp";
  await fs.writeFile(tmp, JSON.stringify({ directory, version, appDigest:digest }));
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
  let previous = await active();
  let bundled;
  try { bundled=JSON.parse(await fs.readFile(join(root,"dist/.app-build.json"),"utf8")); } catch {}
  const digest = bundled?.digest || await appDigest();
  // A completed local Vite build is the bundled fallback. Never register a partial tree.
  if ((!previous || (bundled?.digest && previous.appDigest !== digest)) && (await validDist(join(root, "dist")))) {
    const directory = `bundled-${Date.now()}`;
    await fs.cp(join(root, "dist"), join(builds, directory, "dist"), {
      recursive: true,
    });
    await activate(directory, bundled?.version || "0.4.9", digest);
    previous = await active();
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
        "NICEPROXY_ALPHA_RELEASE_URL не задан: локальная bundled версия " +
          (previous?.version ?? "0.4.9"),
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
      if (typeof v !== "string" || !/^\d+\.\d+\.\d+$/.test(v))
        throw Error("invalid release version");
      if (v === previous?.version) {
        log(`версия ${v}: актуально`);
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
        const directory = `release-${v}-${Date.now()}`;
        await fs.rename(tmp, join(builds, directory));
        ctl.signal.throwIfAborted();
        await activate(directory, v, digest, ctl.signal);
        selected = { directory, version: v };
        log(`версия ${v}: обновлено`);
      }
    }
  } catch (e) {
    log(`запуск локальной после ошибки/таймаута: ${e.message}`);
  } finally {
    clearTimeout(timer);
    ctl.abort();
    await fs.rm(tmp, { recursive: true, force: true });
  }
  if (!selected) {
    throw Error(
      "Нет готовой локальной сборки. Требуется ручная установка: node /путь/к/выпуску/install.mjs --project . --framework react; затем npm run build",
    );
  }
  const path = join(builds, selected.directory, "dist");
  log(`выбрана версия ${selected.version}: ${path}`);
  return path;
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
