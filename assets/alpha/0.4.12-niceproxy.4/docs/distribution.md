# Releases and unified launcher server

The `scripts/`, `examples/` paths and release commands below refer to the root of the source repository. The installed npm package contains the runtime and documentation; development scripts and the sibling Hub are not included.

## Releasing the library

Requires Node.js 22.23.4+ (Astro minimum for building the documentation site). Run `npm ci`, then `npm run release -- X.Y.Z`, replacing `X.Y.Z` with a new, unused version. The command checks generation, build, types, tests, and package contents, creates an **immutable** `releases/X.Y.Z` directory, and switches `releases/latest.json`. An existing version cannot be reused. Source `package.json` files do not need bulk editing: archive versions, the component catalog, and internal dependencies are set by the release builder. Publishing to npm or GitHub is not performed.

New releases contain: `@alpha/core`, `@alpha/react`, `@alpha/qwik`, `@alpha/project-server`, the corresponding source archive `alpha-ui-source-X.Y.Z.tar.gz`, manifest with SHA-512, agent instructions, installer, LICENSE, THIRD_PARTY_NOTICES.md, and third-party license texts. License files are also included in every npm archive. Alpha's Hub lives in a separate project; `../alpha-hub` is used for joint local development and is no longer included in the library release. Old releases containing the hub archive remain unchanged. A release directory can be copied as a whole to another machine.

## Preparing and publishing to npm

Four separate packages are published from the verified release directory. The root workspace is private. The packages set `publishConfig` for public access at `https://registry.npmjs.org/`; README, licenses, runtime, and types are included in the archives. Do not run `npm publish` from the repository root.

```sh
npm ci
npm run release -- X.Y.Z
node scripts/check-release.mjs releases/X.Y.Z
npm run check:npm -- releases/X.Y.Z
```

The last command compares the SHA-512 and size of each package against the manifest, checks names, versions, and the presence of README/licenses, then runs `npm publish --dry-run --ignore-scripts` for each prepared archive. It publishes nothing and does not verify account permissions or version availability in the registry. Pre-releases use the `next` tag; regular releases use `latest`.

Before an actual publish, log in via `npm login --registry=https://registry.npmjs.org/`, verify `npm whoami`, and confirm write access to the `@alpha` organization. A 404 response from `npm view` does not reserve a scope or grant permissions on it. If another scope is needed, first update names, internal dependencies, imports, generators, the installer, and documentation consistently, then cut a new release.

Verify that the chosen version is not yet published for all four packages: `npm view @alpha/core@X.Y.Z version` and similarly for react, qwik, and project-server. A network or authentication error must not be treated as confirmation that a version is free. npm does not allow reusing a published version.

Before publishing, host the source archive for the exact version and provide recipients with a working link in accordance with §4 of `LICENSE`. The README on npm alone does not provide the source code. Open owner decisions regarding rightsholder contacts and Hub distribution are listed in `PUBLIC_RELEASE_AUDIT.md` in the source repository. Addresses and details are not substituted automatically.

Publish **the exact archives** verified above—core first, then adapters and the server:

```sh
npm publish ./releases/X.Y.Z/alpha-core-X.Y.Z.tgz --ignore-scripts --access public --registry=https://registry.npmjs.org/ --tag latest
npm publish ./releases/X.Y.Z/alpha-react-X.Y.Z.tgz --ignore-scripts --access public --registry=https://registry.npmjs.org/ --tag latest
npm publish ./releases/X.Y.Z/alpha-qwik-X.Y.Z.tgz --ignore-scripts --access public --registry=https://registry.npmjs.org/ --tag latest
npm publish ./releases/X.Y.Z/alpha-project-server-X.Y.Z.tgz --ignore-scripts --access public --registry=https://registry.npmjs.org/ --tag latest
```

For a version with a suffix, replace `latest` with `next`. npm may prompt for two-factor authentication. Publishing multiple packages is not atomic: on partial success, inspect the state of each package and proceed only with the archives not yet published. After publishing, compare `npm view @alpha/core@X.Y.Z dist.integrity` against the manifest and repeat for the remaining packages. Installing from npm: `npm install @alpha/core@X.Y.Z @alpha/react@X.Y.Z` (or `@alpha/qwik@X.Y.Z`); the project server is installed separately if needed. The rules in `@alpha/core/AGENTS.md` must be read and linked in the project's instructions manually: a plain `npm install` does not run the release installer.

Components and types are already compiled; the consumer does not need the library source or generator. npm installs package dependencies; for a fully offline installation, prepare an npm dependency cache in advance. Complete standalone portability is verified by `node scripts/check-release.mjs releases/X.Y.Z`.

## Installing into a project

From any project: `node /path/to/releases/X.Y.Z/install.mjs --project . --framework react`. For Qwik: `--framework qwik`. Updating uses the same command from the new release. It installs core, the chosen adapter, and the project server; component versions match. React/Qwik and the bundler remain project dependencies. The installer also creates `ALPHA_UI_AGENT_RULES.md`; add to the root `AGENTS.md`: "Always read and follow ALPHA_UI_AGENT_RULES.md".

Import `@alpha/core/fonts.css`, `@alpha/core/styles.css`, and import components from the adapter. In the core package, `AGENTS.md`, the catalog via `@alpha/core/catalog.json`, tokens, and documentation are available in `dist/`. Guides for [setup](agent-guide.md), [chat](chat.md), and [application agent rules](consumer-agent-rules.md) are included in the package. Archives are built using standard [npm pack](https://docs.npmjs.com/cli/v11/commands/npm-pack/).

In `catalog.json`, the `schema` field denotes the catalog format, and `version` denotes the library version. In the source workspace, package versions may differ from the latest prepared release: staging sets the chosen version separately.

Usage terms are governed by AHCL-1.0. When distributing the library, comply with §4 of `LICENSE`: provide recipients with the corresponding source code or a working download for the exact version for the duration specified by the license. For new releases, the archive is already created alongside the packages. The `release` command does not create a public server or repository; the distributor is responsible for making the source available to recipients. Terms for third-party assets are described in `THIRD_PARTY_NOTICES.md` at the repository root and in each package; open publishing questions are in `PUBLIC_RELEASE_AUDIT.md` in the source repository.

§4 requirements also apply to forks and mirrors: preserve AHCL-1.0 and applicable notices, mark modifications, and do not present a modified version as an official release. Renaming, replacing the LICENSE file, minification, or compilation alone does not grant the right to relicense someone else's code. This clarifies the existing condition; separate rightsholder permissions and third-party asset licenses are governed by `LICENSE`.

## Release source and conformance verification

In `manifest.json`, the `source` field contains `file`, `integrity` (SHA-512), and `size` of the `alpha-ui-source-X.Y.Z.tar.gz` archive. The release README links to this archive. The extra field is compatible with the installer and project server: they continue reading `packages`.

The archive contains canonical `source/`, manual runtime modules and core assets, generated adapters and demos, workspace configuration, `package-lock.json`, build scripts, tests, examples, documentation, and licenses. The list of root files and directories is defined in `scripts/lib/release-source.mjs`. Git, dependencies, build artifacts, old releases, local avatars, env files, keys, logs, and conflict copies are excluded; a symlink in the source aborts archive creation.

Unpack the archive and inside `alpha-ui-source-X.Y.Z` run `npm ci`, then `npm run verify`. Node.js and npm dependencies must be available; the sibling Hub and local avatars are not needed for the build. `RELEASE_SOURCE.json` records the release version and source workspace version. The original `package.json` and lockfile are kept without version substitution: when creating packages, `stagePackage` sets the release version, including the core catalog and internal dependencies. You can reproduce package creation by running `npm run release -- X.Y.Z` in an unpacked copy where that version does not yet exist.

`npm run check:packages` creates a temporary archive using the same code and verifies SHA-512, contents, and byte-for-byte equality with the source. `node scripts/check-release.mjs releases/X.Y.Z` additionally unpacks the source into a separate temporary directory, runs `npm ci` and `npm run verify`, rebuilds the four packages with the release version, and compares the file list and contents against the distributed archives. It then verifies installation and standalone builds of the React/Qwik apps. Run this command only for a trusted local release: it executes its build scripts. For historical releases without `manifest.source`, only package portability is verified; the script explicitly reports that the source was not checked. Old archives are not backfilled retroactively.

## Connecting a project to the Hub once

In the project, add `alpha.project.json`:

```json
{
  "name": "My Project",
  "framework": "react",
  "hub": "http://127.0.0.1:5180",
  "port": 5191,
  "buildScript": "build",
  "output": "dist"
}
```

Add the npm script `alpha:serve`: `alpha-project alpha.project.json`. Run `npm run alpha:serve`. This is the project's build and UI serving server. Sources stay in the project; build commands are determined by its local configuration. An HTTP request cannot inject a command.

The current prebuilt adapter serves a **static client-side build** for React or Qwik. For Vite, set `base: './'` so the app version works under `/runs/<id>/`. Qwik CSR requires an event loader; a working example is in `examples/consumers/qwik`. Qwik SSR/Qwik City, Next.js, and server applications require a custom adapter following the protocol below that builds and starts a new server instance. Native Tauri/Electron binaries are not reinstalled by this web server: their shell must be released separately; the web UI is built with the same packages.

## Running the Hub

No public download address for Alpha's Hub is specified yet. This repository contains the adapter and protocol, not the Hub itself. The commands below assume the separate project has already been provided by the owner. For usage modes requiring mandatory integration, Hub access and a working connection per §3 of `LICENSE` are required; the protocol specification alone does not provide them.

In the separate `../alpha-hub` project: `npm ci`, `npm run build`, `npm start`. Configuration is its `alpha.hub.json`; the default releases directory is `../alphas-base/releases`. For your own projects, replace the `projects` array with links to their servers:

```json
{
  "port": 5180,
  "publicUrl": "http://127.0.0.1:5180",
  "releases": "../alphas-base/releases",
  "autoUpdate": true,
  "projects": [{"id":"my-app","name":"My Project","url":"http://127.0.0.1:5191"}]
}
```

Separate machine: transfer the Alpha's Hub project, wire Alpha's UI dependencies from the chosen release instead of local paths, copy the releases directory, and specify it in the configuration. Then install dependencies, build Hub, and run `npm start`. Documentation and configuration of the client shell belong to the separate Hub project; they are not included in this repository.

The Hub reads the current release, queries project URLs, forcibly replaces old pinned UI dependencies in a **separate copy of the project**, builds it, and serves the current version. When a new `latest` appears, it automatically re-runs. A repeated request for the same manifest does not rebuild the already built project. On an incompatible API, installation failure, or build failure, the new version is not marked as running; the previous URL continues working. Old tabs and lazy Qwik modules continue using the old `/runs/<id>/`, while a new launch receives a new address. Build copies are stored in `.alpha-builds`; the original `package.json` and lockfile are untouched.

By default, servers listen only on 127.0.0.1. For network deployment, use your own protected reverse proxy and the same `token` in both the project server configuration and the project entry in the hub. The token is passed between servers and is not exposed to the panel. The Hub's `publicUrl` must be reachable by the projects. This is a local integration without user accounts or public multi-user authentication. SHA-512 confirms archive compliance with the manifest, but does not replace a trusted source or signature. Do not expose dev servers or an unprotected update endpoint to the public network.

## Contract for an existing server

`GET /.well-known/alpha-ui.json` returns `{schema:1,framework:"react"|"qwik",version:"X.Y.Z"|null,active:"/runs/id/"|null,update:"/_alpha/update"}`.

`POST /_alpha/update` accepts `{manifestUrl:"http://hub/releases/X.Y.Z/manifest.json"}`. The server validates the trusted hub, archive SHA-512 checksums, installs core and the adapter from the release, rebuilds the sources, and verifies availability. It returns the same project manifest with the actual new `version` and `active`. On error, it returns HTTP 500 and preserves the previous instance. Hub does not patch an already built third-party site: a plain URL without this contract receives a clear connection error.

## Implementation boundaries

In the sibling Hub, applications are currently opened via an iframe. The application bootstrap with a 20-second total update timeout is described as a requirement in [application agent rules](consumer-agent-rules.md), but is not implemented automatically by the installer or this server and is not currently present in Hub. The bootstrap file must be written in the consumer application itself; do not look for it in this repository and do not claim it is an existing feature.

## Demos and verification

`npm run demo:projects` starts two independent projects from `examples/consumers` on 5191/5192. Their sources request the old 0.1.0 version. Hub launches them with the current release. Open `http://127.0.0.1:5180` and click "Update and start all" or wait for automatic startup. New releases appear without restarting the Hub.

`npm test` in Alpha's Hub checks the contract, pinned old version, release replacement, errors, and preservation of the previous build. Real independent React/Qwik projects are separately verified through the Hub in the browser.

The project server also compares source contents: the "Update" button rebuilds a changed application even if the UI release has not changed. If both sources and the release are unchanged, the ready build is reused.

## Build copy cleanup

The server automatically deletes old `.alpha-builds` directories on startup and after a successful update (including on a repeated request without rebuilding). By default, the active build and the two newest previous ones are kept. You can set `"retainBuilds": 1` in `alpha.project.json` to keep only the active build, or another integer from 1 to 100. The active build is preserved regardless of file timestamps.

A failed build copy is deleted immediately on error; incomplete copies without an output `index.html` are removed on the next startup. Cleanup only touches directories with version-and-UUID formatted IDs created by the server; unrelated files and symlinks are not deleted. On a deletion error, the working build remains active and the reason is exposed in `cleanupError` of the project protocol.

Old `/runs/<id>/` URLs work only while the build remains in the retained pool. Tabs from older builds, including lazy Qwik modules, must be reloaded after cleanup. Releases in `releases` and project sources are not cleaned up.
