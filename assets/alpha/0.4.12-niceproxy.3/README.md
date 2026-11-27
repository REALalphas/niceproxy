# Alpha's UI

Package archives and their checksums are listed in `manifest.json`.
The corresponding [source code for this release](alpha-ui-source-0.4.12-niceproxy.3.tar.gz), its size, and its SHA-512 are specified in `manifest.source`.
The archive contains canonical components, runtime, build scripts, package-lock.json, and licenses.
After unpacking, run `npm ci`, then `npm run verify`; the release version is recorded in `RELEASE_SOURCE.json`.
Install from this directory: `node install.mjs --project /path/to/app --framework react`.
For Qwik, pass `--framework qwik`.

- [Releases, installation, and Hub integration](docs/distribution.md)
- [Component guide](docs/agent-guide.md)
- [Application agent rules](AGENTS.md)
- [License](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES.md)
