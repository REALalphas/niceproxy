# Alpha's UI — Setup and Usage

## Status of These Rules

These are engineering instructions for agents working with Alpha's UI in an application: they define the integration, modification, and verification workflow for the shared UI. They do not alter `LICENSE` and do not create additional legal restrictions or licensing terms. Rights to use, modify, and distribute are governed by `LICENSE`; permissions granted by it remain intact. In this workflow, a component change is made in the library sources followed by a package update and application verification. Support terms, if agreed separately, also do not automatically modify the license.

## Installation and Integration

1. Install core and an adapter from a single release:
   `node /path/to/release/install.mjs --project . --framework react`
   For Qwik, use `--framework qwik`. If the installer is already available locally, a remote release can be passed via `--from https://<server>/releases/X.Y.Z/`.
2. Import once at the entry point:
   ```tsx
   import '@alpha/core/fonts.css';
   import '@alpha/core/styles.css';
   ```
3. Import components from `@alpha/react` or `@alpha/qwik`. Place regular components inside `.alpha-ui`; `AppShell` creates `.as-shell` on its own. Use props and types from the installed adapter; the component list is available via the `@alpha/core/catalog.json` export (physical file after installation — `node_modules/@alpha/core/dist/catalog.json`).
4. In the browser entry point, install `installControlMotion()` from `@alpha/core` once. When tearing down the scope, call the returned cleanup function. Do not register handlers during SSR or on every render.
5. Add a link in the root `AGENTS.md` to `ALPHA_UI_AGENT_RULES.md`, which the installer creates. Update this file together with the package.

## Updating Without Pinning to a Release

- Specify the update source as the releases directory URL in the project configuration. Do not invent an address: use the provided server. In the current format, it contains `latest.json` with a `version` field, and `X.Y.Z/manifest.json` with package archives and SHA-512 hashes.
- On every startup, resolve the release via `latest.json`. Do not pin an old archive URL or a specific version as a permanent update source. Update core and the chosen adapter together to the same version.
- A separate verified installation and lockfile may pin exact versions for reproducibility. They must not block selecting a new release via the bootstrap script. Do not replace dependencies with `*`: packages are distributed as release archives, and there is no public npm package for such updates.
- Perform the update in a separate build copy or staging directory. Verify the manifest, checksums, version match, installation, build, and availability of the result. Activate only a completed, verified build. Keep the previous working build for offline startup and update failures.
- Do not edit files of the installed package or swap individual JS/QRL files in an already running application.

## Startup Bootstrap

**There is no ready-made bootstrap implementation in this repository.** Below are the requirements for the consuming application's startup script.

Create such a script in the consuming application, choosing a name and location suited to its structure. Route the application's start command through this script; use the actual configuration and start command of the application itself. The library and standard installer do not create a bootstrap script automatically.

Bootstrap behavior:

1. Record the last successfully installed and built local version. Start an attempt to fetch a fresh release from the internet.
2. Cap the entire update attempt at a total timeout of **20 seconds**, including requests, downloading, installation, and preparing the new build. Do not allocate 20 seconds to each step individually.
3. If the new release is completely ready within the deadline, start it. If the release has not changed, start the prebuilt local build.
4. If the network is unavailable, an update fails, or the 20 seconds expire, start the last working local build if one exists. Here, "last" means the last successfully prepared build, not a partially downloaded one.
5. Abort in-flight requests and update processes. Do not allow a late result to switch the active version after the local one has started. Release timers and temporary resources.
6. If no working local version exists, report that startup requires installing the package and show the manual install command. Do not render an empty UI or wait indefinitely.
7. In the output, state the selected version and outcome: updated, up to date, started local build after error/timeout, or manual installation required. Do not prompt for confirmation on every normal update attempt.

For manual updates, use the same installer from the target release:
`node /path/to/release/install.mjs --project . --framework react`.
Then build the application and save it as the working local version. For Qwik, specify `--framework qwik`. When offline, use a local release directory; required dependencies must be available locally or in the package manager cache.

Test the bootstrap with an available server, offline, with a slow response exceeding 20 seconds, a corrupted archive, a build error, and a missing local version. Do not declare auto-update working until these scenarios are verified.

## Do Not Modify Components in the Application

**A local CSS override is also a component modification, even if Alpha's UI sources were untouched.** This prohibition applies to Button, Card, navigation, fields, and all other library components.

- Allowed: choosing public props and variants, passing content and handlers, composing existing components. Application CSS defines the layout of outer containers: grid, direction, gaps between components, available width, and responsive placement.
- Forbidden: tailoring a component to a mockup via local classes, `style`, global selectors, `.as-*`, nested elements, pseudo-elements, `!important`, or overriding `--as-*` variables. Do not use these to alter background, color, font, padding, control dimensions or shape, radius, border, shadow, icons, animation, or states.
- `className` does not grant permission to alter component styling. A wrapper is also not a workaround for this rule: do not add a border, backdrop, overlay layer, or handler on it to mimic a missing variant or behavior.
- Broad rules like `button { ... }`, `aside button { ... }` and page-level token overrides must not alter library components. Do not use tokens as a way to disguise a local modification.
- A request to build a screen or match a mockup does not grant permission to modify components. If a needed variant is missing from the public API, report this and create `ui-unspec/<component_name>.md`. The solution must be a universal extension of Alpha's UI, not an application CSS patch.
- If local overrides have already been added, remove them, restore standard states, and document the genuinely missing capability. Do not describe such work as "only changed layout".

Example of allowed layout CSS:

```css
.page-actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--as-space-3);
}
```

A rule like `.page-actions .as-button { padding: ...; background: ...; }` already modifies the component and is forbidden. The same applies to cards and sidebar or bottom navigation items.

## Components and Styling

- Build screens from public components. Custom compositions and layout CSS are allowed; copying implementations, tampering with internal markup, and pulling in another UI library to work around a missing feature are not.
- Use `--as-*` tokens for colors, spacing, sizes, radii, and motion. Do not duplicate token values in screen CSS.
- Body text — Noto Sans; headings, buttons, navigation, and service title — Manrope; technical values — Fira Code. Font weights: regular 400, emphasized text and headings 500, service title 600. Minimum text size — `1rem`.
- Dimensions in `rem` from a `16px` base, containers in relative units, assets with `aspect-ratio`. Maximum width — `--as-size-content-max`.
- UI icons — Lucide via `Icon`; size `1.5rem`, stroke regular `0.09375rem`, bold `0.125rem`. Logos, photos, and illustrations are separate assets.
- Primary background — canvas; cards — surface/overlay; navigation layers — navigation. Use canvasDeep only when explicitly required.
- Borders — `box-shadow: inset`; `border: 0` is acceptable for resets. Standard exceptions: dashed Disabled on Button and Loading on Profile.
- Corners — `corner-shape: superellipse(1.2)` with `border-radius` fallback; round chat corners — `corner-shape: round`.
- Preserve library motion and its tokens, and respect reduced motion. Do not mix up hover, press, release, focus, and active selection. Buttons and navigation are not text-selectable; read-only fields preserve text copying.
- Qwik: QRL handlers with `$` suffix; do not override container `q:base`. Verify lazy handlers in production and when hosted under a subpath.

## Missing Components: Required Feedback

If a component, prop, state, or behavior is missing, **immediately inform the user** what is needed, where, and why the existing API is insufficient. Do not create a local replacement or hidden workaround in the application.

Create or update `ui-unspec/<component_name>.md` at the application root. One file per universal component; consolidate requirements from different screens into it. The filename must be stable, e.g., `ui-unspec/DatePicker.md`; to extend an existing component, use its name.

The document must make it possible to implement the component in Alpha's UI for different applications:

```md
# ComponentName

## Problem
Screen, user action, and the specific gap.
Installed Alpha's UI version and limitations of the current API.

## Universal Behavior
What the component does independently of the domain.
Scenarios, states, keyboard, focus, and accessibility.

## Proposed API
Props, data, events, and controlled state.
Identical React/Qwik contract; Qwik handlers have the $ suffix.

## Composition and Styling
Which existing components and tokens are used.
Sizes, responsiveness, long content, and required variants.

## Verification
Observable readiness criteria and usage examples.

## Status
Proposed / in progress / available in X.Y.Z / verified in application.
Open questions requiring a decision.
```

Do not tie the API to the current screen's name, specific data, or a single service. Describe a universal component that can be included in the Alpha's UI catalog. Continue independent parts of the task; do not declare the blocked part complete. After implementing in the library, update the package, verify the scenario in the application, and record the result in the same file.

## Verifying the Result

Use the application's commands for build, types, and tests. Check modified screens at wide width and `320px`, real interactions, keyboard navigation, long labels, and required states. In your final response, report completed work, checks run, and remaining `ui-unspec` entries.
