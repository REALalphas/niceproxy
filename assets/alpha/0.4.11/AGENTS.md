# Alpha's UI — setup and usage

## Status of these rules

These are engineering instructions for agents working with Alpha's UI in an application: they define the order of integration, changes, and verification for the shared interface. They do not modify `LICENSE` and do not create additional legal prohibitions or licensing terms. Rights to use, modify, and distribute are governed by `LICENSE`; modifications permitted by it remain allowed. In this workflow, a component change is made in the library source with a package update and application verification. Support terms, if agreed separately, also do not automatically alter the license.

## Setup

1. Install core and an adapter from the same release:
   `node /path/to/release/install.mjs --project . --framework react`
   For Qwik, use `--framework qwik`. If the installer is already local, you can pass a remote release via `--from https://<server>/releases/X.Y.Z/`.
2. Import once in the entry point:
   ```tsx
   import '@alpha/core/fonts.css';
   import '@alpha/core/styles.css';
   ```
3. Import components from `@alpha/react` or `@alpha/qwik`. Place regular components inside `.alpha-ui`; `AppShell` creates `.as-shell` on its own. Use the props and types of the installed adapter; the component catalog is available via the `@alpha/core/catalog.json` export (the physical file after installation is `node_modules/@alpha/core/dist/catalog.json`).
4. In the browser entry point, call `installControlMotion()` from `@alpha/core` once. When destroying the scope, call the returned cleanup function. Do not install handlers during SSR or on every render.
5. Add a reference to `ALPHA_UI_AGENT_RULES.md`, which the installer creates, in the root `AGENTS.md`. Update this file together with the package.

## Release-independent updates

- Configure the update source via the releases directory URL in the project configuration. Do not invent an address: use the provided server. In the current format, it contains `latest.json` with a `version` field, and `X.Y.Z/manifest.json` contains the package archives and SHA-512 checksums.
- Resolve the release via `latest.json` on each startup. Do not pin an old archive URL or a specific version as a permanent update source. Update core and the selected adapter together to the same version.
- A standalone verified installation and lockfile may pin exact versions for reproducibility. They must not block the bootstrap script from selecting a new release. Do not replace dependencies with `*`: packages are distributed as release archives, and there is no public npm package for this update flow.
- Perform updates in a separate build copy or staging directory. Verify the manifest, checksums, version match, installation, build, and output availability. Only activate a completed, verified build. Keep the previous working build for offline startup and on update failure.
- Do not edit files in an installed package or swap individual JS/QRL files in an already running application.

## Startup bootstrap

**There is no ready-made bootstrap implementation in this repository.** The requirements below describe the startup script for the consumer application.

Create this script in the consuming application, choosing its name and location to fit the project's structure. Route the application's start command through this script; use the actual configuration and start command of the application itself. The library and standard installer do not create a bootstrap script automatically.

Bootstrap behavior:

1. Record the last successfully installed and built local version. Start an attempt to fetch the latest release from the network.
2. Cap the entire update attempt at a total timeout of **20 seconds**, including requests, downloading, installation, and preparing the new build. Do not allocate 20 seconds per step.
3. If the new release is completely ready within the timeout, launch it. If the release has not changed, launch the ready local build.
4. If the network is unavailable, the update fails, or 20 seconds elapse, launch the last working local build if one exists. Here, "last" means the most recently successfully prepared build, not a partially downloaded one.
5. Abort any unfinished requests and update processes. Do not allow a late result to switch the active version after the local build has launched. Release the timer and temporary resources.
6. If no working local version exists, report that starting requires installing the package and show the manual installation command. Do not render an empty interface and do not keep waiting indefinitely.
7. In the output, print the selected version and result: updated, up to date, launched local build after error/timeout, or manual installation required. Do not prompt for confirmation on every routine update attempt.

For manual updates, use the same installer from the target release:
`node /path/to/release/install.mjs --project . --framework react`.
Then build the application and save it as the working local version. For Qwik, pass `--framework qwik`. When offline, use a local release directory; required dependencies must be available locally or in the package manager cache.

Test the bootstrap with an available server, offline, with a slow response exceeding 20 seconds, a corrupted archive, a build failure, and a missing local version. Do not declare auto-update working until these scenarios are verified.

## Do not modify components in the application

**Local CSS overrides are also a component modification, even if Alpha's UI sources were not changed.** This prohibition applies to Button, Card, navigation, fields, and all other library components.

- Allowed: choosing public props and variants, passing content and handlers, and composing ready-made components. Application CSS defines the layout of outer containers: grid, direction, gaps between components, available width, and responsive placement.
- Forbidden: tweaking a component to match a mockup using local classes, `style`, global selectors, `.as-*`, nested elements, pseudo-elements, `!important`, or overriding `--as-*` variables. Do not use these to change background, color, font, padding, control dimensions or shape, radius, border, shadow, icons, animation, or states.
- `className` does not grant permission to alter a component's styling. A wrapper is not a workaround either: do not add a border, backdrop, overlay layer, or handler through it to imitate a missing variant or behavior.
- General rules such as `button { ... }`, `aside button { ... }`, and page-level token overrides must not alter library components. Do not use tokens as a way to hide a local modification.
- A request to build a screen or bring it closer to a mockup does not grant permission to modify components. If a needed variant is missing from the public API, report it and create `ui-unspec/<component_name>.md`. The solution must be a universal Alpha's UI extension, not an application CSS patch.
- If local overrides have already been added, remove them, restore standard states, and record the actual missing capability. Do not describe such work as "I only changed the layout".

Example of valid layout styling:

```css
.page-actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--as-space-3);
}
```

A rule like `.page-actions .as-button { padding: ...; background: ...; }` already modifies the component and is forbidden. The same applies to cards and sidebar or bottom navigation items.

## Components and styling

- Build screens from public components. Custom compositions and layout CSS are allowed; copying implementations, interfering with internal markup, or adding another UI library to work around a missing feature is not.
- Use `--as-*` tokens for colors, spacing, sizes, radii, and motion. Do not duplicate token values in screen CSS.
- Body text: Noto Sans; headings, buttons, navigation, and service name: Manrope; technical values: Fira Code. Weights: regular 400, emphasized text and headings 500, service name 600. Minimum text size: `1rem`.
- Sizes in `rem` based on `16px`, containers in relative units, assets with `aspect-ratio`. Maximum width: `--as-size-content-max`.
- UI icons: Lucide via `Icon`; size `1.5rem`, stroke regular `0.09375rem`, bold `0.125rem`. Logos, photos, and illustrations are separate assets.
- Main background: canvas; cards: surface/overlay; navigation layers: navigation. Use canvasDeep only when explicitly required.
- Borders: `box-shadow: inset`; `border: 0` is allowed for reset. Standard exceptions: dashed Disabled on Button and Loading on Profile.
- Corners: `corner-shape: superellipse(1.2)` with `border-radius` fallback; circular chat corners: `corner-shape: round`.
- Preserve library motion and its tokens, and respect reduced motion. Do not mix hover, pressed, release, focus, and active selection. Buttons and navigation are not selectable as text; read-only fields keep text copyable.
- Qwik: QRL handlers with `$` suffix; do not override container `q:base`. Verify lazy handlers in production and when hosted in a subdirectory.

## Missing components: mandatory feedback

If a component, prop, state, or behavior is missing, **notify the user immediately**, specifying what is needed, where, and why the existing API is insufficient. Do not create a local replacement or hidden workaround in the application.

Create or update `ui-unspec/<component_name>.md` in the application root. One file per universal component; combine requirements from different screens into it. The filename must be stable, such as `ui-unspec/DatePicker.md`; use the existing component's name when extending it.

The document should make it possible to implement the component in Alpha's UI for different applications:

```md
# ComponentName

## Problem
Screen, user action, and specific gap.
Installed Alpha's UI version and limitations of the current API.

## Universal behavior
What the component does independently of the domain.
Scenarios, states, keyboard, focus, and accessibility.

## Proposed API
Props, data, events, and controlled state.
Same React/Qwik contract; Qwik handlers have the $ suffix.

## Composition and styling
Which existing components and tokens are used.
Sizes, responsiveness, long content, and required variants.

## Verification
Observable acceptance criteria and usage examples.

## Status
Proposed / in progress / available in X.Y.Z / verified in application.
Open questions requiring a decision.
```

Do not tie the API to the current screen name, specific data, or a single service. Describe a universal component that can be included in the Alpha's UI catalog. Continue independent parts of the task; do not mark the blocked part as complete. After implementing it in the library, update the package, verify the scenario in the application, and record the result in the same file.

## Verification

Use the application's commands for build, types, and tests. Verify changed screens at wide widths and `320px`, real interactions, keyboard navigation, long labels, and required states. In the final response, state what was done, checks run, and remaining `ui-unspec` entries.
