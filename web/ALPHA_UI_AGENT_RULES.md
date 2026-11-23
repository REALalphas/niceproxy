# Alpha UI — integration and use

## Integration

1. Install core and the adapter from one release:
   node /path/to/release/install.mjs --project . --framework react
   For Qwik use --framework qwik. If the installer is local, pass a remote release with --from https://<server>/releases/X.Y.Z/.
2. Import the styles once at the entry point:
   import '@alpha/core/fonts.css';
   import '@alpha/core/styles.css';
3. Import components from @alpha/react or @alpha/qwik. Put regular components inside .alpha-ui; AppShell creates .as-shell. Use the installed adapter's props and types. The catalog is in @alpha/core/dist/catalog.json.
4. Call installControlMotion() from @alpha/core once in the browser entry point. Call the returned cleanup function when the area is destroyed. Do not install handlers during SSR or on every render.
5. Link this file from the root AGENTS.md created by the installer. Update it with the package.

## Release updates

- Configure updates with the release catalog URL provided for the project. The current format has latest.json with version and X.Y.Z/manifest.json with package archives and SHA-512 values.
- Resolve the release through latest.json on every start. Do not pin an old archive or fixed version as the update source. Update core and the selected adapter together.
- A verified install and lockfile may pin exact versions for reproducibility. They must not block release selection by the bootstrap script. Do not use star dependencies. These packages are distributed as release archives, not as public npm updates.
- Update in a separate build copy or staging directory. Verify the manifest, checksums, matching versions, install, build, and output. Activate only a ready build. Keep the previous working build for offline fallback and update failures.
- Do not edit installed package files or replace individual JS/QRL files in a running app.

## Startup bootstrap

Add scripts/alpha-bootstrap.mjs to the app and route startup through it, for example start: node scripts/alpha-bootstrap.mjs. Use the app's real startup command and configuration. Running install.mjs alone is not a bootstrap.

The bootstrap must:

1. Record the last successfully installed and built local version, then try to fetch a newer release.
2. Enforce one 20-second deadline for the complete update attempt, including requests, downloads, installation, and build preparation.
3. Start a fully ready new release within the deadline. If unchanged, start the ready local build.
4. On network failure, update failure, or timeout, start the last working local build if one exists. A partial download is never a working build.
5. Stop unfinished requests and update processes. A late result must not switch the active version after local fallback starts. Clear timers and temporary files.
6. If no working local version exists, report that package installation is required and show the manual command. Do not serve an empty UI or wait without a deadline.
7. Log the selected version and result: updated, up to date, local fallback after error/timeout, or manual installation required.

For a manual update, use the installer from the target release:
node /path/to/release/install.mjs --project . --framework react
Then build the app and record the result as the local working version. Use --framework qwik for Qwik. Offline updates may use a local release directory. Dependencies must be available locally or in the package manager cache.

Test the bootstrap with a reachable server, no network, a response slower than 20 seconds, a corrupt archive, a build failure, and no local version. Do not claim automatic updates work before these cases pass.

## Do not modify library components in the app

A local CSS override is a component modification, even when Alpha UI sources are unchanged. This applies to Button, Card, navigation, fields, and every other library component.

- Allowed: choose public props and variants, provide content and handlers, and compose ready components. App CSS may lay out outer containers with grids, direction, gaps, width, and responsive placement.
- Forbidden: tune a component with local classes, style, global selectors, .as-* selectors, nested elements, pseudo-elements, !important, or --as-* overrides. Do not change a control's background, color, font, padding, size, shape, radius, border, shadow, icons, animation, or states.
- className does not grant permission to restyle a component. A wrapper cannot add a border, backdrop, overlay, or handler to simulate a missing variant or behavior.
- Rules such as button selectors and page token overrides must not change library components. Do not hide a local modification behind tokens.
- A request to match a layout does not authorize component changes. If the public API lacks a required variant, report it and create ui-unspec/<component_name>.md. The solution must be a reusable Alpha UI extension, not an app CSS patch.
- Remove existing local overrides, restore library states, and record the actual missing capability.

Allowed layout example:

.page-actions {
  display: flex;
  flex-wrap: wrap;
  gap: var(--as-space-3);
}

A rule that styles a library button, card, or navigation item changes a component and is forbidden.

## Components and styling

- Build screens from public components. Custom composition and layout CSS are allowed. Do not copy implementations, edit internal markup, or add another UI library to bypass a missing capability.
- Use --as-* tokens for colors, spacing, sizes, radii, and motion. Do not duplicate token values in screen CSS.
- Body text uses Noto Sans. Headings, buttons, navigation, and the service name use Manrope. Technical values use Fira Code. Weights are 400 regular, 500 for emphasis and headings, and 600 for the service name. Minimum text size is 1rem.
- Use rem from a 16 px base. Use relative container units and aspect-ratio for resources. Maximum content width is --as-size-content-max.
- Use Lucide UI icons through Icon. Size is 1.5rem, regular stroke 0.09375rem, bold stroke 0.125rem. Logos, photos, and illustrations are separate resources.
- Use canvas for the main background, surface/overlay for cards, and navigation for navigation layers. Use canvasDeep only when explicitly required.
- Use inset box-shadow for borders. border: 0 is allowed for resets. Library exceptions are Button's Disabled dash and Profile's Loading state.
- Use corner-shape: superellipse(1.2) with a border-radius fallback. Chat corners use corner-shape: round.
- Preserve library motion and motion tokens. Support reduced motion. Keep hover, press, release, focus, and active states distinct. Buttons and navigation must not look like body links. Read-only fields must remain copyable.
- Qwik handlers use a $ suffix. Do not override the container q:base. Test lazy handlers in production and when deployed in a subfolder.

## Missing components: required feedback

If a component, prop, state, or behavior is missing, tell the user immediately what is needed, where it is needed, and why the current API is insufficient. Do not create a local replacement or hidden workaround.

Create or update ui-unspec/<component_name>.md in the app root. Use one file per reusable component and merge requirements from different screens. Keep the filename stable, for example ui-unspec/DatePicker.md. Extend an existing component under its name.

The document must support implementation for different apps:

# ComponentName

## Task
Screen, user action, and the exact gap.
Installed Alpha UI version and current API limits.

## Universal behavior
Domain-independent behavior.
Scenarios, states, keyboard, focus, and accessibility.

## Proposed API
Props, data, events, and controlled state.
React/Qwik contract. Qwik handlers use a $ suffix.

## Composition and styling
Existing components and tokens.
Sizes, responsive behavior, long content, and needed variants.

## Checks
Observable acceptance criteria and usage examples.

## Status
Proposed / in progress / available in X.Y.Z / verified in the app.
Open decisions.

Keep the API independent of one screen name, data shape, or service. Describe a reusable component that can enter the Alpha UI catalog. Continue independent work and do not mark blocked work complete. After library implementation, update the package, verify the app scenario, and record the result in the same file.

## Verification

Use app commands for build, type checks, and tests. Check changed screens at wide and 320 px widths, real actions, keyboard use, long labels, and required states. Report completed work, checks, and remaining ui-unspec entries.
