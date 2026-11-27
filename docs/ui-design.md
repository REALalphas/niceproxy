# Niceproxy UI Composition

## Documented Alpha UI Contracts

Source — Alpha UI 0.4.12-niceproxy.3 documentation (local 0.4.11 extension): `docs/consumer-agent-rules.md`,
`agent-guide.md`, `buttons.md`, `forms.md`, `motion.md`, `icons.md` in the release
sources. For local development, the library is located at `../alphas-base`.

- Components: public API `@alpha/react`; fonts and styles `@alpha/core`.
- Fonts: body text Noto Sans, headings/navigation Manrope, technical
  values Fira Code. Therefore, addresses and DNS values use `Text font="mono"`,
  rather than DrawerButton string labels, which do not have a font property.
- Surfaces and spacing: Card and Stack; AppShell wrapper, container mode.
- Actions: Button default/simple/blank, IconButton for icon-only actions.
- Fields: controlled TextInput/Select/Switch. Inside is the documented
  placement for an editable label; an explicit value takes priority over state.
  `showIcon=false` is kept on regular fields for stable geometry when busy;
  on the password field, the icon is enabled via the public prop.
- Navigation: DrawerButton for navigating to categories/settings; technical
  data is displayed with separate Text elements. Badge is used only for notifications
  inside navigation and is not needed for normal service states.
- Control motion: a single `installControlMotion`; standard library states are preserved.
  Full-screen View Transitions and forced scrolling were removed per user
  request. Screen switching is a synchronous React commit without page crossfade.

Application CSS, inline styles, token overrides, and component internal class
overrides are absent.

## Application Decisions

These are Niceproxy logic decisions, not additional Alpha UI rules:

- The routes list shows protocol, status, and both addresses. One primary
  button creates a route; opening an entry is a secondary action.
- Viewing, creating, editing, and delete confirmation are separate screens.
  The connection type is selected before input begins. One page heading replaces
  duplicate shell and form headings.
- The service shows saved and applied revisions. Success is shown only when healthy
  and revisions match. There is no separate port-assignment screen: the handler and
  required public port are selected when modifying the route itself.
- Cloudflare DNS is accessible via settings; the legacy `#cloudflare` hash is preserved.
  Records are displayed with a separate edit action.
- The 1–2–3 hierarchy from the user's specification is implemented via standard
  default/simple/blank variants. At most one primary action in the current state.

## Data Stability

Refreshing config/health/port-owners does not restart authentication and does not replace
the screen with a full-page loader. Mutations are serialized. Reads from a previous session and reads
started before a successful mutation do not overwrite current data. A stale DNS response
does not overwrite a saved record. Back/Forward and reduced motion are tested.

## Page Layout

`AppShell viewport="full" serviceMode="static" showAccount` fills
the viewport and enables the document canvas. Profile is kept, has the accessible name
"Administrator account", and opens access to the panel.
`Page width="form"` constrains form width with the 44rem token and responsive outer
spacing. The heading sits on the canvas; no separate
card is created around the heading. The login page uses `Page viewport="full"`.

The API is implemented in the library and shipped as local archives with sources
in `assets/alpha/0.4.12-niceproxy.3/`; there is no application CSS.
[AppShell](../ui-unspec/AppShell.md) and [Page](../ui-unspec/Page.md) are verified
in the application and marked as available in this local release.

## Field Behavior and Updates

The path field is empty by default with `/` as its placeholder. An empty value on save
becomes the root `/`. Strip-prefix is available only for a valid explicitly set
non-root path; clearing, root, or an invalid path resets the toggle.
All Select components use `popup="overlay"` — the library dropdown instead of the native system one.
Background refreshes do not trigger the manual refresh indicator; Cloudflare operations
do not trigger reloading config/health/port-owners. Scroll position and draft state are preserved.

## Unified TCP/UDP Rule

The creation menu contains only HTTP/HTTPS and TCP/UDP. The TCP/UDP protocol is selected via one
library overlay picker inside the shared form, without remounting fields.
There is a single "Create rule" button. The form is split into "From" (incoming port, Niceproxy
interface IP) and "To" (service IP/domain, its port). An empty incoming IP
becomes 0.0.0.0; an empty target port becomes the incoming port. When editing,
a saved explicit target port stays explicit and does not change when changing
the incoming port. The preview shows the actual mapping. Port and address errors
are placed next to their fields, and IPv6 is passed without a URL scheme or square brackets.

In the TCP/UDP form, address and port are placed side-by-side in two rows using
`Stack direction="row" columns="wide-start"` from local release .4.
The 2:1 proportions are preserved at 320px. The "From/To" headings and long hints are removed;
accessible field labels, errors, and the approved forwarding diagram are preserved.
