# AppShell

## Problem

In a single-service application with password login, the header must not offer
a non-functional service picker or an empty profile button. Niceproxy uses
Alpha UI 0.4.11: AppShell always renders HeadBar with a service picker and Profile.
Public props allow passing handlers, state, and an image,
but do not allow excluding these optional actions. In Niceproxy, Profile now navigates to the access section, and the service name returns to routes. For applications without such actions, a public static mode is still required. CSS hiding and tampering with internal markup
are not used.

## Universal Behavior

- When there is no service list and no service selection is provided, show a
  static title without a chevron, button role, or Tab stop.
- Allow explicitly disabling the profile for applications without an account menu.
- In profile mode without an image, show a meaningful standard representation
  with an accessible name. Do not show an empty interactive area without an action.
- Existing multi-service and account scenarios must preserve their
  behavior, keyboard navigation, and visible focus.
- Identical behavior in React and Qwik.

## Proposed API

Extend AppShell and HeadBar:

```ts
serviceMode?: 'picker' | 'static'; // Defaults to picker for compatibility.
showAccount?: boolean; // Defaults to true for compatibility.
accountLabel?: string; // Pass from AppShell to HeadBar and Profile.
```

The `onServiceChange`, `onServicePress`, and `onAccountPress` handlers are preserved.
In Qwik, their names have the `$` suffix. In static mode, `onServicePress`
does not create an interactive element. When `showAccount=false`, Profile is absent
from the DOM and focus order.

## Composition and Styling

The change is implemented in Alpha UI sources and then shipped as a unified
core/react/qwik release. Existing HeadBar, Profile, Logo,
Text, and library tokens are used. The header adapts to the absence of Profile without an empty
column; the static title preserves styling and long-title handling.
Local application CSS overrides are not needed.

## Verification

- `serviceMode="static" showAccount={false}`: single service title, without
  a chevron, non-functional buttons, or empty profile space.
- Picker with multiple services works by mouse and keyboard.
- Profile with a handler has an accessible name and triggers exactly one action.
- Modes verified at 320px and wide viewports, with long titles and reduced motion.
- React and Qwik typecheck/build and verification in the consuming application.

## Status

Available and verified in local release Alpha UI 0.4.12-niceproxy.3:
AppShell viewport=full, serviceMode=static, showAccount=false, and accountLabel.
The application does not hide or restyle the header via CSS.


## Page Layout Without Application CSS

An installation prohibiting application CSS requires public settings for a full-screen
shell and outer content-area spacing. In 0.4.11, AppShell uses
a minimum height of 80svh on desktop / 37.5rem on mobile, but does not reset body
margin or offer content-area padding. Stack controls gap and direction,
not outer margins; Card defines its own surface rather than a neutral inset.

Proposed universal props: `viewport="full" | "content"`,
`contentInset` from the library spacing scale; a separate documented root
region for the canvas and margin reset, without consumer local CSS. The region must not
alter internal sizes of nested controls. React/Qwik share the same contract.
Verification: viewport fill at 320px/1440px, proper scroll and sticky navigation,
canvas outside cards, consistent outer spacing, and no horizontal
overflow. Status: implemented and verified via AppShell viewport=full and Page
in local release 0.4.12-niceproxy.3.


## Verified in Application

Available in local release **0.4.12-niceproxy.3**. Archives and corresponding
sources are in `assets/alpha/0.4.12-niceproxy.3/`. This is a local extension
from 0.4.11 sources, not an official external release. Installed packages
were not edited. Full library verification: 55 tests, React/Qwik build and
typecheck, docs, and package contents. Page verified in production React/Qwik
at 1440/320px. In Niceproxy, 1880/1440/320px, shell height >= viewport,
document margin 0, form width <= 44rem, absence of profile
and overflow, real CRUD/ports, and keyboard navigation were verified.

In the current application, `showAccount` is enabled per explicit user request.
The disable prop remains part of the API, though Niceproxy no longer uses it.
