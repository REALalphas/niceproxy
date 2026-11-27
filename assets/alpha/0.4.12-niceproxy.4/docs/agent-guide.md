# How to build interfaces with Alpha's UI

Setup and handling missing components are described in [application agent rules](consumer-agent-rules.md), also available via `@alpha/core/AGENTS.md`. The [20-second timeout bootstrap requirements](consumer-agent-rules.md#startup-bootstrap) apply to the consumer application: Alpha's UI does not include a ready-made implementation, and neither the library nor the installer creates one. During release installation, the rules are copied into `ALPHA_UI_AGENT_RULES.md` in the target project.

This is an engineering workflow; it does not alter the rights to modify and distribute granted by `LICENSE` and does not introduce additional licensing terms.

## Setup

Import once in the entry point:

```tsx
import '@alpha/core/fonts.css';
import '@alpha/core/styles.css';
```

Place regular components inside a `.alpha-ui` scope. `AppShell` creates `.as-shell` on its own. Page background and layout outside components are set by the application via Alpha's UI tokens.

In the client entry point or browser lifecycle, install the shared behavior once:

```tsx
import { installControlMotion } from '@alpha/core';

const disposeControls = installControlMotion();
// Call disposeControls() when destroying the app or scope.
```

Do not call this code during SSR. In an app with remounting or HMR, tie setup and cleanup to its lifecycle.

## Controlled components

React:

```tsx
import { useState } from 'react';
import { TextInput, Switch } from '@alpha/react';

export function Settings() {
  const [name, setName] = useState('');
  const [enabled, setEnabled] = useState(false);
  return <div className="alpha-ui">
    <TextInput id="name" label="Name" value={name} onValueChange={setName} />
    <Switch id="notifications" label="Notifications" checked={enabled} onCheckedChange={setEnabled} />
  </div>;
}
```

Qwik:

```tsx
import { component$, useSignal } from '@builder.io/qwik';
import { TextInput, Switch } from '@alpha/qwik';

export const Settings = component$(() => {
  const name = useSignal('');
  const enabled = useSignal(false);
  return <div className="alpha-ui">
    <TextInput id="name" label="Name" value={name.value}
      onValueChange$={value => { name.value = value; }} />
    <Switch id="notifications" label="Notifications" checked={enabled.value}
      onCheckedChange$={value => { enabled.value = value; }} />
  </div>;
});
```

In Qwik, declare extracted handlers as QRLs using `$`. Do not pass non-serializable platform objects across lazy component boundaries. Do not override the container `q:base`; production hosting is described in the [containers guide](qwik-containers.md).

## Selection and composition

- Use `AppShell` for a ready-made responsive shell; for a custom one, use the available `HeadBar`, `Sidebar`, `BottomNav`, and layout components. The prebuilt shell is not required for every screen.
- Use `Text`, `Button`, `IconButton` for text and actions; use components from the installed catalog for input and selection. An icon without visible text requires an accessible label.
- `Badge` is a notification counter inside navigation. Pass the value via `notifications` on `NavButton` or `BottomNav` items; do not use `Badge` as a standalone block or caption. Its placement next to the icon is handled by the navigation component.
- Use `Stack`, `Card`, and `--as-*` tokens for spacing and surfaces. Application CSS defines outer container layout. Do not alter component styling or states via `className`, `style`, global selectors, `.as-*`, pseudo-elements, or token overrides: that counts as modifying the component, even without editing Alpha's UI sources. Describe a missing variant in `ui-unspec/<component_name>.md` as a universal library extension.
- Check public chat components against the installed API and the [chat contract](chat.md). In current sources these are `ChatMessage`, `ChatButton`, `ChatInput`, `ChatComposer`, `ChatThread`, `ChatSurface`.
- Verify the states required for the scenario: error does not replace focus, readOnly does not equal disabled, and selected navigation does not equal button press.

When a capability is missing, notify the user immediately and create `ui-unspec/<component_name>.md` with universal behavior, proposed API, states, and verification criteria. Do not build a workaround in the application. After implementing it in Alpha's UI, update the package and verify the scenario.

## Verification and updates

In the target application, use its development and verification commands. Test the modified interface in the browser, with keyboard navigation, and at narrow widths. When Qwik, SSR, or desktop APIs are used, verify the corresponding production scenario. Matching package versions and a passing build do not replace testing interactions.

For release installation and updates, see the [release and installation guide](distribution.md). The update source is `latest.json` on the configured server, not a pinned old archive URL. The application bootstrap must complete the update attempt within 20 seconds and fall back to the last working local build on error or timeout. Without one, manual installation is required. The standard installer does not implement bootstrap automatically.

## Shell width and list details

`AppShell width="container"` fills the parent container; the default `content` keeps the `--as-size-content-max` limit.
`DrawerButton secondaryPlacement="below"` places secondary navigation descriptions under the label; the default `inline` suits short counters. Contracts are identical for React/Qwik. An operation history with status and timestamp requires a separate entry item with an independent view action; no such public component exists yet, and the `ActivityItem` variant was rejected by the user. Do not treat `DrawerButton` as a ready-made history item component.

## Pickers in the header

The "Example" tab uses a real HeadBar through AppShell. `serviceOptions`, `serviceValue`, and `onServiceChange` / `onServiceChange$` enable a controlled service picker; logo, title, and chevron are preserved. Without `serviceOptions`, the existing `onServicePress` / `onServicePress$` action is kept.

Optional `context` contains `label`, `value`, `options`, `placeholder?`, `disabled?`; selection is reported via `onContextChange` / `onContextChange$`. This is an auxiliary borderless picker, not a replacement for the service picker. The object contains no server domain logic. A standalone Picker has the same controlled `value`, `options`, `onValueChange` / `onValueChange$`; `variant="plain" | "service"`, `disabled`, `placeholder`, and accessible `label` are available.

In AppShell on a wide screen, the service sits above the sidebar, and the auxiliary context picker sits to the right of the sidebar, above the main area. The header mirrors the column widths of the shell; the length of the service name does not shift the context.

Picker is a compact composition of the existing Select with standard selection handlers. Select supports `variant="field"` (regular field with label), `"plain"` (no permanent border, sized to selected text), and `"service"` (with service logo and title). In compact variants, the label remains accessible to screen readers. Hover, focus, press, and release follow the shared `.as-field-control` rules. Select/Picker support `popup="native" | "overlay"`; overlay starts with the selected text at the field's position and a thickened press outline. It immediately animates height downward (if it fits completely) or upward, while thinning the inset outline. Centering on the selected item is the initial frame only. Width expands up to the longest item within the parent container; a compact picker collapses back to the width of the selected text with standard padding. The selected item stays opaque; the remaining items fade in smoothly outward from it and fade back out on collapse. Opacity on the entire overlay is not used. Row hover changes text color only via transition. The overlay is wired through the shared `installControlMotion()`, preserving the native select and its `input`/`change` events. Clicking outside the list and Escape close it; keyboard navigation and disabled options are supported.

## Full-screen app and page

`AppShell viewport="full"` enables full-screen height and a document canvas without
body margins. By default, `content` preserves the previous embedded-shell behavior.
This is the document-owner mode; use one such shell per document.
`serviceMode="static"` displays the title and logo without a picker button/chevron.
`showAccount={false}` excludes the profile; `accountLabel` passes an accessible name.
The same header props are available on HeadBar.

`Page` sets outer content spacing without a surface or border. `width="form"`
constrains width via the `formMax` token; `content` uses `pageMax`/`contentMax`; `full` fills
its parent. By default `align=start`, `inset=comfortable` (responsive), `gap=6`.
`align=center`, `inset=compact/none`, and `gap=1..10` are available. `Page` itself is not `main`:
it is placed inside AppShell, where `main` already exists. For a standalone entry point,
`Page` can be used inside a separate `main`. The contract is identical for React/Qwik.

For a standalone entry point, `Page viewport="full"` enables the same full-screen height
and document canvas without body margins. Inside AppShell, keep `viewport=content`
by default so page height is not stacked on top of header/navigation height.

`Stack direction="row" columns="equal" | "wide-start" | "wide-end"` sets
two columns without wrapping: 1:1, 2:1, or 1:2. Child fields keep their own
styling. Suitable for a pair of related values; at 320px they remain side by side.
Without `columns`, `Stack` behavior is unchanged. The API is identical for React/Qwik.
