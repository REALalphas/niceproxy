# Common input and selection fields

TextInput, TextArea, Checkbox, Switch, and Select are Alpha's UI extensions, not migrated from an unverified mockup. In the source repository, API and markup live in `source/components/controls/`, wired through `source/components/index.mjs`. For an installed package, use the adapter types and `@alpha/core/catalog.json`. Both adapters share the same structure and core styles.

Fields continue the neutral Simple style: transparent surface, inner border, and distinct hover, focus, and pressed states. Input fields, including TextArea, keep a transparent inner border of color.border (#9994) and the pressed thickness (double borderWidth.control) when focused. The active field color is not replaced with selected or white. Hover on an inactive field uses borderPressed. While the field is held down, the border uses the hover color borderPressed and double borderWidth.control; on release, the active field returns to #9994 at double thickness. Selected Checkbox/Switch keep the selected color; their keyboard focus is indicated by a white border. Checkbox uses Lucide's check Icon. Text is Noto Sans, minimum 1rem. Radii and sizes come from tokens; focus does not change geometry. Transitions of border state, color, checkmark, and thumb position use the shared Switch curve, cubic-bezier(.5,.4,0,1). The thumb and checkmark use fast; --as-control-easing lets the application select the curve just like other controls; reduced motion disables transitions.

All components require unique `id` and `label`. Fields accept `value` and `onValueChange` / `onValueChange$`; Checkbox and Switch accept `checked` and `onCheckedChange` / `onCheckedChange$`. The application updates state. The library neither stores settings nor makes requests. `name`, `required`, and `disabled` are forwarded to the native control. Checkbox accepts a submitted `value`; Switch preserves switch semantics.

TextInput supports text, url, email, password, search, tel, and autoComplete. TextInput/TextArea support readOnly, placeholder, hint, and error. Error takes precedence over hint, is linked to the field via aria-describedby, and sets aria-invalid; validation is performed by the application. TextArea accepts rows and height resizing via a bottom handle bar: the bar is centered at 55% width; its thickness and gap to the border equal the current border thickness (borderWidth.control, doubled on focus, press, and drag), with a grab area spanning the entire bottom edge at height space.3. The browser's native resize corner is disabled. The handle works via mouse, touch, and Up/Down arrow keys on the keyboard, including on readOnly/disabled fields; the field value does not change. Behavior is wired through the shared installControlMotion(). ReadOnly does not keep selected after clicking: hover and press remain; focus does not change the border. ReadOnly text uses color.textSecondary. ReadOnly and disabled show Lucide pencil-off inside the right side of the field: top-right aligned with the center of the first line of text in TextArea, and vertically centered on the right in TextInput. The icon has weight=bold and size 1em, matching the field text size. At rest, opacity=0.33; on press and release, opacity=1. Returning opacity to 0.33 starts after a 1s delay; appearing on press has no delay. The icon has its own textSecondary independently of the field text. The reaction covers the entire field block, including disabled: clicking anywhere triggers the icon reveal; input remains disabled. A disabled block is reachable via Tab and Enter/Space. Icon size does not change on interaction; the shared installControlMotion() is used. Reduced motion disables the opacity transition. It does not overlap text; clicking the block triggers only the visual feedback and does not enable editing. ReadOnly text can be selected and copied; disabled does not receive focus or change value via keyboard.

Select accepts options `{value, label, disabled?}`, value, placeholder, hint, and error. By default `popup="native"`: keyboard and mobile selection belong to the browser, and the open list appearance depends on the OS. The `popup="overlay"` mode is described below and wired via `installControlMotion()`. It is single-select without search or multi-select. Placeholder uses an empty value; do not add a separate option with the same value.

Checkbox/Switch use a native checkbox under the styled control. Tab moves focus, Space toggles; clicking the label also works. Long labels wrap without shrinking the control. Hint describes the control, but is not part of its accessible name.

```tsx
<TextInput id="name" label="Name" value={name} onValueChange={setName} />
<Switch id="notifications" label="Notifications" checked={enabled} onCheckedChange={setEnabled} />
```

In Qwik, pass the corresponding onValueChange$ / onCheckedChange$ and update the application's signal/store. q:base is set by the application container; components do not change it.

When pressing TextInput/TextArea, the border doubles in thickness and uses borderPressed. Dragging the handle keeps the thickened border; the handle bar thickness changes via the Switch transition: press 0.166s, release 0.4s; bar movement (offset) uses the smooth Transition curve cubic-bezier(.2,.66,0,1): lift 0.6s, drop 0.4s.

TextArea resize="vertical" (default) resizes height only and shows the bottom bar; resize="both" resizes width and height and shows a corner arc. Width-only resizing is not provided. The handle shape is determined automatically by the resize direction. Up/Down arrows control height, Left/Right control width, and all four work in `both` mode. Width is constrained by the available container width; dimensions after dragging are saved in rem. The arc has a grab area of size.icon, rounded caps, and a constant SVG size; its path is parallel to the inner border edge with a gap equal to its thickness. SVG non-scaling-stroke preserves the rem token thickness without rescaling via viewBox.

Without `corner-shape: superellipse(1.2)` support, a standard rounded-corner arc matching the field's fallback border-radius is used. The path is selected via `@supports`; the normal gap is preserved in both variants.

Focusing the handle does not mean editing and does not thicken the border. Handle thickening applies only while holding/dragging (`data-resizing`); on release, normal thickness returns even if the handle keeps keyboard focus. Focusing the textarea itself keeps the editing state.

Scrollbars inside .alpha-ui/.as-shell: transparent track, rounded thumb color.border, hover/active color.borderPressed. Chromium uses width space.2 and radius.pill; Firefox uses standard scrollbar-width: thin and scrollbar-color.

The TextArea scrollbar follows the field's inner contour: the top corner curves when scrolled to the top, and the bottom corner curves when scrolled to the bottom in resize="vertical". In resize="both", the thumb stops above the corner handle. A short field may show only the curved segment of the thumb. The thumb has the border's thickness and gap; its length corresponds to the visible fraction of text. Native text scrolling is preserved; mouse, wheel, touch, and keyboard remain available. Without installControlMotion(), the native scrollbar remains.

The border and permanent padding of TextArea belong to the outer container. The inner textarea without padding scrolls in its own region: text and caret stay inside the padding without masks or caret measurement. Handles resize the outer container; scrollbar geometry follows this container, and thumb position follows native textarea scrolling.

Thumb curvature is capped at 75°; with the corner handle, the gap between its end and the thumb equals the border thickness, matching the thumb's inset from the inner edge. When the textarea is focused, the thumb thickens together with the border.

When resizing TextArea, scrollbar geometry and thumb length update immediately before the frame paints. Scrolling animates position and length over motion.fast with motion.transition; a mouse-dragged thumb follows the pointer immediately.

Holding the scrollbar mirrors pressing the resize handle: the border and thumb thicken, and the border gets borderPressed. On release, the state clears; focus on the scrollbar itself does not keep the thickness. Focusing the textarea for editing keeps the regular editing state.

The grab area of both handles is expanded beyond the visible line by space.1 (0.25rem) on each side. The bar keeps 55% width; in resize="both", a transparent SVG stroke expands the hit area around the arc, while the rest of the empty container area does not intercept input.

When all text fits vertically, the scrollbar fades out via opacity over motion.fast with motion.switch. During fade-out, the last thumb length is preserved; a hidden scrollbar does not intercept mouse input and is excluded from keyboard navigation. It smoothly reappears on overflow.

The border of TextInput, Select, and TextArea consists of two inset layers of a single box-shadow. --as-field-status-color stores the error color, while --as-field-frame-color and --as-field-frame-width control highlight independently of status. The status color is drawn under the highlight layer; both layers share --as-field-frame-width; hover, focus, and pressed do not clear the error.

When an error status is present, the normal highlight layer is transparent (--as-field-idle-color), so at rest only the status color is visible. Without status, the normal neutral border remains. Hover, focus, and pressed activate their own highlight layer.



In TextInput and TextArea, the label is shown as an overlaid placeholder text inside an empty field. It stays visible on focus and fades out on input via a left-to-right gradient over motion.normal (0.6s) with motion.universal; field dimensions and padding are preserved. The field name is exposed via aria-label.

Returning the overlaid placeholder takes --as-field-placeholder-duration (0.6s); fading out on input takes motion.normal (0.6s). Color returns on blur over motion.normal.

Blur during input takes motion.fast (0.4s); returning from blur takes motion.normal (0.6s). A fully faded placeholder has opacity: 0.6 and blur(.2rem) via --as-field-placeholder-blur. The mask is applied to the inner text, and the blur to an outer layer with overflow: visible so blur edges are not clipped by the text box.

The shared placeholder is used across all TextInput and TextArea instances in both adapters. In a multiline field, it is aligned to the start of the first line; readonly/disabled preserve the marker and non-editable state.

TextInput/TextArea: labelPlacement="inside" | "above" controls label placement. By default, an editable field uses `inside`, while readonly and disabled use `above`. An explicitly passed prop overrides the default. In `above` mode, the linked label and any regular placeholder passed are preserved.

TextInput picks a Lucide icon by type: text/type, url/link, email/mail, password/key, search/search, tel/phone. TextArea uses type. Type icons have size 1em, like pencil-off, and weight="bold". Gap to text is space.2. The icon prop allows specifying a different icon. For type and search, artwork scale is optically aligned with pencil-off (11/9 and 11/10); others keep scale 1. On focus, it appears via transform: scale(80% → 100% of final scale) over motion.interaction (0.166s) with motion.transition, from 80% of normal size and opacity 0 to normal size and opacity 1; after blur, it fades out after a 1.2s delay by opacity only, without changing visible size. The reduced scale for the next appearance is reset after full fade-out. Readonly and disabled keep pencil-off.

In an editable TextInput, right padding smoothly increases on focus from space.4 to space.4 + 1em + space.2 over motion.normal with motion.transition. After blur, it returns after the icon disappears (1.2s delay + motion.fast). TextArea, readonly, and disabled keep constant padding.

TextInput and TextArea support showIcon?: boolean. Plain text and TextArea default to false, while other types and readonly/disabled default to true. showIcon={true} explicitly enables the icon. showIcon={false} hides both the type icon and pencil-off on readonly/disabled, and removes the right-side icon space reservation.

In TextInput type="search", the right icon region is a "Clear search" button spanning the field height. With a non-empty value, hover/focus-visible smoothly swaps the magnifier for Lucide close; pressing it calls onValueChange("") / onValueChange$("") and returns focus to the input. In an empty field, the button is disabled; readonly/disabled/showIcon=false do not provide clear functionality.

In a non-empty search field without focus, the clear cross is shown. On focus, the magnifier is shown; on button hover/focus-visible, the cross is shown; icon swapping takes motion.interaction (0.166s), opacity uses motion.switch, and cross size uses motion.transition.

Overall search icon visibility animates on the artwork group using the same rules as other icons: scale 80%→100% over interaction/Transition, opacity reveal over interaction/Switch, and 1.2s fade-out delay without shrinking visible size. The fast 0.166s magnifier/cross swap happens separately inside the group. A non-empty search keeps the group visible; all field icons use textSecondary (#ddd).

For all field icons, size and opacity appearance take motion.interaction (0.166s). Fade-out remains fast (0.4s) with a 1.2s delay and no visible shrinking.

The search cross uses the same 1em size and 11/10 final scale as the magnifier; it does not scale up to 11/7.

TextInput type="password": passwordVisible and onPasswordVisibleChange / onPasswordVisibleChange$ control password visibility. The right Lucide eye/eye-off button is available when the field or button itself is focused; after blur, it disappears per the shared rules and does not intercept clicks. Pressing toggles visibility and returns focus to the field; the value does not change. showIcon=false, readonly, and disabled exclude the button.

Password: at rest when focused, key-round is shown. With a non-empty value, hovering the entire field block or focus-visible on the button replaces the key with the eye (show) or eye-off (hide) action; an empty field disables the button. The native mask uses existing Fira Code for round glyphs; revealed password uses primary Noto Sans.

The hidden password mask compensates for Fira Code metrics via size.passwordMaskOffset (0.09375rem): top padding increases and bottom padding decreases by the same amount. Total height, border, and icon center are preserved; when revealing text, regular Noto Sans padding is restored.

When hovering a non-empty password field, the button and icon group appear even without input focus. When the cursor leaves without focus, they hide via the shared transitions; an empty field without focus does not show the button.

When selected/focus-within, switching from key to action occurs only when hovering the right button (or its focus-visible). Without focus, hovering anywhere on the non-empty block shows the action.

## Compact Select

`Select variant="field"` by default keeps the regular field with a visible label. `variant="plain"` hides only the visible label, removes the permanent border, and sizes width to the selected text plus arrow and padding; `variant="service"` adds the service logo and typography. The label remains for accessibility. All variants share a single native select, the same onValueChange/onValueChange$ handlers, and as-field-control animations. Picker is a composition of these compact variants with an automatic id and handling for unknown/empty values.

Native Select uses the shared field press and fade-out cycle. Opening the system popup does not keep bright `:active` held: after the press pulse, the outline smoothly returns to normal focus, including on platforms where the popup intercepts pointerup/keyup. TextInput rules do not change.

After closing a native Select list with the mouse, it returns to its normal outline even if the browser preserves DOM focus. Switching to keyboard shows the standard focus outline; text fields keep their existing rules.

## Select overlay

`Select popup="overlay"` opens on a completed click, after pointer release over the field. While held down, only the normal press highlight runs; releasing outside the field does not open the list. The overlay starts with the field's dimensions and position: the selected row aligns with its text on the initial frame only. The initial frame preserves the thickened inset outline of a pressed field: --as-field-frame-width = calc(2 * --as-borderwidth-control), color --as-color-border-pressed. Before expanding, ::after style is computed; then a CSS transition using existing --as-field-frame-duration and --as-field-frame-easing immediately brings the outline color to --as-color-border. The open selector keeps double thickness, like a focused TextArea; on close, thickness smoothly returns to --as-borderwidth-control. The list expands immediately in height only toward one of two final positions: downward from the field's top edge if the full list fits; otherwise upward to the field's bottom edge. Simultaneously, the pressed outline color fades out; focus thickness persists until close. Width is constant; the list does not stay centered on the selected item.

Closing collapses the overlay back to the current value without opacity, scaling, or text fade-out. When space is insufficient on both sides, height is constrained to the viewport with scrolling.

The selected item is marked by background via --as-select-option-selected-background. By default it uses the lighter --as-color-navigation and remains fully opaque above the darkening ::before. Text of all items, including the selected one, is secondary #ddd (--as-select-option-color) at rest; hover or explicit keyboard navigation highlights only the candidate's text (--as-select-option-hover-color) via transition. Disabled uses --as-select-option-disabled-color. Automatic focus on open does not highlight the selected text. All outlines are drawn solely with inset box-shadow. Reduced motion disables animations. Clicking outside the list, Escape, and selecting a row close it. Keyboard: arrows, Home/End, Enter/Space, Tab, and type-ahead search by initial letters; disabled options are skipped.

The overlay is wired by the shared installControlMotion() and uses the existing native select and its input/change events for controlled React/Qwik values. The Popover API places the list in the top layer. Where CSS Anchor Positioning is supported, the field gets a temporary anchor-name, and the overlay and its inset outline use position-anchor, anchor(), and anchor-size(). Position and width track the field during page and nested container scrolling; scrolling does not close the list. Upward lists anchor by their bottom edge; downward lists anchor by their top edge. Only height animates: anchor coordinates have no transition. After collapse, the temporary anchor-name is restored. Without CSS Anchor Positioning, fixed positioning with close-on-outer-scroll is used; without Popover API, a fixed layer is used. `popup="native"` keeps the standard browser list and remains the Select default. In the demo, overlay is enabled on "Adapter" and the plain Picker; on Picker it can be overridden.

Regular TextInput/TextArea preserve the original CSS transitions and press cycle from release 0.4.9 under standard tokens. Minimum press flash and release cleanup are read from --as-motion-interaction and --as-motion-fast; s/ms and reduced motion are supported. Select handling lives in select-motion.ts and does not alter their handlers. The overlay uses CSS transitions for geometry, inset outline, text color, and neutral selected item background. Selecting an item immediately updates the controlled value and starts collapsing; the new item's background simultaneously transitions to selected while the previous item's background transitions to transparent. On selection, the new item highlights over motion.interaction (no longer than half the collapse duration), then its background transitions back to the normal surface over the remainder of motion.duration. Geometry collapses immediately without waiting for the background. By the time the overlay is removed, the row color already matches the normal field; when closing from outside, the background returns to surface over the full collapse duration. The previous row's background returns to transparent without an extra backdrop; the text clicked for selection keeps its highlight until close finishes.

On open, the selected text transitions from the closed field color to --as-select-option-color; the overlay background consists of two layers: the element's own background via --as-select-overlay-background and ::before background via --as-select-overlay-fill (--as-color-disabled-fill). The primary background keeps the normal surface color. ::before has a constant disabled-fill background; the transition animates only opacity from 0 to 1 on open and 1 to 0 on close, smoothly revealing the normal surface. ::before sits under the rows, and ::after draws the inset outline over the list. Gradients and background-image are not used. From the first frame, the selected row is fully opaque: its background transitions from the normal surface to --as-select-option-selected-background. Text opacity does not change. Hover highlights the item text under the cursor immediately on open; no pointer movement is needed for activation. The overlay preserves the field's computed --as-motion-* and --as-control-easing: geometry, outline release, and backgrounds use --as-motion-duration (fast by default, normal via data-motion-speed), while field press and text color use interaction, and hover uses hover-delay. Expansion and the initial text transition start without delay and do not wait for press completion. Curves come from --as-control-easing or the standard Switch/Transition curves.

For Select popup="overlay", the visual value is moved into an aria-hidden `as-select-value` layer; the native select preserves the value, semantics, and controlled events. The field text moves via translate to the same position as the selected row in the expanded list, with matching duration and curve. The field itself and CSS anchor remain in place. On close, the visual value returns to the field; on selection change, the layer syncs with the new row before collapsing. The opaque surface of the selected row covers the lower text during the transition.

List offset is stored in the registered --as-select-list-offset and animated by a CSS transition on the overlay; the lower field text follows with the same curve and duration. On close, the selected row stays opaque and returns its background to the normal surface.

On close, including clicking outside, the selected text color transitions back to --as-select-option-initial-color (the closed field color) concurrently with the collapse, without hover-delay. Duration is --as-motion-duration, and curve is --as-control-easing or Transition.

The Select popup="overlay" chevron is anchored near the edge of the original field and is not part of the selected item row. The closed chevron shows the calculated expansion direction; on open, it rotates the opposite way via transition rotate with shared motion tokens. Row movement, selecting another item, and list scrolling do not shift it. Direction updates on page scroll, resize, and content changes; a separate chevron in the top layer is bound to the same field CSS anchor.

When the expansion direction changes due to available space, the Lucide chevron swaps its SVG `d` path via transition: down arrow → horizontal line → up arrow (and back). The element itself does not rotate during this swap. Opening and closing separately animate rotate by 180°; both animations use the shared durations and curves.

Overlay item background-color uses its own motion tokens on real pointerdown/click: the shared data-as-pressed/data-as-release button states do not override selection and fade timings. Text color and background have separate timings.

Disabled field chevrons use --as-color-text-disabled, including compact variants. Compact Select plain/service use the bold Lucide icon weight; regular field keeps regular.

Overlay outline timings match regular TextArea release: --as-motion-fast, zero delay, and --as-control-easing with fallback to --as-motion-transition. Geometry speed --as-motion-duration does not change outline duration.

Closed Select and its visual value keep the regular --as-color-text; the chevron keeps the regular color. Open list items use --as-color-text-secondary (#ddd), disabled items use --as-color-text-disabled (#666); item hover keeps --as-select-option-hover-color.

Hover and keyboard candidate highlighting in the list use --as-select-option-hover-color = --as-color-text (#fff). The closed selector keeps the normal color.


The open selector outline mirrors the TextArea pressed → focus transition: color changes via motion.fast/Transition with no delay, and double thickness is preserved. On close, it transitions focus → idle with smooth thinning. No hold, timer, or wait is added before the outline animation.

On close, the overlay reads the final --as-field-frame-width, --as-field-frame-color, and --as-field-status-color of the original Select, taking focus, hover, and disabled into account. Field press-cycle changes during collapse are synced before the panel is removed. Thus plain/flat smoothly fades the inset outline to transparent, while field keeps its normal outline.

Item highlight is drawn in its ::before with an inset of three --as-field-frame-width on all four sides (one thickness for the border itself, two for a clean gap from its inner edge) and an inner radius of max(0rem, --as-radius-control − 3 × --as-field-frame-width). The layer does not go under the overlay's inset outline; row text and dimensions are preserved. Background, inset, and radius changes use CSS transition.

Overlay rows are taller than the field by --as-space-2. Initial and final list offsets compensate for half the extra height, so the text centers of the field and the selected row align during expansion and collapse. Highlight insets are set per axis; ::before radius is compensated by the respective inset along each axis. In seed/close, the vertical inset includes half the height addition; in the open state, a two-thickness gap from the inner outline edge is maintained on all sides.

The vertical radius in seed/close additionally compensates for half the row height addition: radiusY = radiusControl − insetBlock + blockExtra / 2. Thus the final radius matches radiusX, and the added height does not flatten the closed highlight.

Expanded overlay position additionally compensates for half the height addition: downward top = anchor(top) − blockExtra / 2, upward bottom = anchor(bottom) − blockExtra / 2. The offset is animated via the shared CSS variable; on downward expansion, the first item's text stays at the exact position of the closed field.
