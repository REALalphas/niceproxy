# Dialog

## Task

The account connection flow may need an in-panel modal for access details, setup, and feedback. Alpha UI 0.4.11 has no public modal component with focus management. Provider authorization opens in a separate browser window.

## Universal behavior

Opening moves focus into the dialog and disables the rest of the page. Tab and Shift+Tab stay inside the dialog. Escape requests close. Closing restores focus to the trigger. The dialog has an accessible name and optional description.

## Proposed API

`Dialog` accepts controlled `open`, `title`, optional `description`, `children`, and `onOpenChange(open)`. Qwik uses `onOpenChange$`.

## Composition and styling

Use overlay tokens, Alpha UI spacing, and public content components. Scroll long content inside the dialog. At 320 px, title, fields, and actions must work without horizontal scrolling.

## Checks

Verify keyboard opening, screen-reader naming, focus trap, Escape close, and focus restoration. Check long labels and error messages at wide and 320 px widths.

## Status

Proposed. Niceproxy currently uses a card for setup and a separate browser window for OAuth.
