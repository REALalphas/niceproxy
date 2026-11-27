# Stack

## Problem

Paired address and port fields must stay on a single row, with a wider
first field. Previously, Stack row only wrapped items without controlling proportions.

## Universal Behavior and API

`direction="row" columns="equal" | "wide-start" | "wide-end"` sets two
columns in 1:1, 2:1, or 1:2 proportions. Without columns, previous behavior is preserved.
React and Qwik share the same contract. DOM/Tab order remains unchanged.

## Composition and Styling

Library-only outer layout; appearance and states of child fields are unchanged.
Gap uses the standard Stack scale, with column minimum width 0. Errors wrap inside
their own column; fields remain on one row even at 320px.

## Verification

Paired input bounds share the same y coordinate; the first is wider than the second, with no overflow
at 1440/320px. All values, handlers, and the forwarding diagram are preserved.

## Status

Available and verified in local release 0.4.12-niceproxy.4. Full library verify (56 tests), application typecheck/build, and browser check at 1440/320px passed.
