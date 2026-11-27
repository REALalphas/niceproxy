# Page

## Problem

The port-assignment form stretches across the entire screen width. Alpha UI 0.4.11
lacks a neutral page container with responsive outer padding and form
width. The application must not add CSS for this.

## Universal Behavior

Constrain readable form width and page outer spacing; remain a
neutral container without a surface or border, and do not add a second main.
Preserve wrapping of long values, 320px width, and normal focus order.

## Proposed API

`width?: 'form' | 'content' | 'full'`, `align?: 'start' | 'center'`,
`inset?: 'none' | 'compact' | 'comfortable'`, `gap?: 1..10`.
Identical contract in React/Qwik, content via children/Slot.

## Composition and Styling

formMax/pageMax widths and spacing use library tokens. Page sits
inside the shell main; Card is added only for a standalone surface.
Comfortable adapts outer spacing for narrow screens.

## Verification

The form is width-constrained on desktop and fits at 320px, main is not duplicated;
React/Qwik share the same props; package sources and application pass
build/types; browser checks confirm dimensions, keyboard navigation, and zero overflow.

## Status

Available and verified in local release Alpha UI 0.4.12-niceproxy.3.


## Verified in Application

Available in local release **0.4.12-niceproxy.3**. Archives and corresponding
sources are in `assets/alpha/0.4.12-niceproxy.3/`. This is a local extension
from 0.4.11 sources, not an official external release. Installed packages
were not edited. Full library verification: 55 tests, React/Qwik build and
typecheck, docs, and package contents. Page verified in production React/Qwik
at 1440/320px. In Niceproxy, 1880/1440/320px, shell height >= viewport,
document margin 0, form width <= 44rem, absence of profile
and overflow, real CRUD/ports, and keyboard navigation were verified.
