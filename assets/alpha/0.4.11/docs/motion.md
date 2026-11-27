# Motion

Speed and easing are independent. Speeds: `--as-motion-fast: 0.4s`, `--as-motion-normal: 0.6s`. Easings: `--as-motion-switch: cubic-bezier(.5,.4,0,1)` for buttons/state toggles; `--as-motion-transition: cubic-bezier(.2,.66,0,1)` for smooth view transitions. Either curve works with either speed.

Hover: delay 0.033s, duration 0.166s. Press: 0.166s with no delay; release: 0.4s with no delay. Call `installControlMotion()` from `@alpha/core` once at the application level for mouse and keyboard support. Controls use Switch by default. Control easing can be changed via `data-motion-easing="transition"` or `--as-control-easing`. The fast/normal speeds remain independent of the curves for view transitions. Do not use implicit `ease` or `linear` for these transitions. The Loading dash motion is a separate cyclic animation.

`@alpha/core` exports `transitionView(update)`. Wrap the single swappable region in `.as-view`. The React/Qwik demos use this API for navigation. React triggers a synchronous DOM commit via `flushSync`. Qwik waits for the actual DOM update via `waitForViewCommit`, rather than a timer estimating render duration.

View Transition uses Transition/normal by default. For a different speed, set `data-motion-speed="fast"` on `<html>` or the `--as-view-duration` CSS variable; change the curve independently via `--as-motion-transition`. Do not assign the same `alpha-view` name to multiple visible elements at once. Wiring your project's router happens at the application level, not inside Button.

If the API is unavailable or the user has enabled reduced motion, the update runs without snapshots or animation. Update errors are not swallowed. [View Transition API documentation](https://developer.mozilla.org/en-US/docs/Web/API/Document/startViewTransition).
