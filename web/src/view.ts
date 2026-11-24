import { flushSync } from "react-dom";

// Keep normal library control motion; screen changes do not capture/crossfade the page.
export function changeView(update: () => void) {
  flushSync(update);
}
