# Qwik: containers and q:base

`q:base` sets the base URL for resolving lazy QRL modules of a container. It is defined by the application, not by individual Button, Card, or other library components. React and Qwik share the same tokens and CSS, while Qwik retains its own `component$`, `QRL`, and `$` handlers.

In the source repository demo, the root container obtains its base from `new URL('./', import.meta.url)`: after building, this points to the `assets/` module directory. If the host has already set `q:base`, the demo preserves it. Thus the container can be hosted in a subdirectory without tying the library to a domain or site root.

To build for `/alpha/`, set `VITE_APP_BASE=/alpha/` in `apps/qwik/.env.local`, then build the application. For local desktop HTML, the standard relative base `./` is used. `q:base` does not replace router settings, CSS paths, or Vite asset paths. In Electron and Tauri, also verify the chosen loading protocol and CSP: native builds have not been verified in this repository.

In the dev configuration of the demo, `@alpha/qwik` resolves to the generated adapter TSX: Vite/Qwik must process lazy tasks and handlers of the source components. Production uses the built package.

During SSR, pass `base` to `renderToString` or `renderToStream`, pointing to the actual directory of built Qwik modules. Independent applications may have their own containers and bases; ordinary nested components do not need new containers.

Documentation: [Qwik containers](https://qwik.dev/docs/advanced/containers/), [QRL](https://qwik.dev/docs/advanced/qrl/).
