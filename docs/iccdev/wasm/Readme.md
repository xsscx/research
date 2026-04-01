# iccDEV WASM Reference

This page summarizes the WebAssembly build workflow for `iccDEV`.

## Scope

The WASM build is intended for browser and Node.js use cases where the upstream
tool behavior needs to run inside an Emscripten-based environment.

## Quick Start

```bash
cd iccDEV
./wasm.sh
./wasm.sh --debug
./wasm.sh --sanitizer
```

Artifacts are written to the WASM build output directories under `wasm/` and
the assembled browser-facing files are copied into `wasm-pages/`.

## Test With Node.js

```bash
cd wasm-pages
npm install
npm test
npm start
```

## Key Build Requirements

These flags and behaviors are the important part of the WASM workflow:

- `MODULARIZE=1`
- `EXPORT_NAME=createModule`
- `INVOKE_RUN=0`
- `FORCE_FILESYSTEM=1`
- exported runtime methods for `FS` and `callMain`
- memory growth enabled

## Most Important Caveat

Without `INVOKE_RUN=0`, Emscripten may run `main()` before the virtual
filesystem is populated, which causes file-open failures for normal CLI-style
tool invocation from JavaScript.

## Debugging Notes

- Debug builds should keep assertions and stack checks enabled.
- Sanitizer builds should avoid combinations that Emscripten does not support,
  such as ASan with `SAFE_HEAP`.
- Platform-specific native linker flags should be excluded from the Emscripten
  path.

## What To Keep Out Of This File

- branch hashes
- package version snapshots
- exact tool or artifact counts
- workflow-run history
- release packaging details tied to one date or one CI layout

Use this page as a stable overview. Keep release-state details in CI workflows,
release notes, or dated reports.
