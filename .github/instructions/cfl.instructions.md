---
applyTo: "cfl/**"
---

# CFL Instructions - LibFuzzer Harnesses

Use these instructions for `cfl/` source, patch-stack, and LibFuzzer workflow
changes.

## Source Of Truth

- Fuzzer list and aliases: `cfl/fuzzers.sh`
- User-facing workflow: `cfl/README.md`
- Active patch list: `cfl/patches/README.md`
- Retired patch archive: `cfl/retired-patches/`

Avoid count drift in docs. When the exact inventory matters, inspect the source
scripts and filesystem in the current checkout.

## Build And A/B Commands

```bash
cd cfl && ./build.sh --no-patches --refresh-iccdev
cd cfl && ./build.sh --patches --refresh-iccdev
cd cfl && ./build.sh --refresh-iccdev --patch-file NAME.patch
cd cfl && ./fuzz-local.sh -t 60 -w 1
cd cfl && ./status.sh --detail
cd cfl && ./status.sh --json | jq .
.github/scripts/check-afl-cfl-patches.sh
```

Use patched, unpatched, and single-patch builds with the same corpus, timeout,
workers, sanitizer options, and machine class when doing A/B testing.

## Tracking Policy

Track reusable CFL assets:

- harness source, headers, scripts, CMake, Docker, and project config
- active and retired patches
- dictionaries and options files
- minimal curated seeds already intended for repeatable test setup
- promoted repro fixtures with command-line evidence

Do not commit raw runtime bulk:

- `cfl/bin/`
- `cfl/build/`
- `cfl/iccDEV/`
- `cfl/runs/`
- `cfl/findings/`
- large `cfl/corpus-*` runtime output
- logs, `.profraw`, and `.profdata`

## Profile Visualization Harness

- Build `icc_profilevisualize_fuzzer` against the public
  `Tools/CmdLine/IccProfilePlot/IccVizModel.hpp` API.
- Compile `IccVizModel.cpp` as a separate translation unit. Do not include
  `iccProfileVisualize.cpp` from the harness or depend on private
  `processLuts()` linkage.
- Keep PDF/TIFF/SVG writer and argv/filesystem coverage in the tool-level AFL
  lane; CFL owns the in-memory `Enumerate` and `Render*` data-model surface.
- Validate compatibility with `cfl/build.sh --branch ci-qa-issue-1975
  --no-patches --refresh-iccdev` while issue #1975 is active.

If a generated file should travel to another VM, promote it to a stable
fixture path and document the repro. Do not commit bulk run state just because
it exists locally.

## Patch Workflow

1. Reproduce against upstream `iccDEV` with ASAN/UBSAN.
2. Patch in `cfl/iccDEV/`.
3. Generate the patch into `cfl/patches/NNN-name.patch`.
4. Run `.github/scripts/check-afl-cfl-patches.sh` before rebuilding.
5. Reset the nested checkout before rebuilding.
6. Validate both patched and unpatched behavior.
7. Update `cfl/patches/README.md` and only summarize in `cfl/README.md`.

Patch application failures are warnings in patched mode. Non-applicable patches
are skipped so stale local patch stacks do not block AFL/CFL builds. After an
upstream refresh, remove stale build output before judging build or sanitizer
failures:

```bash
rm -rf cfl/iccDEV/Build cfl/build cfl/bin
cd cfl && ./build.sh --no-patches --refresh-iccdev
cd cfl && ./build.sh --patches --refresh-iccdev
```

## Runtime Notes

- Use `ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1` for clear
  sanitizer exits.
- Use `LLVM_PROFILE_FILE=/dev/null` when coverage files are not needed.
- Treat OOM and timeout files as evidence candidates, not automatic commits.
- Keep one-off run counts in dated reports, not hub docs.
