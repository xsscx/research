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
- Retired patch archive: `cfl/patches-retired/`

Avoid count drift in docs. When the exact inventory matters, inspect the source
scripts and filesystem in the current checkout.

## Build And A/B Commands

```bash
cd cfl && ./build.sh --patches --refresh-iccdev
cd cfl && ./build.sh --no-patches --refresh-iccdev
cd cfl && ./build.sh --refresh-iccdev --patch-file NAME.patch
cd cfl && sudo ./ramdisk-fuzz.sh 60
cd cfl && ./status.sh --detail
cd cfl && ./status.sh --json | jq .
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

If a generated file should travel to another VM, promote it to a stable
fixture path and document the repro. Do not commit bulk run state just because
it exists locally.

## Patch Workflow

1. Reproduce against upstream `iccDEV` with ASAN/UBSAN.
2. Patch in `cfl/iccDEV/`.
3. Generate the patch into `cfl/patches/NNN-name.patch`.
4. Reset the nested checkout before rebuilding.
5. Validate both patched and unpatched behavior.
6. Update `cfl/patches/README.md` and only summarize in `cfl/README.md`.

Patch application failures are fatal in patched mode. After an upstream refresh,
remove stale build output before judging a failure:

```bash
rm -rf cfl/iccDEV/Build cfl/build cfl/bin
cd cfl && ./build.sh --patches --refresh-iccdev
```

## Runtime Notes

- Use `ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1` for clear
  sanitizer exits.
- Use `LLVM_PROFILE_FILE=/dev/null` when coverage files are not needed.
- Treat OOM and timeout files as evidence candidates, not automatic commits.
- Keep one-off run counts in dated reports, not hub docs.
