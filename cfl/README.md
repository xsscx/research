# CFL - LibFuzzer Harnesses for iccDEV

Last updated: 2026-05-19

`cfl/` contains the LibFuzzer side of the iccDEV fuzzing workflow: 13
harnesses, sanitizer builds, dictionaries, seed material, and the active patch
stack used for patched vs upstream A/B testing.

Use `cfl/patches/README.md` as the source of truth for the current patch list.
Use `cfl/fuzzers.sh` as the source of truth for the current fuzzer list.

## Fast Path

```bash
# Build current upstream master with the active CFL patch stack.
cd cfl && ./build.sh --patches --refresh-iccdev

# Build current upstream master without CFL patches.
cd cfl && ./build.sh --no-patches --refresh-iccdev

# Build one selected patch for an isolated A/B check.
cd cfl && ./build.sh --refresh-iccdev \
  --patch-file 053-formulacurve-describe-format-specifiers.patch

# Smoke-test all fuzzers on tmpfs.
cd cfl && sudo ./ramdisk-fuzz.sh 60

# Run longer fuzzing on mounted storage.
cd cfl && ./fuzz-local.sh -t 14400 -w 4 -r /mnt/g/fuzz-ssd
```

## A/B Testing Model

| Mode | Command | Purpose |
|------|---------|---------|
| Upstream | `./build.sh --no-patches --refresh-iccdev` | Baseline current iccDEV behavior |
| Patched stack | `./build.sh --patches --refresh-iccdev` | Full CFL hardening stack |
| Single patch | `./build.sh --patch-file NAME.patch --refresh-iccdev` | Isolate one candidate fix |

Keep the same corpus, timeout, worker count, sanitizer options, and machine
class across A/B runs. Compare crashes, sanitizer findings, timeouts, OOMs, and
coverage from the status scripts rather than ad hoc log scraping.

Useful status commands:

```bash
cd cfl && ./status.sh
cd cfl && ./status.sh --detail
cd cfl && ./status.sh --json | jq .
```

## Fuzzers

The active harness set is defined in `cfl/fuzzers.sh`:

```bash
cd cfl && ./fuzzers.sh
```

Current harness areas:

| Area | Harness |
|------|---------|
| Named color CMM | `icc_applynamedcmm_fuzzer` |
| Multi-profile transforms | `icc_applyprofiles_fuzzer` |
| Search optimization | `icc_applysearch_fuzzer` |
| JSON config parsing | `icc_cfg_fuzzer` |
| Profile dump/validate/describe | `icc_dump_fuzzer` |
| CUBE import | `icc_fromcube_fuzzer` |
| XML import | `icc_fromxml_fuzzer` |
| Profile linking | `icc_link_fuzzer` |
| Read/write round trip | `icc_roundtrip_fuzzer` |
| Spectral separation | `icc_specsep_fuzzer` |
| TIFF ICC extraction | `icc_tiffdump_fuzzer` |
| XML export | `icc_toxml_fuzzer` |
| v5 display observer conversion | `icc_v5dspobs_fuzzer` |

## Patch Stack

`cfl/patches/` is the active patch stack. `cfl/patches-retired/` preserves
accepted, superseded, or obsolete patches for audit history.

```bash
cd cfl && ./build.sh --patches --refresh-iccdev
cd cfl && ./build.sh --no-patches --refresh-iccdev
cd cfl && ./build.sh --patch-file 084-tagcurve-setgamma-range-ubsan.patch
```

Patch application failures are fatal in patched mode. After refreshing the
nested `iccDEV` checkout, remove stale build output before judging a failure:

```bash
rm -rf cfl/iccDEV/Build cfl/build cfl/bin
cd cfl && ./build.sh --patches --refresh-iccdev
```

## What Belongs In Git

Track reusable inputs and source needed to reproduce runs on another VM:

| Track | Examples |
|-------|----------|
| Harness and build source | `cfl/*.cpp`, `cfl/*.h`, `cfl/*.sh`, `CMakeLists.txt`, `Dockerfile` |
| Patch source | `cfl/patches/*.patch`, `cfl/patches-retired/*.patch` |
| Dictionaries | `cfl/*.dict`, curated AFL target dictionaries |
| Minimal seed fixtures | `cfl/corpus/`, `cfl/seeds-*`, small named fixtures |
| Promoted repro artifacts | Files moved to `test-profiles/`, `fuzz/`, or `docs/pocs/` with evidence |

Do not commit raw runtime bulk by default:

| Keep Local | Why |
|------------|-----|
| `cfl/bin/`, `cfl/build/`, `cfl/iccDEV/` | Rebuilt locally |
| `cfl/runs/`, `cfl/findings/` | Runtime state and transient findings |
| `cfl/corpus-*` bulk output | Can be hundreds of thousands of files |
| `*.profraw`, `*.profdata`, `*.log` | Large and machine-specific |

When a runtime artifact becomes a durable regression fixture, promote it out of
the runtime directory, give it a descriptive name, add a short PoC note, and
commit that curated file.

## Runtime Workflows

### Ramdisk Smoke Or Fuzz Run

```bash
cd cfl
sudo ./ramdisk-fuzz.sh          # default duration
sudo ./ramdisk-fuzz.sh 60       # smoke test
sudo ./ramdisk-fuzz.sh 120 dump # target alias accepted by helper scripts
```

### Mounted Storage Run

```bash
.github/scripts/ramdisk-seed.sh --ramdisk /mnt/g/fuzz-ssd
cd cfl && ./fuzz-local.sh -r /mnt/g/fuzz-ssd -w 8 -t 3600
.github/scripts/ramdisk-merge.sh --ramdisk /mnt/g/fuzz-ssd
.github/scripts/ramdisk-sync-to-disk.sh --ramdisk /mnt/g/fuzz-ssd
```

### Coverage

```bash
.github/scripts/merge-profdata.sh /tmp/fuzz-ramdisk/profraw
.github/scripts/generate-coverage-report.sh \
  /tmp/fuzz-ramdisk/merged.profdata /tmp/fuzz-ramdisk/coverage-report
```

Set `LLVM_PROFILE_FILE=/dev/null` for fuzzing runs where coverage files are not
needed.

## Triage Rules

- A finding is actionable only after reproducing against the intended baseline.
- Use `ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1` for clear
  sanitizer exits.
- Record the exact build mode, patch set, input path, command line, and
  sanitizer summary before promoting a fixture.
- Keep one-off counts and dated outcomes in reports, not in this README.

## Related Docs

| Doc | Use |
|-----|-----|
| `cfl/patches/README.md` | Current active patch stack |
| `docs/afl/index.md` | AFL++ tool-level fuzzing |
| `docs/Testing/FUZZ_CFL_INVENTORY.md` | Fuzzing asset and tracking policy |
| `.github/instructions/cfl.instructions.md` | Agent maintenance rules for this path |
