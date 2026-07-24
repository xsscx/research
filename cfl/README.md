# CFL - LibFuzzer Harnesses for iccDEV

Last updated: 2026-07-20

`cfl/` contains the LibFuzzer side of the iccDEV fuzzing workflow: active
harnesses, sanitizer builds, dictionaries, seed material, and an optional patch
stack used only for explicit patched-vs-upstream A/B testing.

Use `cfl/patches/README.md` as the source of truth for the current patch list.
Use `cfl/fuzzers.sh` as the source of truth for the current fuzzer list.

## Fast Path

```bash
# Build current upstream master without CFL patches. This is the default.
cd cfl && ./build.sh --refresh-iccdev
cd cfl && ./build.sh --no-patches --refresh-iccdev

# Build current upstream master with the CFL patch stack for A/B testing.
cd cfl && ./build.sh --patches --refresh-iccdev

# Build one selected patch for an isolated A/B check.
cd cfl && ./build.sh --refresh-iccdev \
  --patch-file 053-formulacurve-describe-format-specifiers.patch

# Smoke-test all fuzzers from local corpora.
cd cfl && ./fuzz-local.sh -t 60 -w 1

# Run longer fuzzing on mounted storage.
cd cfl && ./fuzz-local.sh -t 14400 -w 4 -r /mnt/g/fuzz-ssd
```

## A/B Testing Model

| Mode | Command | Purpose |
|------|---------|---------|
| Upstream | `./build.sh --refresh-iccdev` | Baseline current iccDEV behavior |
| Upstream explicit | `./build.sh --no-patches --refresh-iccdev` | Same as default, useful in A/B logs |
| Patched stack | `./build.sh --patches --refresh-iccdev` | CFL hardening stack for comparison |
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
| Multi-profile row transforms | `icc_applyprofiles_row_fuzzer` |
| Search optimization | `icc_applysearch_fuzzer` |
| Search weight validation | `icc_applysearch_weight_fuzzer` |
| IccConnect CMM factory | `icc_connect_fuzzer` |
| JSON config parsing | `icc_cfg_fuzzer` |
| Profile dump/validate/describe | `icc_dump_fuzzer` |
| CUBE import | `icc_fromcube_fuzzer` |
| JSON profile import | `icc_fromjson_fuzzer` |
| XML import | `icc_fromxml_fuzzer` |
| JPEG ICC extraction | `icc_jpegdump_fuzzer` |
| Profile linking | `icc_link_fuzzer` |
| PAWG report generation | `icc_pawgreport_fuzzer` |
| PNG ICC extraction | `icc_pngdump_fuzzer` |
| Read/write round trip | `icc_roundtrip_fuzzer` |
| Spectral separation | `icc_specsep_fuzzer` |
| TIFF ICC extraction | `icc_tiffdump_fuzzer` |
| JSON profile export | `icc_tojson_fuzzer` |
| XML export | `icc_toxml_fuzzer` |
| v5 display observer conversion | `icc_v5dspobs_fuzzer` |

`icc_fromxml_fuzzer` now follows the `iccFromXml` CLI envelope for the default
import path, `-noid`, and `-v=<schema>` validation path on each parseable XML
input. The CFL build also verifies `IccXML` coverage instrumentation so XML
import coverage cannot silently disappear from an uninstrumented library build.

`icc_toxml_fuzzer` suppresses upstream stdout during fuzzing. This keeps
expected XML serialization diagnostics such as non-XML tag notices from
dominating logs while preserving libFuzzer progress and sanitizer reports on
stderr.

`icc_profilevisualize_fuzzer` is retired in `cfl/retired/`. The harness targets
a very new external tool surface and currently does not build against refreshed
upstream `iccDEV` because its expected `processLuts` entry point is not exposed.

## Patch Stack

`cfl/patches/` is an optional patch stack. `cfl/retired-patches/` preserves
accepted, superseded, or obsolete patches for audit history. Plain `build.sh`
does not apply patches; pass `--patches` or `--patch-file` when an A/B run
intentionally needs patched source.

```bash
cd cfl && ./build.sh --patches --refresh-iccdev
cd cfl && ./build.sh --no-patches --refresh-iccdev
cd cfl && ./build.sh --patch-file 001-json-config-parser-no-sanitize.patch
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
| Patch source | `cfl/patches/*.patch`, `cfl/retired-patches/*.patch` |
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

### Local Smoke Or Fuzz Run

```bash
cd cfl
./fuzz-local.sh -t 60           # smoke test
./fuzz-local.sh -t 120 dump     # target alias accepted by helper scripts
```

For maintainer one-liners covering every active fuzzer, including smoke,
explore, rare-path, and sanitizer reproduction modes, use
`docs/Testing/CFL_MANUAL_FUZZER_COMMANDS.md`.

### Mounted Storage Run

```bash
# Prepare /mnt/g/fuzz-ssd with bin/, dict/, logs/, profraw/, and corpus-* dirs.
cd cfl && ./fuzz-local.sh -r /mnt/g/fuzz-ssd -w 8 -t 3600
../.github/scripts/corpus-merge.sh --scratch /mnt/g/fuzz-ssd
rsync -a /mnt/g/fuzz-ssd/corpus-* ./
```

### Coverage

```bash
.github/scripts/merge-profdata.sh /mnt/g/fuzz-ssd/profraw
.github/scripts/generate-coverage-report.sh \
  /mnt/g/fuzz-ssd/merged.profdata /mnt/g/fuzz-ssd/coverage-report
```

Set `LLVM_PROFILE_FILE=/dev/null` for fuzzing runs where coverage files are not
needed.

## Triage Rules

- A finding is actionable only after reproducing against the intended baseline.
- Bundled LibFuzzer inputs are canonical CFL artifacts. Treat unbundled ICC,
  TIFF, XML, or control files as derived triage views only.
- Do not promote ICC-like CFL artifacts by `acsp` magic alone. Compound inputs
  often contain a prefix-valid ICC blob plus control bytes or another payload.
- Do not create an upstream/bisect report unless iccDEV command-line tooling has
  a one-line reproducer for a maintainer-actionable crash or finding.
- Use `ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1` for clear
  sanitizer exits.
- Record the exact build mode, patch set, input path, command line, and
  sanitizer summary before promoting a fixture.
- Keep one-off counts and dated outcomes in reports, not in this README.

## Related Docs

| Doc | Use |
|-----|-----|
| `cfl/patches/README.md` | Current active patch stack |
| `docs/Testing/CFL_MANUAL_FUZZER_COMMANDS.md` | Per-fuzzer maintainer one-liners |
| `docs/afl/index.md` | AFL++ tool-level fuzzing |
| `docs/Testing/FUZZ_CFL_INVENTORY.md` | Fuzzing asset and tracking policy |
| `.github/instructions/cfl.instructions.md` | Agent maintenance rules for this path |
