# CFL - LibFuzzer Harnesses for iccDEV

Last updated: 2026-08-07

`cfl/` contains the LibFuzzer side of the iccDEV fuzzing workflow: active
harnesses, sanitizer builds, dictionaries, and seed material. It builds
upstream `master` without local source patches.

Use `cfl/fuzzers.sh` as the source of truth for the current fuzzer list.

## Fast Path

The default CFL toolchain is `clang-22`/`clang++-22`. Set `CC` and `CXX` only
for an explicit compatibility experiment with another matching Clang runtime.

```bash
# Build current upstream master.
cd cfl && ./build.sh --refresh-iccdev

# Smoke-test all fuzzers from local corpora.
cd cfl && ./fuzz-local.sh -t 60 -w 1

# Build and replay the same corpora under MSan or TSan.
cd cfl && ./build.sh --sanitizer memory
cd cfl && ./fuzz-local.sh -s memory -t 60 -w 1
cd cfl && ./start.sh --sanitizer memory icc_proflib_fuzzer
cd cfl && ./build.sh --sanitizer thread
cd cfl && ./fuzz-local.sh -s thread -t 60 -w 1

# Run longer fuzzing on mounted storage.
cd cfl && ./fuzz-local.sh -t 14400 -w 4 -r /mnt/g/fuzz-ssd
```

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
| ProfilePlot data model | `icc_profilevisualize_fuzzer` (`profileplot`, `plot`) |
| Unrestricted IccProfLib API | `icc_proflib_fuzzer` |
| Read/write round trip | `icc_roundtrip_fuzzer` |
| Spectral separation | `icc_specsep_fuzzer` |
| TIFF ICC extraction | `icc_tiffdump_fuzzer` |
| JSON profile export | `icc_tojson_fuzzer` |
| XML export | `icc_toxml_fuzzer` |
| v5 display observer conversion | `icc_v5dspobs_fuzzer` |

`icc_applynamedcmm_fuzzer` accepts one raw ICC profile with no control prefix,
suffix, or reserved-byte selector. For each parseable profile it runs a bounded
matrix of the NamedCmm transform, intent, interpolation, hint, environment,
encoding, direction, named-color, and same-profile-chain paths. The tracked
profiles in `cfl/seeds-applynamedcmm/` are copied into the runtime
`cfl/corpus-icc_applynamedcmm_fuzzer/` directory by `fuzz-local.sh`; the tracked
seed directory is never used as mutable runtime storage. Validate the contract
with `.github/scripts/validate-cfl-applynamedcmm.sh --replay` after building.
When the separate `ICS-POC/` checkout is present, the runner also copies pure
V5 ICC files from each package `ICC/` directory with collision-safe names. This
adds V5.0.2, V5.1, and V5.1.1 coverage without copying generated package output
into the tracked CFL seed directory. Set `CFL_ICS_POC_ROOT` when the checkout
is elsewhere.

An independent PCC needs a second profile and is intentionally outside this
single-file contract. JSON parsing/export and calculator-debug output are owned
by `icc_cfg_fuzzer` and tool QA respectively.

`icc_connect_fuzzer` also accepts an ordinary raw ICC profile. It reads the
encoded profile size and treats four bytes after that payload as optional
controls; it never removes the final four bytes from a raw seed. The config
fuzzer accepts ordinary JSON with no selector prefix and round-trips all public
top-level and nested `CIccCfg*` objects. Both AFL and CFL use
`cfl/icc_cfg.dict`, and
`docs/Testing/json-configs/connect-config-complete.json` is the shared
schema-shaped seed. Validate these contracts with
`.github/scripts/validate-afl-cfl-config-alignment.sh`.

The local inventory already has separately attributable multi-profile,
XML/JSON serializer, V5 display-observer, and image/carrier targets. Strengthen
those targets before adding overlapping harnesses, and keep image/carrier MSan
findings behind fully instrumented dependency boundaries.

Address-sanitizer builds consume iccDEV's standard-library-only UBSAN
ignorelist. This keeps known libstdc++ integer idioms out of fuzzer findings
without suppressing project-owned code; it also prevents repeated diagnostics
from turning the weighted ApplySearch seed replay into a false timeout.

Sanitizer modes are separate builds. `address` writes `cfl/bin/` and uses the
normal LibFuzzer engine. `memory` writes `cfl/bin-msan/`, enables MSan origin
tracking, and also uses LibFuzzer. `thread` writes `cfl/bin-tsan/` and uses the
bounded corpus runner because it is intended for deterministic concurrent
replay rather than mutation. The runners keep state in `cfl/runs/`,
`cfl/runs-msan/`, and `cfl/runs-tsan/` respectively. Use matching
`--sanitizer` values with `start.sh`, `status.sh`, and `stop.sh`, or `-s` with
`fuzz-local.sh`. Omitting the selector chooses the default address build in
`cfl/bin/`; it does not fall back to `cfl/bin-msan/`.

The MSan build compiles and statically links a pinned, instrumented LLVM
libc++ runtime. This is required because using the system's uninstrumented
libstdc++ produces false uninitialized-read reports inside standard-library
operations. The MSan lane uses LibFuzzer sanitizer-coverage counters but not
Clang source-profile instrumentation, whose runtime is not MSan-instrumented.

The NamedCmm, Connect, config, TIFF image, and JSON/XML conversion harnesses do
not impose a fixed input-size ceiling. Their `.options` use `max_len = 0`, so
the CFL runners derive and pass the largest supplied corpus-file size without a
repository ceiling; add representative large profiles when testing those
lanes. Keep RSS and per-input timeouts as the resource controls. This matters
for conversion lanes: a 3.8 MiB ICC QA input has been observed to serialize to
more than 85 MiB of JSON.

`icc_fromxml_fuzzer` now follows the `iccFromXml` CLI envelope for the default
import path, `-noid`, and `-v=<schema>` validation path on each parseable XML
input. The CFL build also verifies `IccXML` coverage instrumentation so XML
import coverage cannot silently disappear from an uninstrumented library build.

`icc_toxml_fuzzer` suppresses upstream stdout during fuzzing. This keeps
expected XML serialization diagnostics such as non-XML tag notices from
dominating logs while preserving libFuzzer progress and sanitizer reports on
stderr.

`icc_profilevisualize_fuzzer` targets the public, data-first `IccVizModel` API
from `Tools/CmdLine/IccProfilePlot`. The build compiles `IccVizModel.cpp`
separately and links the harness through `IccVizModel.hpp`; it does not include
the CLI implementation or depend on the private, file-writing `processLuts()`
function. Use the issue #1975 compatibility baseline locally with:

```bash
cd cfl
./build.sh --branch ci-qa-issue-1975 --refresh-iccdev
ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1 \
  ./bin/icc_profilevisualize_fuzzer -runs=1 corpus/
```

This is the CFL half of the ProfilePlot A/B split: it renders every descriptor
returned by `Enumerate()` in memory. The AFL `profileplot`,
`profileplot-graph`, and `profileplot-raster` lanes own real CLI JSON and raw
file output. `./fuzz-local.sh -t 60 -w 1 profileplot` selects this harness.
The runner installs `test-profiles/sRGB_v4_ICC_preference.icc` into the mutable
runtime corpus and keeps a 64 KiB input limit so that fixture's graph and CLUT
descriptors are both reachable.

`icc_proflib_fuzzer` is the direct library lane. It passes the complete input
buffer to IccProfLib without a minimum profile size or command-line semantic
gates, selects among lazy, sub-profile, eager, and validating memory readers,
then exercises every discovered tag, profile validation, PCC accessors, copy
construction, and serialization. The `profile`, `proflib`, and `iccproflib`
aliases select it in the CFL scripts.

## Upstream Baseline

`cfl/patches/` has no active patches. `cfl/retired-patches/` preserves
superseded patches for audit history. After refreshing the nested `iccDEV`
checkout, remove stale build output before judging build or sanitizer failures:

```bash
rm -rf cfl/iccDEV/Build cfl/build cfl/bin
cd cfl && ./build.sh --refresh-iccdev
```

## What Belongs In Git

Track reusable inputs and source needed to reproduce runs on another VM:

| Track | Examples |
|-------|----------|
| Harness and build source | `cfl/*.cpp`, `cfl/*.h`, `cfl/*.sh`, `CMakeLists.txt`, `Dockerfile` |
| Retired patch history | `cfl/retired-patches/*.patch` |
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
./fuzz-local.sh -s memory -t 60 dump
./start.sh dump --sanitizer thread --time 60 --foreground
./status.sh dump --sanitizer thread --detail
```

ThreadSanitizer builds use a deterministic corpus replayer rather than
LibFuzzer mutation. The replay log is written below `cfl/runs-tsan/`, starts
with the corpus and duration, reports progress every 10 seconds, and ends with
`stat::number_of_executed_units`. A ThreadSanitizer finding is written to the
same log and stops the run. The launcher allows one target timeout beyond the
requested duration so a slow final input cannot leave a background replay
running indefinitely. Use `applyprofiles` for the general image pipeline or
`applyprofiles-row` to force the batched row-apply path corresponding to the
tool's `-threads` mode.

Both `start.sh` and `fuzz-local.sh` execute each harness from runtime state below
`cfl/runs/`, with `FUZZ_TMPDIR` pointing at that fuzzer's work directory.
Corpora remain under `cfl/corpus-*`, findings use the configured artifact
directory, and generated tool files must not appear in the repository root.

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

- Replay one CFL artifact and require confirmation from an independently built,
  unpatched iccDEV tool with `./cfl/triage.sh --sanitizer memory
  applynamedcmm /path/to/artifact`. Add `--mark` only after confirmation is
  wanted under `cfl/marked/`; the generated `.cmd` invokes the command-line
  tool, never the LibFuzzer harness. The generated `.docker.cmd` uses the
  published upstream image. Build the independent MSan tools with
  `./afl/build-iccdev-msan.sh`.
- Reproduce the named-CMM finding entirely inside the published container with
  `./cfl/reproduce-applynamedcmm-msan-docker.sh /path/to/profile.icc`. The
  wrapper uses the [published iccDEV package](https://github.com/InternationalColorConsortium/iccDEV/pkgs/container/iccdev/1290825757?tag=latest)
  and pins image digest
  `sha256:0504c43e0204e36aa36377fceee1de9c5f49468d578202c388525c75d42da079`
  (iccDEV `da7e075`), disables networking, mounts the input read-only, relaxes
  seccomp only for MSan shadow mapping, builds the unpatched command-line tool,
  verifies the expected signature and tool `EXIT=134`, then returns 86 to mark
  a confirmed MSan reproduction.
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
| `cfl/patches/README.md` | Zero-patch inventory |
| `docs/Testing/CFL_MANUAL_FUZZER_COMMANDS.md` | Per-fuzzer maintainer one-liners |
| `docs/afl/index.md` | AFL++ tool-level fuzzing |
| `docs/Testing/FUZZ_CFL_INVENTORY.md` | Fuzzing asset and tracking policy |
| `.github/instructions/cfl.instructions.md` | Agent maintenance rules for this path |
