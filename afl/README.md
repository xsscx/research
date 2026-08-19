# AFL++ Tool Fuzzing

`afl/` runs AFL++ against real iccDEV command-line tools. It complements `cfl/`,
which fuzzes library-level harnesses with LibFuzzer.

Use `afl/targets.sh` as the source of truth for available targets and target
argv shapes. Do not hand-maintain target counts in this README.

After changing an `iccApplyNamedCmm` target shape or seed policy, run the
binary-independent contract check:

```bash
.github/scripts/validate-afl-applynamedcmm-targets.sh
```

The four NamedCmm lanes and their intended CLI coverage are documented in
`docs/afl/index.md`.

## Quick Start

```bash
./afl/build-afl-runtime.sh
./afl/build.sh
./afl/start.sh --list
./afl/start.sh dump
./afl/status.sh dump --detail
./afl/report.sh all --no-coverage
./afl/triage.sh dump
./afl/stop.sh dump
```

`build.sh` links iccDEV libraries statically by default. This keeps AFL
instrumentation and post-campaign LLVM coverage/profiling in the same binary
image, avoiding split executable/shared-library coverage maps. Use
`./afl/build.sh --shared` only when intentionally comparing shared-library
behavior.

Every AFL build enables the full Clang sanitizer set used for security testing:
AddressSanitizer, UndefinedBehaviorSanitizer, IntegerSanitizer,
float-divide-by-zero, and float-cast-overflow. Sanitizer findings are fatal, and
`build.sh` verifies the deployed `iccDumpProfile` contains each sanitizer
runtime handler before reporting success. Runtime options shared by fuzzing,
mapping, minimization, seed validation, and triage live in
`afl/sanitizer-env.sh`.

When an `iccApplyToLink` AFL artifact remains actionable under canonical
iccDEV replay, mark it for the project tool suite with
`./afl/triage.sh applytolink --mark` or
`./afl/triage.sh applytolink-cube --mark`. The marker copy lands under
`afl/marked/<target>/` next to a `.cmd` file containing the exact replay
command, and `.github/scripts/test-iccApplyToLink.sh` sweeps those marked
inputs when present.

Build the isolated AFL iccDEV checkout with comparison-guided variants when a
campaign plateaus on parser-heavy paths:

```bash
AFL_BUILD_DIR=$PWD/afl/iccDEV/Build-AFL-CMPLOG AFL_BIN_DIR=$PWD/afl/bin-cmplog ./afl/build.sh --cmplog --clean
AFL_CMPLOG_BINARY=$PWD/afl/bin-cmplog/iccDumpProfile ./afl/start.sh dump
```

```bash
AFL_BUILD_DIR=$PWD/afl/iccDEV/Build-AFL-LAF AFL_BIN_DIR=$PWD/afl/bin-laf ./afl/build.sh --laf --clean
AFL_BIN_DIR=$PWD/afl/bin-laf ./afl/start.sh dump
```

For `iccFromCube`, low bitmap density is expected against the full statically
linked iccDEV edge map, but keyword and number-heavy parsing benefits from
comparison-aware variants. Keep the baseline output tree separate from these
experiments:

```bash
AFL_BUILD_DIR=$PWD/afl/iccDEV/Build-AFL-LAF AFL_BIN_DIR=$PWD/afl/bin-laf ./afl/build.sh --laf --clean
AFL_BIN_DIR=$PWD/afl/bin-laf AFL_BASE=$PWD/afl/laf ./afl/start.sh fromcube --fresh --reseed
```

```bash
AFL_BUILD_DIR=$PWD/afl/iccDEV/Build-AFL-CMPLOG AFL_BIN_DIR=$PWD/afl/bin-cmplog ./afl/build.sh --cmplog --clean
AFL_BASE=$PWD/afl/cmplog ./afl/start.sh fromcube --fresh --reseed --cmplog-binary $PWD/afl/bin-cmplog/iccFromCube
```

`build.sh` requires `clang-21`/`clang++-21` and AFL++ wrappers built against
LLVM 21. `build-afl-runtime.sh` checks out stable commit
`05507e1880dc6df997c19e01423444ef37c36846`, raises the compiled testcase
ceiling to 4 MiB, and installs the matching runtime and compiler wrappers.
Override `AFL_CLANG_FAST` or `AFL_CLANG_FASTXX` only when pointing at a
different LLVM 21 wrapper install with an adequate testcase ceiling.

## Review-Driven Improvements

The campaign review in `~/afl-review.md` identifies these practical next steps:

| Area | Current repo support | Recommended use |
|------|----------------------|-----------------|
| CmpLog | `./afl/build.sh --cmplog` and `AFL_CMPLOG_BINARY=... ./afl/start.sh ...` | Use on comparison-heavy ICC parsers after a baseline corpus exists. |
| Compare splitting | `./afl/build.sh --laf` | Run as a separate campaign variant, not over the baseline output tree. |
| Context/path variants | `./afl/build.sh --ctx` and `./afl/build.sh --ngram N` | Use for A/B coverage experiments with separate build and bin dirs. |
| Corpus minimization | `./afl/minimize.sh` | Run on mature queues with low favored ratios or plateauing cycles. |
| Slow target lanes | `*-fast` targets in `afl/targets.sh` | Prefer small-seed fast lanes for expensive report/visualization tools. |
| Hangs | `./afl/triage.sh <target>` | Replay saved hangs with the configured upstream argv and timeout. |
| Coverage mapping | `./afl/map.sh` | Compare queue, crash, hang, or input coverage before promoting artifacts. |
| Source coverage | AFLplusplus `cov-analysis` | Build a dedicated coverage binary and annotate AFL queues with LLVM source coverage. |
| Static reachability | AFLplusplus `fuzz-reachability` | Cross-reference cov-analysis with reachable-but-unreached functions. |
| Dashboard | AFL++ StatsD + Prometheus + Grafana | Export long-run trends without parsing `fuzzer_stats` manually. |

Persistent mode and custom ICC mutators remain future work. They require either
tool changes or a dedicated AFL custom mutator shared object; do not emulate them
with shell wrappers around the existing CLI tools.

## FromXml Include Lane

`fromxml-includes` complements the standalone `fromxml` and `fromxml-noid`
lanes. It stages the external TXT/XML dependencies from the checked
`afl/fromxml-includes.manifest`, keeps those support files read-only, and fuzzes
the 10 standalone primary XML profiles below AFL++'s 1 MiB testcase ceiling
from the staged working directory. The validator also directly replays the five
oversized standalone profiles without truncation. The manifest records
`Calc/calcImport.xml` as a transitive support fragment. XML comments are removed
before dependency attributes are collected, so commented examples are not
staged as live includes.

Validate and stage the lane before a campaign:

```bash
.github/scripts/validate-afl-fromxml-includes.sh
./afl/start.sh fromxml-includes --seed-only --fresh
./afl/start.sh fromxml-includes --fresh
```

Replay include-lane queues and findings through `afl/triage.sh`, `afl/map.sh`,
or `afl/minimize.sh`. These helpers restore the staged working directory.
Running `iccFromXml` directly from the repository root is not equivalent:
relative `Filename` dependencies will be missing. AFL state belongs under
`afl/afl-<target>/output/<instance>/`; a single campaign uses `default`, while
parallel campaigns use `main` and `secondary_N`.

The JSON `-cfg` lanes use isolated work trees under `afl/work/<target>/root`.
Config-controlled relative output filenames must never be created in the
repository root. The work trees are disposable runtime state; AFL queues and
findings remain under the normal target output directory.

## Dashboard and Coverage

AFL++, `cov-analysis`, and `fuzz-reachability` can be installed outside the repo
under `~/work/copilot/tools/`. Source `~/work/copilot/tools/env.sh` to prefer
that local toolchain over system packages.

AFL++ can emit StatsD metrics for Grafana dashboards. Start the local
Prometheus/StatsD/Grafana stack from `afl/dashboard/`, then export StatsD knobs
when launching fuzzers:

```bash
cd afl/dashboard && docker compose up -d
AFL_STATSD=1 AFL_STATSD_TAGS_FLAVOR=dogstatsd ./afl/start.sh dump --parallel 4
```

The dashboard stack exposes Prometheus on port 9090, Grafana on port 3000, and
the StatsD exporter on UDP 8125 / TCP 9102. Keep remote terminal/control off;
this dashboard is local infrastructure for fuzzer telemetry only.

For source coverage, use the script-managed static coverage workflow. It builds
a separate static LLVM coverage binary, optionally generates `fuzz-reachability`
output with a static gllvm build, and annotates the AFL queue report with
`cov-analysis --reachability`:

```bash
source ~/work/copilot/tools/env.sh
./afl/coverage.sh dump --jobs 2
```

`coverage.sh` auto-selects the newest installed Clang coverage compiler,
preferring Clang 22. Override with `AFL_COVERAGE_CC=/path/to/clang-N` and
`AFL_COVERAGE_CXX=/path/to/clang++-N` when reproducing older reports. Keep the
static reachability analyzer on the same LLVM major as source coverage; rebuild
the local tool with:

```bash
LLVM_MAJOR=21 bash "$HOME/work/copilot/tools/fuzz-reachability/scripts/setup.sh"
reachability check-toolchain
```

`coverage.sh` writes HTML, text, JSON, profdata, reachability JSON, static
reachability lists, and target-sensitive runtime function lists under a
timestamped `afl/reports/generated/afl-coverage-*` directory by default. Use
`--no-reachability` when only raw LLVM source coverage is needed.

Static reachability files are named for what they contain:

- `statically_reachable-<tool>.txt`
- `statically_unreachable-<tool>.txt`

Runtime coverage-derived lists are target-specific:

- `covered-<target>.txt`
- `not_covered_but_statically_reachable-<target>.txt`
- `covered_but_statically_unreachable-<target>.txt`

The static lists are whole-tool graph outputs and can be identical across
argument variants that share the same binary. The runtime lists come from each
target's `coverage.json` and reflect the actual AFL queue replay for that
variant.

## JPEG Seed Policy

The `jpegdump` and `jpegdump-inject` compatibility lanes fuzz JPEG media only.
They seed up to 200 files from `fuzz/graphics/jpg`, and `afl/start.sh` rejects
raw `.icc` files and JPEGs without an embedded ICC profile by checking
`exiftool -b -ICC_Profile`. Use ICC-profile corpora only for ICC-profile targets
such as `dump`, `toxml`, `pawgreport`, or `applyprofiles`.

Validate the contract after seed changes:

```bash
.github/scripts/validate-afl-jpeg-seeds.sh
```

Durable run summaries live in `afl/reports/`. Generated coverage HTML, JSON,
profdata, AFL queues, and minimized corpora live under
`afl/reports/generated/` by default and are ignored by git. There is no
`afl/report/` directory; `afl/report.sh` is the generator script.

After fresh campaigns have run, generate all-target stats, maps, triage,
coverage, reachability, and profiling references with:

```bash
source ~/work/copilot/tools/env.sh
./afl/report.sh all --jobs 2 --target-timeout 3600
```

`report.sh` writes `status.json`, `targets.tsv`, `index.md`, per-target
`afl-showmap` files, triage logs, `cov-analysis` output, static reachability
lists, runtime function lists, reachability JSON, and `coverage.profdata`
paths. Targets without a fresh AFL queue are marked `not_started`. If one
coverage/reachability target exceeds `--target-timeout`, the report logs a
warning and continues with later targets instead of blocking the whole index.

Open the AFL-specific static report viewer from the `afl/` tree:

```bash
./afl/report-ui.sh
```

The viewer uses browser `fetch()`, so open it through the local HTTP URL printed
by `afl/report-ui.sh`; opening `afl/dashboard/report-viewer/index.html`
directly as a `file://` URL will not load report files. The scripts maintain
`afl/reports/generated/latest` as an ignored symlink to the most recent report.

Pass an explicit generated report directory when needed:

```bash
./afl/report-ui.sh afl/reports/generated/afl-report-YYYYMMDDTHHMMSSZ
```

Pass an external report root when reviewing session artifacts from
`~/work/copilot`; the launcher mounts it below
`afl/reports/generated/external-*` for local viewing:

```bash
./afl/report-ui.sh /home/h02332/work/copilot/afl-report-stats-validation-20260702T0940
```

The checked-in UI lives at `afl/dashboard/report-viewer/`. The launcher serves
only the local `afl/` directory, so generated Markdown, JSON, TSV, coverage
HTML, and external-report symlinks are browsed from the same AFL-specific root.

To run every AFL target from a fresh state and then generate that report:

```bash
source ~/work/copilot/tools/env.sh
./afl/run-all.sh all --seconds 300 --jobs 2 --report-target-timeout 3600
```

When `afl-health` reports dead or plateaued campaigns across many binaries, use
the coverage-boost preset to resume existing queues, reseed each target, enable
matching CmpLog binaries from `afl/bin-cmplog/` when present, and raise AFL's
testcase cache:

```bash
./afl/run-all.sh all --coverage-boost --seconds 3600 --parallel 1 --no-coverage
```

Use `--no-coverage` for a faster stats/maps/triage pass, or `--dry-run` to audit
the target list before launching campaigns.

## Campaign Recipes

Use isolated output directories for each instrumentation strategy:

```bash
./afl/start.sh dump --mode explore
./afl/start.sh dump --mode exploit
./afl/start.sh dump --mode rare
./afl/start.sh dump --mode fast
./afl/start.sh dump --mode mopt
```

The named modes set both AFL++ mutation strategy (`-P`) and power schedule
(`-p`) where appropriate. `mopt` emits the AFL++ 5.x bare `-L` flag. For a
comparison-guided parser campaign, build `afl/bin-cmplog/` first and run:

```bash
./afl/start.sh fromxml --mode cmplog
```

`cmplog` selects explore mutation, the rare-edge schedule, `-l 2AT`, splicing,
and the matching binary from `afl/bin-cmplog/`. For a synchronized eight-worker
campaign with varied explore/exploit strategies and explore, fast, exploit,
rare, coe, lin, quad, and seek power schedules, use:

```bash
./afl/start.sh dump --mode diverse
```

The default `applysearch` lane fuzzes the destination ICC profile in the normal
`iccApplySearch data enc interpolation src intent @@ intent -INIT init` shape.
It uses a small screened ICC sample capped at 256 KiB with fast calibration and
trim disabled; after seed-filter changes, restart it fresh to avoid resuming
stale queues:

```bash
./afl/start.sh applysearch --fresh --reseed
```

```bash
./afl/minimize.sh dump --queue
AFL_CMIN_BIN=afl-cmin.bash AFL_CMIN_EXTRA_ARGS="-T all" ./afl/minimize.sh dump --queue
./afl/minimize.sh dump --queue --tmin --tmin-limit 25
```

```bash
./afl/map.sh dump --queue --out "$HOME/work/copilot/afl-dump-showmap.txt"
```

For slow or nearly converged targets, prefer a fresh lane over repeatedly
resuming a stale queue:

```bash
./afl/start.sh applysearch-cfg --fresh --reseed --mode rare --mopt
./afl/start.sh pawgreport-fast --fresh --map-size 131072
./afl/start.sh applysearch-fast --fresh --reseed
./afl/start.sh applysearch-hybrid-pcc --fresh --reseed
```

For `iccProfilePlot`, keep the CLI surfaces separate and validate the shared
fixture before starting:

```bash
.github/scripts/validate-afl-profileplot-targets.sh --replay
./afl/start.sh profileplot --fresh
./afl/start.sh profileplot-graph --fresh
./afl/start.sh profileplot-raster --fresh
```

The list lane emits descriptor JSON, the graph lane fixes `chroma:xy`, and the
raster lane fixes `clut:A2B0` while writing samples beneath the process scratch
prefix.

## Artifact Policy

Track reusable orchestration assets such as `afl/*.sh`, `afl/targets.sh`, and
curated dictionaries. Keep runtime output local:

- `afl/bin/`
- `afl/iccDEV/`
- `afl/afl-*/input/`
- `afl/afl-*/output*/`
- `afl/afl-*/cmin*/`

Promote only durable crash, hang, timeout, or minimized queue evidence to
`test-profiles/`, `fuzz/`, or `docs/pocs/` with an exact one-line replay command.

## References

- User workflow: `docs/afl/index.md`
- Target definitions: `afl/targets.sh`
- Build variants: `afl/build.sh`
- Queue runner: `afl/start.sh`
- Status and triage: `afl/status.sh`, `afl/triage.sh`
- Coverage and minimization: `afl/map.sh`, `afl/minimize.sh`
- Source coverage/reachability: `afl/coverage.sh`
- Startup-root reachability audits: `afl/startup-roots.sh`
- Runtime staging and replay review: `docs/afl/runtime-staging-and-replay.md`
- Dashboard: `afl/dashboard/`
- Upstream tools: AFLplusplus AFL++, `cov-analysis`, and `fuzz-reachability`
