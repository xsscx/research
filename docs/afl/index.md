# AFL++ Tool Fuzzing

`afl/` fuzzes real iccDEV command-line tools with AFL++ instrumentation. This
complements `cfl/`, which uses LibFuzzer harnesses and optional patch stacks.

Use `afl/targets.sh` as the source of truth for available targets.

## Fast Path

```bash
# Build AFL-instrumented upstream iccDEV tools without local AFL patches.
./afl/build.sh

# List targets and start a run.
./afl/start.sh --list
./afl/start.sh dump
./afl/start.sh toxml --parallel 4

# Inspect, stop, and triage.
./afl/status.sh
./afl/status.sh --json | jq .
./afl/stop.sh dump
./afl/triage.sh dump
```

To preserve actionable replay artifacts for the checked-in iccDEV shell suites,
mark them during triage:

```bash
./afl/triage.sh applytolink --mark
./afl/triage.sh applytolink-cube --mark
bash .github/scripts/test-iccApplyToLink.sh --quick --asan
```

`--mark` copies sanitizer, signal, and timeout artifacts into
`afl/marked/<target>/` and writes a neighboring `.cmd` file with the exact
canonical iccDEV replay command. `test-iccApplyToLink.sh` automatically sweeps
`afl/marked/applytolink/` and `afl/marked/applytolink-cube/` when those
directories exist. Override the sweep inputs with colon-separated
`ICCDEV_APPLYTOLINK_AFL_DIRS` and `ICCDEV_APPLYTOLINK_CUBE_AFL_DIRS`.

## Target Model

`afl/targets.sh` maps short target names to:

- the instrumented binary in `afl/bin/`
- seed directories
- the dictionary copied into the per-target directory
- any fixed arguments needed to drive multi-argument tools

`./afl/build.sh` defaults to an unpatched upstream iccDEV checkout. Use
`./afl/build.sh --patches` to apply the local AFL patch stack from
`afl/patches/` before building instrumented tools.

The current target list includes tool-level coverage for profile dumping,
XML/JSON conversion, image extraction, CUBE import, PAWG reporting, profile
visualization, profile linking, and CMM apply flows. Run `./afl/start.sh --list`
for the exact list in the active checkout.

## Coverage and Reachability Toolchain

`afl/build.sh` requires `clang-22`/`clang++-22` and AFL++ wrappers rebuilt
against LLVM 22. On Ubuntu 26.04 this means installing `clang-22`,
`llvm-22-tools`, `llvm-22-dev`, and `libclang-rt-22-dev`, then rebuilding AFL++
with `llvm-config-22`.

For source coverage, `afl/coverage.sh` selects `clang-22`/`clang++-22` when
available and `cov-analysis` then uses the matching `llvm-profdata-22` and
`llvm-cov-22`. Override with `AFL_COVERAGE_CC` and `AFL_COVERAGE_CXX` only when
reproducing older LLVM reports.

For static reachability, rebuild the local analyzer after changing LLVM major:

```bash
LLVM_MAJOR=22 bash "$HOME/work/copilot/tools/fuzz-reachability/scripts/setup.sh"
reachability check-toolchain
```

## Reports

`./afl/report.sh all` emits the final `targets.tsv` in the order reported by
`./afl/start.sh --list`. Targets without AFL output are recorded as
`not_started` and skipped quickly; targets with output run map, triage, source
coverage, and reachability steps unless disabled. Use `--target-jobs N` to run
independent targets concurrently; choose `--jobs * --target-jobs` near the
available CPU count. The default whole-target coverage timeout is 3600 seconds,
so a full all-target report can still run for hours when several active targets
need coverage replay.

For quick status, use `./afl/report.sh all --stats-only --target-jobs 8` or
`./afl/report.sh all --no-coverage --target-jobs 8`. For focused reachability,
prefer a single target command such as
`./afl/report.sh fromcube --jobs 2 --target-timeout 3600`.
Use `./afl/report.sh TARGET --marked-only` when reviewing already marked
reproduction artifacts; it skips maps and coverage and triages only
`afl/marked/TARGET`.
During long runs, monitor `afl/reports/generated/latest/targets.tsv`, the
per-target logs under `afl/reports/generated/latest/logs/`, and
`./afl/status.sh --json`.

## A/B Role

| AFL++ | CFL |
|-------|-----|
| Runs real tool binaries | Runs LibFuzzer harnesses |
| Best for CLI parsing, file handling, and user-facing repros | Best for deep library coverage |
| Triage against upstream reference tools | Compare patched vs unpatched builds |

Use AFL++ findings to produce concrete tool repros, then validate the same
root cause through upstream ASAN/UBSAN builds before filing or patching.

## What Belongs In Git

Track reusable AFL assets:

- `afl/*.sh` orchestration scripts
- `afl/targets.sh`
- curated per-target dictionaries such as `afl/afl-dump/dump.dict`
- curated seed inputs only when they are intentionally promoted fixtures

Keep runtime output local unless promoted:

- `afl/bin/`
- `afl/iccDEV/`
- `afl/afl-*/output*/`
- AFL queue, crash, hang, stats, and log output

If a crash, hang, timeout, or minimized queue entry becomes durable evidence,
move it to `test-profiles/`, `fuzz/`, or `docs/pocs/` with a short repro note
instead of committing a raw runtime directory.

## Triage Rule

AFL-instrumented crashes are not automatically upstream bugs. Re-run the input
against the intended upstream reference build under ASAN/UBSAN and record the
exact command, input path, exit mode, and sanitizer summary.

Locally retained findings with exact replay commands are recorded in
`docs/afl/local-reproductions.md`.

Timeout-only artifacts are not automatically actionable. `afl/triage.sh`
separates `TIMEOUT`, `TIMEOUT_WITH_SANITIZER`, `SANITIZER`, `SIGNAL`,
`SOFT_FAIL`, and `CLEAN`. For stricter hang replay, set
`AFL_TRIAGE_HANG_REPEATS=N`. Set `AFL_TRIAGE_MARK_TIMEOUTS=0` to avoid marking
plain timeout-only inputs while still preserving sanitizer and signal findings.
Tool scratch paths default under `afl/tmp`; override with `AFL_TMP_ROOT` only
when a run needs a different local scratch directory.

```bash
ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1,print_stacktrace=1 \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile path/to/input.icc ALL
```

## Notes

- Keep exact target counts, corpus sizes, and dated coverage figures in reports
  or command output.
- Use `./afl/status.sh --detail` when deciding what to stop, reap, or triage.
- Use `./afl/stop.sh --reap` only for stale empty output state.
