# AFL++ Tool Fuzzing

`afl/` fuzzes real iccDEV command-line tools with AFL++ instrumentation. This
complements `cfl/`, which uses LibFuzzer harnesses and optional patch stacks.

Use `afl/targets.sh` as the source of truth for available targets.

## Fast Path

```bash
# Build AFL-instrumented upstream iccDEV tools without CFL patches.
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

## Target Model

`afl/targets.sh` maps short target names to:

- the instrumented binary in `afl/bin/`
- seed directories
- the dictionary copied into the per-target directory
- any fixed arguments needed to drive multi-argument tools

`./afl/build.sh` defaults to an unpatched upstream iccDEV checkout. Use
`./afl/build.sh --patches` only for deliberate CFL patch A/B comparisons.

The current target list includes tool-level coverage for profile dumping,
XML/JSON conversion, image extraction, CUBE import, PAWG reporting, profile
visualization, profile linking, and CMM apply flows. Run `./afl/start.sh --list`
for the exact list in the active checkout.

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
