# AFL++ Fuzzing Reference

This directory documents the AFL++ workflow used to fuzz upstream `iccDEV`
tools directly, without a custom wrapper harness.

## Why AFL++

- Targets the real tool binaries rather than a library-only harness.
- Exercises argument parsing, file handling, and end-to-end tool behavior.
- Complements the `cfl/` LibFuzzer setup rather than replacing it.

## Quick Start

```bash
# Build the AFL-instrumented tool set
./afl/build.sh

# Start fuzzing a target
./afl/start.sh dump
./afl/start.sh toxml --parallel 4
./afl/start.sh --list

# Monitor and stop
./afl/status.sh
./afl/stop.sh dump

# Triage crashes against the upstream reference build
./afl/triage.sh dump
```

## Directory Layout

| Path | Purpose |
|------|---------|
| `afl/build.sh` | Build `iccDEV` with AFL instrumentation |
| `afl/start.sh` | Start one target, optionally in parallel |
| `afl/status.sh` | Show AFL runtime status |
| `afl/stop.sh` | Stop running jobs |
| `afl/triage.sh` | Re-run crashes against the unpatched upstream build |
| `afl/harvest.sh` | Pull artifacts and seed local corpora |
| `afl/bin/` | AFL-instrumented binaries and shared libraries |
| `afl/afl-*/` | Per-target input and output directories |

## Target Model

`afl/start.sh --list` prints the current target map. The launcher wires each
deployed iccDEV tool binary to either a direct `@@` input or a documented fixed
argument scaffold from `docs/iccDEV/Tools/`, so multi-argument tools can be
fuzzed without a custom wrapper.

## Relationship to CFL

| AFL++ | CFL |
|-------|-----|
| Fuzzes the real tool binaries | Fuzzes custom LibFuzzer harnesses |
| Good for end-to-end tool behavior | Good for deep library coverage |
| Crash repro is close to user-facing execution | Coverage is usually deeper and faster |

Use both when possible.

## Triage Rule

Treat AFL crashes as findings only after reproducing them against the upstream
reference build under ASAN/UBSAN. The patched or instrumented fuzz build is not
the source of truth for upstream crash validity.

## Notes

- Keep exact target lists, corpus sizes, and coverage figures in dated reports
  or command output, not in this overview.
- For the current LibFuzzer side of the workflow, use `cfl/README.md`.
