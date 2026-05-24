# AFL++ Instructions - Tool-Level Fuzzing

Use these instructions for files under `afl/` and AFL++ work that drives real
iccDEV tool binaries.

## Source Of Truth

- Target list and argument scaffolds: `afl/targets.sh`
- User-facing workflow: `docs/afl/index.md`
- Shared dictionaries: `cfl/*.dict`
- Runtime outputs: ignored under `afl/afl-*/output*/`

Do not duplicate exact target counts in docs. Run `./afl/start.sh --list` or
read `afl/targets.sh` in the current checkout.

## Standard Commands

```bash
./afl/build.sh          # default: unpatched upstream iccDEV
./afl/build.sh --patches # optional CFL patch A/B comparison
./afl/start.sh --list
./afl/start.sh dump
./afl/start.sh toxml --parallel 4
./afl/status.sh --detail
./afl/status.sh --json | jq .
./afl/stop.sh dump
./afl/triage.sh dump
```

## Tracking Policy

Track reusable AFL assets:

- orchestration scripts
- `afl/targets.sh`
- curated dictionaries
- promoted seed or repro fixtures

Do not commit raw run output:

- `afl/bin/`
- `afl/iccDEV/`
- `afl/afl-*/output*/`
- logs, queues, crash/hang directories, and stats files

Promote an artifact only after it has a stable name, a reproducible command,
and a clear purpose. Prefer `test-profiles/`, `fuzz/`, or `docs/pocs/` for
durable fixtures.

## Triage Rule

An AFL crash is actionable only after replay against the intended upstream
reference build under ASAN/UBSAN. Record the exact tool path, input path,
arguments, sanitizer options, exit code, and summary.

Use:

```bash
ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1,symbolize=1 \
UBSAN_OPTIONS=halt_on_error=1,print_stacktrace=1 \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile path/to/input.icc ALL
```

Adjust the tool and arguments to match the AFL target.

## Corpus Minimization

For ASAN-instrumented binaries, prefer `afl-cmin.bash` over Python `afl-cmin`
when memory pressure is high. Keep minimized results local unless they are
promoted as curated fixtures.
