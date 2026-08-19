---
applyTo: "afl/**,docs/afl/**"
---

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

## JPEG AFL Seed Contract

The `jpegdump` and `jpegdump-inject` lanes fuzz JPEG media only. They must seed
only `.jpg`/`.jpeg` files from `fuzz/graphics/jpg` that contain an embedded ICC
profile. Do not seed either lane from `test-profiles/`, `extended-test-profiles/`,
`fuzz/graphics/icc/`, or any raw `.icc` corpus. Keep `SEED_LIMIT=200` and run
`.github/scripts/validate-afl-jpeg-seeds.sh` after changing JPEG AFL seeding.

## Standard Commands

```bash
./afl/build-afl-runtime.sh
./afl/build.sh          # default: unpatched upstream iccDEV
./afl/start.sh --list
./afl/start.sh dump
./afl/start.sh toxml --parallel 4
./afl/status.sh --detail
./afl/status.sh --json | jq .
./afl/stop.sh dump
./afl/triage.sh dump
.github/scripts/check-afl-cfl-patches.sh
.github/scripts/validate-afl-applynamedcmm-targets.sh
.github/scripts/validate-afl-jpeg-seeds.sh
.github/scripts/validate-afl-profileplot-targets.sh
.github/scripts/validate-afl-target-configs.sh --local
```

The runtime builder pins AFL++ stable commit
`05507e1880dc6df997c19e01423444ef37c36846`, LLVM 21, and a 4 MiB compiled
testcase ceiling. The `applyprofiles-hybrid-embedded` lane requires that
runtime, uses the complete generated multispectral TIFF, and sets `-G` to
3 MiB. Do not restore the historical 64x64 crop. `start.sh` must reject a
runtime whose compiled ceiling is lower than a target's requested `-G` value.

## iccApplyNamedCmm CLI Shapes

Keep distinct AFL targets for the one-profile legacy-data lane, `-cfg` JSON,
the fixed-v5-then-fuzzed-profile hybrid chain, and the fixed-v5/fuzzed-PCC
hybrid chain. Use `applynamedcmm-hybrid-chain` for this argv shape:

```text
-exportcfganddata OUT DATA 3 1 FIXED_CMYK_V5 10003 @@ 10
```

NamedCMM hybrid seeds must be complete ICC files smaller than the lane's 1 MiB
policy and must pass the target dry run with exit 0. Use a per-process scratch
path for exported JSON; never make parallel workers overwrite one fixed config
path.

Do not copy CFL's corpus-derived large-input policy into AFL++. CFL NamedCmm
seeds are pure ICC files, but only complete files below 1 MiB may be promoted
to an AFL `@@` corpus with this build. Keep larger profiles in CFL, or add an
explicit AFL lane that holds the large profile fixed and fuzzes a bounded
companion input; never truncate a CFL profile for promotion.

Do not hardcode `AFL_MAP_SIZE=131072` for NamedCMM lanes. Use `afl/start.sh`'s
default unless the current instrumented binary has been measured explicitly;
the target map can exceed 131072 bytes.

Run `.github/scripts/validate-afl-applynamedcmm-targets.sh` after changing any
NamedCMM target arguments, seed limits, dry-run policy, or export path handling.

## iccProfilePlot CLI Shapes

Keep separate `profileplot`, `profileplot-graph`, and `profileplot-raster`
targets for descriptor enumeration, graph JSON, and CLUT raw-output coverage.
Use `test-profiles/sRGB_v4_ICC_preference.icc` as the durable fixture contract:
it must enumerate `chroma:xy` and `clut:A2B0`. Raster output must use the
per-process scratch prefix. Run
`.github/scripts/validate-afl-profileplot-targets.sh --replay` after changing
the arguments, fixture, identifiers, or output-path handling.

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
ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1,print_stacktrace=1 \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile path/to/input.icc ALL
```

Adjust the tool and arguments to match the AFL target.

## Corpus Minimization

For ASAN-instrumented binaries, prefer `afl-cmin.bash` over Python `afl-cmin`
when memory pressure is high. Keep minimized results local unless they are
promoted as curated fixtures.
