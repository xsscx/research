# Fuzzing Asset Map And Tracking Policy

This file is the compact map for fuzzing-related material in this repository.
It is intentionally policy-driven rather than count-driven, so it stays useful
as corpora grow.

## Directory Roles

| Path | Role |
|------|------|
| `afl/` | AFL++ tooling for real iccDEV CLI binaries |
| `cfl/` | LibFuzzer harnesses, dictionaries, and curated seeds |
| `fuzz/` | Shared malicious inputs, signatures, PoCs, and reusable corpus material |
| `test-profiles/` | Stable ICC and image fixtures used by tools and tests |
| `extended-test-profiles/` | Larger reusable profile corpus |
| `docs/pocs/` | Reproduction notes and command evidence |

## What To Track

Track files that make another VM reproducible:

| Track | Examples |
|-------|----------|
| Source and orchestration | `afl/*.sh`, `afl/targets.sh`, `cfl/*.sh`, `cfl/*.cpp`, `cfl/*.h` |
| Retired patch history | `cfl/retired-patches/*.patch` |
| Dictionaries | `cfl/*.dict`, curated per-target AFL dictionaries |
| Curated seeds | `cfl/corpus/`, small `cfl/seeds-*` fixtures, `test-profiles/` |
| Promoted findings | Named repro files in `fuzz/`, `test-profiles/`, or `docs/pocs/` |

## What To Keep Local

Keep bulk runtime state out of normal commits:

| Keep Local | Reason |
|------------|--------|
| `afl/bin/`, `cfl/bin/` | Rebuilt from source |
| `afl/iccDEV/`, `cfl/iccDEV/` | Nested upstream checkout |
| `afl/afl-*/output*/` | AFL queue/crash/hang runtime state |
| `cfl/runs/`, `cfl/findings/` | Local run state and transient triage output |
| Large `cfl/corpus-*` run output | Can be hundreds of thousands of files |
| `*.log`, `*.profraw`, `*.profdata` | Machine-specific noise |

Existing ignored runtime trees in this checkout are large enough that blanket
tracking would add noise. Promote selected artifacts instead of committing raw
run directories.

## Promotion Checklist

Before adding a generated seed or artifact:

1. Give it a stable, descriptive filename.
2. Put it in the narrowest reusable path: `test-profiles/`, `fuzz/`, or
   `docs/pocs/`.
3. Record the exact replay command and sanitizer options.
4. State the upstream commit and tool configuration used to validate it.
5. Keep logs and profiler output out of the commit unless the artifact itself
   is the subject of the change.

## Run Notes

Build and run against upstream `master`. Use status JSON for comparison inputs:

```bash
cd cfl && ./status.sh --json | jq .
./afl/status.sh --json | jq .
```

## Related Docs

| Doc | Use |
|-----|-----|
| `../afl/index.md` | AFL++ workflow |
| `../../cfl/README.md` | CFL workflow |
| `../../cfl/patches/README.md` | Zero-patch inventory |
| `README.md` | Testing docs index |
