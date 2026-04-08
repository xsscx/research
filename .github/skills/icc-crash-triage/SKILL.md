---
name: icc-crash-triage
description: >
  Triage ASAN/UBSAN fuzzer crash findings against ICC profile tools.
  Classifies by exit code, attributes by stack trace file path, maps CWE,
  and determines upstream vs analyzer ownership.
---

# ICC Fuzzer Crash Triage

## Overview

Systematic workflow for analyzing ASAN (heap-buffer-overflow, heap-use-after-free,
stack-buffer-overflow, SEGV) and UBSAN (runtime error) findings from CFL LibFuzzer
or AFL++ campaigns against iccDEV ICC profile tools.

## Workflow

### 1. Exit Code Gate

Before classifying ANY finding, determine the exit code:

- Exit 1-127: Tool rejected input gracefully. NOT a crash. STOP.
- Exit 128+: Signal termination. Proceed to step 2.
- Exit 0 with ASAN/UBSAN stderr: Memory safety bug. Proceed to step 2.

The tool exit code is authoritative. The fuzzer DEADLYSIGNAL is a test artifact.

```bash
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  timeout 30 iccDEV/Build/Tools/<ToolDir>/<tool> <crash-file>; echo "EXIT: $?"
```

### 2. Attribute by Stack Trace File Path

Read ASAN/UBSAN stack frame #2-#3 and classify by source file path:

| Path contains | Owner | Action |
|---------------|-------|--------|
| `iccanalyzer-lite/` | OUR CODE | Fix immediately |
| `colorbleed_tools/` | OUR CODE | Fix immediately |
| `cfl/icc_*_fuzzer.cpp` | OUR CODE | Fix harness |
| `iccDEV/IccProfLib/` | UPSTREAM | CFL patch + report upstream |
| `iccDEV/Tools/` | UPSTREAM | CFL patch + report upstream |
| `libtiff` / `libpng` | SYSTEM LIB | Fix our call site |

NEVER classify by profile filename. A profile named `ub-runtime-error-*` does
NOT mean the bug is upstream.

### 3. Verify Commit Alignment

```bash
echo "CFL: $(cd cfl/iccDEV && git rev-parse --short HEAD)"
echo "Upstream: $(cd iccDEV && git rev-parse --short HEAD)"
```

### 4. Pattern Recognition

| Pattern | CWE | Fix Reference |
|---------|-----|---------------|
| AddXform ownership UAF | CWE-416 | Check icCmmStatBadXform before delete |
| NaN bypass in clamp | CWE-681 | `if (v != v) return 0.0;` FIRST |
| Float-to-int overflow | CWE-681 | Range-check before `(int)` cast |
| Unchecked Begin() null | CWE-476 | Check return before Apply() |
| Strip geometry overflow | CWE-122 | Bounds check in TIFF Open() |

### 5. Severity Assessment

```bash
ASAN_OPTIONS=print_scariness=1:halt_on_error=0:detect_leaks=0 \
  cfl/bin/<fuzzer> <crash-file> 2>&1
```

Verify upstream impact with unpatched tools at `iccDEV/Build/Tools/`.
For multi-profile fuzzers, unbundle first:
```bash
.github/scripts/unbundle-fuzzer-input.sh <fuzzer_name> <crash-file>
```

### 6. Fix and Verify

1. Reproduce: `ASAN_OPTIONS=detect_leaks=0 timeout 10 cfl/bin/<fuzzer> <crash-file>`
2. Fix: Patch fuzzer or create `cfl/patches/NNN-*.patch`
3. Rebuild: `cd cfl && ./build.sh`
4. Verify: Re-run crash file -- must exit 0 with no ASAN/UBSAN
5. Document: Update patch table, commit reproducer

### 7. Reproduction Discipline

MANDATORY rules for all reproduction steps (derived from 9-turn session failure):

- VERIFY then CITE then CLAIM. Never write a reproduction doc before running it.
- Fresh clone for every reproduction. Never reuse existing checkouts.
- All commands must be 1-liner copy-paste ready. No backslash continuations.
- Delete CMakeCache.txt and CMakeFiles/ before every branch switch.
- Test profiles may be GENERATED (not in git). Check with git ls-files first.
- Run the EXACT command end-to-end before including it in any document.

See `.github/prompts/iccdev-bisect-reproduction.prompt.md` for full workflow.

## Naming Conventions

- `segv-<Function>-<File>-Line<N>.icc` -- SEGV crashes
- `hbo-<Function>-<File>-Line<N>.icc` -- Heap buffer overflow
- `ub-<description>-<File>-Line<N>.icc` -- UBSAN undefined behavior
- `crash-<sha256>` -- Raw LibFuzzer artifacts

## References

- `.github/prompts/triage-fuzzer-oom.prompt.yml` -- OOM-specific workflow
- `.github/prompts/triage-cve-poc.prompt.yml` -- CVE PoC analysis
- `.github/instructions/cfl.instructions.md` -- Patch system details
- `docs/pocs/iccdev-issue-reproductions.md` -- 63 PoC reproduction steps
