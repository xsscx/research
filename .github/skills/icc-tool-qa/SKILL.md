---
name: icc-tool-qa
description: Run bounded deterministic iccApplyProfiles sanitizer, Memcheck, or Helgrind validation after fuzzing or toolchain changes. Use for QA intervals and reproducible fault classification; use icc-crash-triage for an already identified crash artifact.
---

# ICC Tool QA

Use the checked-in runners under
`.github/ci/quality-assurance/scripts/` and record their evidence directory.

## Workflow

1. Work from a Linux-native checkout and evidence directory. Reject `/mnt/*`
   for measured WSL workloads.
2. Use `iccApplyProfiles_sanitizer_qa.sh` with the canonical ASAN/UBSAN build.
3. Build a separate non-sanitized Debug binary with `--parallel 32` before
   Memcheck or Helgrind. Never stack Valgrind on an ASAN/UBSAN binary.
4. Bound each interval with `--seconds`; retain per-case logs and `summary.tsv`.
5. Classify sanitizer/Valgrind diagnostics, timeouts, clean tool rejections,
   and invalid outputs separately. A nonzero tool exit is not itself a crash.
6. Reproduce any finding with the canonical iccDEV tool and exact target
   arguments before handing it to `icc-crash-triage`.

Read `docs/afl/iccapplyprofiles-qa.md` for commands, expected outputs, and the
2026-09-01 baseline.
