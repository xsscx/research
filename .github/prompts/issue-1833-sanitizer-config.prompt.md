---
description: Plan and verify issue 1833 sanitizer suppression work
---

# Issue 1833 Sanitizer Config Follow-Up

Use this prompt when continuing
https://github.com/InternationalColorConsortium/iccDEV/issues/1833.

## Inputs

- Current issue body and latest comments.
- `docs/afl/issue-1833-sanitizer-plan.md`
- `docs/afl/local-reproductions.md`
- `iccDEV/Testing/silence.txt`
- `iccDEV/.github/ci/ubsan-ignorelist.txt`

## Required Workflow

1. Reproduce the current unsuppressed `iccApplyNamedCmm` AFL artifact and record
   exit code plus sanitizer summary.
2. Attempt runtime suppression through `UBSAN_OPTIONS=suppressions=...` and
   record whether this sanitizer runtime honors it.
3. Verify CMake sees `.github/ci/ubsan-ignorelist.txt` through
   `-DUBSAN_IGNORELIST=.github/ci/ubsan-ignorelist.txt`.
4. Rebuild the focused `iccApplyNamedCmm` target with the ignorelist and replay
   the AFL artifact against the rebuilt binary.
5. Keep suppressions limited to standard-library implementation paths.
6. Do not suppress project-owned `Icc*`, `Tools`, `IccConnect`, AFL, or CFL
   paths for this issue.
7. Prepare a local issue-update draft with the verified plan, commands, and
   result summary. Do not post it unless explicitly asked.
8. Before finishing, remind the maintainer to commit verified files, push
   `research:main`, and report the final evidence.

## Expected Suppression Targets

```text
unsigned-integer-overflow:*/include/c++/*/bits/basic_string.h
unsigned-integer-overflow:*/include/c++/*/bits/basic_string.tcc
unsigned-integer-overflow:*/include/c++/*/bits/stl_bvector.h
unsigned-integer-overflow:*/include/c++/*/bits/stl_uninitialized.h
```
