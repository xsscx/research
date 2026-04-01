# Fuzz and CFL Inventory

This file is a lightweight map of the fuzzing-related material that appears in
this repository. It is intentionally descriptive rather than count-driven.

## Directory Roles

| Path | Role |
|------|------|
| `fuzz/` | Shared malicious inputs, signatures, PoCs, and corpus material |
| `cfl/` | ClusterFuzzLite harnesses, dictionaries, corpora, and build scripts |
| `.github/instructions/cfl.instructions.md` | Detailed workflow and maintenance guidance |

## How To Use This Material

1. Start with `cfl/README.md` for the current harness and build workflow.
2. Use `docs/Testing/README.md` for test fixtures and saved reports.
3. Use
   `docs/analysis/ICCANALYZER_CFL_PATCH_COVERAGE_MATRIX.md`
   for analyzer-to-patch coverage status.

## Notes

- Treat repository sizes, binary totals, dictionary totals, and corpus counts as
  volatile.
- When exact current inventory matters, inspect the filesystem directly instead
  of relying on historical summaries.
- Keep long-form one-off inventories out of hub docs unless they are dated
  reports with a clear snapshot scope.
