# AFL Reachability List Semantics

- Date: 2026-07-01
- Scope: AFL coverage and reachability reports under `afl/`.
- Source report reviewed: `/home/h02332/work/codex/afl-report-20260701T003248Z`

## Issue

The previous `reached-*.txt` and `not_reached-*.txt` names implied runtime
coverage. Their file headers showed different semantics:

- `reached-*`: statically-reachable functions
- `not_reached-*`: statically-unreachable functions

Those files are SanitizerCoverage allowlist/ignorelist artifacts emitted by
`fuzz-reachability`, not true covered/not-covered reports.

## Fix

New report names separate static graph data from runtime coverage data:

- `statically_reachable-<tool>.txt`
- `statically_unreachable-<tool>.txt`
- `covered-<target>.txt`
- `not_covered_but_statically_reachable-<target>.txt`
- `covered_but_statically_unreachable-<target>.txt`

Static reachability remains keyed by tool binary, so variants that share a
binary can share identical static files. Runtime coverage lists are keyed by
target variant and are generated from each variant's `coverage.json`.

## Reviewed Patterns

Static reachability files were identical within these target families:

- `applyprofiles`, `applyprofiles-fast`, `applyprofiles-deep`,
  `applyprofiles-hybrid-embedded`, `applyprofiles-hybrid-pcc`
- `applysearch`, `applysearch-weight-positive`,
  `applysearch-weight-positive-fast`, `applysearch-weight-zero`,
  `applysearch-weight-nan`
- `applytolink`, `applytolink-cube`
- `specseptotiff`, `specseptotiff-compress`, `specseptotiff-sep`
- `tiffdump`, `tiffdump-extract`

The matching `coverage.json`, `coverage.profdata`, and `summary.txt` files
differed across those variants, confirming that executions were variant-specific
even when the static reachability graph was not.

The static unreachable allowlist can overstate what the per-target summary
reports because it contains whole static graph output. For example,
`not_reached-specseptotiff-sep.txt` had 730 `fun:` entries, while
`cov-specseptotiff-sep-static/summary.txt` reported 345 target-present
unreachable functions.

## Covered-Unreachable Anomalies

Every reviewed report had covered functions that static reachability classified
as unreachable. Across 19 of 20 variants the same two constructors appeared:

- `_ZN22CIccSimpleMatrixSolverC2Ev`
- `_ZN24CIccSimpleMatrixInverterC2Ev`

`toxml` had a third anomaly:

- `_ZN18CIccStandardFileIOC2Ev`

These are now emitted into
`covered_but_statically_unreachable-<target>.txt` so they can be audited
directly.

## Displayed Summary Counts

| Target | Reachable | Not Yet Reached | Unreachable | Covered-Unreachable |
|---|---:|---:|---:|---:|
| applyprofiles family | 2585 | 2238-2449 | 457 | 2 |
| applysearch family | 2614 | 2194-2492 | 399 | 2 |
| applytolink family | 2469 | 2041-2296 | 329 | 2 |
| pawgreport | 2534 | 1270 | 335 | 2 |
| specseptotiff family | 2406 | 2368 | 345 | 2 |
| tiffdump family | 2427 | 2129-2263 | 346 | 2 |
| toxml | 3072 | 2890 | 310 | 3 |
| v5dspobs | 2388 | 1855 | 339 | 2 |

## Next Investigation

Review the covered-unreachable constructors before treating static unreachable
lists as hard exclusions. The repeated `IccSolve.cpp` constructors are the
highest-priority static reachability classification issue because they fire in
nearly every run.

Follow-up root cause: `afl/reports/2026-07-01-startup-root-reachability-gap.md`
models the missing `.init_array` startup root path that makes these constructors
statically reachable via C++ static initialization.
