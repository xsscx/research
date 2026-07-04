# PAWG Report AFL Reachability - cmin Replay

Generated: 2026-07-04T17:01:04Z

## Scope

- Target: `pawgreport`
- Tool: `afl/bin/iccPawgReport`
- AFL queue source: `afl/afl-pawgreport/output/main/queue`
- Optimized replay corpus: `/home/xss/work/copilot/afl-pawgreport-cmin-output-20260704/main/queue`
- Generated report root: `afl/reports/generated/afl-report-pawgreport-reachability-20260704T163738Z`

The full PAWG queue replay stalled in `cov-analysis` on long-running PAWG inputs
despite `-T 5`. The completed report therefore uses the existing minimized
PAWG queue (`254` files) in an AFL-compatible output layout while reusing the
same static coverage binary and reachability graph.

## Commands

```bash
source "$HOME/work/copilot/tools/env.sh"

./afl/report.sh pawgreport \
  --report-root afl/reports/generated/afl-report-pawgreport-reachability-20260704T163738Z \
  --jobs 2 \
  --target-timeout 0

AFL_COVERAGE_OUTPUT_DIR="$HOME/work/copilot/afl-pawgreport-cmin-output-20260704" \
  ./afl/coverage.sh pawgreport \
  --report-root afl/reports/generated/afl-report-pawgreport-reachability-20260704T163738Z/coverage \
  --report-name pawgreport \
  --instance main \
  --jobs 2 \
  --reuse-build
```

## Results

| Metric | Result |
|---|---:|
| Static defined functions | 7853 |
| Static reachable functions | 7073 |
| Static unreachable functions | 780 |
| Runtime-present functions in coverage JSON | 3032 |
| Runtime-covered functions | 1205 |
| Target-present covered functions list | 1204 |
| Reachable but not reached | 1339 |
| Covered but statically unreachable | 2 |
| Reachable-only function coverage | 44.57% |
| Reachable-only line coverage | 40.05% |
| Reachable-only region coverage | 40.20% |
| Reachable-only branch coverage | 35.70% |

`cov-analysis` completed with reachability annotation:

```text
[+] Reachability: reachable=2544 not-reached=1341 unreachable=333 anomaly=2
[OK] Coverage workflow complete
```

## Artifacts

- HTML coverage: `afl/reports/generated/afl-report-pawgreport-reachability-20260704T163738Z/coverage/cov-pawgreport-static/html/index.html`
- Text summary: `afl/reports/generated/afl-report-pawgreport-reachability-20260704T163738Z/coverage/cov-pawgreport-static/summary.txt`
- JSON coverage: `afl/reports/generated/afl-report-pawgreport-reachability-20260704T163738Z/coverage/cov-pawgreport-static/coverage.json`
- Profdata: `afl/reports/generated/afl-report-pawgreport-reachability-20260704T163738Z/coverage/cov-pawgreport-static/coverage.profdata`
- Reachability JSON: `afl/reports/generated/afl-report-pawgreport-reachability-20260704T163738Z/coverage/reachability-iccPawgReport-static.json`
- Static reachable list: `afl/reports/generated/afl-report-pawgreport-reachability-20260704T163738Z/coverage/statically_reachable-iccPawgReport.txt`
- Static unreachable list: `afl/reports/generated/afl-report-pawgreport-reachability-20260704T163738Z/coverage/statically_unreachable-iccPawgReport.txt`
- Not-covered reachable list: `afl/reports/generated/afl-report-pawgreport-reachability-20260704T163738Z/coverage/not_covered_but_statically_reachable-pawgreport.txt`
- Covered-unreachable anomaly list: `afl/reports/generated/afl-report-pawgreport-reachability-20260704T163738Z/coverage/covered_but_statically_unreachable-pawgreport.txt`

## Review Notes

High-value reachable but unreached areas include byte-swap helpers, UTF
conversion, color signature/name formatting, `OpenIccProfile`/`ReadIccProfile`,
MPE ACS/CAM write/describe methods, and PAWG executable-header validators
(`ValidateElf`, `ValidateShebang`, `ValidateGzipHeader`). These are good
targets for future PAWG seed promotion or dedicated fast lanes.

The two covered-but-statically-unreachable anomalies are:

```text
fun:CIccSimpleMatrixSolver::CIccSimpleMatrixSolver()
fun:CIccSimpleMatrixInverter::CIccSimpleMatrixInverter()
```

They should be treated as reachability-classifier anomalies, not PAWG crashes.
The PAWG AFL status report had no saved crashes or hangs for the reviewed
instances.

## LLVM 22 Follow-up Validation

After installing Clang/LLVM 22 and rebuilding `fuzz-reachability` with
`LLVM_MAJOR=22`, the same optimized PAWG cmin corpus completed with a fully
LLVM 22-aligned coverage and reachability toolchain:

```text
OK: analyzer toolchain on LLVM 22 (min 21); rustc LLVM 21
  clang     /usr/bin/clang-22
  clang++   /usr/bin/clang++-22
  llvm-link /usr/bin/llvm-link-22

[+] LLVM tools: llvm-profdata-22, llvm-cov-22
[+] Reachability: reachable=2533 not-reached=1330 unreachable=334 anomaly=2
[OK] Coverage workflow complete
```

The validation report was written outside the repository at
`/home/xss/work/copilot/afl-coverage-reachability-clang22-20260704` so generated
coverage HTML, JSON, profdata, and temporary build trees remain untracked.

| LLVM 22 metric | Result |
|---|---:|
| Runtime-covered functions | 1205 |
| Target-present covered functions list | 1204 |
| Reachable but not reached | 1328 |
| Covered but statically unreachable | 2 |
| Static reachable list entries | 6238 |
| Static unreachable list entries | 651 |
| Reachable-only function coverage | 44.59% |
| Reachable-only line coverage | 40.01% |
| Reachable-only region coverage | 40.20% |
| Reachable-only branch coverage | 35.70% |
