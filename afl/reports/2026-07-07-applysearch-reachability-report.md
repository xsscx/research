# iccApplySearch AFL Reachability Report

- Date: 2026-07-07
- Target: `applysearch`
- Tool: `iccApplySearch`
- Generated report root: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z`
- Dashboard default: `afl/reports/generated/latest` -> `afl-report-applysearch-reachability-20260707T125542Z`

## Commands Run

Toolchain check:

```bash
source "$HOME/work/copilot/tools/env.sh"
command -v cov-analysis
command -v reachability
command -v clang-22
command -v clang++-22
reachability check-toolchain
```

Observed toolchain:

```text
/usr/local/bin/cov-analysis
/home/xss/work/copilot/tools/fuzz-reachability/.venv/bin/reachability
/usr/bin/clang-22
/usr/bin/clang++-22
OK: analyzer toolchain on LLVM 22 (min 21); rustc LLVM 21
```

Report run:

```bash
AFL_REPORT_COVERAGE_TIMEOUT=5 ./afl/report.sh applysearch \
  --report-root afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z \
  --jobs 2 \
  --target-timeout 0
```

Report completion:

```text
[OK] AFL report complete
     Index:  afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/index.md
     Status: afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/status.json
     TSV:    afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/targets.tsv
```

## AFL State

`./afl/status.sh applysearch --json` reported a live default instance at the
snapshot used for this report:

- Runtime: 42h14m41s
- Executions: 5,625,502
- Corpus: 2,696
- Found: 2,620
- Edge coverage: 9.66% (14,663 / 151,738)
- Stability: 100.00%
- Crashes: 0
- Hangs: 133 in AFL stats, but triage found no replayable hangs in the canonical crash/hang locations

`afl/triage.sh applysearch` output:

```text
--- Crashes ---
  No crashes found

--- Hangs ---
  No hangs found

[OK] Triage complete
```

## Reachability Output

Static reachability completed for the `iccApplySearch` binary with LLVM 22:

```text
reachable 8507 / defined 9767  (1627 indirect-only, 635 low-confidence, 1260 unreachable)  [backend=type-based]
wrote afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/coverage/reachability-iccApplySearch-static.json
wrote afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/coverage/statically_reachable-iccApplySearch.txt
wrote afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/coverage/statically_unreachable-iccApplySearch.txt
```

Runtime replay completed:

```text
[+] Replaying 2771 queue files...
[+] Merging 2 profile(s)...
[+] Reachability: reachable=2614 not-reached=2134 unreachable=400 anomaly=2
[OK] Coverage workflow complete
```

Reachable-only coverage summary:

```text
TOTAL  17.16% (480/2798) functions, 12.77% (5089/39861) lines, 13.87% (4034/29083) regions, 11.60% (2474/21320) branches
```

`iccApplySearch.cpp` itself has partial command-line and replay coverage:

```text
iccApplySearch.cpp  18.18% (2/11) functions, 26.67% (88/330) lines, 34.69% (68/196) regions, 23.33% (35/150) branches
```

Core search/CMM coverage highlights:

```text
IccCmmSearch.cpp  68.75% (11/16) functions, 52.06% (164/315) lines, 42.92% (97/226) regions, 34.21% (52/152) branches
IccSearch.h      70.37% (19/27) functions, 74.58% (220/295) lines, 83.54% (137/164) regions, 78.43% (80/102) branches
IccCmm.cpp       31.60% (85/269) functions, 20.46% (1288/6294) lines, 20.41% (1013/4964) regions, 15.83% (577/3646) branches
IccMpeCalc.cpp   25.00% (37/148) functions, 27.73% (886/3195) lines, 31.84% (766/2406) regions, 33.53% (684/2040) branches
```

Runtime function-list files:

- `covered-applysearch.txt`: 487 lines including header
- `not_covered_but_statically_reachable-applysearch.txt`: 2,135 lines including header
- `covered_but_statically_unreachable-applysearch.txt`: 7 lines including header
- `statically_reachable-iccApplySearch.txt`: 8,516 lines including header
- `statically_unreachable-iccApplySearch.txt`: 1,266 lines including header

The two covered-but-statically-unreachable anomalies are:

```text
fun:CIccSimpleMatrixSolver::CIccSimpleMatrixSolver()
fun:CIccSimpleMatrixInverter::CIccSimpleMatrixInverter()
```

These match the prior static-classifier startup/constructor anomaly class and
should not be treated as `iccApplySearch` crashes.

## Coverage Interpretation

The current `applysearch` lane reaches the specialized search engine well:
`IccCmmSearch.cpp` and `IccSearch.h` are much higher than the whole-tool average.
The remaining gap is not basic tool startup; it is profile/config diversity.

High-value reachable but unreached areas include:

- JSON configuration helpers and pcc weight parsing paths (`jsonToValue`,
  `jsonToList`, `saveJsonAs`, `IccJsonUtil.cpp`)
- color encoding and signature formatting paths (`icColorValue`,
  `icGetSigStr`, `icGetJsonColorEncoding`)
- profile read/write and PCC metadata paths (`CIccProfile::ReadPccTags`,
  `getPccObserver`, `getPccIlluminant`, `getCustomToStandardPcc`)
- alternate PCS transform paths (`CIccPcsXform::push*`)
- CMM thread/MRU variants (`CIccThreadedCmm`, `CIccMruCmm`,
  `CIccApplyMruCmm`)

The next useful seed work should keep the valid command shape but add path
diversity:

- fresh `applysearch-cfg` JSON configs for pcc weight maps, interpolation keys,
  environment variables, and nested search objects
- small PCC/v5 profiles that exercise observer, illuminant, and custom-to-standard
  PCC metadata
- valid data encodings beyond the current fixed 8-bit RGB lane, especially float
  and alternate precision forms
- a separate rerun of the `applysearch-weight-*` lanes after the main report,
  because those lanes target the fixed-weight PCC attachment paths directly

## Report UI

The generated report is available through the existing AFL dashboard launcher:

```bash
./afl/report-ui.sh afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z
```

Default launcher behavior also works because `afl/reports/generated/latest`
points to this report:

```bash
./afl/report-ui.sh
```

The URL printed by the launcher will be:

```text
http://127.0.0.1:8765/dashboard/report-viewer/?report=reports/generated/afl-report-applysearch-reachability-20260707T125542Z
```

## Artifact Index

- Markdown index: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/index.md`
- TSV: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/targets.tsv`
- Coverage log: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/logs/applysearch-coverage.log`
- HTML coverage: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/coverage/cov-applysearch-static/html/index.html`
- Summary: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/coverage/cov-applysearch-static/summary.txt`
- JSON coverage: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/coverage/cov-applysearch-static/coverage.json`
- Profdata: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/coverage/cov-applysearch-static/coverage.profdata`
- Reachability JSON: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/coverage/reachability-iccApplySearch-static.json`
- Static reachable list: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/coverage/statically_reachable-iccApplySearch.txt`
- Static unreachable list: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/coverage/statically_unreachable-iccApplySearch.txt`
- Not-covered reachable list: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/coverage/not_covered_but_statically_reachable-applysearch.txt`
- Covered-unreachable anomaly list: `afl/reports/generated/afl-report-applysearch-reachability-20260707T125542Z/coverage/covered_but_statically_unreachable-applysearch.txt`
