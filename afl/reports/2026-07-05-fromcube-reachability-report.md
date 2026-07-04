# iccFromCube AFL Reachability Report

- Date: 2026-07-05
- Target: `fromcube`
- Tool: `iccFromCube`
- Generated report root: `afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z`
- Dashboard default: `afl/reports/generated/latest` -> `afl-report-fromcube-reachability-20260705T124855Z`

## Commands Run

Toolchain check:

```bash
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
AFL_REPORT_COVERAGE_TIMEOUT=5 ./afl/report.sh fromcube \
  --report-root afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z \
  --jobs 2 \
  --target-timeout 0
```

Report completion:

```text
[OK] AFL report complete
     Index:  afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/index.md
     Status: afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/status.json
     TSV:    afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/targets.tsv
```

## AFL State

`./afl/status.sh fromcube --json` reported the stopped default instance:

- Runtime: 15h39m16s
- Executions: 14,524,076
- Corpus: 717
- Found: 692
- Edge coverage: 2.88% (3,340 / 115,928)
- Stability: 99.94%
- Crashes: 0
- Hangs: 35 in AFL stats, but triage found no replayable hangs in the canonical crash/hang locations

`afl/triage.sh fromcube` output:

```text
--- Crashes ---
  No crashes found

--- Hangs ---
  No hangs found

[OK] Triage complete
```

## Reachability Output

Static reachability completed for the `iccFromCube` binary:

```text
reachable 6419 / defined 7270  (1572 indirect-only, 600 low-confidence, 851 unreachable)  [backend=type-based]
wrote afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/coverage/reachability-iccFromCube-static.json
wrote afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/coverage/statically_reachable-iccFromCube.txt
wrote afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/coverage/statically_unreachable-iccFromCube.txt
```

Runtime replay completed:

```text
[+] Replaying 725 queue files...
[+] Merging 714 profile(s)...
[+] Reachability: reachable=2416 not-reached=2276 unreachable=336 anomaly=2
```

Reachable-only coverage summary:

```text
TOTAL  5.42% (140/2585) functions, 4.02% (1459/36311) lines, 4.82% (1278/26528) regions, 3.09% (600/19396) branches
```

`iccFromCube.cpp` itself is well covered:

```text
iccFromCube.cpp  94.44% (17/18) functions, 88.55% (294/332) lines, 92.05% (220/239) regions, 89.02% (146/164) branches
```

Runtime function-list files:

- `covered-fromcube.txt`: 146 lines including header
- `not_covered_but_statically_reachable-fromcube.txt`: 2,279 lines including header
- `covered_but_statically_unreachable-fromcube.txt`: 7 lines including header
- `statically_reachable-iccFromCube.txt`: 6,428 lines including header
- `statically_unreachable-iccFromCube.txt`: 857 lines including header

The two covered-but-statically-unreachable anomalies are:

```text
fun:CIccSimpleMatrixSolver::CIccSimpleMatrixSolver()
fun:CIccSimpleMatrixInverter::CIccSimpleMatrixInverter()
```

These match the prior class of static-classifier startup/constructor anomalies and should not be treated as `iccFromCube` crashes.

## Command-Line Alignment

The target arguments are aligned with the upstream tool. `iccFromCube` requires exactly two user arguments:

```text
Usage: iccFromCube cube_file output_icc_file
```

`afl/targets.sh` currently drives:

```bash
AFL_ARGS=("@@" "${tmp_prefix}.icc")
```

That maps cleanly to `cube_file output_icc_file`. No argv-level fix is needed for this target. The remaining alignment work is corpus/code-path alignment: drive valid `.cube` features that exercise less-covered profile construction and library paths while keeping the two-argument CLI shape.

Existing seed sources already include custom-domain and LUT-range inputs:

- `docs/iccDEV/Tools/test-data/test-identity.cube`
- `docs/iccDEV/Tools/test-data/test-warmfilm-5x5x5.cube`
- `fuzz/graphics/cube/*`
- `cfl/icc_fromcube_fuzzer_seed_corpus`
- `cfl/corpus-icc_fromcube_fuzzer`

Next useful path work:

- Add or promote small valid ASCII `.cube` seeds for `LUT_3D_INPUT_RANGE`, unequal `DOMAIN_MIN`/`DOMAIN_MAX`, same-range shared curve paths, and distinct per-channel curve paths.
- Keep fuzzing as `iccFromCube @@ <tmp>.icc`; avoid adding fake flags because the tool rejects `argc != 3`.
- Re-run this report after seed changes and compare `not_covered_but_statically_reachable-fromcube.txt` against the current generated report.

## 2026-07-05 Corpus Alignment Follow-up

The `fromcube` target had a seed-ordering gap: `SEED_LIMIT=256` sampled large
directory sources before all curated path-shaping `.cube` fixtures were
guaranteed to reach AFL. The target now promotes a small validated seed set
through `SEED_FILES` so these files are always staged before directory sampling:

- `fuzz/graphics/cube/control-clean-no-domain-ascii.cube`
- `fuzz/graphics/cube/ub-tagmpe-size-line1158-shared-curves.cube`
- `fuzz/graphics/cube/ub-curveset-line3456-distinct-curves.cube`
- `test-profiles/cube/path-input-range-video-flags-3x3x3.cube`
- `fuzz/graphics/cube/dbz-matrix-identity.cube`

Added fixture:

- `test-profiles/cube/path-input-range-video-flags-3x3x3.cube`

The added fixture is a compact ASCII 3x3x3 cube that exercises:

- `TITLE`
- blank lines and comments
- `LUT_3D_INPUT_RANGE`
- `LUT_IN_VIDEO_RANGE`
- `LUT_OUT_VIDEO_RANGE`
- valid 3D table parsing and ICC output generation

Validation commands:

```bash
iccDEV/Build/Tools/IccFromCube/iccFromCube \
  test-profiles/cube/path-input-range-video-flags-3x3x3.cube \
  /tmp/fromcube-newseed-upstream.icc

ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1,symbolize=0,allocator_may_return_null=1 \
UBSAN_OPTIONS=halt_on_error=1,print_stacktrace=1 \
  afl/bin/iccFromCube \
  test-profiles/cube/path-input-range-video-flags-3x3x3.cube \
  /tmp/fromcube-newseed-afl.icc
```

Both runs returned `0` and created non-empty ICC output.

Reseeding the local `fromcube` input corpus after the target update reported:

```text
[*] Seeds:      57 files
dry-run rejected 516 crashing/hanging seed(s)
```

The staged corpus includes:

```text
control-clean-no-domain-ascii.cube
dbz-matrix-identity.cube
path-input-range-video-flags-3x3x3.cube
test-identity.cube
test-warmfilm-5x5x5.cube
ub-curveset-line3456-distinct-curves.cube
ub-tagmpe-size-line1158-shared-curves.cube
```

A 300-second resumed AFL run against the long-lived local output used the
correct command shape:

```text
afl-fuzz ... -- /home/xss/research/afl/bin/iccFromCube @@ /home/xss/work/copilot/tmp/afl-fromcube-2254183.icc
```

That run did not import the newly staged seed files into the existing queue
because AFL resume mode used `-i-`. It finished cleanly with no crashes and no
replayable hangs:

```text
[*] Statistics: 692 new corpus items found, 2.88% coverage achieved, 0 crashes saved, 35 timeouts saved, total runtime 0 days, 0 hrs, 5 min, 1 sec
```

To test the aligned corpus without disturbing the long-running output tree, a
fresh scratch run used the staged input directory directly:

```bash
AFL_BASE=/tmp/fromcube-aligned-afl.../afl \
AFL_INPUT_DIR=/home/xss/research/afl/afl-fromcube/input \
AFL_RUN_TIME=120 \
  ./afl/start.sh fromcube --seed-order sorted
```

Scratch dry-run evidence showed the promoted path seeds produce distinct
instrumentation:

```text
path-input-range-video-flags-3x3x3.cube: len = 742, map size = 2995
ub-curveset-line3456-distinct-curves.cube: len = 113, map size = 3045
ub-tagmpe-size-line1158-shared-curves.cube: len = 113, map size = 2990
```

Scratch run result:

```text
runtime: 0h2m0s
execs: 47490
corpus: 224
found: 167
coverage: 2.88%
crashes: 0
hangs: 0
```

Interpretation: the promoted seed set reaches the same AFL edge-coverage level
as the long-lived queue much faster and without crashes. The next coverage
growth step should run from a fresh aligned output, or explicitly import these
seeds into the long-lived queue before resuming; merely reseeding `afl-fromcube/input`
does not affect an AFL `-i-` resume run.

## Report UI

The generated report is available through the existing AFL dashboard launcher:

```bash
./afl/report-ui.sh afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z
```

Default launcher behavior also works because `afl/reports/generated/latest` points to this report:

```bash
./afl/report-ui.sh
```

The URL printed by the launcher will be:

```text
http://127.0.0.1:8765/dashboard/report-viewer/?report=reports/generated/afl-report-fromcube-reachability-20260705T124855Z
```

## Artifact Index

- Markdown index: `afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/index.md`
- TSV: `afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/targets.tsv`
- HTML coverage: `afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/coverage/cov-fromcube-static/html/index.html`
- Summary: `afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/coverage/cov-fromcube-static/summary.txt`
- JSON coverage: `afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/coverage/cov-fromcube-static/coverage.json`
- Profdata: `afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/coverage/cov-fromcube-static/coverage.profdata`
- Reachability JSON: `afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/coverage/reachability-iccFromCube-static.json`
- Static reachable list: `afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/coverage/statically_reachable-iccFromCube.txt`
- Static unreachable list: `afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/coverage/statically_unreachable-iccFromCube.txt`
- Not-covered reachable list: `afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/coverage/not_covered_but_statically_reachable-fromcube.txt`
- Covered-unreachable anomaly list: `afl/reports/generated/afl-report-fromcube-reachability-20260705T124855Z/coverage/covered_but_statically_unreachable-fromcube.txt`
