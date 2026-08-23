# 2026-06-30 AFL Dump Reachability Coverage

## Scope

- Target: `dump`
- Tool: `iccDumpProfile`
- Research repo: `~/research`
- AFL runtime root: `/home/h02332/work/codex/afl-runtime-verify`
- Analysis root: `/home/h02332/work/codex/afl-analysis-20260630T203504Z`
- Toolchain: AFL++ `5.00c`, `cov-analysis-1.0`, `reachability` LLVM 22

## Fuzz Run

Command line captured in `fuzzer_stats`:

```text
afl-fuzz -i /home/h02332/work/codex/afl-runtime-verify/afl-dump/input -o /home/h02332/work/codex/afl-runtime-verify/afl-dump/output -V 300 -x /home/h02332/work/codex/afl-runtime-verify/afl-dump/dump.dict -m none -t 5000 -- /home/h02332/work/codex/afl-static-verify-bin/iccDumpProfile -v 100 @@ ALL
```

Verified runtime stats:

| Metric | Value |
|---|---:|
| Run time | 300 seconds |
| Executions | 58078 |
| Exec/sec | 193.58 |
| Corpus entries | 858 |
| New corpus entries | 292 |
| AFL bitmap coverage | 9.95% |
| Edges found | 11309 / 113699 |
| Saved crashes | 0 |
| Saved hangs | 0 |

Post-run helpers:

- `afl/status.sh dump --detail`: passed.
- `afl/map.sh dump --queue`: mapped 858 inputs and 11309 edges.
- `afl/triage.sh dump`: no crashes or hangs found.
- `afl/minimize.sh dump --queue`: reduced 858 queue entries to 416.

## Reachability

Command:

```bash
source /home/h02332/work/copilot/tools/env.sh
AFL_BASE=/home/h02332/work/codex/afl-runtime-verify \
AFL_COVERAGE_ICCDEV_DIR="$HOME/research/iccDEV" \
AFL_COVERAGE_TIMEOUT=2 \
./afl/coverage.sh dump --report-root /home/h02332/work/codex/afl-analysis-20260630T203504Z --jobs 2
```

`reachability run` summary:

| Metric | Value |
|---|---:|
| Defined functions | 6086 |
| Reachable functions | 5470 |
| Indirect-only functions | 1481 |
| Low-confidence functions | 559 |
| Unreachable defined functions | 616 |

Reachability artifacts:

- `/home/h02332/work/codex/afl-analysis-20260630T203504Z/reachability-dump-static.json`
- `/home/h02332/work/codex/afl-analysis-20260630T203504Z/reached.txt`
- `/home/h02332/work/codex/afl-analysis-20260630T203504Z/not_reached.txt`

## Coverage

`cov-analysis --reachability` report:

- HTML: `/home/h02332/work/codex/afl-analysis-20260630T203504Z/cov-dump-static/html/index.html`
- Text: `/home/h02332/work/codex/afl-analysis-20260630T203504Z/cov-dump-static/text/`
- Summary: `/home/h02332/work/codex/afl-analysis-20260630T203504Z/cov-dump-static/summary.txt`
- JSON: `/home/h02332/work/codex/afl-analysis-20260630T203504Z/cov-dump-static/coverage.json`
- Profdata: `/home/h02332/work/codex/afl-analysis-20260630T203504Z/cov-dump-static/coverage.profdata`

Reachable-only totals from `summary.txt`:

| Coverage area | Result |
|---|---:|
| Functions | 7.35% (190 / 2586) |
| Lines | 6.74% (2489 / 36941) |
| Regions | 7.35% (1966 / 26746) |
| Branches | 7.08% (1387 / 19602) |

Reachability annotation:

| Annotation | Count |
|---|---:|
| Reachable functions in report | 2397 |
| Reachable but not reached | 2207 |
| Statically unreachable | 338 |
| Covered yet unreachable anomalies | 2 |

## Findings

- The static AFL build and static coverage build avoided the prior mismatched
  shared-library coverage data path.
- The 300-second `dump` campaign found queue growth but no saved crashes or
  hangs.
- The main remaining work is seed design for the 2207 reachable-but-unreached
  functions, with priority on parser and tag handlers visible in
  `cov-dump-static/summary.txt`.
- The 2 covered-yet-unreachable anomalies should be reviewed before using the
  unreachable set as a hard exclusion list.
