# AFL Reports

This directory tracks durable summaries for AFL++ runs and post-run analysis.
Generated runtime artifacts live under `afl/reports/generated/` by default and
are ignored by git.

Use the checked-in workflow:

```bash
source ~/work/copilot/tools/env.sh
./afl/build.sh --static
AFL_RUN_TIME=300 ./afl/start.sh dump
./afl/status.sh dump --detail
./afl/map.sh dump --queue --out /path/to/showmap.txt
./afl/triage.sh dump
./afl/minimize.sh dump --queue
./afl/coverage.sh dump --jobs 2
./afl/report.sh all --jobs 2 --target-timeout 3600
./afl/report-ui.sh
```

Report files should cite exact command outputs, artifact paths, and whether
coverage was annotated with reachability.

Use `--target-timeout` or `AFL_REPORT_TARGET_TIMEOUT` for all-target coverage
reports. A timed-out target is recorded in its coverage log and the report
continues with the remaining targets.

Expect `./afl/report.sh all` to take hours when many targets have live AFL
output. The script writes `targets.tsv` as it goes, runs targets in
`afl/targets.sh` order, skips `not_started` targets quickly, and bounds each
coverage/reachability target with `--target-timeout` by default. Use
`./afl/report.sh all --stats-only` for a fast inventory or target-specific
commands such as `./afl/report.sh fromcube --jobs 2` for focused reachability
updates.

Coverage reports should record the LLVM major used for both source coverage and
static reachability. On this VM the expected path is Clang/LLVM 22:
`afl/coverage.sh` auto-selects `clang-22`/`clang++-22`, `cov-analysis` uses
`llvm-profdata-22`/`llvm-cov-22`, and `reachability check-toolchain` should
report `analyzer toolchain on LLVM 22`.

Use `afl/dashboard/report-viewer/` for the static AFL report UI. The launcher
serves the local `afl/` tree and opens the latest generated report unless a
report directory is passed explicitly.

Reachability list naming is semantic:

- `statically_reachable-*.txt` and `statically_unreachable-*.txt` are static
  SanitizerCoverage allowlist/ignorelist artifacts from `fuzz-reachability`.
- `covered-*.txt`, `not_covered_but_statically_reachable-*.txt`, and
  `covered_but_statically_unreachable-*.txt` are target-sensitive runtime
  lists derived from `coverage.json`.
