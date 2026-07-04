# AFL Local Reporting Layout

- Date: 2026-07-01
- Scope: AFL-only UI, UX, stats, coverage, profile tooling, scripts, fixtures,
  and generated reports under `afl/`.
- Commit base: updates follow `227e455f` (`afl: cache reachability and tune fast search lane`).

## Changes

- Default generated report roots now live under `afl/reports/generated/`:
  - `afl/report.sh` writes `afl/reports/generated/afl-report-<timestamp>/`.
  - `afl/run-all.sh` writes `afl/reports/generated/afl-report-<timestamp>/`.
  - `afl/coverage.sh` writes `afl/reports/generated/afl-coverage-<timestamp>/`.
  - Full report generation now supports a whole-target coverage/reachability
    timeout (`--target-timeout`, default 3600s) so a slow target such as
    `pawgreport` cannot block the remaining dashboard index.
- Generated payloads remain ignored by git through
  `afl/reports/generated/.gitignore`.
- The AFL-specific static report UI lives in
  `afl/dashboard/report-viewer/index.html`.
- The UI launcher lives in `afl/report-ui.sh` and serves the local `afl/` tree.
  External report roots are mounted through ignored
  `afl/reports/generated/external-*` symlinks before serving.
- There is no `afl/report/` directory. `afl/report.sh` is the report generator,
  `afl/reports/` stores durable summaries, and `afl/reports/generated/` stores
  ignored runtime report payloads.

## Validation

Commands run:

```bash
bash -n afl/report.sh afl/run-all.sh afl/coverage.sh afl/report-ui.sh
file afl/report-ui.sh afl/reports/generated/.gitignore afl/reports/generated/README.md afl/dashboard/report-viewer/index.html afl/README.md afl/reports/README.md
./afl/report.sh applysearch-weight-positive-fast --no-coverage --report-root afl/reports/generated/smoke-report-ui
./afl/report.sh fromcube --no-coverage --target-timeout 1 --report-root afl/reports/generated/smoke-report-fromcube
```

Smoke report output:

```text
[OK] AFL report complete
     Index:  afl/reports/generated/smoke-report-ui/index.md
     Status: afl/reports/generated/smoke-report-ui/status.json
     TSV:    afl/reports/generated/smoke-report-ui/targets.tsv
```

Viewer smoke:

```text
viewer smoke ok
```

## Current AFL Paths

- Checked-in durable reports: `afl/reports/`
- Ignored generated reports: `afl/reports/generated/`
- AFL report UI: `afl/dashboard/report-viewer/`
- AFL UI launcher: `afl/report-ui.sh`
- AFL dashboard metrics stack: `afl/dashboard/`
- External session report mounts: `afl/reports/generated/external-*`

## Notes

The smoke report disabled coverage to keep validation bounded. Full coverage
reports still use the existing `afl/coverage.sh` workflow and now write their
HTML, JSON, text, demangled symbol lists, profdata, and temporary coverage build
trees below `afl/reports/generated/` unless an explicit `--report-root` is
passed. Use `--target-timeout` for all-target reports with reachability enabled.

To inspect a repo-local report:

```bash
./afl/report-ui.sh afl/reports/generated/afl-report-YYYYMMDDTHHMMSSZ
```

To inspect a session artifact without copying it into the repository:

```bash
./afl/report-ui.sh /home/h02332/work/copilot/afl-report-stats-validation-20260702T0940
```
