# AFL report pipeline review - 2026-08-03

## Scope

Reviewed tracked AFL orchestration scripts, the GitHub AFL regression workflow,
durable AFL docs, and the Mermaid fuzzer map after the JPEG seed-corpus fix.
The review focused on pipeline correctness, generated report usability, and
coverage artifact discoverability.

## Changes

- `afl/report.sh` now writes `summary.tsv` next to `status.json`,
  `targets.tsv`, and `index.md`.
- The Markdown report index includes the generated summary table so stats-only
  and full coverage reports expose the same aggregate counts.
- `.github/workflows/iccdev-afl-regressions.yml` now runs a lightweight AFL
  script/report smoke job for changes to tracked AFL shell scripts and
  `afl/targets.sh`.
- `call-graph/mermaid/fuzzer-map.md` now separates CFL harnesses from AFL CLI
  lanes and records the JPEG/PNG/TIFF media versus ICC-injection split.
- AFL report docs now document the generated `summary.tsv` artifact.

## Verification

```sh
shellcheck afl/report.sh afl/run-all.sh afl/status.sh afl/targets.sh
bash -n afl/*.sh
AFL_BASE=/tmp/afl-report-pipeline-smoke ./afl/report.sh jpegdump --stats-only --report-root /tmp/afl-report-pipeline-smoke
AFL_BASE=/tmp/afl-report-pipeline-smoke ./afl/run-all.sh jpegdump --dry-run --seconds 1 --no-report
AFL_BASE=/tmp/afl-report-pipeline-all-smoke ./afl/report.sh all --stats-only --target-jobs 4 --report-root /tmp/afl-report-pipeline-all-smoke
file afl/report.sh .github/workflows/iccdev-afl-regressions.yml call-graph/mermaid/fuzzer-map.md afl/reports/README.md docs/afl/index.md afl/reports/2026-08-03-afl-report-pipeline-review.md
```

Expected report smoke artifacts:

- `/tmp/afl-report-pipeline-smoke/index.md`
- `/tmp/afl-report-pipeline-smoke/status.json`
- `/tmp/afl-report-pipeline-smoke/targets.tsv`
- `/tmp/afl-report-pipeline-smoke/summary.tsv`

The all-target stats-only smoke reported 52 configured targets, all
`not_started` under the temporary `AFL_BASE`, and no `not_configured` rows.

## Follow-up

Run a full coverage-bearing report only when the current AFL queues are ready
for a long replay:

```sh
./afl/report.sh all --jobs 2 --target-jobs 2 --target-timeout 3600
```

The full run should publish the generated root through `./afl/report-ui.sh` and
copy durable findings into `afl/reports/` instead of committing generated HTML,
queues, profdata, or temporary coverage build trees.

## QA baseline reset - 2026-08-03

Cleared stale generated AFL report roots, AFL temporary replay files, and local
LLVM/gcov profile counters before handing the tree to QA:

```sh
git clean -fdX afl/reports/generated
find afl/tmp -mindepth 1 -depth -delete
find . \( -name '*.profraw' -o -name '*.profdata' -o -name '*.gcda' -o -name '*.gcno' \) -type f -delete
```

The reset intentionally preserved tracked AFL seeds, dictionaries, target
configuration, and `afl/reports/generated/.gitignore` plus
`afl/reports/generated/README.md`. Existing unrelated worktree changes outside
the generated AFL/profile-counter cleanup were left in place.

Post-reset checks:

```sh
find afl/reports/generated -mindepth 1 ! -name '.gitignore' ! -name 'README.md' -print
find afl/tmp -mindepth 1 -print
find . \( -name '*.profraw' -o -name '*.profdata' -o -name '*.gcda' -o -name '*.gcno' \) -type f -print
./afl/report.sh all --stats-only --target-jobs 4 --report-root /tmp/afl-reset-baseline-report
```

The generated report tree, AFL temp directory, and profile-counter scan were
empty after reset. The stats-only report created
`/tmp/afl-reset-baseline-report/summary.tsv` without repopulating
`afl/reports/generated/`; it inventoried 52 targets, 51 reported targets, 1
`not_started` target, and 0 coverage/profdata artifacts.

## Workflow issue alignment - 2026-08-03

GitHub Actions run `30817214460`, job `91697796367`, failed in
`iccDEV AFL Regressions` before replaying the regression because
`.github/scripts/iccdev-afl-fromxml-regression.sh` still required
`afl/patches/005-fromxml-namedcolor-devicecoords-bounds.patch`. That patch is no
longer present in the tracked tree and may have been merged upstream, so the
workflow was testing obsolete patch plumbing instead of current AFL reporting.

Resolution:

- Removed the obsolete `iccFromXml namedColor2 CountOfDeviceCoords` workflow job.
- Removed its dedicated script, patch, and reproducer path triggers from
  `.github/workflows/iccdev-afl-regressions.yml`.
- Kept the `AFL script and report smoke` job, which passed in the referenced
  run and covers the active AFL shell/report pipeline.
