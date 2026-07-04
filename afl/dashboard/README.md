# AFL++ StatsD Dashboard

Local dashboard stack for AFL++ StatsD metrics. This follows the AFL++ StatsD
workflow documented in `docs/rpc_statsd.md`: AFL++ sends StatsD packets, the
StatsD exporter converts them for Prometheus, and Grafana displays the trends.

Start the stack locally:

```bash
cd afl/dashboard && docker compose up -d
```

Launch a fuzzer with metrics enabled:

```bash
AFL_STATSD=1 AFL_STATSD_TAGS_FLAVOR=dogstatsd ./afl/start.sh dump --parallel 4
```

Endpoints:

| Service | URL |
|---------|-----|
| Grafana | `http://127.0.0.1:3000` |
| Prometheus | `http://127.0.0.1:9090` |
| StatsD exporter | `http://127.0.0.1:9102` |

The default StatsD UDP listener is exposed on `127.0.0.1:8125` from the host.
Use `AFL_STATSD_HOST` and `AFL_STATSD_PORT` only when the exporter is not local.

## Report viewer

The static report viewer in `report-viewer/` reads generated AFL reports from
`afl/reports/generated/`. There is no `afl/report/` directory; `afl/report.sh`
is the report generator, and `afl/reports/` is the report tree. Generate or
refresh a report first:

```bash
./afl/report.sh all --no-coverage
./afl/report-ui.sh
```

For coverage plus reachability, keep the all-target report bounded so slow
targets such as `pawgreport` cannot block the generated dashboard:

```bash
./afl/report.sh all --jobs 2 --target-timeout 3600
```

The viewer defaults to `reports/generated/latest`. To inspect a specific
repo-local report, either pass it to the launcher or open the printed URL with
`?report=reports/generated/<report-dir>`:

```bash
./afl/report-ui.sh afl/reports/generated/afl-report-YYYYMMDDTHHMMSSZ
```

Reports written outside the repository, for example under `~/work/copilot`, can
also be passed directly. The launcher mounts them as ignored symlinks under
`afl/reports/generated/external-*` so the browser can fetch them from the same
local AFL root:

```bash
./afl/report-ui.sh /home/h02332/work/copilot/afl-report-stats-validation-20260702T0940
./afl/report-ui.sh /home/h02332/work/copilot/afl-coverage-applysearch-weight-zero-20260702T0935
```

The `latest` symlink is updated only for reports written below
`afl/reports/generated/`. External reports are served by their generated
`external-*` mount URL and do not replace `latest`.
