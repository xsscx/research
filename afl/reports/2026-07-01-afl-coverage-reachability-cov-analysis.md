# AFL Coverage, Reachability, and cov-analysis Report

- Date: 2026-07-01
- Report root: `afl/reports/generated/afl-report-20260701T143906Z`
- Latest symlink: `afl/reports/generated/latest -> afl-report-20260701T143906Z`
- Scope: all AFL targets with existing queues, maps, triage, LLVM coverage,
  `cov-analysis`, static reachability, runtime function lists, and profdata.

## Commands

```bash
source ~/work/copilot/tools/env.sh
./afl/report.sh all --jobs 32 --report-root afl/reports/generated/afl-report-20260701T143906Z
```

The original `toxml` crash input was also replayed against the rebuilt patched
AFL binary:

```bash
ASAN_OPTIONS='print_scariness=1:halt_on_error=1:abort_on_error=1:detect_leaks=0' timeout 20s afl/bin/iccToXml afl/afl-toxml/output/default/crashes/id:000000,sig:06,src:001969,time:33120678,execs:5206488,op:havoc,rep:10 ~/work/copilot/toxml-patched-replay.xml
```

Result: `REPRO_EXIT:0`, `XML successfully created`.

## Fixes Applied During Refresh

`afl/coverage.sh` now isolates the selected AFL instance before invoking
`cov-analysis` when an output tree has multiple instances. The isolated tree is
hardlink-copied under the report `tmp/` directory, with a normal copy fallback
for cross-filesystem cases. This fixed the `pawgreport` ARG_MAX failure without
requiring the previous manual output-root copy:

- `pawgreport` selected `output/main`
- isolated input: `coverage/tmp/cov-analysis-output-pawgreport-main`
- replayed queue files: 1815
- merged profiles: 1815
- profile data: `coverage/cov-pawgreport-static/coverage.profdata`

`afl/coverage.sh` also no longer repoints `afl/reports/generated/latest` when it
is called with a nested `.../<report>/coverage` report root. Only top-level
generated report directories update that symlink.

## Artifact Summary

| Artifact | Count |
|---|---:|
| Target rows | 50 |
| Reported targets | 26 |
| Not-started targets | 24 |
| `afl-showmap` maps | 26 |
| Triage logs | 26 |
| Coverage report directories | 26 |
| `coverage.profdata` files | 26 |
| Static reachability JSON files | 10 real files, 36 report entries including aliases |
| Runtime function lists | 156 |

Warning scan across the full refresh log and per-target logs found no
`WARN: coverage failed`, `Argument list too long`, missing profraw, missing
corpus, or shell `command not found` failures.

## Triage Notes

The checked-in AFL triage path intentionally replays against the canonical
unpatched upstream iccDEV tool in `iccDEV/Build/Tools/`. Therefore the `toxml`
triage log still records the original crash artifact as a 15s timeout against
canonical upstream:

```text
[TIMEOUT] id:000000,sig:06,src:001969,time:33120678,execs:5206488,op:havoc,rep:10 - hung for 15s
```

The patched AFL binary replay is clean, so this is now a reporting distinction:
canonical upstream remains useful for crash fidelity, while patched `afl/bin`
verification confirms the local CFL patch prevents the overflow.

## Reachability Summary

Columns are: statically reachable functions, reachable-but-not-covered runtime
list entries, statically unreachable functions, runtime-covered functions, and
covered-unreachable anomalies.

| Target | Reachable | Not Covered Reachable | Unreachable | Covered | Covered-Unreachable |
|---|---:|---:|---:|---:|---:|
| applyprofiles | 7904 | 2004 | 1828 | 580 | 2 |
| applyprofiles-fast | 7904 | 1976 | 1828 | 608 | 2 |
| applyprofiles-deep | 7904 | 1980 | 1828 | 604 | 2 |
| applyprofiles-hybrid-embedded | 7904 | 2339 | 1828 | 245 | 2 |
| applyprofiles-hybrid-pcc | 7904 | 2347 | 1828 | 237 | 2 |
| applysearch | 8436 | 2216 | 1304 | 396 | 2 |
| applysearch-weight-positive | 8436 | 2313 | 1304 | 299 | 2 |
| applysearch-weight-positive-fast | 8436 | 2317 | 1304 | 295 | 2 |
| applysearch-weight-zero | 8436 | 2451 | 1304 | 161 | 2 |
| applysearch-weight-nan | 8436 | 2470 | 1304 | 142 | 2 |
| applytolink | 6376 | 2008 | 856 | 463 | 2 |
| applytolink-cube | 6376 | 1919 | 856 | 552 | 2 |
| dump | 6383 | 2057 | 757 | 352 | 2 |
| pawgreport | 7016 | 1267 | 778 | 1278 | 2 |
| pawgreport-fast | 7016 | 1423 | 778 | 1122 | 2 |
| pawgreport-read | 7016 | 1461 | 778 | 1084 | 2 |
| roundtrip | 6204 | 1994 | 858 | 418 | 2 |
| roundtrip-mpe | 6204 | 2090 | 858 | 322 | 2 |
| specseptotiff | 6394 | 2094 | 780 | 336 | 2 |
| specseptotiff-compress | 6394 | 2021 | 780 | 409 | 2 |
| specseptotiff-desc | 6394 | 2044 | 780 | 386 | 2 |
| specseptotiff-sep | 6394 | 2092 | 780 | 338 | 2 |
| tiffdump | 6266 | 2219 | 872 | 220 | 2 |
| tiffdump-extract | 6266 | 2027 | 872 | 412 | 2 |
| toxml | 8137 | 2668 | 636 | 417 | 3 |
| v5dspobs | 6222 | 1826 | 865 | 574 | 2 |

## Coverage Totals

Totals are reachable-only `summary.txt` rows from each target coverage report;
full raw coverage remains in each target's `coverage.json`.

| Target | Functions | Lines | Regions | Branches |
|---|---:|---:|---:|---:|
| applyprofiles | 20.78% (578/2782) | 14.83% (5826/39295) | 15.51% (4398/28365) | 12.53% (2591/20684) |
| applyprofiles-fast | 21.78% (606/2782) | 15.84% (6226/39295) | 16.94% (4804/28365) | 13.39% (2770/20684) |
| applyprofiles-deep | 21.64% (602/2782) | 15.75% (6189/39295) | 16.71% (4741/28365) | 13.08% (2706/20684) |
| applyprofiles-hybrid-embedded | 8.73% (243/2782) | 5.53% (2174/39295) | 5.22% (1480/28365) | 3.72% (769/20684) |
| applyprofiles-hybrid-pcc | 8.45% (235/2782) | 5.80% (2279/39295) | 6.34% (1799/28365) | 4.57% (946/20684) |
| applysearch | 14.02% (394/2811) | 10.15% (4078/40159) | 10.99% (3194/29052) | 8.91% (1901/21324) |
| applysearch-weight-positive | 10.57% (297/2811) | 6.84% (2745/40159) | 7.41% (2153/29052) | 5.29% (1128/21324) |
| applysearch-weight-positive-fast | 10.42% (293/2811) | 6.74% (2705/40159) | 7.32% (2127/29052) | 5.25% (1119/21324) |
| applysearch-weight-zero | 5.66% (159/2811) | 3.69% (1481/40159) | 3.92% (1140/29052) | 2.91% (620/21324) |
| applysearch-weight-nan | 4.98% (140/2811) | 3.49% (1402/40159) | 3.70% (1075/29052) | 2.79% (596/21324) |
| applytolink | 17.44% (461/2644) | 13.87% (5209/37545) | 15.65% (4245/27125) | 12.46% (2482/19918) |
| applytolink-cube | 20.80% (550/2644) | 15.69% (5891/37545) | 16.67% (4521/27125) | 13.96% (2781/19918) |
| dump | 13.52% (350/2589) | 12.02% (4448/36993) | 12.82% (3439/26830) | 12.02% (2363/19660) |
| pawgreport | 47.19% (1277/2706) | 44.45% (17618/39637) | 44.44% (12706/28593) | 40.41% (8544/21142) |
| pawgreport-fast | 41.39% (1120/2706) | 38.84% (15396/39637) | 39.25% (11223/28593) | 36.62% (7743/21142) |
| pawgreport-read | 39.99% (1082/2706) | 35.90% (14231/39637) | 36.64% (10477/28593) | 33.16% (7010/21142) |
| roundtrip | 16.14% (416/2578) | 11.13% (4050/36375) | 11.85% (3146/26552) | 9.31% (1815/19486) |
| roundtrip-mpe | 12.41% (320/2578) | 8.13% (2959/36375) | 8.68% (2306/26552) | 6.80% (1326/19486) |
| specseptotiff | 12.83% (334/2603) | 9.69% (3577/36926) | 10.99% (2973/27060) | 9.10% (1799/19766) |
| specseptotiff-compress | 15.64% (407/2603) | 14.04% (5183/36926) | 16.05% (4342/27060) | 14.83% (2932/19766) |
| specseptotiff-desc | 14.75% (384/2603) | 13.14% (4853/36926) | 14.70% (3977/27060) | 13.55% (2679/19766) |
| specseptotiff-sep | 12.91% (336/2603) | 11.28% (4166/36926) | 12.71% (3439/27060) | 11.90% (2353/19766) |
| tiffdump | 8.35% (218/2611) | 5.80% (2131/36770) | 6.26% (1681/26835) | 4.87% (956/19612) |
| tiffdump-extract | 15.74% (411/2611) | 14.09% (5180/36770) | 16.39% (4399/26835) | 14.67% (2877/19612) |
| toxml | 12.84% (414/3225) | 7.85% (3787/48267) | 8.09% (2845/35180) | 6.20% (1582/25529) |
| v5dspobs | 22.29% (572/2566) | 17.50% (6339/36233) | 19.84% (5238/26397) | 14.94% (2893/19358) |

## Main Issues and Improvement Plan

1. Patch verification: the rebuilt patched AFL `iccToXml` binary cleanly replays
   the original crash, but canonical upstream triage still reports it as a
   timeout. Keep both signals, but add a report field that distinguishes
   canonical-upstream crash fidelity from patched-AFL regression status.
2. Report robustness: `coverage.sh` now isolates selected AFL instances, fixing
   the previous `pawgreport` ARG_MAX failure. A follow-up should chunk
   `llvm-profdata merge` inside `cov-analysis` so very large single-instance
   corpora are also safe.
3. Not-started coverage: 24 targets are still not started. Prioritize
   `applynamedcmm*`, `applyprofiles-cfg`, `applyprofiles-row`,
   `applysearch-cfg`, `fromxml`, `fromjson`, `pngdump*`, `jpegdump*`, and
   `profilevisualize*` because they cover distinct parsers or UI/report paths.
4. Low-yield lanes: `applysearch-weight-nan`, `applysearch-weight-zero`,
   `tiffdump`, and hybrid `applyprofiles` lanes remain below 10% line coverage.
   Seed these from successful related lanes, then run CmpLog/LAF/ctx/ngram AFL
   variants with separate `AFL_BUILD_DIR` and `AFL_BIN_DIR` outputs.
5. Reachability modeling: most targets still have two covered-unreachable
   anomalies, while `toxml` has three. Continue the startup-root work documented
   in `2026-07-01-startup-root-reachability-gap.md` so static initialization and
   tool-registration roots are modeled explicitly.
6. Corpus lifecycle: merge and minimize the high-growth queues before the next
   coverage refresh, especially `pawgreport`, `applyprofiles*`, and
   `applysearch*`. Promote only durable minimized inputs back into curated
   corpora and keep raw queues under ignored AFL output trees.
