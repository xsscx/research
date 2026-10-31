# CFL slow-unit A/B QA - 2026-10-31

## Decision

The optional CFL patch stack resolves every collected `proflib`, `dump`, and
`pawgreport` slow-unit replay. No new iccDEV work-budget patch is required for
this set. The research harnesses did need unique temporary filenames for safe
multi-worker use, and manual campaigns should keep `FUZZ_TMPDIR` on the native
Linux filesystem.

No replay produced an ASan, UBSan, integer-sanitizer, leak, crash, or timeout
finding. The evidence supports campaign-throughput hardening. It does not show
a production denial of service in the current Release tools.

## Test contract

- Research repository base: `2681acc6ce36c7f0084ef3770e41f79e64e781ee`
- Upstream iccDEV `master`: `b6ce0cf7c3820eeaced7070ec3916678fd3f497e`
- Host: Ubuntu 26.04 under WSL2
- Unpatched control: existing ASan/UBSan/integer/coverage CFL build
- Patched side: `./cfl/build.sh --with-patches --refresh-iccdev`
- Release control: fresh `~/qa/iccDEV-release-slow-units-20261031` checkout,
  Release plus LTO, no sanitizer or coverage instrumentation
- Artifact bytes were copied to `~/qa/cfl-slow-units-20261031` for native-Linux
  I/O. SHA-1 values matched the shared `/mnt/f/artifacts` collection.

Runtime artifacts, coverage files, profiler data, and the `~/qa` checkouts are
local evidence and are not tracked by Git.

## Collected inputs

Ten harness/path pairs reduce to six distinct byte streams:

| SHA-1 | Bytes | Declared tags | Observed lanes |
|---|---:|---:|---|
| `a9a1ead154bc4321e9c4fbae369a5ed31347ffd4` | 103462 | 8448 | pawgreport |
| `58803509d502e33166a16c243aef700aa59b5132` | 329295 | 22617 | proflib, dump, pawgreport |
| `d071d19faba5a747719b81e8ad743b8ec0a45181` | 370691 | 22617 | proflib |
| `13342b8e7557dacf83b9c3c36e8387cfaa636874` | 370691 | 22617 | proflib, pawgreport |
| `3546814b0a709f7514af3d562abd5cfaaf5b483a` | 371495 | 29294 | dump, pawgreport |
| `9f67970eee0879fbbb9e8cfe8050414808993ddf` | 653480 | 8 | pawgreport |

The first five inputs amplify tag-directory parsing, validation, description,
and raw PAWG detail work. The eight-tag `9f6797...` input is distinct: profiling
placed it in PAWG Q1 round-trip grid evaluation and repeated CMM `Apply()`.

## A/B replay

The unpatched measurements except `9f6797...` were captured while the U2-U8
campaigns were active, so they prove reproduction but include host-load jitter.
The patched measurements were captured after the campaigns stopped.

| Harness/input | Unpatched seconds | Patched seconds | Patched exit |
|---|---:|---:|---:|
| proflib `588035...` | 40.72 | 0.02 | 0 |
| proflib `d071d1...` | 51.84 | 0.03 | 0 |
| proflib `13342b...` | not separately timed | 0.04 | 0 |
| dump `588035...` | 41.69 | 0.03 | 0 |
| dump `354681...` | 84.86 | 0.03 | 0 |
| pawgreport `a9a1ea...` | 9.14 | 0.81 | 0 |
| pawgreport `588035...` | 50.76 | 3.17 | 0 |
| pawgreport `13342b...` | 61.85 | 3.30 | 0 |
| pawgreport `354681...` | 92.21 | 2.89 | 0 |
| pawgreport `9f6797...` | 115.52 | 2.30 | 0 |

The patched build compiled all 24 CFL fuzzers. Focused regression tests also
passed:

- `iccdev.profile-tag-count-bound`
- `iccdev.pawg-q1-quality-contract`

After the temp-file change, 16 concurrent `icc_dump_fuzzer` replays and 16
concurrent `icc_toxml_fuzzer` replays shared one native `FUZZ_TMPDIR`. Every
process exited successfully, no sanitizer diagnostic appeared, and no temporary
file remained. A post-change `dump` replay of `354681...` stayed at 0.03
seconds.

## Release control and profiling

From native Linux storage, clean Release `iccDumpProfile` completed each of the
six byte streams in 0.01 to 0.05 seconds. Release `iccPawgReport` completed them
in 0.07 to 1.12 seconds. The slowest Release report was `9f6797...` at 1.12
seconds.

Direct tool runs against `/mnt/f` were discarded as performance controls.
`perf` showed wall time dominated by `CIccFileIO` seek/tell calls crossing the
Windows filesystem boundary. The CFL report harness copies each input to its
temporary directory before evaluation, so `FUZZ_TMPDIR` location affects
campaign throughput.

A 20-second profile of the unpatched instrumented `9f6797...` replay showed the
Q1 call chain `QualityRoundTrip -> measure_round_trip -> CMM Apply`. The
sanitizer-coverage comparison hook accounted for 55.72 percent of sampled
cycles. This explains why an acceptable Release operation count becomes a
115-second CFL unit at `-O0` with sanitizer, integer, coverage, and value-profile
instrumentation.

## Patch attribution and upstream scope

| Area | Local result | Upstream disposition |
|---|---|---|
| Patches `001` and `007` | Build reports `Already applied` at `b6ce0cf` | Already integrated; no new proposal needed |
| Patches `003` and `004` | Bound the calculator/Q1 work represented by `9f6797...` | Non-urgent PAWG policy topic; Release is 1.12 seconds, so this QA alone is not a vulnerability report |
| Patches `005`, `006`, and `008` | Bound raw detail work and reject the 8448-29294 tag directories early | Keep for patched campaigns; `008` is a core-reader compatibility change and needs a real-corpus tag-count audit plus maintainer agreement before upstream proposal |
| Unique dump/toxml temp files | Removes cross-process truncate/unlink races with `-workers=16` | Research-harness correctness fix; it does not change iccDEV library behavior |
| Native `FUZZ_TMPDIR` | Removes mounted-filesystem latency from file-backed harness work | Campaign configuration guidance only |

The upstream PAWG and calculator code is actively maintained rather than
abandoned legacy: the local upstream history shows repeated PAWG changes through
2026-10-25 and calculator fixes through 2026-10-25. Any maintainer discussion
should therefore use current `master`, the existing PAWG contract tests, and a
specific behavior proposal rather than assuming the code is dormant.

For these inputs, the recommended upstream sequence is:

1. Do not file a security issue from sanitizer-only slowness.
2. Collect tag-count distribution from legitimate ICC corpora before proposing
   the 1,000-tag core-reader limit.
3. If PAWG budgets are proposed, define the accuracy/reporting contract for
   skipped Q1/Q3 evaluation and include Release measurements.
4. Open a maintainer discussion only when that compatibility and policy evidence
   is ready. The present local patch mode remains useful for high-throughput
   untrusted-input campaigns.

## Client restart

Each campaign VM must pull this research commit and rebuild; pulling without
rebuilding leaves the old unpatched binaries in place:

```bash
git pull --ff-only
cd ~/research
./cfl/build.sh --with-patches --refresh-iccdev
mkdir -p /tmp/cfl-pawg
```

For a manual PAWG command, use `FUZZ_TMPDIR=/tmp/cfl-pawg` and keep
`-artifact_prefix=/mnt/f/artifacts/pawg-`. Use a distinct native temp directory
for each target on a VM. Shared artifacts and coverage may remain under
`/mnt/f`; temporary tool inputs should not.

## Validation limits

This QA replayed every collected slow-unit path, built all address-sanitizer CFL
harnesses, ran the two focused patch regressions, and exercised the two changed
file-backed harnesses with 16 concurrent processes each. It did not run a new
30,000-second multi-VM campaign, MSan, TSan, the full upstream CTest suite, or
hosted CI. Those are not required to establish the local A/B result.
