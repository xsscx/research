# AFL and CFL Runtime Staging Review

This note records the durable contracts verified after the
`afl-repro-include-txt-files.txt` investigation.

## FromXml include reproduction

The reported `iccFromXml` inputs reference files such as
`cyan-SmoothScaleXYZ.txt` relative to the process working directory. Replaying
from the repository root or from `iccDEV/Testing` fails before reaching the
same parser path. Replaying from the fixture directory succeeds and exposes the
UBSAN finding in `IccMpeCalc.cpp`.

The `fromxml-includes` target already stages all live `Filename` dependencies,
including transitive XML imports, below `afl/support/fromxml-includes`. AFL runs
from that directory, mutates only the primary XML input, and writes normal AFL
state to `afl/afl-fromxml-includes/output/default`. Sidecar TXT/XML files are
support state, not queue or crash artifacts.

Use this checked workflow:

```bash
.github/scripts/validate-afl-fromxml-includes.sh
./afl/triage.sh fromxml-includes
```

## Output layout and isolation

A single AFL instance owns `output/default/queue`. Parallel campaigns own
`output/main/queue` and `output/secondary_N/queue`. `input/` is the staged seed
corpus; it is not the live queue.

The config-driven `applynamedcmm-cfg`, `applyprofiles-cfg`, and
`applysearch-cfg` targets accept destination filenames from mutated JSON.
They run below `afl/work/<target>/root`, where required source profiles and
media are copied read-only. This prevents ordinary mutated relative output
names from being created in the repository root. AFL queues and findings stay
in each target's `output/<instance>` tree.

## Hybrid PCC startup

`applyprofiles-hybrid-pcc` previously screened hundreds of unrelated ICC files
with a slow full TIFF transform before starting AFL. The compatible seed is
`MultSpectralRGB.icc`; it is now the only seed. The target uses process-specific
TIFF and JSON output paths and a 15-second dry-run/AFL timeout.

## CFL runtime

`cfl/start.sh` already uses one work directory per fuzzer. `cfl/fuzz-local.sh`
now follows the same rule. Corpora remain in `cfl/corpus-*`, artifacts remain
under the configured `cfl/runs` tree, and temporary tool files use the matching
per-fuzzer work directory.

## Low map-density review

Map density is coverage of every instrumented edge in the linked CLI, not a
target-specific pass threshold. The two reported lanes were reaching their
intended paths:

- `applyprofiles-hybrid-embedded` had one complete 2.1 MiB, 600 by 420 TIFF
  seed, a 15-second timeout, 99.97 percent stability, 148 queue entries, no
  timeouts, and continuing discoveries. Its 2.77 percent bitmap coverage is
  consistent with the deliberately narrow embedded/PCC CLI shape and slow full
  image transform.
- `profileplot-raster` passed the replay validator for `clut:A2B0`, held 399
  queue entries, ran at about 93 executions per second with 100 percent
  stability, had no timeouts, and was still finding inputs. Its 3.72 percent
  bitmap coverage is likewise a narrow raster-mode slice of `iccProfilePlot`.
- `applynamedcmm` passed its four-lane target-contract validator. The retained
  run had 1,162 queue entries, about 135 executions per second, 100 percent
  stability, no timeouts, and 836 pending inputs. Its authoritative
  `fuzzer_stats` snapshot reported 8.57 percent bitmap coverage after the
  earlier UI observation of 4.61 percent, showing active coverage growth rather
  than a stalled target.

Do not treat either percentage alone as a hung or misconfigured fuzzer. A
failed target replay, zero executions, unstable coverage, persistent timeouts,
or no usable CLUT/embedded fixture would be configuration evidence; none was
present in this review.
