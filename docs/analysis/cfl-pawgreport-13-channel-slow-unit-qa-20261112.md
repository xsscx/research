# CFL PAWG 13-channel slow-unit QA - 2026-11-12

## Decision

The two `icc_pawgreport_fuzzer` slow units are bounded campaign-throughput
findings. They do not reproduce an OOM, sanitizer finding, crash, timeout, or
unacceptable Release-tool cost. No new local iccDEV patch is warranted.

Both profiles exercise PAWG Q3 smoothness on a 13-channel n-D LUT. The current
8,388,608-corner Q3 budget deliberately keeps this case in scope: 14 paths at
65 samples and 8,192 interpolation corners per sample require 7,454,720 corner
visits. Lowering the budget would discard valid 13-channel quality coverage to
optimize sanitizer-and-coverage campaign throughput. The existing budget
already rejects the next exponential step.

No artifact or regression test is tracked for this review.

## Inputs

The remote artifact names are labels, not content hashes. The byte streams were
copied read-only to native Linux storage before replay.

| Artifact | SHA-256 | Bytes | Declared ICC size |
|---|---|---:|---:|
| `pawg-slow-unit-1bf6c506e9217dba55ca51e9c708ceeaf937c02a` | `c338e1bbf2cf67dedd3596751b6ef5044adfa14e649a5419da97a23974da49d1` | 219431 | 164524 |
| `pawg-slow-unit-0f1c76c35e937938f3aac3cb88923aa022cc1902` | `1770790c21132e79623867eda9831909d8023230303903fddcc988d32a83c703` | 219463 | 164524 |

Both headers declare a v4.2 printer profile with `DCLR` device data and Lab PCS.
The extra bytes after the declared profile size are reported normally by PAWG
S2, S9, and C10. They do not cause the observed Q3 work.

## Test contract

- Research repository base: `a23c07d58081044ef2a05103b772d89bfd22bd63`
- Upstream iccDEV source: `93eb27922619e826e13a049ce9d8a9440582909a`
- ASan side: current coverage-instrumented CFL `icc_pawgreport_fuzzer`
- MSan side: CFL `icc_pawgreport_fuzzer` built with patches 001-018
- Unpatched tool side: canonical MSan `iccPawgReport` at the same upstream commit
- Release control: fresh source checkout at the same upstream commit, Release
  build without sanitizer or coverage instrumentation
- Containment: every parser execution used
  `.github/scripts/icc-hostile-input-runner.sh`

The standalone tool returns 1 because these malformed profiles receive PAWG
FAIL findings. That is the expected report exit and is not a process failure.

## Replay results

| Input | Remote marker | ASan CFL | Patched MSan CFL | Unpatched MSan tool | Unpatched Release tool |
|---|---:|---:|---:|---:|---:|
| `c338e1...` | 10 s | 12.00 s, exit 0 | 4.05 s, exit 0 | 1.77 s, exit 1 | 0.34 s, exit 1 |
| `1770790...` | 25 s | 11.72 s, exit 0 | 4.07 s, exit 0 | 1.91 s, exit 1 | 0.34 s, exit 1 |

No replay emitted an ASan, UBSan, or MSan diagnostic. The different remote and
local slow-unit times are consistent with instrumentation, host load, and
campaign configuration rather than input-dependent unbounded work.

Q1 is already rejected by the 100,000-sample Cartesian-grid budget. Q2 checks
96 shaper curves in the first input and 48 in the second. Q3 completes 896
reported steps for each input and produces finite metrics:

| Input | Q3 average step | Q3 maximum step | Q3 maximum curvature | Discontinuities |
|---|---:|---:|---:|---:|
| `c338e1...` | 0.2051 | 5.5368 | 0.5454 | 0 |
| `1770790...` | 0.3201 | 6.8677 | 5.0306 | 0 |

## Reproduction

Copy each remote artifact into the runner's `/tmp` handoff root, then use the
contained fixed-input replay. For example:

```bash
install -m 0440 /mnt/f/artifacts/pawg-slow-unit-1bf6c506e9217dba55ca51e9c708ceeaf937c02a /tmp/pawg-slow-10s.icc && .github/scripts/icc-hostile-input-runner.sh --input /tmp/pawg-slow-10s.icc --workdir "$PWD" -- cfl/bin-msan/icc_pawgreport_fuzzer -runs=1 @INPUT0@
```

The unpatched canonical MSan tool control is:

```bash
.github/scripts/icc-hostile-input-runner.sh --input /tmp/pawg-slow-10s.icc --workdir "$PWD" -- iccDEV/Build-MSan/Tools/IccPawgReport/iccPawgReport --json @INPUT0@
```

## Scope

This result does not change the upstream disposition in the optional patch
stack. PAWG sample budgets alter whether a quality metric runs, so a lower Q3
limit needs an explicit accuracy and reporting policy. The Release control does
not justify that compatibility tradeoff for these inputs.
