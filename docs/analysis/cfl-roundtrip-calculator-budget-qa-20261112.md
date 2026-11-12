# CFL RoundTrip calculator-budget QA - 2026-11-12

## Outcome

Three new `icc_roundtrip_fuzzer` slow units use serialized calculator operators
whose selectors process tens of thousands of stack values per sampled pixel.
The existing patch 010 cost model detects that work, but its temporary
250,000,000-unit ceiling still admitted these profiles on the 17-point fuzzing
grid.

The synchronized AFL and CFL copies of
`010-roundtrip-calculator-work-budget.patch` now use a temporary
100,000,000-unit ceiling. This keeps the existing sample-times-cost policy and
rejects the three new slow units before grid evaluation. It does not change the
calculator parser, the calculator stack maximum, or ordinary transform apply
calls.

No regression test, script, corpus entry, or fixture was added. The artifacts
remain external under `/mnt/f/artifacts`.

## Artifacts and structure

- `rt-slow-unit-6e5e3726351b51ce145fbe9191d9382713cf7f4d`
  - 4,116 bytes
  - SHA-256: `105741472df161b0b435bb5aa1880dea70e5c974f14cf9a9ef134ec03e7dbb58`
  - calculator selectors include `tget[23,9475]`, `abs[8451]`,
    `sub[1030]`, and `tget[0,10261]`
- `rt-slow-unit-2b4b12369b9c555dac375a4749a927198a544d3c`
  - 4,300 bytes
  - SHA-256: `94fc220c03e4a67a44be8f0df090c445c64d0ae118604b9b31179c9a83cb862e`
  - its AToB1 calculator contains `copy(1,32769)`
- `rt-slow-unit-fd72a624be0f89d5a3cb27020259cbffd17200c9`
  - 4,372 bytes; its declared ICC profile size is 4,336 bytes
  - SHA-256: `46c5ed21c4467b04f423ad8d2928f9099a6663a532113d5dcf3179cf67fbcd68`
  - its AToB1 calculator contains `copy(1,24577)`

All three are RGB/XYZ v5 profiles with calculator MPE transform tags. Their
last two fuzzer-control bytes select intent 0 and non-MPE-preference mode. The
unpatched `iccDumpProfile` loaded and described each profile successfully
inside the hostile-input boundary.

At a 17-cubed grid, the old ceiling allowed about 50,885 estimated work units
per sample. The 100,000,000-unit ceiling allows about 20,354. Each new artifact
exceeds the new per-sample allowance through one large selector or the sum of
several large selectors.

## Contained replay

The campaign reported 11, 14, and 16 second slow-unit markers. On this host,
the prior patched sanitizer binary completed a sequential replay of the first
artifact in 25,686 ms. A concurrent three-artifact replay completed the inputs
in 25,723, 31,256, and 35,280 ms; those concurrent values include CPU
contention. All returned exit 0 without a sanitizer or memory-limit finding.

After the patch 010 ceiling change, a concurrent contained replay reported:

| Artifact prefix | Target time | Result |
|---|---:|---|
| `6e5e3726` | 13 ms | exit 0 |
| `2b4b1236` | 9 ms | exit 0 |
| `fd72a624` | 7 ms | exit 0 |

The source path and selector-cost arithmetic attribute the fast result to the
intended `icCmmStatTooManySamples` return from the library budget gate. The
harness treats that status as a rejected evaluation and returns 0.

## Compatibility controls

Three existing tracked calculator profiles were replayed before and after the
change through the same patched sanitizer harness:

| Existing profile | SHA-256 | Before | After |
|---|---|---:|---:|
| `argbCalc.icc` | `dd35538ec507b931024ea66491e5034be1d3cf3881726b4d74acb756ecaec965` | 747 ms | 726 ms |
| `srgbCalc++Test.icc` | `3e241240b630d6c4cf539b6564c8caa96da6eb4748bfd014078032f5c31b636a` | 6,239 ms | 5,113 ms |
| `Rec2100HlgFull.icc` | `9844eabc22927804fdb60f7ce5126176e750ecf54c3bad3249738e3d4df71b4a` | 4,199 ms | 3,516 ms |

The controls retained their nontrivial full-evaluation timings and all exited
0 without sanitizer or resource-limit findings. `argbCalc.icc` is byte-for-byte
the earlier October 31 RoundTrip control.

## Build and patch-stack checks

The decisive build was:

```bash
./cfl/build.sh clean
./cfl/build.sh --with-patches
```

It cloned upstream `93eb279`, applied patches 001 through 017, and built 24/24
fuzzers with no failures or skips. The libraries reported 2,446 ASan, 381
UBSan, and 3,198 coverage symbols. The resulting RoundTrip fuzzer SHA-256 is
`416bb2295d9e8f7ba14c4475945737554af4e6bd6c404652c2a87e9053d810d6`.

`.github/scripts/check-afl-cfl-patches.sh` accepted every patch. The AFL and
CFL patch 010 files are byte-identical.

## Product-control limitation

A clean Release+LTO `iccRoundTrip` was built from a fresh upstream `93eb279`
clone. Its SHA-256 is
`c865f9f55ef3c3851bfdc097df195dca8e761816193348cd2edceb3c650a4e91`.
The hostile-input launcher rejected the replay before execution because
`iccRoundTrip` is not on its executable-name allowlist. The binary was not run
outside containment and the launcher was not changed as part of this scoped
work.

Therefore this result is classified as a local AFL/CFL campaign-throughput
budget correction. It is not evidence of a production denial of service, and
the 100,000,000-unit value is not an upstream policy recommendation.
