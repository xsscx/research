# CFL round-trip slow-unit QA — 2026-10-31

## Result

`rt-slow-unit-798edbee7f8fdd5ddecaf819414e1d7535a6083b` is a valid
2,420-byte RGB/XYZ v5 profile. Its SHA-256 is
`dd35538ec507b931024ea66491e5034be1d3cf3881726b4d74acb756ecaec965`.

The slowdown was fuzzer instrumentation multiplying fixed production sampling:
the first evaluator used a 33³ grid and PRMG used a fixed 101³ grid. A clean
unpatched Release `iccRoundTrip` completed the full calculation in 0.16 s,
so this is campaign noise rather than a product denial of service.

## A/B results

| Configuration | Time | Peak RSS | Result |
|---|---:|---:|---|
| Patched ASan before granularity work | 17.79 s | 60,356 KiB | exit 0 |
| PRMG 17³ only | 4.86 s | 60,432 KiB | exit 0 |
| Both fuzzer grids at 17³ | 0.73 s | 60,288 KiB | exit 0 |
| Clean unpatched Release tool, full defaults | 0.16 s | 6,204 KiB | exit 0 |
| Patched Release tool, full defaults | 0.16 s | 5,824 KiB | exit 0 |

Optional patch `015-prmg-fuzzer-granularity.patch` adds source-compatible
five-argument overloads. Existing four-argument calls keep the historical
101-point default. The CFL harness uses compile-time overload detection, so it
also compiles against unpatched iccDEV; in patched mode both fuzzing phases use
17 points.

Patched and unpatched Release tool output was byte-identical:
`8311e538ddd860e088c6ceea98a01d51f92bcffe7a474e89b60110e9ffb673b9`.
The unpatched-header harness compile and the complete 24-fuzzer patched ASan
build both passed.

## Replay

```bash
cd ~/research/cfl
bin/icc_roundtrip_fuzzer -runs=1 -timeout=60 /mnt/f/artifacts/rt-slow-unit-798edbee7f8fdd5ddecaf819414e1d7535a6083b
iccRoundTrip /mnt/f/artifacts/rt-slow-unit-798edbee7f8fdd5ddecaf819414e1d7535a6083b 0 0
```
