# CFL ProfileVisualize slow-unit QA — 2026-10-31

## Result

The two October 31 ProfileVisualize slow units are deterministic campaign
throughput findings, not crashes or Release-mode denial-of-service findings.
The harness enumerated a profile once, then the string-ID render API enumerated
and probed every descriptor again for every graph and raster request.

Optional patch `013-profilevisualize-descriptor-render.patch` adds descriptor
overloads while preserving the existing string-ID API. Patched CFL reuses the
descriptor it already holds.

## Artifacts

| SHA-1 / filename | Bytes | SHA-256 |
|---|---:|---|
| `20c23d55b7ece1a181b9bcb7a64b5c694c4a126f` | 382,351 | `860fab322f481969f5c7d03ecd35e17131e75ccf8006e93c309b3b01f0af90f4` |
| `88e6dae93f75a6893828c9141a25260ff328ebe1` | 651,776 | `d87590b0b744370767d88c29b12c6fdba9f1bbc24b0c1262ddf650a846a349d8` |

The first file declares a 257,872-byte ICC profile and carries trailing data.
The second carries a profile plus eight bytes.

## A/B results

Times are single-input wall times on Ubuntu 26.04 WSL2. Release controls used
clean native-Linux checkouts at upstream `b6ce0cf`.

| Artifact | Unpatched ASan | Patched ASan | Unpatched Release | Patched Release |
|---|---:|---:|---:|---:|
| `20c23d…` | 20.76 s / 377,748 KiB | 3.74 s / 78,440 KiB | 0.28 s | 0.07 s |
| `88e6da…` | 34.31 s / 368,876 KiB | 0.90 s / 82,720 KiB | 0.41 s | 0.03 s |

All runs exited 0 without sanitizer diagnostics. The unpatched
`iccProfilePlot <artifact> list` control took 0.11 s and 0.31 s.

## Compatibility

- All six generated TIFFs and both PDFs were byte-identical between unpatched
  and patched Release builds.
- PDF SHA-256 values were
  `284d40c377449f382cf576c9b247dc85f6d60eabb40bf083ccd26f79d766a709`
  and
  `2389c8cdc38e79a220dc1fea19af0ba6a2ecf0283b7f23e57d50c5b695373b48`.
- Existing ID-based `list`, `graph chroma:xy`, and `raster clut:A2B0`
  calls remained compatible. The raster hash was
  `553201e6625d1ed2a0d003dc5d91396886e758be651c9faf8b6ddc86b100b6b8`.
- The patch stack applied cleanly and all 24 ASan CFL fuzzers built.

The ProfileVisualize default `max_len` was also raised from 64 KiB to 1 MiB
in the options, manual commands, README, and workflow assertion so the
documented multi-channel profile surface remains reachable.

## Replay

```bash
cd ~/research/cfl
bin/icc_profilevisualize_fuzzer -runs=1 -timeout=60 /mnt/f/artifacts/pv-slow-unit-20c23d55b7ece1a181b9bcb7a64b5c694c4a126f
bin/icc_profilevisualize_fuzzer -runs=1 -timeout=60 /mnt/f/artifacts/pv-slow-unit-88e6dae93f75a6893828c9141a25260ff328ebe1
iccProfilePlot /mnt/f/artifacts/pv-slow-unit-88e6dae93f75a6893828c9141a25260ff328ebe1 list
```
