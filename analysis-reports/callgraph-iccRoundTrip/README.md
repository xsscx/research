# iccRoundTrip Call Graph & Fuzzer Fidelity Report

**Date**: 2026-07-20
**Tool**: iccRoundTrip.cpp (221 lines)
**Fuzzer**: icc_roundtrip_fuzzer.cpp

---

## 1. Purpose

This report documents the static call graph analysis of `iccRoundTrip.cpp`
and its fidelity alignment with the `icc_roundtrip_fuzzer`. The tool evaluates
ICC profile round-trip accuracy and PRMG interoperability.

## 2. Tool Scope

iccRoundTrip performs two evaluation passes:
1. **Round-trip evaluation** — constructs forward+inverse CMM pipeline, iterates
   over test samples, computes DeltaE statistics via CIccMinMaxEval::Compare
2. **PRMG analysis** — evaluates profile against Perceptual Reference Medium
   Gamut using CIccPRMG::EvaluateProfile

### API Surface (23 call sites, 19 matched by fuzzer)

| Phase | Call Sites | In Fuzzer | Notes |
|-------|-----------|-----------|-------|
| CLI parsing | 3 | 0 | Intent/MPE from trailing bytes in fuzzer |
| Round-trip eval | 2 | 2 | EvaluateProfile — main attack surface |
| PRMG analysis | 2 | 2 | Full PRMG pipeline coverage |
| Result access | 9 | 8 | All eval members accessed |
| Deep calls | 7 | 7 | Internal CMM pipeline fully covered |

### Fidelity: 95.0% (19/20 fuzzable) — NEAR-PERFECT

The fuzzer copies the CIccMinMaxEval class verbatim from the tool source
(lines 79-146), ensuring identical DeltaE computation paths. The only
uncovered call is CIccInfo::GetRenderingIntentName (printf-only).

### Attack Surface

EvaluateProfile internally:
- Opens the ICC profile
- Constructs a CIccCmm with forward + inverse transforms
- Iterates over a grid of test values
- Calls Apply() for round-trip, then Compare() for each sample
- This exercises full LUT interpolation, curves, and matrix operations

## 3. Input Format

ICC profile data with 2 trailing control bytes:
- `data[size-1]`: icRenderingIntent (% 4)
- `data[size-2]`: nUseMPE flag (% 2)
- Minimum size: 130 bytes | Maximum size: 1MB

## 4. Files

| File | Description |
|------|-------------|
| `tool-callgraph.json` | Full JSON call graph with fidelity data |
| `tool-callgraph.dot` | Graphviz DOT graph |
| `tool-callgraph.svg` | Rendered SVG call graph |
| `README.md` | This report |

### Commands

```bash
python3 cfl/iccRoundTrip-callgraph.py --dot graph.dot --render svg
python3 cfl/iccRoundTrip-callgraph.py --json report.json
python3 cfl/iccRoundTrip-callgraph.py --summary
```
