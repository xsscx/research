# iccApplyNamedCmm Call Graph & Fuzzer Fidelity Report

**Date**: 2026-07-20
**Tool**: iccApplyNamedCmm.cpp (611 lines)
**Fuzzer**: icc_applynamedcmm_fuzzer.cpp

---

## 1. Purpose

This report documents the static call graph analysis of `iccApplyNamedCmm.cpp`
and its fidelity alignment with the `icc_applynamedcmm_fuzzer`. The tool applies
ICC color profiles using CIccNamedColorCmm, supporting both named color and
pixel-based color transformations.

## 2. Tool Scope

iccApplyNamedCmm supports 4 distinct Apply() interfaces:
1. **Named2Pixel** — Named color input → pixel output
2. **Pixel2Pixel** — Pixel input → pixel output (most common)
3. **Named2Named** — Named color → named color lookup
4. **Pixel2Named** — Pixel input → closest named color

### API Surface (35 call sites, 24 matched by fuzzer)

| Phase | Call Sites | In Fuzzer | Notes |
|-------|-----------|-----------|-------|
| Config parsing | 6 | 0 | JSON/legacy — fuzzer uses hardcoded params |
| CMM construction | 9 | 7 | PCC and PCC env vars not exercised |
| CMM execution | 6 | 6 | Begin + space queries fully covered |
| Apply (4 types) | 5 | 5 | All 4 interfaces + batch apply |
| Encoding | 2 | 2 | 6 encoding types × 2 directions |
| Output | 3 | 0 | Legacy/JSON/IT8 output writing |
| Fuzzer extras | 4 | 4 | CMM query APIs |

### Fidelity: 82.8% (24/29 fuzzable) — HIGH

The fuzzer exercises all 4 Apply() interface types with comprehensive
pixel value testing (black, white, gray, primaries, edge cases, NaN, Inf,
batch). It also tests 6 encoding types for both ToInternalEncoding and
FromInternalEncoding paths.

### Pixel Value Coverage

The fuzzer tests 10 distinct value patterns through Apply():
1. Black (all zeros)
2. White (all ones)
3. Gray (all 0.5)
4. Primary colors (one channel at 1.0)
5. Negative values (-0.1)
6. Over-range values (1.5)
7. NaN values
8. +Inf values
9. Fuzz-data derived values
10. Batch (3 pixels at once)

## 3. Input Format

4-byte control header + ICC profile data:
- `byte[0]` (flags): useBPC(0x01), useD2Bx(0x02), adjustPcsLuminance(0x04),
  useV5SubProfile(0x08), interp(0x10), envVars(0x80)
- `byte[1]`: icRenderingIntent (& 0x03)
- Minimum size: 132 bytes | Maximum size: 2MB

## 4. Files

| File | Description |
|------|-------------|
| `tool-callgraph.json` | Full JSON call graph with fidelity data |
| `tool-callgraph.dot` | Graphviz DOT graph |
| `tool-callgraph.svg` | Rendered SVG call graph |
| `README.md` | This report |

### Commands

```bash
python3 cfl/iccApplyNamedCmm-callgraph.py --dot graph.dot --render svg
python3 cfl/iccApplyNamedCmm-callgraph.py --json report.json
python3 cfl/iccApplyNamedCmm-callgraph.py --summary
```
