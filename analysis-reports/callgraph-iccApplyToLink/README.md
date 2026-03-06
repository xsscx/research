# iccApplyToLink Call Graph & Fuzzer Fidelity Report

**Date**: 2026-03-06
**Tool**: iccApplyToLink.cpp (869 lines)
**Fuzzer**: icc_link_fuzzer.cpp

---

## 1. Purpose

This report documents the static call graph analysis of `iccApplyToLink.cpp`
and its fidelity alignment with the `icc_link_fuzzer`. The tool creates
device link profiles by chaining two or more ICC profiles through the CIccCmm pipeline.

## 2. Tool Scope

iccApplyToLink is a **profile linking** tool. It:
1. Reads 2+ ICC profiles from disk
2. Builds a CIccCmm pipeline with various hints (BPC, luminance, sub-profiles)
3. Executes Begin() to initialize
4. Iterates over a full LUT grid calling Apply() for each grid point
5. Creates a device link profile (or TIFF) capturing the combined transform

### API Surface (24 call sites, 14 matched by fuzzer)

| Phase | Call Sites | In Fuzzer | Notes |
|-------|-----------|-----------|-------|
| CLI argument parsing | 3 | 0 | Tool-specific arg parsing |
| CMM construction | 8 | 6 | ReadIccProfile, AddXform, hints |
| CMM execution | 6 | 6 | Begin, Apply, color space queries |
| Output writing | 5 | 0 | Device link profile save |
| Fuzzer extras | 2 | 2 | CMM state queries |

### Fidelity: 66.7% (14/21 fuzzable)

Excellent CMM pipeline coverage. The fuzzer exercises:
- `ReadIccProfile()` with `bUseSubProfile` flag (matching tool behavior)
- `AddXform(CIccProfile*, ...)` with all 6 control flags
- Both BPC and luminance matching hints
- Preview LUT type variant

### Control Byte Encoding

3 trailing bytes control fuzzer behavior:
- `ctrl (byte[-3])`: bFirstTransform(0x01), !bUseD2Bx(0x02), bUseBPC(0x04), bUseLuminance(0x08), bUseSubProfile(0x10), nLutType=Preview(0x20)
- `byte[-2]`: icXformInterp (linear vs tetrahedral)
- `byte[-1]`: icRenderingIntent (% 4)

Note: Link fuzzer needs `ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=256` (2 profiles per input = 2x ASAN memory).

## 3. Files

| File | Description |
|------|-------------|
| `tool-callgraph.json` | Full JSON call graph with fidelity data |
| `tool-callgraph.dot` | Graphviz DOT graph |
| `tool-callgraph.svg` | Rendered SVG call graph |
| `README.md` | This report |

### Generate

```bash
python3 .github/scripts/callgraphs/iccApplyToLink-callgraph.py --dot graph.dot --render svg
python3 .github/scripts/callgraphs/iccApplyToLink-callgraph.py --json report.json
```
