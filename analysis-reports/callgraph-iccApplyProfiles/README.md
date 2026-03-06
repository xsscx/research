# iccApplyProfiles Call Graph & Fuzzer Fidelity Report

**Date**: 2026-03-06
**Tool**: iccApplyProfiles.cpp (638 lines)
**Fuzzer**: icc_applyprofiles_fuzzer.cpp

---

## 1. Purpose

This report documents the static call graph analysis of `iccApplyProfiles.cpp`
and its fidelity alignment with the `icc_applyprofiles_fuzzer`. The tool applies
ICC color profiles to TIFF images using the CIccCmm pipeline.

## 2. Tool Scope

iccApplyProfiles is a **CMM execution** tool. It:
1. Reads a source TIFF image
2. Builds a CIccCmm pipeline from one or more ICC profiles
3. Executes Begin() to initialize the pipeline
4. Calls Apply() per-pixel to transform color values
5. Writes the result to a destination TIFF

### API Surface (38 call sites, 13 matched by fuzzer)

| Phase | Call Sites | In Fuzzer | Notes |
|-------|-----------|-----------|-------|
| Config parsing | 2 | 0 | JSON/legacy CLI args — fuzzer uses hardcoded params |
| Source TIFF I/O | 8 | 0 | CTiffImg operations — fuzzer feeds profiles directly |
| CMM construction | 7 | 3 | AddXform, hint manager |
| CMM execution | 8 | 7 | Begin, Apply, GetSourceSpace, GetDestSpace |
| Dest TIFF I/O | 5 | 0 | Output-only operations |
| Pixel loop | 5 | 0 | TIFF scanline processing |
| Fuzzer extras | 3 | 3 | CMM query APIs |

### Fidelity: 36.1% (13/36 fuzzable)

The low percentage is by design — the fuzzer focuses exclusively on the
**CMM pipeline** (AddXform→Begin→Apply) which is the security-critical
attack surface. TIFF I/O is excluded because:
- Vulnerabilities occur in profile parsing and CMM execution, not TIFF handling
- The fuzzer feeds profile data directly without image containers
- CTiffImg is a separate, well-tested library (libtiff)

### Pixel Value Coverage

The fuzzer exercises 8 distinct pixel value patterns through Apply():
1. Black (all zeros)
2. White (all ones)
3. Gray (all 0.5)
4. Primary colors (one channel at 1.0)
5. Control-data derived values (0-255 normalized)
6. Negative values (-0.1)
7. Over-range values (1.1)
8. NaN values

## 3. Input Format

First 75% of fuzzer input is ICC profile data, last 25% is control data:
- `control[0]`: icRenderingIntent (% 4)
- `control[1]`: icXformInterp (bit 0: linear vs tetrahedral)
- `control[3]`: use_d2bx flag (bit 0)

## 4. Files

| File | Description |
|------|-------------|
| `tool-callgraph.json` | Full JSON call graph with fidelity data |
| `tool-callgraph.dot` | Graphviz DOT graph |
| `tool-callgraph.svg` | Rendered SVG call graph |
| `README.md` | This report |

### Render DOT graph

```bash
python3 cfl/iccApplyProfiles-callgraph.py --dot graph.dot --render svg
python3 cfl/iccApplyProfiles-callgraph.py --json report.json
python3 cfl/iccApplyProfiles-callgraph.py --summary
```
