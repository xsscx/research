# iccApplyProfiles Call Graph & Fuzzer Fidelity Report

**Date**: 2026-03-06 (updated)
**Tool**: iccApplyProfiles.cpp (638 lines)
**Fuzzer**: icc_applyprofiles_fuzzer.cpp (~480 lines, full TIFF I/O pipeline)

---

## 1. Purpose

This report documents the static call graph analysis of `iccApplyProfiles.cpp`
and its fidelity alignment with the `icc_applyprofiles_fuzzer`. The tool applies
ICC color profiles to TIFF images using the CIccCmm pipeline.

## 2. Tool Scope

iccApplyProfiles is a **CMM execution** tool. It:
1. Reads a source TIFF image (CTiffImg::Open, GetIccProfile)
2. Builds a CIccCmm pipeline from one or more ICC profiles (with BPC/Luminance hints)
3. Executes Begin() to initialize the pipeline
4. Encodes source pixels (8/16/32-bit, Lab/XYZ PCS conversions)
5. Calls Apply() per-pixel to transform color values
6. Decodes destination pixels (with UnitClip clamping)
7. Writes the result to a destination TIFF (with embedded ICC profile)

### API Surface (49 tool call sites, 44 matched by fuzzer)

| Phase | Call Sites | In Fuzzer | Notes |
|-------|-----------|-----------|-------|
| Config parsing | 2 | 0 | JSON/legacy CLI args — CLI-only, excluded |
| Source TIFF I/O | 12 | 12 | CTiffImg Open, Get*, GetIccProfile |
| CMM construction | 9 | 6 | AddXform(buffer+file), BPC/Luminance hints |
| CMM execution | 8 | 8 | Begin, Apply, GetSourceSpace, GetDestSpace, parent space |
| Dest TIFF I/O | 5 | 5 | Create, CIccFileIO profile embedding |
| Pixel loop | 13 | 13 | ReadLine, 8/16/32-bit encode/decode, Lab/XYZ PCS, UnitClip, WriteLine |
| Fuzzer extras | 3 | 3 | GetNumXforms, Valid, GetLastSpace |

### Fidelity: 97.8% (44/45 fuzzable)

The only unmatched fuzzable call site is `OpenIccProfile` (PCC profile loading
for viewing condition adjustment — a CLI-argument-specific path). All TIFF I/O,
pixel encoding/decoding, Lab/XYZ PCS conversions, and profile embedding paths
are fully exercised.

**Previous fidelity**: 36.1% (13/36) — the original fuzzer fed profile data
directly without TIFF containers. The rewrite creates synthetic TIFF images,
exercises the full CTiffImg pipeline, and matches the tool's pixel loop exactly.

### Pixel Encoding Coverage

The fuzzer exercises all pixel encoding/decoding paths from the tool:
- **8-bit**: `sptr[k] / 255.0` normalization, CIELAB ±128 offset
- **16-bit**: `pS16[k] / 65535.0` normalization, CIELAB ±0x8000 offset
- **32-bit**: Direct float copy or per-channel cast, `icLabToPcs` for Lab
- **Lab→XYZ PCS**: `icLabFromPcs → icLabtoXYZ → icXyzToPcs` gate
- **XYZ→Lab PCS**: `icXyzFromPcs → icXYZtoLab → icLabToPcs` gate
- **Dest clamping**: `UnitClip()` for all 8/16-bit output

### Photo Mode Coverage

| Photo Mode | Source | Destination |
|------------|--------|-------------|
| PHOTO_RGB | ✓ | ✓ (via icSigRgbData) |
| PHOTO_CIELAB | ✓ | ✓ (via icSigLabData/icSigXYZData) |
| PHOTO_MINISBLACK | ✓ | ✓ (default) |
| PHOTO_MINISWHITE | ✓ | ✓ (via CMYK/multi-color) |

## 3. Input Format

First 75% of fuzzer input is ICC profile data, last 25% is control data:
- `control[0]`: icRenderingIntent (% 4)
- `control[1]`: icXformInterp (bit 0: linear vs tetrahedral)
- `control[2]`: flags — bit0=BPC, bit1=luminance, bit2=V5sub, bit3=embed_icc,
                bit4-5=bps_select (0=8,1=16,2=32), bit6-7=photo_select
- `control[3]`: bit0=use_d2bx, bit1-2=width(1-4), bit3-4=height(1-4)
- `control[4+]`: pixel seed data for TIFF scanlines

## 4. Pipeline Phases (fuzzer matches tool)

1. Write ICC profile to temp file
2. Create source TIFF with embedded ICC profile (SetIccProfile)
3. Open source TIFF, extract metadata + embedded profile (GetIccProfile)
4. Build CMM with BPC/Luminance hints, AddXform(buffer or file)
5. Begin CMM, validate color spaces (source, dest, parent)
6. Create destination TIFF with appropriate photo mode
7. Embed destination profile via CIccFileIO (Open, Read8, GetLength)
8. Pixel loop: ReadLine → encode → Apply → decode → WriteLine
9. CMM query methods (GetNumXforms, Valid, GetLastSpace)

## 5. Files

| File | Description |
|------|-------------|
| `callgraph.json` | Full JSON call graph with fidelity data |
| `callgraph.dot` | Graphviz DOT graph |
| `callgraph.svg` | Rendered SVG call graph |
| `README.md` | This report |

### Render DOT graph

```bash
python3 .github/scripts/callgraphs/iccApplyProfiles-callgraph.py --dot graph.dot --render svg
python3 .github/scripts/callgraphs/iccApplyProfiles-callgraph.py --json report.json
python3 .github/scripts/callgraphs/iccApplyProfiles-callgraph.py --summary
```
