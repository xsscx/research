# iccSpecSepToTiff — Call Graph & Fuzzer Fidelity Analysis

## Tool Overview

**iccSpecSepToTiff** concatenates multiple single-channel spectral TIFF files
into a single multi-channel TIFF, with optional embedded ICC profile.

- **Source**: `iccDEV/Tools/CmdLine/IccSpecSepToTiff/iccSpecSepToTiff.cpp` (272 lines)
- **Fuzzer**: `cfl/icc_specsep_fuzzer.cpp`
- **Input format**: N single-channel TIFF files + optional ICC profile

## Fidelity Summary

| Metric | Value |
|--------|-------|
| Total call sites | 31 |
| CLI-only excluded | 5 |
| Fuzzable call sites | 26 |
| Matched by fuzzer | 26 |
| **Coverage** | **100.0%** |
| Fidelity rating | VERY HIGH |

The fuzzer reproduces the full pipeline: open N input TIFFs → validate format
consistency → allocate buffers → create output TIFF → scanline interleave →
write output → optional ICC profile embedding.

## Key Attack Surface

1. **CTiffImg::Open/ReadLine** — libtiff-based TIFF parsing
2. **Scanline interleaving** — `memcpy` across N input channels per pixel
3. **ICC profile embedding** — arbitrary profile bytes embedded in output TIFF
4. **Fuzzer bonus**: `CIccProfile::Read → Validate → FindTag` on embedded profiles

## Fuzzer Hardening

- Input TIFFs synthesized from fuzz data (5 photometric modes, 8/16/32-bit)
- Up to 8 input files with format consistency validation
- `std::nothrow` for all allocations
- TIFF error/warning handlers silenced

## Files

| File | Description |
|------|-------------|
| `tool-callgraph.json` | Full JSON call graph with fidelity data |
| `tool-callgraph.dot` | Graphviz DOT graph |
| `tool-callgraph.svg` | Rendered SVG call graph |
| `README.md` | This report |
