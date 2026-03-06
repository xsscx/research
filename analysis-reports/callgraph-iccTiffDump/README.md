# iccTiffDump — Call Graph & Fuzzer Fidelity Analysis

## Tool Overview

**iccTiffDump** displays TIFF header metadata and extracts/dumps embedded ICC
profiles, including recursive processing of V5 embedded profiles.

- **Source**: `iccDEV/Tools/CmdLine/IccTiffDump/iccTiffDump.cpp` (252 lines)
- **Fuzzer**: `cfl/icc_tiffdump_fuzzer.cpp`
- **Input format**: TIFF files with optional embedded ICC profiles

## Fidelity Summary

| Metric | Value |
|--------|-------|
| Total call sites | 38 |
| CLI-only excluded | 5 |
| Fuzzable call sites | 33 |
| Matched by fuzzer | 29 |
| **Coverage** | **87.9%** |
| Fidelity rating | HIGH |

The fuzzer covers the core attack surface: TIFF field reading, ICC profile
extraction, profile parsing, CIccInfo formatting, and recursive embedded
profile processing.

## Gaps (4 unfuzzed call sites)

The 4 unfuzzed sites are **metadata display functions** (`GetId()` lookups for
planar config, photometric, compression, and extra samples). These are simple
lookup-table functions with no security relevance.

## Key Attack Surface

1. **OpenIccProfile(pProfMem, nLen)** — ICC profile parsing from TIFF memory
2. **DumpProfileInfo recursion** — Embedded V5 profile tag processing
3. **TIFFGetField × 8** — libtiff header field parsing
4. **TIFFReadDirectory** — Multi-page TIFF directory iteration

## Fuzzer Design

- **In-memory I/O**: Uses `TIFFClientOpen` with custom read/seek/close callbacks
  (zero disk I/O — all processing in RAM)
- TIFF magic validation (II/MM) for early rejection
- ICC profile size bounded: `> 128` and `< 10MB`
- TIFF error/warning handlers silenced

## Files

| File | Description |
|------|-------------|
| `tool-callgraph.json` | Full JSON call graph with fidelity data |
| `tool-callgraph.dot` | Graphviz DOT graph |
| `tool-callgraph.svg` | Rendered SVG call graph |
| `README.md` | This report |
