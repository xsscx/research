# iccFromCube — Call Graph & Fuzzer Fidelity Analysis

## Tool Overview

**iccFromCube** parses CUBE LUT files (text format used in video/color grading)
and creates ICC v5 device link profiles with MPE A2B0 tags containing 3D CLUTs.

- **Source**: `iccDEV/Tools/CmdLine/IccFromCube/iccFromCube.cpp` (466 lines)
- **Fuzzer**: `cfl/icc_fromcube_fuzzer.cpp`
- **Input format**: `.cube` text files (TITLE, LUT_3D_SIZE, DOMAIN_MIN/MAX, float triplets)

## Fidelity Summary

| Metric | Value |
|--------|-------|
| Total call sites | 33 |
| CLI-only excluded | 3 |
| Fuzzable call sites | 30 |
| Matched by fuzzer | 30 |
| **Coverage** | **100.0%** |
| Fidelity rating | VERY HIGH |

The fuzzer contains an **exact copy** of the CubeFile class from the tool source
and reproduces the entire `main()` flow.

## Key Attack Surface

1. **CubeFile::parseHeader()** — Text parsing with `atof`/`atoll`, keyword matching
2. **CubeFile::parse3DTable()** — N³ float triplet parsing into CLUT array
3. **CIccCLUT::Init(size)** — Allocates `size³ × 3` floats (fuzzer caps at 64³)

## Fuzzer Hardening

- LUT size capped at 64 (max 786K floats ≈ 3MB) to prevent OOM
- All allocations use `std::nothrow`
- Temp file I/O via `FUZZ_TMPDIR` environment variable

## Files

| File | Description |
|------|-------------|
| `tool-callgraph.json` | Full JSON call graph with fidelity data |
| `tool-callgraph.dot` | Graphviz DOT graph |
| `tool-callgraph.svg` | Rendered SVG call graph |
| `README.md` | This report |
