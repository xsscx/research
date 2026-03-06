# iccV5DspObsToV4Dsp Call Graph & Fuzzer Fidelity Report

**Date**: 2026-07-20
**Tool**: IccV5DspObsToV4Dsp.cpp (248 lines)
**Fuzzers**: icc_v5dspobs_fuzzer.cpp (primary), icc_spectral_fuzzer.cpp, icc_spectral_b_fuzzer.cpp

---

## 1. Purpose

This report documents the static call graph analysis of `IccV5DspObsToV4Dsp.cpp`
and its fidelity alignment with three related fuzzers. The tool converts ICC v5
display + observer profiles into a legacy ICC v4 display profile.

## 2. Tool Scope

iccV5DspObsToV4Dsp performs a V5→V4 conversion using direct MPE pipeline operations:
1. Load V5 display profile with spectral emission AToB1 tag
2. Load V5 observer/PCC profile with spectralViewingConditions and C2S tags
3. Extract CurveSet + EmissionMatrix MPE elements from AToB1
4. Initialize MPE pipelines (Begin + GetNewApply)
5. Generate TRC curves (2048 samples × 3 channels via CurveSet Apply)
6. Compute RGB colorant XYZ values (EmissionMatrix → C2S pipeline)
7. Save V4 display profile with TRC + colorant tags

### API Surface (40 call sites, 39 matched by fuzzer)

| Phase | Call Sites | In Fuzzer | Notes |
|-------|-----------|-----------|-------|
| Load display | 2 | 1 | ReadIccProfile with sub-profile flag |
| Validate display | 3 | 3 | Version/class/AToB1 checks |
| MPE validation | 5 | 5 | CurveSet + EmissionMatrix structure |
| Load PCC | 6 | 6 | Observer profile with svcn/c2sp tags |
| MPE init | 5 | 5 | Begin + GetNewApply for both pipelines |
| V4 build | 5 | 5 | Header, description, copyright |
| TRC generation | 3 | 3 | 2048-sample curve generation loop |
| Colorant XYZ | 10 | 10 | RGB primaries through MPE + C2S |
| Output | 1 | 1 | SaveIccProfile |

### Fidelity: 100.0% (39/39 fuzzable) — VERY HIGH

The v5dspobs fuzzer achieves complete coverage of the tool's pipeline.
It uses a split input format (4-byte size prefix + two profile blobs)
to match the tool's two-file input model.

### MPE Pipeline Architecture

```
Display Profile (AToB1):
  CurveSet(3→3)  →  EmissionMatrix(3→spectral)

Observer/PCC Profile (c2sp):
  customToStandardPcc(3→3)  — spectral → XYZ

Combined for colorant computation:
  EmissionMatrix(RGB primary) → C2S(spectral→XYZ) → icDtoF → s15Fixed16
```

### Related Fuzzers

| Fuzzer | Focus |
|--------|-------|
| `icc_v5dspobs_fuzzer` | Full V5→V4 conversion pipeline (primary) |
| `icc_spectral_fuzzer` | Spectral tag Read/Write/Validate paths |
| `icc_spectral_b_fuzzer` | Spectral TIFF profile embedding path |

## 3. Input Format

Split input: `[4-byte BE size][display_profile][observer_profile]`
- First 4 bytes: big-endian uint32 size of display profile
- Next N bytes: display profile (V5 display class with spectral data)
- Remaining bytes: observer/PCC profile (V5 with svcn + c2sp tags)
- Minimum size: 264 bytes | Maximum size: 10MB

## 4. Files

| File | Description |
|------|-------------|
| `tool-callgraph.json` | Full JSON call graph with fidelity data |
| `tool-callgraph.dot` | Graphviz DOT graph |
| `tool-callgraph.svg` | Rendered SVG call graph |
| `README.md` | This report |

### Commands

```bash
python3 .github/scripts/callgraphs/iccV5DspObsToV4Dsp-callgraph.py --dot graph.dot --render svg
python3 .github/scripts/callgraphs/iccV5DspObsToV4Dsp-callgraph.py --json report.json
python3 .github/scripts/callgraphs/iccV5DspObsToV4Dsp-callgraph.py --summary
```
