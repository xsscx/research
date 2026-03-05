# iccDumpProfile Call Graph & Fuzzer Fidelity Report

**Date**: 2026-02-12 (original), updated 2026-03-05
**Tool commit**: 6c44e39 (iccDumpProfile callgraph analysis)
**Current state**: 19 fuzzers, 67 patches, 102 security heuristics (v3.3.0)

---

## 1. Purpose

This report documents the static call graph analysis of `iccDumpProfile.cpp`
(the primary iccDEV profile dump tool) and its fidelity alignment with the
`icc_deep_dump_fuzzer`. The analysis ensures fuzzer coverage accurately
mirrors the tool's actual attack surface — no more, no less.

## 2. Tool Scope: iccDumpProfile.cpp

iccDumpProfile.cpp is a **display-only** ICC profile tool. It parses profiles
and dumps their contents — it **never executes** tag data.

### API Surface (54 call sites, 48 fuzzable)

| Category | Calls | In Scope |
|----------|-------|----------|
| Profile loading | `ValidateIccProfile`, `OpenIccProfile` | ✅ |
| Tag access | `FindTag`, `GetType`, `IsArrayType` | ✅ |
| Tag display | `Describe` | ✅ |
| Tag validation | `Validate`, `icMaxStatus` | ✅ |
| Header formatting | `Fmt.Get*Name` (13 variants) | ✅ |
| Signature decode | `icGetSig`, `icF16toF`, `icFtoD` | ✅ |
| Tag table analysis | `std::sort`, `std::upper_bound`, `unordered_map` | ✅ |
| **Tag execution** | **`Begin`, `Apply`** | **❌ OUT OF SCOPE** |
| **CMM transforms** | **`AddXform`, `Begin`, `Apply`** | **❌ OUT OF SCOPE** |
| **Re-read/Attach** | **`Attach`, `LoadTag`** | **❌ OUT OF SCOPE** |

### AST Gates (24 total, 12 security-relevant)

Security-critical gates control:
- NULL deref guards (pTag != NULL)
- Validation vs non-validating read path (-v flag)
- Profile load failure handling
- Spectral/biSpectral float parsing (icF16toF anomalous values)
- Tag boundary checks (OOB, overlap, gap, alignment)
- Tag iteration mode (ALL vs single tag)

---

## 3. Fidelity Alignment

The deep_dump fuzzer was aligned to match iccDumpProfile's actual API surface.
Code paths outside the tool's scope were removed to avoid false crashes.

### Removed (out of iccDumpProfile scope)

| Function | Lines Removed | Reason |
|----------|---------------|--------|
| `pMPE->Begin(icElemInterpLinear)` | ExerciseTags:636 | Tool calls Describe/Validate, not Begin |
| `pMPE->Begin(icElemInterpLinear)` | ExerciseCalculatorTags:833 | Same — Begin enters execution path |
| `pCurve->Apply(0.5f)` | ExerciseTags:737 | Tool calls Describe on curves, not Apply |
| `ExerciseCMM()` | Phase 5 (68 lines) | Tool never does CMM transforms |
| `ExerciseAttach()` | Phase 6 (26 lines) | Tool never re-reads via Attach |

### Retained (in iccDumpProfile scope)

| Function | Why |
|----------|-----|
| `ExerciseTags` | Mirrors DumpTagEntry→FindTag→DumpTagCore flow |
| `ExerciseCalculatorTags` | Validate + Describe on MPE tags (minus Begin) |
| `ExerciseSignatureLookups` | Rendering intent + technology signature coverage |
| `AnalyzeHeader` | Header field analysis matching tool output |
| `AnalyzeTagStructure` | Tag table structural integrity checks |
| `CIccMemIO::Attach` + `Read` | OpenIccProfile non-validating path |

### Fidelity Metrics

```
Fuzzable call sites:  48  (54 total - 6 CLI-only)
Matched by fuzzer:    45  (93.8%)
Missed:                3  (icMaxStatus variants)
CLI-only excluded:     6  (printUsage, strncmp, strtol, icGetSigVal, DumpTagSig)
```

---

## 4. Crash Stack Analysis

The original crash that prompted this alignment:

```
#0 CIccCalculatorFunc::InitSelectOp  IccMpeCalc.cpp:3663  ← CRASH
#1 CIccCalculatorFunc::InitSelectOps IccMpeCalc.cpp:3634
#2 CIccCalculatorFunc::Begin         IccMpeCalc.cpp:3597
#3 CIccMpeCalculator::Begin          IccMpeCalc.cpp:4878
#4 CIccTagMultiProcessElement::Begin IccTagMPE.cpp:1331
#5 ExerciseTags                      icc_deep_dump_fuzzer.cpp:636
```

**Root cause**: The fuzzer called `pMPE->Begin()` which enters the MPE
calculator execution path — a code path that iccDumpProfile.cpp **never
takes**. iccDumpProfile only calls `pTag->Describe()` and `pTag->Validate()`
on MPE tags.

**Fix**: Removed `Begin()` call from ExerciseTags. The crash path is now
unreachable from the fuzzer, which correctly reflects the tool's actual
attack surface.

---

## 5. Fuzzer Coverage Map

The 19 CFL fuzzers collectively cover all iccDEV tool API surfaces.
This callgraph analysis was done for `iccDumpProfile` (the largest tool).
Similar analyses would be valuable for:

| Tool | Fuzzer(s) | API Surface | Status |
|------|-----------|-------------|--------|
| iccDumpProfile | dump, deep_dump, profile, calculator, multitag | Describe, Validate, FindTag | ✅ Aligned |
| iccRoundTrip | io, roundtrip | Read, Write, EvaluateProfile | Not analyzed |
| iccApplyProfiles | apply, applyprofiles | CIccCmm: AddXform, Begin, Apply | Not analyzed |
| iccApplyNamedCmm | applynamedcmm | CIccNamedColorCmm | Not analyzed |
| iccApplyToLink | link | CIccCmm 2-profile link | Not analyzed |
| IccV5DspObsToV4Dsp | spectral, spectral_b, v5dspobs | MPE pipeline | Not analyzed |
| XML tools | fromxml, toxml | LoadXml, ToXml | Not analyzed |
| IccFromCube | fromcube | CUBE LUT import | Not analyzed |
| IccSpecSepToTiff | specsep | CTiffImg pipeline | Not analyzed |
| IccTiffDump | tiffdump | CTiffImg, FindTag | Not analyzed |

---

## 6. Files

| File | Description |
|------|-------------|
| `tool-callgraph.json` | Full JSON call graph with fidelity data (54 call sites) |
| `tool-callgraph.dot` | Graphviz DOT graph of iccDumpProfile |
| `tool-callgraph.svg` | Rendered SVG call graph |
| `fuzzer-callgraph.json` | Deep dump fuzzer call graph (pre-alignment) |
| `README.md` | This report |

### Render DOT graph

```bash
dot -Tpng tool-callgraph.dot -o tool-callgraph.png
dot -Tsvg tool-callgraph.dot -o tool-callgraph.svg
```

### Generate callgraph from source

```bash
python3 cfl/iccDumpProfile-callgraph.py --dot graph.dot --render svg
python3 cfl/iccDumpProfile-callgraph.py --fuzzer cfl/icc_deep_dump_fuzzer.cpp --format json
```

---

## 7. Relationship to iccanalyzer-lite

iccanalyzer-lite has its own callgraph module (`IccAnalyzerCallGraph.cpp`, 486 LOC)
that generates DOT/JSON callgraph output via the `-cg` flag. This report is
complementary — it analyzes the **iccDEV tools** rather than iccanalyzer-lite itself.

The callgraph analysis methodology could be extended to all 16 iccDEV CLI tools
and all 19 fuzzers to create a complete fidelity matrix.
