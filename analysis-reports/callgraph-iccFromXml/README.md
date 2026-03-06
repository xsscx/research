# iccFromXml Call Graph & Fuzzer Fidelity Report

**Date**: 2026-03-06
**Tool**: IccFromXml.cpp (115 lines)
**Fuzzer**: icc_fromxml_fuzzer.cpp

---

## 1. Purpose

This report documents the static call graph analysis of `IccFromXml.cpp`
and its fidelity alignment with the `icc_fromxml_fuzzer`. This is the
**primary OOM attack surface** — the XML→ICC parsing pipeline where
most allocation-related vulnerabilities originate.

## 2. Tool Scope

IccFromXml is an **XML parser** tool. It:
1. Registers XML tag and MPE factories
2. Calls `CIccProfileXml::LoadXml()` to parse XML into an ICC profile
3. Validates the parsed profile
4. Saves the result as an ICC file

### API Surface (19 call sites, 16 matched by fuzzer)

| Phase | Call Sites | In Fuzzer | Notes |
|-------|-----------|-----------|-------|
| Factory init | 2 | 2 | Identical in fuzzer's LLVMFuzzerInitialize |
| CLI args | 3 | 0 | -noid, -v flags |
| XML parsing | 2 | 2 | LoadXml, Validate — MAIN ATTACK SURFACE |
| Output | 2 | 2 | SaveIccProfile (both valid and invalid paths) |
| Fuzzer extras | 3 | 3 | XXE protection, error suppression |
| Deep calls | 7 | 7 | Internal LoadXml chain (OOM hotspots) |

### Fidelity: 100.0% (16/16 fuzzable) — NEAR-PERFECT

The fuzzer is an almost exact copy of the tool code (lines 24-109).
Only differences:
1. Schema validation skipped (matches tool default when -v not passed)
2. XXE protection added (xmlSubstituteEntitiesDefault(0))
3. -noid flag hardcoded to false

## 3. OOM Hotspots

| Location | File | Trigger | Patch |
|----------|------|---------|-------|
| CIccLocalizedUnicode copy ctor | IccTagBasic.cpp:7123 | mluc with many entries | 067 |
| ProfileSeqDesc::ParseXml | IccTagXml.cpp | Many ProfileDescription elements | 067 |
| icFixXml (char* overload) | IccUtilXml.cpp:307 | Large XML text → unchecked strcpy | 065 |
| XML entity expansion | libxml2 | Billion laughs attack | XXE disabled |

## 4. Deep Call Chain

```
LLVMFuzzerTestOneInput
  └─ CIccProfileXml::LoadXml
       ├─ xmlParseFile (libxml2 DOM)
       ├─ icXmlParseProfHdr
       └─ CIccTag*::ParseXml (50+ tag types)
            ├─ CIccTagXmlMultiLocalizedUnicode::ParseXml → OOM
            ├─ CIccTagXmlProfileSeqDesc::ParseXml → OOM
            ├─ CIccMpeXml*::ParseXml (calculator)
            └─ icFixXml → BUFFER OVERFLOW
```

## 5. Files

| File | Description |
|------|-------------|
| `tool-callgraph.json` | Full JSON call graph with OOM hotspot data |
| `tool-callgraph.dot` | Graphviz DOT graph (OOM nodes highlighted red) |
| `tool-callgraph.svg` | Rendered SVG call graph |
| `README.md` | This report |

### Generate

```bash
python3 cfl/iccFromXml-callgraph.py --dot graph.dot --render svg
python3 cfl/iccFromXml-callgraph.py --json report.json
```
