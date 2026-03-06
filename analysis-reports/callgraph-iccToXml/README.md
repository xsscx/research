# iccToXml Call Graph & Fuzzer Fidelity Report

**Date**: 2026-07-20
**Tool**: IccToXml.cpp (56 lines)
**Fuzzer**: icc_toxml_fuzzer.cpp

---

## 1. Purpose

This report documents the static call graph analysis of `IccToXml.cpp`
and its fidelity alignment with the `icc_toxml_fuzzer`. The tool converts
ICC binary profiles to XML format using the CIccProfileXml class.

## 2. Tool Scope

iccToXml is the simplest tool in the iccDEV suite. It:
1. Registers XML tag/MPE factories
2. Opens and reads an ICC profile via CIccFileIO
3. Calls ToXml() to serialize the profile to an XML string
4. Writes the XML to an output file

### API Surface (15 call sites, 9 matched by fuzzer)

| Phase | Call Sites | In Fuzzer | Notes |
|-------|-----------|-----------|-------|
| Factory init | 2 | 2 | Identical factory registration |
| CLI parsing | 1 | 0 | Usage message guard |
| Profile loading | 2 | 1 | Fuzzer uses CIccMemIO instead of CIccFileIO |
| XML conversion | 2 | 1 | ToXml fully covered; 40MB reserve is tool-only |
| Output writing | 3 | 0 | File I/O — fuzzer discards output |
| Deep calls | 5 | 5 | All tag Read/ToXml paths exercised |

### Fidelity: 64.3% (9/14 fuzzable) — HIGH

The fuzzer exercises the complete Read→ToXml pipeline which is the
security-critical attack surface. File I/O operations are excluded
because the fuzzer feeds profile data via CIccMemIO.

### OOM Concerns

- `std::string::reserve(40000000)` — tool always pre-allocates 40MB for XML output
- Large CLUT/curve tags can generate XML exceeding 40MB, triggering reallocation

## 3. Input Format

Raw ICC profile binary data (entire fuzzer input is the profile).
- Minimum size: 128 bytes
- Maximum size: 5MB

## 4. Files

| File | Description |
|------|-------------|
| `tool-callgraph.json` | Full JSON call graph with fidelity data |
| `tool-callgraph.dot` | Graphviz DOT graph |
| `tool-callgraph.svg` | Rendered SVG call graph |
| `README.md` | This report |

### Commands

```bash
python3 .github/scripts/callgraphs/iccToXml-callgraph.py --dot graph.dot --render svg
python3 .github/scripts/callgraphs/iccToXml-callgraph.py --json report.json
python3 .github/scripts/callgraphs/iccToXml-callgraph.py --summary
```
