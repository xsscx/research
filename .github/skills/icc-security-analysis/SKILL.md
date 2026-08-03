---
name: icc-security-analysis
description: >
  Full ICC color profile security analysis using CLI tools.
  Runs structural inspection, registry-backed security scan, round-trip
  validation, and generates findings report. Supports ICC profiles, TIFF,
  PNG, and JPEG with embedded ICC extraction.
allowed-tools:
  - bash
  - read
  - grep
  - glob
  - iccTest
---

# ICC Profile Security Analysis

## Overview

Analyze ICC color profiles against ICC.1-2022-05 and ICC.2-2023 specifications,
detecting CVE patterns, CWE violations, malformed structures, and exploitation
vectors. Supports binary ICC profiles and image files with embedded ICC data.

## Workflow

### 1. Structural Inspection

Use `iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile` for header, tag table,
and field values. Identify profile class, color space, PCS, version, creator,
and notable tags.

### 2. Round-Trip and Representation Checks

Use active `iccDEV/Build/Tools/` CLIs for round-trip and representation checks.
Do not hardcode heuristic totals; cite tool output or checked-in registry data.

For profile-representation mutation, use ColorBleed:
`colorbleed_tools/iccToXml_unsafe`, `colorbleed_tools/iccFromXml_unsafe`,
`colorbleed_tools/iccToJson_unsafe`, and `colorbleed_tools/iccFromJson_unsafe`.
Use `colorbleed_tools/qa-roundtrip-colorbleed.sh` for the full ICC -> XML/JSON
-> ICC -> XML converter sweep. Do not use `-sort` with `iccToJson_unsafe`
during ColorBleed QA until that wrapper path is sanitizer-clean.

### 3. Report

Summarize findings by severity and heuristic ID. Note round-trip completeness
and any structural anomalies. For container files (TIFF/PNG/JPEG), state
whether an embedded ICC profile was extracted.

## CLI Commands

```bash
# Header and tag inspection
iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <profile.icc>

# XML/JSON representation checks
iccDEV/Build/Tools/IccToXml/IccToXml <profile.icc> /tmp/profile.xml
iccDEV/Build/Tools/IccToJson/IccToJson <profile.icc> /tmp/profile.json

# Round-trip through XML
iccDEV/Build/Tools/IccFromXml/IccFromXml /tmp/profile.xml /tmp/roundtrip.icc
```

## ICC.1-2022-05 Quick Reference

| Field | Constraint |
|-------|-----------|
| Magic | 'acsp' (0x61637370) at bytes 36-39 |
| Version | BCD: byte 8=major, byte 9=minor.bugfix nibbles |
| PCS D50 | X=0.9642, Y=1.0000, Z=0.8249 at bytes 68-79 |
| Intent | 0-3 only (Perceptual/Relative/Saturation/Absolute) |
| Reserved | Bytes 100-127 must be 0x00 |
| Tag table | No duplicate sigs, no partial overlaps, 4-byte alignment |
| Required | desc + wtpt + cprt + chad (if non-D50) per class |

## Exit Codes

- 0: Clean (no findings)
- 1: Finding detected (NOT a crash)
- 2: Error (malformed input)
- 3: Usage error

## Policy Notes

- Security analysis defaults to V2 engine (`icctest`)
- Structural inspection defaults to V1 engine
- Exit code 1 is NOT a crash -- it means findings were detected
- Report ASAN/UBSAN output verbatim if present
- For parity claims, `verify-parity-summary.json` is the source of truth

## References

- `.github/instructions/iccanalyzer-lite.instructions.md` -- Heuristic details
- `.github/prompts/triage-cve-poc.prompt.yml` -- CVE PoC workflow
- `docs/analysis/` -- Previous analysis reports
