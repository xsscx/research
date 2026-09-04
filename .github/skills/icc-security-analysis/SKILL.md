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

For a repository-wide image-fixture audit, inventory tracked files with
`git ls-files` rather than a default glob so hidden regression inputs are not
missed. Report untracked or generated images separately. For TIFF containers,
compare raw `tiffdump` tag values, types, and counts with a libtiff-backed read;
do not infer bit depth or format correctness from a filename. A successful exit
does not erase a structural warning.

### 2. PAWG, Round-Trip, and Representation Checks

Use active `iccDEV/Build/Tools/` CLIs for round-trip and representation checks.
Do not hardcode heuristic totals; cite tool output or checked-in registry data.
Run `iccPawgReport` in text and JSON modes for the current PAWG security,
conformance, and quality assessment. When using MCP or REST, follow the
`iccdev-pawg-mcp` skill and discover runtime capabilities.

For profile-representation mutation, use ColorBleed:
`colorbleed_tools/iccToXml_unsafe`, `colorbleed_tools/iccFromXml_unsafe`,
`colorbleed_tools/iccToJson_unsafe`, and `colorbleed_tools/iccFromJson_unsafe`.
For TIFF containers, run `colorbleed_tools/iccTiffDump_unsafe` first so the
TIFF directory dump, sandbox status, and byte-exact embedded ICC artifact are
preserved even when iccDEV parsing or validation fails.
Use `colorbleed_tools/qa-roundtrip-colorbleed.sh` for the full ICC -> XML/JSON
-> ICC -> XML converter and TIFF extraction sweep. Do not use `-sort` with `iccToJson_unsafe`
during ColorBleed QA until that wrapper path is sanitizer-clean.
The default TIFF QA input is the intentionally tracked
`colorbleed_tools/test-data/1x1-rgb8--sRGB_v4_ICC_preference.tiff`. Exit 66
indicates a missing or unresolved input path, not a TIFF or ICC parser finding.
On upstream iccDEV `3e348201` or later, exit 5 can follow successful extraction
when bounded recursive tag loading rejects a deeply nested profile. Retain and
compare the extracted bytes, and classify the result as a soft parser failure
unless sanitizer or signal evidence proves a crash.

### 3. Report

Summarize findings by severity and heuristic ID. Note round-trip completeness
and any structural anomalies. For container files (TIFF/PNG/JPEG), state
whether an embedded ICC profile was extracted.

## CLI Commands

```bash
# Header and tag inspection
iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <profile.icc>

# PAWG assessment
iccDEV/Build/Tools/IccPawgReport/iccPawgReport --json <profile.icc>

# Sandboxed TIFF inspection and byte-exact ICC extraction
colorbleed_tools/iccTiffDump_unsafe <input.tif> /tmp/embedded.icc

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

- `iccPawgReport` and `iccdev-mcp` are the active upstream analyzer surfaces.
- Retired analyzer parity files are historical and are not current release
  evidence.
- Exit code 1 is a soft failure unless signal or sanitizer evidence proves a
  crash.
- Report ASAN/UBSAN output verbatim if present.

## References

- `.github/skills/iccdev-pawg-mcp/SKILL.md` -- PAWG, MCP, REST, and container validation
- `.github/prompts/triage-cve-poc.prompt.md` -- CVE PoC workflow
- `docs/analysis/` -- Previous analysis reports
