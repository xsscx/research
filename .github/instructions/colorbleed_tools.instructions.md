---
applyTo: "colorbleed_tools/**"
---

# colorbleed_tools — Path-Specific Instructions

## What This Is

Unsafe ICC↔XML conversion tools for mutation testing and profile generation.
These are deliberately built WITHOUT sanitizer hardening to match how typical
applications consume ICC profiles — exposing real-world crash surfaces.

## Build

```bash
cd colorbleed_tools && make setup && make
```

- `make setup`: clones iccDEV, builds the C++ library without ASAN
- `make`: compiles `iccToXml_unsafe` and `iccFromXml_unsafe`
- Binaries: `colorbleed_tools/iccToXml_unsafe`, `colorbleed_tools/iccFromXml_unsafe`
- These are intentionally UNsafe — no ASAN, no bounds checks beyond library defaults

## Purpose

1. **ICC → XML**: Convert binary ICC profiles to human-readable XML for inspection
2. **XML → ICC**: Reconstruct ICC profiles from XML (enables manual mutation testing)
3. **Round-trip testing**: ICC → XML → ICC to verify parse/serialize fidelity
4. **Crash reproduction**: Run against known-bad profiles without ASAN to see
   real-world behavior (crashes, hangs, incorrect output)

## Usage

```bash
# Convert ICC to XML
./iccToXml_unsafe input.icc output.xml

# Convert XML to ICC
./iccFromXml_unsafe input.xml output.icc

# Round-trip test
./iccToXml_unsafe test.icc /tmp/test.xml
./iccFromXml_unsafe /tmp/test.xml /tmp/test_rt.icc
diff <(xxd test.icc) <(xxd /tmp/test_rt.icc)
```

## Integration with MCP Server

The MCP server's `profile_to_xml` and `upload_and_analyze` tools use these binaries:
```python
# In mcp-server/icc_profile_mcp.py
ICCTOXML = "colorbleed_tools/iccToXml_unsafe"
ICCFROMXML = "colorbleed_tools/iccFromXml_unsafe"
```

## Integration with iccanalyzer-lite

The analyzer's `-r` (round-trip) mode uses `iccToXml_unsafe` to convert profiles
to XML for structural comparison. If these binaries are missing, the round-trip
analysis phase is skipped.

## Security Considerations

- These tools process UNTRUSTED input — they are attack surface
- Do NOT add ASAN/UBSAN — the point is to test without sanitizers
- Crashes in these tools indicate real vulnerabilities in iccDEV
- When a crash is found:
  1. Minimize with `cfl/bin/icc_toxml_fuzzer -minimize_crash=1 <crash_file>`
  2. Report to upstream: `github.com/InternationalColorConsortium/iccDEV/issues`
  3. Create a CFL patch if the fix is straightforward

## File Structure

```
colorbleed_tools/
├── Makefile           # Build system
├── build.sh           # Alternative build script
├── Readme.md          # Usage documentation
├── iccToXml_unsafe    # Binary: ICC → XML converter (built, not committed)
└── iccFromXml_unsafe  # Binary: XML → ICC converter (built, not committed)
```

## Logging Convention

These tools log warnings and errors to stderr:
```
WARNING: Tag 'desc' has unexpected type signature
ERROR: Failed to read tag data at offset 0x1234
```

Stdout is reserved for the XML output (iccToXml) or status messages (iccFromXml).
