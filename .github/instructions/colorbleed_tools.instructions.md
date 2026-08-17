---
applyTo: "colorbleed_tools/**"
---

# colorbleed_tools - Path-Specific Instructions

## What This Is

Unsafe ICC representation and TIFF extraction tools for mutation testing,
profile generation, and forensic container analysis.
Release/debug builds keep the real-world unsafe conversion surface, while the
default clang build is sanitizer-instrumented for QA and crash attribution.

## Build

```bash
cd colorbleed_tools && make setup && make
```

- `make setup`: clones iccDEV and builds the C++ library
- `make`: compiles `iccToXml_unsafe`, `iccFromXml_unsafe`,
  `iccToJson_unsafe`, `iccFromJson_unsafe`, and `iccTiffDump_unsafe`
- `make qa`: runs the XML/JSON/TIFF/blob round-trip QA script
- Binaries: `colorbleed_tools/iccToXml_unsafe`,
  `colorbleed_tools/iccFromXml_unsafe`, `colorbleed_tools/iccToJson_unsafe`,
  `colorbleed_tools/iccFromJson_unsafe`, `colorbleed_tools/iccTiffDump_unsafe`
- These are intentionally unsafe wrappers around unpatched iccDEV parser code.

## Purpose

1. **ICC -> XML**: Convert binary ICC profiles to human-readable XML for inspection
2. **XML -> ICC**: Reconstruct ICC profiles from XML (enables manual mutation testing)
3. **ICC -> JSON**: Convert binary ICC profiles to IccJSON for structured mutation
4. **JSON -> ICC**: Reconstruct ICC profiles from IccJSON
5. **TIFF -> ICC**: Dump TIFF structure and preserve embedded ICC bytes for analysis
6. **Round-trip testing**: ICC -> XML/JSON -> ICC to verify parse/serialize fidelity
7. **Crash reproduction**: Run release/debug builds for real-world behavior
   checks, then sanitizer builds for attribution and regression gates.

## Usage

```bash
# Convert ICC to XML
./iccToXml_unsafe input.icc output.xml

# Convert XML to ICC
./iccFromXml_unsafe input.xml output.icc

# Convert ICC to JSON
./iccToJson_unsafe input.icc output.json

# Convert JSON to ICC
./iccFromJson_unsafe input.json output.icc

# Dump TIFF structure, ICC diagnostics, and exact embedded profile bytes
./iccTiffDump_unsafe input.tif output.icc

# Round-trip test
./qa-roundtrip-colorbleed.sh

# Strict sanitizer reproducer mode
COLORBLEED_STRICT_SANITIZERS=1 ./iccFromXml_unsafe input.xml /tmp/out.icc
```

Do not pass `-sort` to `iccToJson_unsafe` in ColorBleed QA. The wrapper rejects
that option with exit code 64 until the sorted JSON writer path is
sanitizer-clean.

## Integration with iccanalyzer-lite

The analyzer's `-r` (round-trip) mode uses `iccToXml_unsafe` to convert profiles
to XML for structural comparison. If these binaries are missing, the round-trip
analysis phase is skipped.

## Security Considerations

- These tools process UNTRUSTED input - they are attack surface
- Use release/debug builds for unsanitized behavior checks, and sanitizer builds
  for finding attribution and regression gates.
- Crashes in these tools indicate real vulnerabilities in iccDEV
- Sanitizer builds suppress only known-benign STL/libstdc++ template noise in
  `sanitizer-ignorelist.txt` and `silence.txt`. Keep iccDEV parser UB visible
  unless an operation is proven intentional and well-defined.
- Set `COLORBLEED_STRICT_SANITIZERS=1` when a reproducer must exit on the first
  ASAN/UBSAN report. Strict sanitizer findings exit with code 86.
- When a crash is found:
  1. Minimize with `cfl/bin/icc_toxml_fuzzer -minimize_crash=1 <crash_file>`
  2. Report to upstream: `github.com/InternationalColorConsortium/iccDEV/issues`
  3. Create a CFL patch if the fix is straightforward

## File Structure

```
colorbleed_tools/
|-- Makefile           # Build system
|-- build.sh           # Alternative build script
|-- Readme.md          # Usage documentation
|-- qa-roundtrip-colorbleed.sh # XML/JSON/TIFF/blob QA sweep
|-- sanitizer-ignorelist.txt # Compile-time sanitizer ignorelist
|-- silence.txt        # Runtime UBSAN suppressions for ad hoc reproductions
|-- iccToXml_unsafe    # Binary: ICC -> XML converter (built, not committed)
|-- iccFromXml_unsafe  # Binary: XML -> ICC converter (built, not committed)
|-- iccToJson_unsafe   # Binary: ICC -> JSON converter (built, not committed)
|-- iccFromJson_unsafe # Binary: JSON -> ICC converter (built, not committed)
`-- iccTiffDump_unsafe # Binary: TIFF dump and ICC extractor (built, not committed)
```

## Logging Convention

These tools log warnings and errors to stderr:
```
WARNING: Tag 'desc' has unexpected type signature
ERROR: Failed to read tag data at offset 0x1234
```

Stdout is reserved for status and structured dump messages. Converted XML,
JSON, and extracted ICC bytes are written to the requested output path.
