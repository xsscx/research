# iccToXml

Converts a binary ICC profile to XML format for human-readable inspection and editing.

## Usage

```
IccToXml src_icc_profile dest_xml_file
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `src_icc_profile` | **Required** | Path to input ICC profile (.icc) |
| `dest_xml_file` | **Required** | Path for output XML file (.xml) |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | Error reading profile or writing XML |

## Examples

### Basic conversion

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# Convert sRGB Display profile
iccToXml test-profiles/sRGB_D65_MAT.icc /tmp/sRGB.xml

# Convert CMYK Output profile
iccToXml test-profiles/CMYK-3DLUTs2.icc /tmp/CMYK.xml

# Convert NamedColor profile
iccToXml test-profiles/NamedColor.icc /tmp/NamedColor.xml
```

### Convert v5/iccMAX profiles

```bash
# v5 Spectral profile
iccToXml test-profiles/Rec2020rgbSpectral.icc /tmp/Rec2020.xml

# 17-channel Input profile
iccToXml test-profiles/17ChanPart1.icc /tmp/17Chan.xml

# v5 LCDDisplay profile
iccToXml iccDEV/Testing/Display/LCDDisplay.icc /tmp/LCDDisplay.xml
```

### Convert DisplayP3 profile

```bash
iccToXml test-profiles/ios-gen-DisplayP3.icc /tmp/DisplayP3.xml
```

## Output Format

The XML output uses the IccLibXML schema with elements for:
- `<IccProfile>` root element with version and class attributes
- `<Header>` — all header fields as XML elements
- `<Tags>` — each tag as a typed XML element with decoded values

## Round-Trip Workflow

Use with [iccFromXml](../iccFromXml/) for round-trip testing:

```bash
# ICC → XML → ICC
iccToXml original.icc /tmp/profile.xml
iccFromXml /tmp/profile.xml /tmp/roundtrip.icc

# Compare
diff <(xxd original.icc) <(xxd /tmp/roundtrip.icc)
```

## Profile Classes Tested

| Class | Example Profile | Status |
|-------|----------------|--------|
| Display (mntr) | sRGB_D65_MAT.icc | ✅ PASS |
| Output (prtr) | CMYK-3DLUTs2.icc | ✅ PASS |
| NamedColor (nmcl) | NamedColor.icc | ✅ PASS |
| Input (scnr) | 17ChanPart1.icc | ✅ PASS |
| ColorSpace (spac) | LCDDisplay.icc | ✅ PASS |

## Security Notes

For untrusted profiles, use ASAN-instrumented build:

```bash
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccToXml suspicious.icc /tmp/output.xml
```

Known XML serialization crash patterns are detected by iccanalyzer-lite heuristics H142-H145.

## Related Tools

- [iccFromXml](../iccFromXml/) — Convert XML back to ICC binary
- [iccDumpProfile](../iccDumpProfile/) — Text dump without XML conversion
- [colorbleed_tools](../../../../colorbleed_tools/) — Unsafe ICC↔XML for mutation testing

## Version

Built with IccProfLib Version 2.3.1.5, IccLibXML Version 2.3.1.5
