# iccFromXml

Reconstructs a binary ICC profile from an XML representation.

## Usage

```
IccFromXml xml_file saved_profile_file {-noid -v{=[relax_ng_schema_file]}}
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `xml_file` | **Required** | Path to input XML file (.xml) |
| `saved_profile_file` | **Required** | Path for output ICC profile (.icc) |
| `-noid` | Optional | Skip Profile ID (MD5) calculation |
| `-v` | Optional | Validate XML against RelaxNG schema |
| `-v=schema.rng` | Optional | Validate against specified schema file |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | XML parse error or profile creation failure |

## Examples

### Basic XML to ICC conversion

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# First create XML from an existing profile
iccToXml test-profiles/sRGB_D65_MAT.icc /tmp/sRGB.xml

# Reconstruct ICC from XML
iccFromXml /tmp/sRGB.xml /tmp/sRGB_reconstructed.icc
```

### Skip Profile ID calculation

The `-noid` flag skips the MD5 Profile ID computation, useful for testing:

```bash
iccFromXml /tmp/sRGB.xml /tmp/sRGB_noid.icc -noid
```

### Round-trip different profile classes

```bash
# CMYK Output profile
iccToXml test-profiles/CMYK-3DLUTs2.icc /tmp/CMYK.xml
iccFromXml /tmp/CMYK.xml /tmp/CMYK_rt.icc

# NamedColor profile
iccToXml test-profiles/NamedColor.icc /tmp/NamedColor.xml
iccFromXml /tmp/NamedColor.xml /tmp/NamedColor_rt.icc

# v5 Spectral profile
iccToXml test-profiles/Rec2020rgbSpectral.icc /tmp/Rec2020.xml
iccFromXml /tmp/Rec2020.xml /tmp/Rec2020_rt.icc
```

### Parse upstream test XMLs

The iccDEV Testing/ directory contains canonical XML sources:

```bash
iccFromXml iccDEV/Testing/Display/LCDDisplay.xml /tmp/LCDDisplay.icc
```

## Mutation Testing Workflow

Create modified profiles by editing the intermediate XML:

```bash
# 1. Convert to XML
iccToXml original.icc /tmp/original.xml

# 2. Edit XML (e.g., change colorSpace, modify LUT values)
sed -i 's/RGB/CMYK/' /tmp/original.xml

# 3. Reconstruct modified profile
iccFromXml /tmp/original.xml /tmp/mutated.icc

# 4. Test the mutated profile
iccDumpProfile /tmp/mutated.icc
```

## Profile Classes Tested

| Class | Example | Status |
|-------|---------|--------|
| Display (mntr) | sRGB → XML → ICC | ✅ PASS |
| Output (prtr) | CMYK → XML → ICC | ✅ PASS |
| NamedColor (nmcl) | NamedColor → XML → ICC | ✅ PASS |
| Display v5 | Rec2020 → XML → ICC | ✅ PASS |
| Display v5 | LCDDisplay.xml → ICC | ✅ PASS |

## Related Tools

- [iccToXml](../iccToXml/) — Convert ICC to XML (the inverse operation)
- [iccDumpProfile](../iccDumpProfile/) — Verify reconstructed profiles
- CFL fuzzer: `icc_fromxml_fuzzer` — Fuzz the XML→ICC parser

## Version

Built with IccProfLib Version 2.3.1.5, IccLibXML Version 2.3.1.5
