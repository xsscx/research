# iccPngDump

Extracts ICC profiles from PNG images (iCCP chunk) or injects ICC profiles into PNG images.

## Usage

### Extract ICC profile

```
iccPngDump <input.png> [output.icc]
```

### Inject ICC profile

```
iccPngDump <input.png> --write-icc <profile.icc> --output <output.png>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `input.png` | **Required** | Path to input PNG image |
| `output.icc` | Optional | Path to save extracted ICC profile |
| `--write-icc profile.icc` | Optional | ICC profile to inject |
| `--output output.png` | Required with --write-icc | Path for output PNG |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success — ICC profile found and extracted/injected |
| 1 | No ICC profile found in PNG |

## Examples

### Extract ICC from PNG

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# Extract from CVE-related PNG
iccPngDump fuzz/graphics/png/CVE-2022-26730-variant-009.png /tmp/extracted.icc

# Inspect extracted profile
iccDumpProfile /tmp/extracted.icc
```

### Check for ICC profile

```bash
# Dump PNG ICC info
iccPngDump fuzz/graphics/png/BigEndian-image--Rec2100HlgFull.png
iccPngDump fuzz/graphics/png/BigEndian-image--calcOverMem_tget.png
```

### Inject ICC profile into PNG

```bash
# Inject sRGB profile
iccPngDump input.png --write-icc test-profiles/sRGB_D65_MAT.icc --output /tmp/injected.png

# Verify
iccPngDump /tmp/injected.png /tmp/verify.icc
```

## ICC in PNG Format

PNG files embed ICC profiles in the `iCCP` chunk. The profile data is zlib-compressed
within the chunk. The `iCCP` chunk contains:
- Profile name (1–79 bytes, null-terminated)
- Compression method (always 0 = deflate)
- Compressed ICC profile data

## Tested Configurations

| Test | Input | ICC Present | Status |
|------|-------|-------------|--------|
| CVE PNG extraction | CVE-2022-26730 | Yes | ✅ PASS |
| Rec2100 HLG PNG | BigEndian Rec2100 | Yes | ✅ PASS |
| Calculator PNG | calcOverMem | Yes | ✅ PASS |
| ICC injection | sRGB into PNG | N/A | ✅ PASS |

## Related Tools

- [iccJpegDump](../iccJpegDump/) — Extract/inject ICC from JPEG files
- [iccTiffDump](../iccTiffDump/) — Extract ICC from TIFF files
- iccanalyzer-lite: PNG ICC extraction via `png_get_iCCP()` (iCCP chunk)

## Version

Built with IccProfLib version 2.3.1.5
