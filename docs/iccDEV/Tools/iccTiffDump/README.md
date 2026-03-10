# iccTiffDump

Displays TIFF file metadata and optionally extracts the embedded ICC profile.

## Usage

```
iccTiffDump tiff_file {exported_icc_file}
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `tiff_file` | **Required** | Path to input TIFF image |
| `exported_icc_file` | Optional | Path to save extracted ICC profile |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | TIFF open error or no ICC profile found |

## Examples

### Dump TIFF metadata

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# 8-bit TIFF
iccTiffDump test-profiles/catalyst-8bit-ACESCG.tiff

# 16-bit TIFF
iccTiffDump test-profiles/catalyst-16bit-ITU2020.tiff

# 32-bit TIFF
iccTiffDump test-profiles/catalyst-32bit-ITU709.tiff
```

### Dump TIFFs with interesting ICC variants

```bash
# TIFF with mismatched ICC profile
iccTiffDump test-profiles/catalyst-16bit-mismatch.tiff

# TIFF with mutated ICC profile
iccTiffDump test-profiles/catalyst-16bit-mutated.tiff
```

### Extract ICC profile from TIFF

```bash
# Extract the embedded ICC profile (TIFFTAG_ICCPROFILE, tag 34675)
iccTiffDump test-profiles/catalyst-8bit-ACESCG.tiff /tmp/extracted.icc

# Then inspect the extracted profile
iccDumpProfile /tmp/extracted.icc
```

### Dump spectral TIFF (81 channels)

```bash
# Multi-channel spectral TIFF from iccDEV test data
iccTiffDump iccDEV/Testing/hybrid/Data/smCows380_5_780.tif
```

### Dump fuzzed TIFFs from corpus

```bash
# Test with fuzz corpus TIFFs
iccTiffDump fuzz/graphics/tif/BigEndian-image.tiff
iccTiffDump fuzz/graphics/tif/LittleEndian-image.tiff
```

## Output Format

The output includes:
- **Dimensions**: Width × Height
- **Bits Per Sample**: 8, 16, 32
- **Samples Per Pixel**: 1 (gray), 3 (RGB), 4 (CMYK)
- **Photometric Interpretation**: RGB, MinIsBlack, etc.
- **Compression**: None, LZW, ZIP
- **Planar Configuration**: Contiguous or Separated
- **ICC Profile**: Present/absent, size in bytes

## Security Notes

This tool reads TIFF metadata only — it does NOT process pixel data. However, TIFF
tag parsing can still trigger vulnerabilities:

- IFD offset out-of-bounds (CWE-125)
- Strip/tile geometry mismatch (CWE-122, see CFL-082)
- IFD chain cycles (CWE-835)

For untrusted TIFFs, use ASAN-instrumented build:

```bash
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccTiffDump malicious.tiff
```

**Note**: iccTiffDump reads metadata only — it is NOT affected by the CFL-082
strip buffer vulnerability (that requires ReadLine() for pixel data).

## Tested Configurations

| TIFF Type | BPS | ICC Present | Status |
|-----------|-----|-------------|--------|
| 8-bit RGB | 8 | Yes (ACES CG) | ✅ PASS |
| 16-bit RGB | 16 | Yes (ITU 2020) | ✅ PASS |
| 32-bit RGB | 32 | Yes (ITU 709) | ✅ PASS |
| Mismatched ICC | 16 | Yes (wrong space) | ✅ PASS |
| Mutated ICC | 16 | Yes (corrupted) | ✅ PASS |
| ICC extraction | 8 | Yes → file | ✅ PASS |
| 81-channel spectral | 16 | No | ✅ PASS |

## Related Tools

- [iccApplyProfiles](../iccApplyProfiles/) — Apply ICC transforms to TIFFs
- [iccSpecSepToTiff](../iccSpecSepToTiff/) — Create multi-channel spectral TIFFs
- iccanalyzer-lite: H139-H141, H149-H150 — TIFF security heuristics
- CFL fuzzer: `icc_tiffdump_fuzzer` — Fuzz the TIFF parser

## Version

Built with IccProfLib version 2.3.1.5
