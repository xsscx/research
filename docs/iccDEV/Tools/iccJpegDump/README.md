# iccJpegDump

Extracts ICC profiles from JPEG images (APP2 markers) or injects ICC profiles into JPEG images.

## Usage

### Extract ICC profile

```
iccJpegDump <input.jpg> [output.icc]
```

### Inject ICC profile

```
iccJpegDump <input.jpg> --write-icc <profile.icc> --output <output.jpg>
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `input.jpg` | **Required** | Path to input JPEG image |
| `output.icc` | Optional | Path to save extracted ICC profile |
| `--write-icc profile.icc` | Optional | ICC profile to inject |
| `--output output.jpg` | Required with --write-icc | Path for output JPEG |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success — ICC profile found and extracted/injected |
| 1 | No ICC profile found in JPEG (graceful — NOT a crash) |

## Examples

### Extract ICC from JPEG

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# Extract ICC profile from a JPEG with embedded ICC
iccJpegDump fuzz/graphics/jpg/CVE-2022-26730-variant-009.jpg /tmp/extracted.icc

# Inspect the extracted profile
iccDumpProfile /tmp/extracted.icc
```

### Check for ICC profile (no extraction)

```bash
# Just dump — exit 0 = has ICC, exit 1 = no ICC
iccJpegDump input.jpg
```

### Inject ICC profile into JPEG

```bash
# Inject sRGB profile into a JPEG
iccJpegDump input.jpg --write-icc test-profiles/sRGB_D65_MAT.icc --output /tmp/injected.jpg

# Verify injection
iccJpegDump /tmp/injected.jpg /tmp/verify.icc
```

### Batch check fuzz corpus JPEGs

```bash
for jpg in fuzz/graphics/jpg/*.jpg; do
  result=$(iccJpegDump "$jpg" 2>&1)
  echo "$jpg: exit=$?"
done
```

## ICC in JPEG Format

JPEG files embed ICC profiles in APP2 markers with the `ICC_PROFILE\0` identifier.
Large profiles (>64KB) are split across multiple APP2 segments with sequence numbers.

The extraction handles:
- Single APP2 segment (profiles < 64KB)
- Multi-segment reassembly (profiles ≥ 64KB)
- EXIF-based ICC profile references

## Known Limitations

- JPEGs without ICC profiles return exit 1 (this is expected, not an error)
- Some fuzzed JPEGs may have corrupted APP2 markers — tool handles gracefully

## Tested Configurations

| Test | Input | ICC Present | Status |
|------|-------|-------------|--------|
| CVE JPEG extraction | CVE-2022-26730 | Yes | ✅ PASS |
| Gray JPEG | 2x2-gray--LCDDisplay.jpg | No | ✅ exit 1 (expected) |
| Crash JPEG | LittleEndian-crash.jpg | No | ✅ exit 1 (expected) |
| ICC injection | sRGB into JPEG | N/A | ✅ PASS |

## Related Tools

- [iccPngDump](../iccPngDump/) — Extract/inject ICC from PNG files
- [iccTiffDump](../iccTiffDump/) — Extract ICC from TIFF files
- iccanalyzer-lite: JPEG ICC extraction via APP2 multi-segment reassembly

## Version

Built with IccProfLib version 2.3.1.5
