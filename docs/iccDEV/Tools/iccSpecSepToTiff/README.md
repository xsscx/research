# iccSpecSepToTiff

Concatenates several spectral separation TIFF files into a single multi-channel TIFF,
with optional embedded ICC profile.

## Usage

```
iccSpecSepToTiff output compress sep infile_fmt start end incr {profile}
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `output` | **Required** | Path for output TIFF file |
| `compress` | **Required** | 0=No compression, 1=Compressed |
| `sep` | **Required** | 0=Contiguous, 1=Separated planes |
| `infile_fmt` | **Required** | printf format string for input files (e.g., `spec_%06d.tiff`) |
| `start` | **Required** | First channel number |
| `end` | **Required** | Last channel number |
| `incr` | **Required** | Increment between channels |
| `profile` | Optional | ICC profile to embed in output TIFF |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 255 (-1) | Input file not found or invalid TIFF format |

## Examples

### Merge spectral TIFF sequence

Given spectral separation TIFFs named `spec_000380.tiff` through `spec_000780.tiff`
at 5nm intervals:

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# Merge 380nm–780nm at 5nm steps (81 channels)
iccSpecSepToTiff /tmp/spectral_merged.tiff 0 0 \
  "spec_%06d.tiff" 380 780 5

# With compression and embedded spectral ICC profile
iccSpecSepToTiff /tmp/spectral_merged.tiff 1 0 \
  "spec_%06d.tiff" 380 780 5 \
  test-profiles/Rec2020rgbSpectral.icc
```

### Using iccDEV test data

```bash
# The iccDEV Testing/ directory has spectral TIFF test data
# Check what's available
ls iccDEV/Testing/hybrid/Data/

# Note: smCows380_5_780.tif is already a merged spectral TIFF (81 channels)
# SpecSepToTiff expects separated single-channel TIFFs as input
```

### Separated planes output

```bash
iccSpecSepToTiff /tmp/spectral_sep.tiff 0 1 \
  "spec_%06d.tiff" 380 780 5
```

## Spectral TIFF Pipeline

```
Individual spectral TIFFs          Multi-channel TIFF
  spec_000380.tiff ─┐
  spec_000385.tiff  ├──→ iccSpecSepToTiff ──→ spectral_merged.tiff (81 channels)
  spec_000390.tiff  │
  ...               │
  spec_000780.tiff ─┘
```

## Creating Test Input

Pre-built spectral seed TIFFs are available at `iccDEV/Testing/Fuzzing/seeds/tiff/spectral/` (147 files).
Each series consists of single-channel (SPP=1) MINISBLACK TIFFs with sequential numbering:

```bash
# 4×4 8-bit baseline series (10 channels)
ls iccDEV/Testing/Fuzzing/seeds/tiff/spectral/spec_*.tif

# Full visible spectrum 8-bit (380–780nm at 5nm, 81 channels)
ls iccDEV/Testing/Fuzzing/seeds/tiff/spectral/wl_*.tif

# 8×8 8-bit series
ls iccDEV/Testing/Fuzzing/seeds/tiff/spectral/ch8_*.tif

# 16-bit all-white series
ls iccDEV/Testing/Fuzzing/seeds/tiff/spectral/white_*.tif

# 256×256 large image series
ls iccDEV/Testing/Fuzzing/seeds/tiff/spectral/lg_*.tif

# BigTIFF format series
ls iccDEV/Testing/Fuzzing/seeds/tiff/spectral/big_*.tif
```

To create custom sequential TIFFs, use Python with the `tifffile` library or
any tool that generates single-channel TIFF images. Requirements:
- All input TIFFs must have identical dimensions
- 1 sample per pixel (MINISBLACK photometric)
- 8-bit or 16-bit BitsPerSample

## Input Requirements

| Parameter | Required Value | Notes |
|-----------|---------------|-------|
| SamplesPerPixel | 1 | Multi-channel TIFFs are rejected (exit 255) |
| Photometric | MINISBLACK or MINISWHITE | RGB/CMYK/etc. are rejected |
| BitsPerSample | 8 or 16 | 32-bit float is rejected |
| Dimensions | Identical across all inputs | Width and height must match exactly |

The source code enforces these requirements at line 120:
`const int minargs = 8; // argc = 8 without profile, 9 with profile`

## ICC Profile Embedding

When an optional ICC profile argument is provided (`argc > 8`), the tool:

1. Opens the ICC profile via `CIccFileIO::Open()` → `Read8()` → `GetLength()`
2. Embeds the raw ICC bytes into the output TIFF via `SetIccProfile()`
3. The ICC data appears as TIFFTAG_ICCPROFILE (tag 34675) in the output

```bash
# Embed a spectral ICC profile
iccSpecSepToTiff /tmp/out.tiff 0 0 \
  "iccDEV/Testing/Fuzzing/seeds/tiff/spectral/spec_%03d.tif" 1 10 1 \
  test-profiles/Rec2020rgbSpectral.icc

# Verify embedding
iccTiffDump /tmp/out.tiff /tmp/extracted.icc
iccDumpProfile /tmp/extracted.icc
```

## Known Limitations

- Requires sequential TIFF files matching the printf format exactly
- All input TIFFs must have identical dimensions and 1 sample per pixel
- The spectral TIFF at `iccDEV/Testing/hybrid/Data/smCows380_5_780.tif` has
  81 SPP — it cannot be used as input (it's the expected output format)

## Tested Configurations (2026-03-12)

### Dedicated test suite (34/34 PASS)

Run with: `bash .github/scripts/test-specseptotiff.sh`

| Category | Tests | Status |
|----------|-------|--------|
| Error handling (missing args, bad files) | 6 | ✅ All PASS |
| Basic merging (10-channel, 81-channel, 8×8, 16-bit) | 6 | ✅ All PASS |
| Compression (LZW on/off, contig/sep) | 4 | ✅ All PASS |
| Separation modes (contig, separated, compress+sep) | 4 | ✅ All PASS |
| ICC profile embedding (various profiles) | 4 | ✅ All PASS |
| Cross-validation (output verification with iccTiffDump) | 10 | ✅ All PASS |

### Mass testing (48 option combos)

All combinations of `compress × sep × profile × seed_series`:

| Compress | Sep | ICC Profile | Seed Series | Status |
|----------|-----|-------------|-------------|--------|
| 0 | 0 | None | spec, wl, ch8, white | ✅ All PASS |
| 0 | 1 | None | spec, wl, ch8, white | ✅ All PASS |
| 1 | 0 | None | spec, wl, ch8, white | ✅ All PASS |
| 1 | 1 | None | spec, wl, ch8, white | ✅ All PASS |
| 0–1 | 0–1 | sRGB_D65_MAT.icc | spec, wl, ch8, white | ✅ All PASS |
| 0–1 | 0–1 | Rec2020rgbSpectral.icc | spec, wl, ch8, white | ✅ All PASS |

**0 ASAN, 0 UBSAN across all 82 test runs.**

## Code Coverage (V2.1 Fuzzer vs Tool)

| Component | Tool (mass test) | Fuzzer (2,256 corpus) | Winner |
|-----------|-----------------|----------------------|--------|
| TiffImg.cpp Lines | 65.20% | 69.26% | Fuzzer +4.06% |
| TiffImg.cpp Branches | 49.22% | 59.38% | Fuzzer +10.16% |
| IccIO.cpp Lines | 5.60% | 5.60% | Tied |

## Security Notes

For untrusted input TIFFs, use ASAN-instrumented build:

```bash
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccSpecSepToTiff /tmp/out.tiff 0 0 "malicious_%06d.tiff" 1 10 1
```

## Related Tools

- [iccTiffDump](../iccTiffDump/) — Inspect the merged spectral TIFF
- [iccApplyProfiles](../iccApplyProfiles/) — Apply ICC transforms to TIFF images
- CFL fuzzer: `icc_specsep_fuzzer` (V2.1) — Fuzz the spectral separation pipeline
  with ICC profile embedding support
- Test script: `.github/scripts/test-specseptotiff.sh` — 34-test dedicated suite

## Version

Built with IccProfLib version 2.3.1.5
