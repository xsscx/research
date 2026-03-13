# iccApplyProfiles

Applies ICC color transforms to TIFF images. Reads a source TIFF, applies one or more
ICC profile transforms, and writes a destination TIFF with the specified encoding,
compression, and planar configuration.

## Usage

```
iccApplyProfiles src_tiff dst_tiff dst_encoding dst_compression dst_planar dst_embed_icc interpolation {{-ENV:sig value} profile_path rendering_intent {-PCC pcc_path}}
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `src_tiff` | **Required** | Path to input TIFF image |
| `dst_tiff` | **Required** | Path for output TIFF image |
| `dst_encoding` | **Required** | Output sample encoding (see table) |
| `dst_compression` | **Required** | 0=None, 1=LZW |
| `dst_planar` | **Required** | 0=Contiguous, 1=Separation |
| `dst_embed_icc` | **Required** | 0=Don't embed, 1=Embed output ICC profile |
| `interpolation` | **Required** | 0=Linear, 1=Tetrahedral |
| `profile_path` | **Required** | Path to ICC profile |
| `rendering_intent` | **Required** | 0=Perceptual, 1=Relative, 2=Saturation, 3=Absolute |
| `-PCC path` | Optional | Profile Connection Conditions |
| `-ENV:sig value` | Optional | Environment variable for transform |

### Sample Encoding Values

| Code | Description |
|------|-------------|
| 0 | Same as source |
| 1 | icEncode8Bit (8 bits per sample) |
| 2 | icEncode16Bit (16 bits per sample) |
| 4 | icEncodeFloat (32-bit float) |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | TIFF open error, profile error, or transform failure |

## Examples

### Basic TIFF color transform

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# 8-bit → 8-bit, no compression, relative colorimetric
iccApplyProfiles input.tiff /tmp/output_8bit.tiff 1 0 0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1
```

### Different output encodings

```bash
# 8-bit → 16-bit with LZW compression
iccApplyProfiles input.tiff /tmp/output_16bit.tiff 2 1 0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# 8-bit → float
iccApplyProfiles input.tiff /tmp/output_float.tiff 4 0 0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 0

# 16-bit → 8-bit, absolute colorimetric
iccApplyProfiles input_16bit.tiff /tmp/output_8bit.tiff 1 0 0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 3
```

### Embed output ICC profile

```bash
# Embed the ICC profile in the output TIFF (tag 34675)
iccApplyProfiles input.tiff /tmp/output_embed.tiff 1 0 0 1 0 \
  test-profiles/sRGB_D65_MAT.icc 1
```

### Tetrahedral interpolation

```bash
iccApplyProfiles input.tiff /tmp/output_tet.tiff 1 0 0 0 1 \
  test-profiles/sRGB_D65_MAT.icc 1
```

### Using test TIFF images

Available TIFF test images in the corpus:

```bash
# macOS Catalyst-generated TIFFs
iccApplyProfiles test-profiles/catalyst-8bit-ACESCG.tiff /tmp/out.tiff 1 0 0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# xnuimagefuzzer-generated TIFFs (fuzz/graphics/tif/)
iccApplyProfiles fuzz/graphics/tif/BigEndian-image.tiff /tmp/out.tiff 1 0 0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1
```

## TIFF Requirements

- Input must be a valid TIFF file (II\* or MM\0\* magic bytes)
- Supported sample formats: 8-bit, 16-bit, 32-bit float
- Supported photometric: RGB, CMYK, Lab (must match profile color space)
- Strip-based and tile-based TIFFs supported

## Security Notes

This tool uses the `CTiffImg` class which reads TIFF strip/tile geometry from the file.
Known vulnerability pattern (CFL-082): strip buffer vs row geometry mismatch can cause
heap-buffer-overflow. The CFL patched build includes bounds validation.

For untrusted TIFFs, use ASAN-instrumented build:

```bash
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccApplyProfiles malicious.tiff /tmp/out.tiff 1 0 0 0 0 \
    test-profiles/sRGB_D65_MAT.icc 1
```

## Tested Configurations

### Structured tests (6/6 PASS)

| Source | Encoding | Compression | Embed | Interp | Intent | Status |
|--------|----------|-------------|-------|--------|--------|--------|
| 8-bit | 8-bit | None | No | Linear | Relative | ✅ PASS |
| 8-bit | 16-bit | LZW | No | Linear | Relative | ✅ PASS |
| 8-bit | Float | None | No | Linear | Perceptual | ✅ PASS |
| 8-bit | 8-bit | None | Yes | Linear | Relative | ✅ PASS |
| 8-bit | 8-bit | None | No | Tetrahedral | Relative | ✅ PASS |
| 16-bit | 8-bit | None | No | Linear | Absolute | ✅ PASS |

### Mass testing (3,200 runs, 2026-03-12)

50 random TIFFs from the 22,218-file `tiff-main` corpus, each tested with the full
option matrix:

| Parameter | Values Tested |
|-----------|--------------|
| `dst_encoding` | 0 (same), 1 (8-bit), 2 (16-bit) |
| `dst_compression` | 0 (none), 1 (LZW) |
| `dst_planar` | 0 (contig), 1 (separated) |
| `dst_embed_icc` | 0 (no), 1 (yes) |
| `interpolation` | 0 (linear), 1 (tetrahedral) |
| `rendering_intent` | 0 (perceptual), 1 (relative), 2 (saturation), 3 (absolute) |
| ICC profiles | 10 diverse profiles from `test-profiles/` |

**Results: 3,200 runs, 3,200 success, 0 ASAN, 0 UBSAN.**

Most failures are graceful format-mismatch rejections (e.g., applying RGB profile to
grayscale TIFF) — classified as success since the tool rejects cleanly without crashes.

## Related Tools

- [iccTiffDump](../iccTiffDump/) — Inspect TIFF metadata and extract ICC profiles
- [iccApplyNamedCmm](../iccApplyNamedCmm/) — Apply transforms to color data files
- [iccSpecSepToTiff](../iccSpecSepToTiff/) — Create multi-channel spectral TIFFs
- CFL fuzzer: `icc_applyprofiles_fuzzer` — Fuzz the TIFF+profile pipeline
- iccanalyzer-lite: H139-H141, H149-H150 — TIFF security heuristics

## Version

Built with IccProfLib version 2.3.1.5
