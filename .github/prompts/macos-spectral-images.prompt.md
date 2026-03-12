# macOS Agent — Monochrome Spectral Image Generation Plan

## Goal
Generate single-channel monochrome TIFF images on macOS using CoreGraphics
for use as iccSpecSepToTiff inputs and CFL fuzzer seeds.

## Background

iccSpecSepToTiff merges N single-channel (SPP=1) grayscale TIFFs into one
multi-channel spectral TIFF. The WSL-2 agent has already created Python-generated
test images. macOS images add diversity via CoreGraphics' native TIFF writer
(different byte ordering, compression codecs, metadata patterns).

## What macOS Agent Should Generate

### Format Requirements (ALL images must match these)
- **SamplesPerPixel**: 1 (mandatory — tool rejects multi-channel)
- **PhotometricInterpretation**: MINISBLACK (1) or MINISWHITE (0)
- **BitsPerSample**: 8 or 16
- **Resolution**: 72 dpi (or any consistent value)
- **All images in a set must have IDENTICAL**: width, height, BPS, resolution

### Image Sets to Create

#### Set A: CoreGraphics grayscale TIFFs (16-bit, 4×4)
Create 81 files named `cg_wl_{380..780}.tif` (5nm wavelength steps).
Each file: 4×4 pixels, 16-bit gray, MINISBLACK.
Pixel values: gradient based on wavelength (e.g., `v = (wl-380) * 800`).

```swift
// Swift pseudocode
let colorSpace = CGColorSpaceCreateDeviceGray()
let ctx = CGBitmapContext(nil, 4, 4, 16, 4*2,
    colorSpace, CGImageAlphaInfo.none.rawValue)
// Fill with wavelength-dependent gradient
// Write via CGImageDestination with kUTTypeTIFF
```

#### Set B: CoreGraphics 8-bit small (32×32)
Create 31 files named `cg_8b_{400..700}.tif` (10nm steps).
32×32 pixels, 8-bit gray, MINISBLACK.

#### Set C: Large images (256×256, 16-bit)
Create 10 files named `cg_lg_{001..010}.tif`.
256×256, 16-bit gray. For stress testing the merge.

#### Set D: Images with embedded ICC profiles
Create 10 files named `cg_icc_{001..010}.tif`.
32×32, 16-bit gray, with system ICC profiles embedded:
- `/System/Library/ColorSync/Profiles/Generic Gray Gamma 2.2 Profile.icc`
- `/System/Library/ColorSync/Profiles/sRGB Profile.icc` (gray component)

#### Set E: Numbered digit images (visual verification)
Create 10 files named `cg_digit_{0..9}.tif`.
64×64, 8-bit gray. Each contains a rendered digit (0-9) using
CoreText/NSFont for visual verification of merge order.

### Output Location
Stage all files to: `fuzz/xnuimagegenerator/tiff/spectral/`

After generation, commit to fuzz repo (master branch):
```bash
cd fuzz && git add xnuimagegenerator/tiff/spectral/ && git commit -m "fuzz: macOS CoreGraphics spectral TIFFs"
```

### Validation Script (run on macOS before commit)
```bash
for f in fuzz/xnuimagegenerator/tiff/spectral/cg_*.tif; do
  sips --getProperty all "$f" 2>/dev/null | grep -E '(pixel|bits|samples|space)'
done
```

Verify: all show `samplesPerPixel: 1`, consistent dimensions per set.

## WSL-2 Integration After macOS Delivery

WSL-2 agent will:
1. Pull the macOS-generated TIFFs
2. Copy to `iccDEV/Testing/Fuzzing/seeds/tiff/spectral/`
3. Run `test-specseptotiff.sh` with the new images
4. Seed CFL `corpus-icc_specsep_fuzzer/` and `corpus-icc_tiffdump_fuzzer/`
5. Run `test-iccdev-tools-comprehensive.sh` on merged outputs

## Why macOS Images Add Value

1. **CoreGraphics TIFF writer** uses different IFD tag ordering than libtiff
2. **Byte ordering**: macOS may use big-endian (MM) vs Python's little-endian (II)
3. **Compression**: CoreGraphics supports LZW, PackBits, Deflate natively
4. **ICC embedding**: System profiles have Apple-specific extensions
5. **Metadata**: CoreGraphics adds Software, DateTime, and other tags
6. **Fuzzer diversity**: Different TIFF encoders exercise different parser paths
