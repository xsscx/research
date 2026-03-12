# macOS Agent: Generate Diverse Image Seeds for iccDEV Coverage

## Context

iccDEV has 5 image-consuming tools with significant coverage gaps in CFL fuzzers.
This prompt specifies exact image configurations the macOS agent should generate
using xnuimagefuzzer and CoreGraphics APIs.

## Phase 1: TIFF Diversity (27 files)

Generate TIFFs with **specific** configurations targeting uncovered iccDEV code paths.
3 sizes per config: 4×4, 32×32, 256×256.

| # | Configuration | BPS | SPP | Photometric | ICC Profile | Notes |
|---|--------------|-----|-----|-------------|-------------|-------|
| 1 | sRGB 8-bit | 8 | 3 | RGB | sRGB IEC61966 | Baseline |
| 2 | sRGB 16-bit | 16 | 3 | RGB | sRGB IEC61966 | 16-bit encoding path |
| 3 | DisplayP3 8-bit | 8 | 3 | RGB | Display P3 | Wide gamut |
| 4 | AdobeRGB 8-bit | 8 | 3 | RGB | AdobeRGB 1998 | Print gamut |
| 5 | Grayscale 8-bit | 8 | 1 | MINISBLACK | GenericGray | Mono path |
| 6 | Grayscale 16-bit | 16 | 1 | MINISBLACK | GenericGray | 16-bit mono |
| 7 | CMYK 8-bit | 8 | 4 | SEPARATED | (system CMYK) | Multi-ink path |
| 8 | Alpha+RGB 8-bit | 8 | 4 | RGB+alpha | sRGB | Extra samples |
| 9 | BT.2020 16-bit | 16 | 3 | RGB | ITU-R BT.2020 | HDR gamut |

**Requirements**: Each TIFF must have an embedded ICC profile (TIFFTAG_ICCPROFILE tag 34675).
Use `CGImageDestinationAddImage` with `kCGImagePropertyTIFFCompression` = none.

## Phase 2: Monochrome Spectral Sequences (109 files)

For iccSpecSepToTiff input — tool reads N single-channel TIFFs and interleaves them.

**CRITICAL requirements** (tool will reject otherwise):
- ALL files: SPP=1 (single channel), MINISBLACK or MINISWHITE photometric
- Within each set: EXACT same Width, Height, BitsPerSample, Resolution
- No palette/indexed color
- Resolution: 72 DPI

| Set | Files | BPS | Dims | Content |
|-----|-------|-----|------|---------|
| A | wl_380.tif..wl_780.tif (81 files, step 5nm) | 16 | 4×4 | Gradient ramp per wavelength |
| B | ch8_01.tif..ch8_08.tif (8 files) | 8 | 32×32 | Distinct gray levels per channel |
| C | lg_001.tif..lg_010.tif (10 files) | 16 | 256×256 | Larger images with patterns |
| D | digit_0.tif..digit_9.tif (10 files) | 8 | 64×64 | Rendered digit patterns |

**Naming**: Files must follow `printf`-style sequential naming so iccSpecSepToTiff
can open them with format strings: e.g., `wl_%03d.tif` with start=380, end=780, step=5.

## Phase 3: JPEG + PNG with Embedded ICC (6 files)

For future iccJpegDump/iccPngDump fuzzer seeds.

| # | Format | ICC Profile | Size | Notes |
|---|--------|-------------|------|-------|
| 1 | JPEG | sRGB | 256×256 | Standard JPEG+ICC (APP2 segment) |
| 2 | JPEG | DisplayP3 | 512×512 | Wide gamut JPEG |
| 3 | JPEG | AdobeRGB | 128×128 | Print-targeted |
| 4 | PNG | sRGB (iCCP) | 64×64 | Standard PNG+ICC |
| 5 | PNG | DisplayP3 (iCCP) | 256×256 | Wide gamut PNG |
| 6 | PNG | Grayscale (iCCP) | 32×32 | Mono PNG+ICC |

## Phase 4: Fuzzed Variants

Run xnuimagefuzzer on Phase 1-3 outputs with:
- `FUZZ_ICC_DIR=/System/Library/ColorSync/Profiles`
- ICC mismatch mode (CMYK profile on RGB image)
- ICC mutation mode (bit flips in embedded ICC data)

## Output Directory Structure

Place all outputs under `fuzz/xnuimagegenerator/tiff/iccdev-coverage/`:
```
iccdev-coverage/
├── rgb-8bit-srgb/        # Config 1
├── rgb-16bit-srgb/       # Config 2
├── rgb-8bit-p3/          # Config 3
├── rgb-8bit-adobe/       # Config 4
├── gray-8bit/            # Config 5
├── gray-16bit/           # Config 6
├── cmyk-8bit/            # Config 7
├── rgba-8bit/            # Config 8
├── rgb-16bit-bt2020/     # Config 9
├── spectral/
│   ├── wl/               # Set A (81 files)
│   ├── ch8/              # Set B (8 files)
│   ├── lg/               # Set C (10 files)
│   └── digit/            # Set D (10 files)
├── jpeg-icc/             # Phase 3 JPEGs
└── png-icc/              # Phase 3 PNGs
```

## After Generation

Commit to the `fuzz` repo (`master` branch — fuzz/ is a separate git repo):
```bash
cd fuzz
git add xnuimagegenerator/tiff/iccdev-coverage/
git commit -m "fuzz: add iccDEV coverage-targeted image seeds (Phase 1-3)"
git push origin master
```

The WSL-2 agent will then seed these into the SSD fuzzer corpora.
