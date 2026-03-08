---
mode: agent
description: Analyze xnuimagefuzzer output quality and validate image generation
---

# Image Fuzzer Output Quality Analysis

## Context
xnuimagefuzzer generates fuzzed images via 15 CGBitmapContext configurations and 22+
output formats (PNG, JPEG, TIFF×5, GIF, BMP, HEIF/HEIC, WebP, JP2, DNG, TGA, ASTC,
KTX, PDF, ICNS, EXR, plus ICC variant outputs). Quality analysis validates that outputs
have sufficient visual diversity for effective fuzzing.

## Expected Output
Each `--pipeline` run produces images across 4 phases:
- **Clean**: 15 contexts × base formats = ~90 files
- **Format**: 15 contexts × 22+ multi-format outputs = ~330 files
- **Fuzz**: 15 contexts × 8 mutation strategies × format outputs = ~2,000+ files
- **ICC**: Up to 4 ICC variants per TIFF/PNG save (real, stripped, mismatched, mutated)
- **Combo**: Combined mutation + ICC + multi-format

Total output per full run: **2,000+ images** (varies by `FUZZ_ICC_DIR` availability).

## Quality Metrics
1. **File validity** — Each output must be a valid image file (not truncated/empty)
2. **Dimension diversity** — Mix of sizes from 16×16 to 512×512 (minimum 16×16 enforced)
3. **Color diversity** — Each image should have ≥5 unique pixel values
4. **Format coverage** — All major output formats present (PNG, JPEG, TIFF, GIF, BMP, HEIF minimum)
5. **No duplicates** — SHA256 dedup shows 0% duplicate rate
6. **No crashes** — Zero ASAN/UBSAN errors during generation
7. **ICC variant coverage** — Stripped, mismatched, real ICC, and mutated ICC variants present
8. **TIFF subformat diversity** — Uncompressed, LZW, PackBits, JPEG-in-TIFF, Deflate present

## Scoring (target: 90+/100)
- 30 pts: File validity (all files parse as valid images)
- 15 pts: Dimension diversity (≥5 distinct sizes)
- 15 pts: Color diversity (≥80% files have ≥5 unique colors)
- 15 pts: Format coverage (≥10 distinct formats present)
- 10 pts: ICC variant coverage (all 4 types present)
- 10 pts: No duplicates
- 5 pts: TIFF subformat diversity (≥3 compression types)

## Known Limitations
- 32BitFloat and HDR float variants produce near-black images (float→8-bit clamping)
- 1BitMonochrome may not generate on macOS 15 (CGBitmapContext returns NULL)
- Structure-aware mutations add PNG chunk-level corruption (IHDR, PLTE, tRNS, sRGB, gAMA, cHRM)
- HEIF/HEIC requires hardware encoder (may not be available in CI)
- ICC real/mutated variants require `FUZZ_ICC_DIR` environment variable

## Analysis Steps
1. Download fuzzed-images artifact from CI
2. Count files per format: `find . -name "*.png" | wc -l` (repeat for jpg, gif, bmp, tiff, heif, webp, jp2, etc.)
3. Validate with: `file -b "$f"` — should report image type, not "data"
4. Check dimensions: `identify "$f"` or `exiftool -ImageWidth -ImageHeight "$f"` or `sips -g pixelWidth -g pixelHeight "$f"`
5. Check color diversity: `convert "$f" -unique-colors -format "%c" histogram:info:`
6. Check ICC variants: `find . -name "*icc*" -o -name "*no_icc*" -o -name "*mismatch*" | wc -l`
7. Check TIFF compression: `tiffinfo "$f" | grep Compression` for each TIFF variant
8. Compute score against the 8 metrics above
