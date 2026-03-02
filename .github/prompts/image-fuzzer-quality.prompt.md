---
mode: agent
description: Analyze xnuimagefuzzer output quality and validate image generation
---

# Image Fuzzer Output Quality Analysis

## Context
xnuimagefuzzer generates fuzzed images via 15 CGBitmapContext configurations and 6 output
formats (PNG, JPEG, GIF, BMP, TIFF, HEIF). Quality analysis validates that outputs have
sufficient visual diversity for effective fuzzing.

## Expected Output
17 seed specs × 6 files each = 102 expected files per run.
Each seed generates: original + corrupted + 4 format variants.

## Quality Metrics
1. **File validity** — Each output must be a valid image file (not truncated/empty)
2. **Dimension diversity** — Mix of sizes from 16×16 to 512×512 (minimum 16×16 enforced)
3. **Color diversity** — Each image should have ≥5 unique pixel values
4. **Format coverage** — All 6 output formats present
5. **No duplicates** — MD5 dedup shows 0% duplicate rate
6. **No crashes** — Zero ASAN/UBSAN errors during generation

## Scoring (target: 90+/100)
- 40 pts: File validity (all files parse as valid images)
- 20 pts: Dimension diversity (≥5 distinct sizes)
- 20 pts: Color diversity (≥80% files have ≥5 unique colors)
- 10 pts: Format coverage (all 6 formats present)
- 10 pts: No duplicates

## Known Limitations
- 32BitFloat and HDR float variants produce near-black images (float→8-bit clamping)
- 1BitMonochrome may not generate on macOS 15 (CGBitmapContext returns NULL)
- Structure-aware mutations add PNG chunk-level corruption (IHDR, PLTE, tRNS, sRGB, gAMA, cHRM)

## Analysis Steps
1. Download fuzzed-images artifact from CI
2. Count files per format: `find . -name "*.png" | wc -l` (repeat for jpg, gif, bmp, tiff, heif)
3. Validate with: `file -b "$f"` — should report image type, not "data"
4. Check dimensions: `identify "$f"` or `sips -g pixelWidth -g pixelHeight "$f"`
5. Check color diversity: `convert "$f" -unique-colors -format "%c" histogram:info:`
6. Compute score against the 5 metrics above
