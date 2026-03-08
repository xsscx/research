# XNU Image Fuzzer - ICC Profile Analysis Index

## Documents Generated

### 1. **ICC_PROFILE_ANALYSIS.md** (839 lines)
Comprehensive technical reference with complete function bodies, exact line numbers, and deep analysis:
- All 5 ICC-related functions with full code
- All 15 createBitmapContext* function signatures
- Color space creation for each function
- CoreGraphics API calls (CGImageDestinationAddImage, CGColorSpaceCreateWithICCData)
- Complete list of 30+ supported image formats
- ICC profile mutation strategies (6 variants)
- Environment variable handling
- Full pipeline workflow

**Use this for**: Understanding complete implementation details, debugging, auditing code paths

---

### 2. **ICC_QUICK_REFERENCE.txt** (280 lines)
Quick lookup guide with line numbers and key information in compact format:
- Line number references for all functions
- Critical API calls highlighted
- Bitmap context configurations summary
- Environment variables quick lookup
- ICC embedding pipeline steps
- Injection strings (10 security test strings)
- Metrics and provenance format
- Key findings summary

**Use this for**: Quick lookups, understanding structure, finding specific sections

---

## Key Findings Summary

### ICC Profile Handling Pipeline

1. **Loading** (Line 2003)
   - `loadICCProfilePaths()` reads `FUZZ_ICC_DIR` environment variable
   - Scans for `.icc` and `.icm` files

2. **Embedding** (Lines 1906-1987)
   - `embedICCProfile()` is the main function
   - Uses `CGColorSpaceCreateWithICCData()` (Lines 1917, 2785)
   - Only re-renders if color space has 3 components (RGB)
   - Falls back to raw data attachment if creation fails

3. **Mutation** (Lines 2710-2760)
   - `mutateICCProfile()` implements 6 corruption strategies
   - Targets: signature, header fields, CLUT tags, profile size, bit flips

4. **Output** (Lines 1983, 2833, 707)
   - Uses `CGImageDestinationAddImage()` to write images
   - Supports PNG, TIFF, JPEG formats for ICC embedding

### Bitmap Context Diversity

All 15 functions create different combinations of:
- **Color Spaces**: DeviceRGB, DeviceGray, DeviceCMYK, ExtendedLinearSRGB
- **Bit Depths**: 1, 8, 16, 32-bit
- **Alpha Handling**: Premultiplied, non-premultiplied, alpha-only
- **Byte Order**: Big-endian, little-endian
- **Special**: Inverted colors, float components, indexed color

### Format Support

30+ formats including:
- **Lossless**: PNG, GIF, TIFF (multiple compression types), BMP, ICO
- **Lossy**: JPEG (multiple quality levels)
- **Advanced**: HEIC, HEIF, WebP, JPEG 2000, OpenEXR, DNG, PDF, ICNS

### Environment-Driven

- `FUZZ_ICC_DIR`: Where to find ICC profiles
- `FUZZ_OUTPUT_DIR`: Where to save fuzzed images
- `LLVM_PROFILE_FILE`: Coverage instrumentation data

---

## Critical Code Sections

### ICC Embedding Entry Point
**Lines 1787-1792** in `performAllImagePermutations()`:
```c
NSString *iccPath = iccProfiles[i % [iccProfiles count]];
NSString *iccName = [[iccPath lastPathComponent] stringByDeletingPathExtension];
NSData *iccImage = embedICCProfile(fuzzedImage, iccPath, @"png");
NSString *iccFileName = provenanceFileName(@"seed_icc", specs[i].permutation, -1, iccName, i + 1, @"png");
NSString *iccFilePath = [outputDir stringByAppendingPathComponent:iccFileName];
[iccImage writeToFile:iccFilePath atomically:YES];
```

### Color Space Creation - ICC
**Line 1917** in `embedICCProfile()`:
```c
CGColorSpaceRef iccColorSpace = CGColorSpaceCreateWithICCData((CFDataRef)iccData);
```

**Line 2785** in `embedICCProfileData()`:
```c
CGColorSpaceRef iccColorSpace = CGColorSpaceCreateWithICCData((CFDataRef)iccData);
```

### Image Destination Writing
**Line 1983** in `embedICCProfile()`:
```c
CGImageDestinationAddImage(dest, recoloredImage, NULL);
```

**Line 2833** in `embedICCProfileData()`:
```c
CGImageDestinationAddImage(dest, outputImage, NULL);
```

---

## Test Injection Strings

10 security-focused strings used for fuzzing (Lines 185-213):
1. Buffer overflow: 60 A's
2. XSS: `<script>console.error('XNU Image Fuzzer');</script>`
3. SQL injection: `' OR ''='`
4. Format string: `%d %s %d %s`
5. Control/baseline: `XNU Image Fuzzer`
6. SQL command: `123456; DROP TABLE users`
7. Special characters: `!@#$%^&*()_+=`
8. Path traversal: `..//..//..//win`
9. Null bytes: `\0\0\0`
10. XXE injection: XML with DOCTYPE

---

## Metrics and Provenance

**Provenance Filename Format** (Line 2058):
```
{inputName}_perm{permutation:02d}_{injection:02d}_{iccName}_{seq:03d}.{ext}
```

Example: `seed_icc_perm01_sRGB2014_001.png`

**Metrics Recorded** (Lines 2097-2115):
- SHA256 hash
- Shannon entropy
- Output/input file sizes
- Size delta
- Timestamp
- Iteration number, permutation, injection index
- ICC profile name

**Output Files**:
- Per-image JSON: `{imagePath}.metrics.json`
- Summary CSV: `{outputDir}/fuzz_metrics_summary.csv`

---

## Quick Navigation

| Task | File | Section |
|------|------|---------|
| Find ICC function | ICC_QUICK_REFERENCE.txt | Section 1 |
| View function body | ICC_PROFILE_ANALYSIS.md | Section 1 |
| Find CGColorSpaceCreate calls | ICC_QUICK_REFERENCE.txt | Section 3 |
| Understand pipeline | ICC_QUICK_REFERENCE.txt | Section 5 |
| Get environment variables | ICC_QUICK_REFERENCE.txt | Section 4 |
| See all formats | ICC_QUICK_REFERENCE.txt | Section 7 |
| ICC mutation strategies | ICC_QUICK_REFERENCE.txt | Section 10 |
| Post-encoding corruption | ICC_QUICK_REFERENCE.txt | Section 9 |
| Injection strings | ICC_QUICK_REFERENCE.txt | Section 12 |
| Pipeline phases | ICC_QUICK_REFERENCE.txt | Section 14 |

---

## Original File Information

- **File**: `xnuimagetools/XNU Image Fuzzer/XNU Image Fuzzer/xnuimagefuzzer.m`
- **Total Lines**: 5119
- **Version**: 1.8.1
- **Author**: David Hoyt
- **License**: GNU General Public License v3

---

Generated: 2024
Analysis Coverage: Complete ICC profile handling pipeline
