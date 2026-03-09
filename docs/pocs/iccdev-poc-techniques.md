# iccDEV PoC Reproduction Techniques

## Overview

This document catalogs minimized proof-of-concept reproduction techniques for
iccDEV security issues. The primary technique is **stdin pipe injection** using
`printf` to supply color data to tools that read from `/dev/stdin`, eliminating
the need for separate input data files. Additional techniques cover TIFF, JPEG,
PNG, .cube, and XML input vectors.

**Source of truth**: Reproduction patterns are derived from closed issues in
[InternationalColorConsortium/iccDEV](https://github.com/InternationalColorConsortium/iccDEV/issues?q=is%3Aissue+is%3Aclosed)
and cross-referenced with the 63 PoC reproductions in
[iccdev-issue-reproductions.md](iccdev-issue-reproductions.md).

---

## Table of Contents

1. [The printf Pipe Technique](#1-the-printf-pipe-technique)
2. [Color Data Encoding Reference](#2-color-data-encoding-reference)
3. [Tool-Specific Input Vectors](#3-tool-specific-input-vectors)
4. [TIFF Image PoC Techniques](#4-tiff-image-poc-techniques)
5. [JPEG Image PoC Techniques](#5-jpeg-image-poc-techniques)
6. [PNG Image PoC Techniques](#6-png-image-poc-techniques)
7. [.cube LUT PoC Techniques](#7-cube-lut-poc-techniques)
8. [XML Profile PoC Techniques](#8-xml-profile-poc-techniques)
9. [Multi-Profile PoC Techniques](#9-multi-profile-poc-techniques)
10. [Environment Setup](#10-environment-setup)
11. [Regression Testing Patterns](#11-regression-testing-patterns)
12. [Issue Cross-Reference](#12-issue-cross-reference)

---

## 1. The printf Pipe Technique

### Core Pattern

The `printf` pipe technique supplies color data via stdin to `iccApplyNamedCmm`
and `iccApplySearch`, the only two iccDEV tools that read from `/dev/stdin`.
This triggers the full CMM pipeline — profile loading, tag parsing, transform
creation, and color application — using a single one-liner without auxiliary
input files.

```bash
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | iccApplyNamedCmm /dev/stdin 3 0 <profile.icc> 0
```

### Anatomy of the printf String

```
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n"
        ─┬───  ─────┬───────  ─────┬───────
         │          │              │
         │          │              └── Color values (3 channels = RGB)
         │          └── Encoding type (see §2 below)
         └── Color space signature (ICC 4-char sig with quotes + trailing space)
```

**Line 1 — Color space declaration**: `'RGB '` (the quotes and trailing space are
part of the ICC signature format). Other common signatures:

| Signature | Color Space | Channels |
|-----------|-------------|----------|
| `'RGB '` | RGB | 3 |
| `'CMYK'` | CMYK | 4 |
| `'Lab '` | CIELAB | 3 |
| `'XYZ '` | CIEXYZ | 3 |
| `'GRAY'` | Grayscale | 1 |
| `'CLR5'` | 5-channel | 5 |
| `'CLR6'` | 6-channel | 6 |

**Line 2 — Encoding type**: One of the encoding keywords (see §2).

**Line 3 — Color values**: Space-separated or tab-separated floating-point values.
The number of values must match the channel count of the declared color space.

### Variations

#### Tab-separated values (equivalent)
```bash
printf "'RGB '\nicEncodeFloat\n0.5\t0.5\t0.5\n" | iccApplyNamedCmm /dev/stdin 3 0 profile.icc 0
```

#### CMYK input (4 channels)
```bash
printf "'CMYK'\nicEncodeFloat\n0.5 0.5 0.5 0.5\n" | iccApplyNamedCmm /dev/stdin 3 0 profile.icc 0
```

#### Lab input
```bash
printf "'Lab '\nicEncodeFloat\n50.0 0.0 0.0\n" | iccApplyNamedCmm /dev/stdin 3 0 profile.icc 0
```

#### Multiple color samples (multiple lines)
```bash
printf "'RGB '\nicEncodeFloat\n0.0 0.0 0.0\n0.5 0.5 0.5\n1.0 1.0 1.0\n" | iccApplyNamedCmm /dev/stdin 3 0 profile.icc 0
```

#### Here-document form (for readability in scripts)
```bash
iccApplyNamedCmm /dev/stdin 3 0 profile.icc 0 <<EOF
'RGB '
icEncodeFloat
0.5 0.5 0.5
EOF
```

### Real Issue Examples Using This Technique

#### Issue #619 — HBO in CIccTagFloatNum::Interpolate()
```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccOpDefSubElement-Exec-IccMpeCalc_cpp-Line377.icc

# Step 2
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | \
  iccApplyNamedCmm /dev/stdin 3 0 \
  hbo-CIccOpDefSubElement-Exec-IccMpeCalc_cpp-Line377.icc 0
```
**Bug**: Heap-buffer-overflow READ at IccTagBasic.cpp:6789 — `CIccTagFloatNum::Interpolate()`
reads past allocated array bounds when TintArray has malformed float data.

#### Issue #620 — HBO/SEGV in CIccCLUT::Interp3d()
```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/npd-CIccMpeCalculator-GetNewApply-IccMpeCalc_cpp-Line4929.icc

# Step 2
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | \
  iccApplyNamedCmm /dev/stdin 3 0 \
  npd-CIccMpeCalculator-GetNewApply-IccMpeCalc_cpp-Line4929.icc 0
```
**Bug**: SEGV (wild-addr-read) at IccTagLut.cpp:2721 — negative value cast to unsigned
in CLUT grid index causes wild pointer dereference. UB at line 2682 precedes crash.

#### Issue #621 — HBO in CIccMatrixMath::SetRange()
```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccMatrixMath-SetRange-IccMatrixMath_cpp-Line379.icc

# Step 2
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | \
  iccApplyNamedCmm /dev/stdin 3 0 \
  hbo-CIccMatrixMath-SetRange-IccMatrixMath_cpp-Line379.icc 0
```
**Bug**: 4-byte WRITE heap-buffer-overflow at IccMatrixMath.cpp:379 — `SetRange()`
writes past matrix allocation when spectral range mapping creates undersized matrix.
SCARINESS: 36.

#### Issue #623 — HBO in CIccCalculatorFunc::ApplySequence()
```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccCalculatorFunc-ApplySequence-IccMpeCalc_cpp-Line3715.icc

# Step 2
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | \
  iccApplyNamedCmm /dev/stdin 3 0 \
  hbo-CIccCalculatorFunc-ApplySequence-IccMpeCalc_cpp-Line3715.icc 0
```
**Bug**: Heap-buffer-overflow READ at IccMpeCalc.cpp:3711 — calculator stack underflow
causes read past allocated calculator data memory (28488-byte region).

#### Issue #625 — SBO in CIccPcsXform::pushXYZConvert() (multi-profile)
```bash
# Step 1
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccPcsXform-pushXYZConvert-IccCmm_cpp-Line3000.icc

# Step 2
wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccPcsXform-pushXYZConvert-IccCmm_cpp-Line3000-part2.icc

# Step 3 — Note: two profiles, tab-separated values, intent=1
printf "'RGB '\nicEncodeFloat\n0.5\t0.5\t0.5\n" | \
  iccApplyNamedCmm /dev/stdin 3 1 \
  hbo-CIccPcsXform-pushXYZConvert-IccCmm_cpp-Line3000.icc 1 \
  hbo-CIccPcsXform-pushXYZConvert-IccCmm_cpp-Line3000-part2.icc 1
```
**Bug**: Heap-buffer-overflow READ at IccCmm.cpp:3000 — `pushXYZConvert()` reads
past 4-byte MPE matrix allocation during PCS connection. Demonstrates multi-profile
attack chain.

---

## 2. Color Data Encoding Reference

### Encoding Keywords

| Keyword | Code | Description | Value Range |
|---------|------|-------------|-------------|
| `icEncodeValue` | 0 | Lab/XYZ native values | Lab: 0-100, -128-127 |
| `icEncodePercent` | 1 | Percentage encoding | 0.0 – 100.0 |
| `icEncodeUnitFloat` | 2 | Normalized float | 0.0 – 1.0 |
| `icEncodeFloat` | 3 | Raw float (scientific OK) | Any float |
| `icEncode8Bit` | 4 | 8-bit integer | 0 – 255 |
| `icEncode16Bit` | 5 | 16-bit integer | 0 – 65535 |
| `icEncode16BitV2` | 6 | ICC v2 16-bit style | 0 – 65535 |

### Recommended Encoding for PoCs

`icEncodeFloat` (code 3) is the recommended encoding for PoC reproduction because:
- No clamping — values pass through directly to the CMM
- Simple syntax — `0.5 0.5 0.5` is easy to read and modify
- Maximum coverage — exercises floating-point paths in the library
- Supports edge cases — NaN, Inf, negative values, subnormals

### Edge Case Color Values

```bash
# Zero values (black point)
printf "'RGB '\nicEncodeFloat\n0.0 0.0 0.0\n" | iccApplyNamedCmm /dev/stdin 3 0 profile.icc 0

# Maximum values (white point)
printf "'RGB '\nicEncodeFloat\n1.0 1.0 1.0\n" | iccApplyNamedCmm /dev/stdin 3 0 profile.icc 0

# Negative values (wide-gamut / out-of-gamut)
printf "'RGB '\nicEncodeFloat\n-0.5 0.5 1.5\n" | iccApplyNamedCmm /dev/stdin 3 0 profile.icc 0

# Very large values (overflow testing)
printf "'RGB '\nicEncodeFloat\n1e38 1e38 1e38\n" | iccApplyNamedCmm /dev/stdin 3 0 profile.icc 0

# NaN injection (undefined behavior testing)
printf "'RGB '\nicEncodeFloat\nnan nan nan\n" | iccApplyNamedCmm /dev/stdin 3 0 profile.icc 0
```

---

## 3. Tool-Specific Input Vectors

### iccApplyNamedCmm (stdin pipe — primary PoC tool)

```bash
# Syntax
printf "<colorspace>\n<encoding>\n<values>\n" | \
  iccApplyNamedCmm /dev/stdin <encoding_code> <intent> <profile.icc> <intent> [<profile2.icc> <intent> ...]

# Minimal reproduction
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | iccApplyNamedCmm /dev/stdin 3 0 profile.icc 0

# Multi-profile chain (exercises PCS connection)
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | iccApplyNamedCmm /dev/stdin 3 1 src.icc 1 dst.icc 1
```

**Intent values**: 0=Perceptual, 1=Relative, 2=Saturation, 3=Absolute.
Add +40 for BPC, +10 to disable D2Bx/B2Dx.

### iccDumpProfile (file-based — most common for parser bugs)

```bash
# Full dump
iccDumpProfile profile.icc

# Specific tag dump
iccDumpProfile profile.icc <tag_index>
```

**Trigger pattern**: Profile loading triggers `Read()` for every tag. Malformed
tag data causes crashes during parsing, not during color application.

### iccToXml (file-based — XML serialization bugs)

```bash
# Convert to XML (exercises Describe/ToXml paths)
iccToXml profile.icc /tmp/output.xml
```

**Trigger pattern**: Exercises `ToXml()` codepath on every tag type. Type confusion,
buffer overflows, and stack exhaustion happen during XML generation.

### iccFromXml (file-based — XML parsing bugs)

```bash
# Parse XML to ICC
iccFromXml input.xml /tmp/output.icc

# With schema validation
iccFromXml -v input.xml /tmp/output.icc
```

**Trigger pattern**: Malformed XML triggers crashes in `ParseTag()`, `icFixXml()`,
`icCurvesFromXml()`, and recursive struct parsing.

### iccRoundTrip (file-based — CMM pipeline bugs)

```bash
# Default round-trip evaluation
iccRoundTrip profile.icc

# With granularity
iccRoundTrip profile.icc <nGranularity>
```

**Trigger pattern**: Exercises `EvaluateProfile()` which builds CMM pipeline,
iterates grid points, and calls Apply(). High-dimensional profiles cause CWE-400.

### iccApplyProfiles (TIFF + ICC — image processing bugs)

```bash
# Apply profile to TIFF
iccApplyProfiles input.tif output.tif <intent> <interpolation> \
  <PCC_type> <PCC_offset> <num_profiles> profile.icc <intent>
```

**Trigger pattern**: TIFF strip geometry mismatches cause heap-buffer-overflow
in `CTiffImg::ReadLine()`. See CFL-082.

### iccTiffDump (TIFF metadata — tag parsing bugs)

```bash
# Dump TIFF metadata and embedded ICC
iccTiffDump image.tif
```

### iccJpegDump (JPEG — ICC extraction bugs)

```bash
# Extract ICC from JPEG APP2 marker
iccJpegDump image.jpg

# Extract and save ICC profile
iccJpegDump image.jpg extracted.icc
```

### iccPngDump (PNG — ICC extraction bugs)

```bash
# Extract ICC from PNG iCCP chunk
iccPngDump image.png

# Extract and save ICC profile
iccPngDump image.png extracted.icc
```

### iccFromCube (.cube LUT parsing)

```bash
# Convert .cube LUT to ICC DeviceLink
iccFromCube input.cube output.icc
```

### iccV5DspObsToV4Dsp (multi-profile — v5→v4 conversion)

```bash
# Convert v5 Display+Observer pair to v4
iccV5DspObsToV4Dsp v5_display.icc observer.icc output_v4.icc
```

### iccSpecSepToTiff (spectral TIFF — band merging)

```bash
# Merge spectral bands into TIFF
iccSpecSepToTiff <nBands> <TIFF_per_band...> output.tif profile.icc <intent>
```

---

## 4. TIFF Image PoC Techniques

### Creating Minimal TIFF Files

TIFF is a container format with flexible geometry. Malformed TIFFs trigger bugs in
`CTiffImg::Open()` and `CTiffImg::ReadLine()`.

#### Using Python (tifffile or Pillow)

```bash
# Create minimal 1×1 RGB TIFF
python3 -c "
from PIL import Image
import io
img = Image.new('RGB', (1, 1), (128, 128, 128))
img.save('/tmp/minimal.tif', 'TIFF')
"
```

#### Using ImageMagick

```bash
# Create minimal TIFF with embedded ICC
convert -size 1x1 xc:gray /tmp/minimal.tif
convert /tmp/minimal.tif -profile sRGB.icc /tmp/with-icc.tif

# Create multi-strip TIFF (strip geometry bugs)
convert -size 100x100 xc:gray -define tiff:rows-per-strip=10 /tmp/stripped.tif

# Create CMYK TIFF
convert -size 1x1 xc:gray -colorspace CMYK /tmp/cmyk.tif
```

#### Using raw bytes (minimal TIFF header)

```bash
# Create minimal TIFF with dd (little-endian, 1×1, 8-bit RGB)
printf 'II\x2a\x00\x08\x00\x00\x00' > /tmp/raw.tif  # TIFF LE header, IFD at offset 8
# ... (full construction requires IFD entries — use Python for reliable generation)
```

### TIFF PoC Reproduction Patterns

```bash
# Apply ICC profile to TIFF (triggers CTiffImg::ReadLine)
iccApplyProfiles input.tif /tmp/out.tif 0 0 0 0 1 profile.icc 1

# Dump TIFF metadata (safe — metadata only)
iccTiffDump input.tif

# Spectral separation (multi-band TIFF)
iccSpecSepToTiff 3 band1.tif band2.tif band3.tif /tmp/merged.tif profile.icc 0
```

### Known TIFF Attack Patterns

| Pattern | CWE | Tool | Description |
|---------|-----|------|-------------|
| Strip size mismatch | CWE-122 | iccApplyProfiles | StripByteCounts < RowsPerStrip × BytesPerLine |
| Extreme dimensions | CWE-400 | iccApplyProfiles | Width/Height > 65535 |
| Zero dimensions | CWE-476 | iccApplyProfiles | Width=0 or Height=0 |
| IFD offset OOB | CWE-125 | iccTiffDump | IFD data offset beyond EOF |
| Circular IFD chain | CWE-835 | iccTiffDump | NextIFD pointer loops |
| BPS mismatch | CWE-131 | iccApplyProfiles | BitsPerSample not in {1,8,16,32} |

---

## 5. JPEG Image PoC Techniques

### ICC in JPEG (APP2 Marker)

ICC profiles are embedded in JPEG files using the APP2 marker (0xFFE2) with the
signature `ICC_PROFILE\0`. For profiles > 65533 bytes, they are split across
multiple APP2 chunks.

#### Creating JPEG with ICC

```bash
# Embed ICC profile in JPEG
convert -size 1x1 xc:gray -profile sRGB.icc /tmp/with-icc.jpg

# Extract ICC from JPEG
iccJpegDump /tmp/with-icc.jpg /tmp/extracted.icc
```

#### Using Python

```python
from PIL import Image
import io

img = Image.new('RGB', (1, 1), (128, 128, 128))
with open('profile.icc', 'rb') as f:
    icc_data = f.read()
img.save('/tmp/with-icc.jpg', 'JPEG', icc_profile=icc_data)
```

### JPEG PoC Patterns

```bash
# Extract and analyze embedded ICC
iccJpegDump image.jpg /tmp/extracted.icc
iccDumpProfile /tmp/extracted.icc

# Analyze extracted profile with full heuristics
iccanalyzer-lite -a /tmp/extracted.icc
```

### Known JPEG Attack Patterns

| Pattern | CWE | Tool | Description |
|---------|-----|------|-------------|
| Truncated APP2 | CWE-125 | iccJpegDump | APP2 length exceeds file size |
| Multi-chunk ICC | CWE-120 | iccJpegDump | Split ICC with mismatched chunk count |
| Malformed ICC in APP2 | varies | iccJpegDump | Valid JPEG, corrupt embedded ICC |

---

## 6. PNG Image PoC Techniques

### ICC in PNG (iCCP Chunk)

ICC profiles are embedded in PNG files using the `iCCP` chunk, which contains a
null-terminated profile name followed by zlib-compressed ICC profile data.

#### Creating PNG with ICC

```bash
# Embed ICC profile in PNG
convert -size 1x1 xc:gray -profile sRGB.icc /tmp/with-icc.png

# Extract ICC from PNG
iccPngDump /tmp/with-icc.png /tmp/extracted.icc
```

#### Using Python

```python
from PIL import Image
img = Image.new('RGB', (1, 1), (128, 128, 128))
with open('profile.icc', 'rb') as f:
    icc_data = f.read()
img.save('/tmp/with-icc.png', icc_profile=icc_data)
```

### PNG PoC Patterns

```bash
# Extract and analyze embedded ICC
iccPngDump image.png /tmp/extracted.icc
iccDumpProfile /tmp/extracted.icc

# Full heuristic analysis of extracted profile
iccanalyzer-lite -a /tmp/extracted.icc
```

### Known PNG Attack Patterns

| Pattern | CWE | Tool | Description |
|---------|-----|------|-------------|
| Truncated iCCP | CWE-125 | iccPngDump | iCCP chunk length exceeds data |
| Corrupt zlib stream | CWE-400 | iccPngDump | Invalid compressed ICC data |
| Oversized profile name | CWE-120 | iccPngDump | iCCP name field not null-terminated |

---

## 7. .cube LUT PoC Techniques

### .cube Format Structure

```
# Comment line (becomes ICC copyright tag)
TITLE "My LUT"
LUT_3D_SIZE 33
DOMAIN_MIN 0.0 0.0 0.0
DOMAIN_MAX 1.0 1.0 1.0
0.000000 0.000000 0.000000
0.003906 0.000000 0.000000
...
```

#### Creating Minimal .cube

```bash
# Minimal valid .cube (2×2×2 LUT)
cat > /tmp/minimal.cube << 'EOF'
LUT_3D_SIZE 2
0.0 0.0 0.0
1.0 0.0 0.0
0.0 1.0 0.0
1.0 1.0 0.0
0.0 0.0 1.0
1.0 0.0 1.0
0.0 1.0 1.0
1.0 1.0 1.0
EOF
iccFromCube /tmp/minimal.cube /tmp/output.icc
```

### Known .cube Attack Patterns

| Pattern | CWE | Tool | Description |
|---------|-----|------|-------------|
| Missing LUT_3D_SIZE | CWE-20 | iccFromCube | No grid size declaration |
| Extreme grid size | CWE-400 | iccFromCube | LUT_3D_SIZE > 256 (N³ entries) |
| Truncated data | CWE-125 | iccFromCube | Fewer entries than N³ expected |
| NaN/Inf values | CWE-682 | iccFromCube | Invalid float in LUT entries |

---

## 8. XML Profile PoC Techniques

### ICC XML Format

iccDEV uses a custom XML schema for ICC profiles. The `iccFromXml` tool converts
XML back to binary ICC, and `iccToXml` converts binary to XML.

#### Creating Minimal XML ICC Profile

```bash
# Convert a good profile to XML, then mutate
iccToXml good-profile.icc /tmp/profile.xml

# Edit XML to introduce bugs, then convert back
iccFromXml /tmp/mutated.xml /tmp/output.icc
```

### XML PoC Patterns from fuzz/xml/icc/

The corpus at `fuzz/xml/icc/` contains 42 named XML crash PoCs plus 74 AFL-minimized
samples. These target the `CIccProfileXml::ParseTag()` path.

```bash
# Reproduce XML parsing crash
iccFromXml fuzz/xml/icc/crash-CIccTagXmlStruct-ParseTag.xml /tmp/out.icc

# Reproduce with schema validation
iccFromXml -v fuzz/xml/icc/crash-file.xml /tmp/out.icc
```

### Known XML Attack Patterns

| Pattern | CWE | Tool | Description |
|---------|-----|------|-------------|
| Deeply nested structs | CWE-674 | iccFromXml | Recursive ParseTag() stack overflow |
| Oversized array data | CWE-787 | iccFromXml | DumpArray/LoadArray bounds |
| Type confusion | CWE-843 | iccFromXml | Wrong element type in CurveSet |
| XXE injection | CWE-611 | iccFromXml | External entity resolution |
| Unterminated strings | CWE-170 | iccToXml | ColorantTable name field overflow |

---

## 9. Multi-Profile PoC Techniques

Several bugs only manifest when multiple profiles are chained in a CMM pipeline.
The PCS connection logic (`CIccPcsXform::Connect`) is a rich attack surface.

### Two-Profile Chain

```bash
# Profile A → PCS → Profile B (exercises PCS connection)
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | \
  iccApplyNamedCmm /dev/stdin 3 1 profileA.icc 1 profileB.icc 1
```

### Three-Profile Chain

```bash
# Src → Link → Dst (exercises DeviceLink handling)
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | \
  iccApplyNamedCmm /dev/stdin 3 0 src.icc 0 link.icc 0 dst.icc 0
```

### v5 Display + Observer Conversion

```bash
# Two-profile v5→v4 conversion
iccV5DspObsToV4Dsp display_v5.icc observer.icc output_v4.icc
```

### Profile Linking

```bash
# Create device link from profile chain
iccApplyToLink output_link.icc 3 0 profileA.icc 1 profileB.icc 1
```

### Issue #625 Pattern — Multi-Profile PCS Attack

The most complex PoC pattern involves two malformed profiles that individually
parse correctly but trigger bugs during PCS connection:

```bash
# Download both parts of the PoC
wget -q https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccPcsXform-pushXYZConvert-IccCmm_cpp-Line3000.icc
wget -q https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/hbo-CIccPcsXform-pushXYZConvert-IccCmm_cpp-Line3000-part2.icc

# Reproduce — note both profiles use intent=1 (Relative)
printf "'RGB '\nicEncodeFloat\n0.5\t0.5\t0.5\n" | \
  iccApplyNamedCmm /dev/stdin 3 1 \
  hbo-CIccPcsXform-pushXYZConvert-IccCmm_cpp-Line3000.icc 1 \
  hbo-CIccPcsXform-pushXYZConvert-IccCmm_cpp-Line3000-part2.icc 1
```

---

## 10. Environment Setup

### ASAN Build (Required for PoC Verification)

```bash
cd iccDEV/Build
cmake Cmake \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer" \
  -DCMAKE_CXX_FLAGS="-g -O0 -fsanitize=address,undefined -fno-omit-frame-pointer"
make -j$(nproc)
```

### Runtime Environment Variables

```bash
# Catch all errors without stopping (full crash chain analysis)
export ASAN_OPTIONS=halt_on_error=0,detect_leaks=0

# Stop on first error (precise crash location)
export ASAN_OPTIONS=halt_on_error=1,detect_leaks=0

# UBSAN with stack traces
export UBSAN_OPTIONS=halt_on_error=0,print_stacktrace=1

# Library path (for shared library builds)
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML:$LD_LIBRARY_PATH
```

### Tool Path Setup

```bash
# Add all tools to PATH
export PATH="$(find iccDEV/Build/Tools -type d -name 'Icc*' | tr '\n' ':')$PATH"
export PATH="iccDEV/Build/IccXML/CmdLine/IccToXml:iccDEV/Build/IccXML/CmdLine/IccFromXml:$PATH"
```

### Timeout Wrapper (for CWE-400 PoCs)

```bash
# Wrap any tool with 30-second timeout
timeout 30 iccDumpProfile profile.icc

# With coverage collection
LLVM_PROFILE_FILE=/tmp/poc-%m.profraw \
  timeout 30 iccApplyNamedCmm /dev/stdin 3 0 profile.icc 0 < /tmp/input.txt
```

---

## 11. Regression Testing Patterns

### One-Liner Regression Test

```bash
# Test that a fix prevents the crash (exit code 0 or 1 = OK, 128+ = crash)
printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | \
  timeout 30 iccApplyNamedCmm /dev/stdin 3 0 poc-profile.icc 0 2>&1; \
  echo "EXIT=$?"
```

### Batch Regression Script

```bash
#!/bin/bash
# Run all printf-pipe PoCs and report crashes
POCS=(
  "hbo-CIccOpDefSubElement-Exec-IccMpeCalc_cpp-Line377.icc"
  "hbo-CIccMatrixMath-SetRange-IccMatrixMath_cpp-Line379.icc"
  "hbo-CIccCalculatorFunc-ApplySequence-IccMpeCalc_cpp-Line3715.icc"
  "npd-CIccMpeCalculator-GetNewApply-IccMpeCalc_cpp-Line4929.icc"
)

for poc in "${POCS[@]}"; do
  result=$(printf "'RGB '\nicEncodeFloat\n0.5 0.5 0.5\n" | \
    timeout 30 iccApplyNamedCmm /dev/stdin 3 0 "$poc" 0 2>&1)
  exit_code=$?
  if [ $exit_code -ge 128 ]; then
    echo "CRASH ($exit_code): $poc"
  elif echo "$result" | grep -q "AddressSanitizer"; then
    echo "ASAN:  $poc"
  else
    echo "OK:    $poc"
  fi
done
```

### Exit Code Classification

| Exit Code | Meaning | Action |
|-----------|---------|--------|
| 0 | Success | Fix verified — no crash |
| 1-127 | Graceful rejection | Tool rejected input — NOT a crash |
| 128+ | Signal termination | CRASH — bug still present |
| 134 | SIGABRT (ASAN) | ASAN detected memory error |
| 137 | SIGKILL (timeout) | CWE-400 — infinite loop/recursion |
| 139 | SIGSEGV | Segmentation fault |

---

## 12. Issue Cross-Reference

### Issues Using printf Pipe Technique

| Issue | Bug Type | CWE | Tool | Profile |
|-------|----------|-----|------|---------|
| [#619](https://github.com/InternationalColorConsortium/iccDEV/issues/619) | HBO READ | CWE-122 | iccApplyNamedCmm | hbo-CIccOpDefSubElement-Exec-*.icc |
| [#620](https://github.com/InternationalColorConsortium/iccDEV/issues/620) | SEGV | CWE-476 | iccApplyNamedCmm | npd-CIccMpeCalculator-GetNewApply-*.icc |
| [#621](https://github.com/InternationalColorConsortium/iccDEV/issues/621) | HBO WRITE | CWE-122 | iccApplyNamedCmm | hbo-CIccMatrixMath-SetRange-*.icc |
| [#623](https://github.com/InternationalColorConsortium/iccDEV/issues/623) | HBO READ | CWE-122 | iccApplyNamedCmm | hbo-CIccCalculatorFunc-ApplySequence-*.icc |
| [#625](https://github.com/InternationalColorConsortium/iccDEV/issues/625) | HBO READ | CWE-122 | iccApplyNamedCmm | hbo-CIccPcsXform-pushXYZConvert-* (2 files) |

### Issues Using File-Based Input

See [iccdev-issue-reproductions.md](iccdev-issue-reproductions.md) for the full
catalog of 63 reproductions across all tools and input methods.

### Heuristic Coverage

These issues are covered by iccanalyzer-lite heuristics:

| Issue | Heuristic | Detection Method |
|-------|-----------|------------------|
| #619 | H56 (Calculator Complexity), H146 (SBO GetValues) | Array size validation |
| #620 | H147 (NPD Post-Read) | Null pointer state check |
| #621 | H98 (Spectral MPE) | Spectral element validation |
| #623 | H56, H57 (Calculator/LUT) | Calculator stack bounds |
| #625 | H146 (SBO GetValues) | MPE matrix size vs channels |

---

## See Also

- [iccdev-issue-reproductions.md](iccdev-issue-reproductions.md) — 63 PoC reproductions
- [../iccdev-shell-helpers/unix.md](../iccdev-shell-helpers/unix.md) — Build and test commands
- [../iccdev-shell-helpers/windows.md](../iccdev-shell-helpers/windows.md) — Windows MSVC build
- [../../.github/prompts/triage-fuzzer-crash.prompt.md](../../.github/prompts/triage-fuzzer-crash.prompt.md) — Crash triage workflow
- [../../.github/prompts/cve-enrichment.prompt.md](../../.github/prompts/cve-enrichment.prompt.md) — CVE mapping
