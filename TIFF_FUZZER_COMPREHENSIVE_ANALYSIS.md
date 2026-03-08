# Comprehensive TIFF Fuzzer Analysis for ICC/CFL Framework

## Executive Summary

The CFL framework contains **two TIFF-based fuzzers** and supporting TIFF infrastructure:
1. **icc_tiffdump_fuzzer.cpp** - Extracts and parses ICC profiles from TIFF files (in-memory mode)
2. **icc_specsep_fuzzer.cpp** - Tests spectral separation TIFF creation and processing

The fuzzers exercise **CTiffImg** (TiffImg.cpp) which is the core TIFF I/O wrapper around libtiff. However, **several code paths remain untested** and dictionary coverage is incomplete.

---

## 1. icc_tiffdump_fuzzer.cpp — Full Source Code Analysis

### **File Location**
`cfl/icc_tiffdump_fuzzer.cpp` (224 lines)

### **Architecture & Design**
- **In-memory TIFF processing** with custom libtiff I/O callbacks
- **Zero-copy design**: MemTIFF struct holds pointer + offset + size
- **Silent error handling**: Suppresses libtiff warnings/errors during fuzzing
- **Multiple IFD traversal**: `while (TIFFReadDirectory(tif))` loop

### **TIFF API Calls & Code Paths Exercised**

#### **Initialization**
```cpp
// Lines 85-88: Error handler setup
TIFFSetErrorHandler(SilentTIFFErrorHandler);
TIFFSetWarningHandler(SilentTIFFWarningHandler);

// Lines 26-79: Custom I/O callbacks
- mem_read()     : Sequential read from buffer
- mem_write()    : No-op (read-only)
- mem_seek()     : SEEK_SET, SEEK_CUR, SEEK_END handling
- mem_close()    : No-op
- mem_size()     : Return buffer size
- mem_map()      : Not supported (returns 0)
- mem_unmap()    : Not supported
```

#### **TIFF File Operations**
```cpp
// Line 105-110: Open from memory
TIFF* tif = TIFFClientOpen("memory", "rm", &mem_tiff, 
  mem_read, mem_write, mem_seek, mem_close,
  mem_size, mem_map, mem_unmap);

// Lines 122-129: Read standard TIFF tags
TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);
TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &samples);
TIFFGetField(tif, TIFFTAG_BITSPERSAMPLE, &bps);
TIFFGetField(tif, TIFFTAG_PHOTOMETRIC, &photo);
TIFFGetField(tif, TIFFTAG_ROWSPERSTRIP, &rowsPerStrip);
TIFFGetField(tif, TIFFTAG_SAMPLEFORMAT, &sampleFormat);
TIFFGetField(tif, TIFFTAG_ORIENTATION, &orientation);

// Line 149: Extract ICC profile
TIFFGetField(tif, TIFFTAG_ICCPROFILE, &icc_len, &icc_data);

// Line 219: Iterate multiple IFDs
while (TIFFReadDirectory(tif)) { ... }

// Line 221: Close TIFF
TIFFClose(tif);
```

#### **ICC Profile Processing**
```cpp
// Lines 153-217: Profile parsing chain
CIccProfile* pProfile = OpenIccProfile(prof_mem, icc_len);
pProfile->m_Header          : Version, colorSpace, PCS, spectralPCS
Fmt.GetVersionName()        : Version formatting
Fmt.GetColorSpaceSigName()  : Color space formatting
Fmt.GetSpectralColorSigName() : Spectral color formatting
icF16toF()                  : Fixed-point conversion for ranges
pProfile->FindTag()         : Profile description, embedded profiles
pProfile->ReadTags()        : Full tag enumeration
```

### **TIFF Tags Exercised**
| Tag | Code | Purpose |
|-----|------|---------|
| IMAGEWIDTH | 0x0100 | Image width |
| IMAGELENGTH | 0x0101 | Image height |
| SAMPLESPERPIXEL | 0x0115 | Samples per pixel |
| BITSPERSAMPLE | 0x0102 | Bits per sample |
| PHOTOMETRIC | 0x0106 | Color interpretation |
| ROWSPERSTRIP | 0x0116 | Rows per strip |
| SAMPLEFORMAT | 0x0153 | Data format (uint/float) |
| ORIENTATION | 0x0112 | Image orientation |
| **ICCPROFILE** | **0x8773** | **Embedded ICC profile** |

### **Validation Checks**
```cpp
// Lines 133-144: Strict validation matching production tool
if (rowsPerStrip == 0 || samples == 0 || bps == 0) return 0;

if ((bps == 32 && sampleFormat != SAMPLEFORMAT_IEEEFP) ||
    (bps != 32 && sampleFormat != SAMPLEFORMAT_UINT) ||
    orientation != ORIENTATION_TOPLEFT) return 0;
```

### **Code Paths NOT Exercised (Dead Zones)**

| Dead Zone | Reason | Impact |
|-----------|--------|--------|
| **Multi-strip/tile handling** | Only reads IFD metadata, no pixel data | Can't detect strip corruption |
| **Large file handling** | Size limited to 50 MB (line 93) | No OOM detection |
| **PHOTOMETRIC_PALETTE** | Never generated | Palette interpretation untested |
| **Other orientations** | Validator rejects non-TOPLEFT (line 141) | Orientation transforms untested |
| **LZW/JPEG compression** | Not decoded at fuzzer level | Decompression bugs missed |
| **Separate planar config** | TIFF opened but not read | Planar layout untested |
| **Tile-based TIFFs** | No tile reading code | Tiling format untested |
| **Multi-page TIFFs** | Only IFD traversal, no image reading | Seeks on complex IFD chains untested |
| **EXTRASAMPLES handling** | TIFFGetField reads but not validated | Alpha channel integrity untested |
| **Resolution tags** | No TIFFGetField calls for XRESOLUTION/YRESOLUTION | Resolution parsing untested |
| **Embedded sub-profiles** | ReadTags() called but not recursive traversal | Deeply nested profiles untested |

---

## 2. icc_specsep_fuzzer.cpp — Spectral Separation Fuzzer

### **File Location**
`cfl/icc_specsep_fuzzer.cpp` (327 lines)

### **Purpose**
Tests **IccSpecSepToTiff** tool: creates multi-channel TIFF from input TIFFs, applies ICC profiles, performs spectral separation.

### **Code Paths Exercised**

#### **Input Parsing (Lines 84-99)**
```cpp
nFiles = 1-8 input TIFF files
width = 1-64 pixels
height = 1-64 pixels
photometric = MINISBLACK, MINISWHITE, RGB, CIELAB, ICCLAB
bitsPerSample = 8, 16, or 32 (float)
compress = LZW or none
separate = planar config (separate vs contig)
```

#### **TIFF Creation (CTiffImg::Create)**
```cpp
// Lines 149-151: Write TIFF with fuzzer-selected parameters
tiff.Create(tmpfile, width, height, bitsPerSample,
            nPhoto, inputSpp + nExtraSamples, nExtraSamples,
            72, 72, false, separate);

// Lines 175-176: Write pixel data
tiff.WriteLine((icUInt8Number*)(pixelData + rowOffset));
```

#### **TIFF Reading (CTiffImg::Open)**
```cpp
// Line 204: Open and validate input
if (!infiles[i].Open(tmpfiles[i])) { ... }

// Lines 209-224: Format consistency validation
- Same width, height, bps across all inputs
- Same photometric interpretation
- Same resolution
```

#### **Spectral Separation Loop (Lines 273-310)**
```cpp
for (uint32_t i = 0; i < f->GetHeight(); i++) {
  // Read scanlines from all input files
  for (uint8_t j = 0; j < nFiles; j++) {
    infiles[j].ReadLine(sptr);
  }
  
  // MINISWHITE inversion (line 288-294)
  if (nPhoto == PHOTO_MINISWHITE && !bFloat) {
    sptr[k] ^= 0xff;  // Previously unreachable!
  }
  
  // Interleave samples
  for (uint32_t k = 0; k < f->GetWidth(); k++) {
    for (uint8_t j = 0; j < nFiles; j++) {
      memcpy(tptr, sptr, bytesPerSample_img);
    }
    // Zero-fill extra samples
    for (unsigned int j = 0; j < nExtraSamples; j++) {
      memset(tptr, 0, bytesPerSample_img);
    }
  }
  outimg.WriteLine(outbuf);
}
```

#### **ICC Profile Embedding (Lines 249-269)**
```cpp
CIccMemIO memIO;
if (memIO.Attach(profile.get(), profileSize)) {
  CIccProfile iccProf;
  if (iccProf.Read(&memIO)) {
    iccProf.Validate(report);
    iccProf.FindTag(icSigSpectralViewingConditionsTag);
    iccProf.FindTag(icSigSpectralDataInfoTag);
    iccProf.FindTag(icSigProfileDescriptionTag);
    iccProf.FindTag(icSigAToB0Tag);
  }
}
```

### **Key Coverage Comments**
- **Line 214-215**: "Format consistency validation — matches iccSpecSepToTiff.cpp lines 177-185"
- **Line 287**: "MINISWHITE inversion — exercises iccSpecSepToTiff.cpp lines 248-252"
  - **This branch was previously unreachable** until recently added!

### **Code Paths NOT Exercised**

| Dead Zone | Reason | Impact |
|-----------|--------|--------|
| **Single-sample inputs** | Always 1-8 files, line 84 | Single-channel separation untested |
| **Palette photometric** | Filtered at line 209 | Palette-based spectral untested |
| **Resolution mismatches** | Validation at line 220 | Error handling for res mismatches untested |
| **Strip format errors** | No explicit error paths exercised | Corrupt strip handling untested |
| **Memory allocation failures** | new throws caught implicitly | OOM recovery untested |
| **Planar + Float combination** | Not explicitly tested | Separate float channels untested |
| **Extra samples > 1** | nExtraSamples is 0 or 1 | Multi-channel alpha untested |
| **Huge byte buffers** | Min 16 bytes input, but 10MB limit | Edge case buffer allocation untested |

---

## 3. CTiffImg (TiffImg.cpp/TiffImg.h) — Core TIFF I/O Library

### **File Locations**
- Header: `cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/TiffImg.h`
- Implementation: `cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/TiffImg.cpp` (459 lines)

### **TIFF API Calls Summary**

#### **Write Path (Create method, lines 124-241)**
```cpp
TIFFOpen(szFname, "w")               // Line 170
TIFFSetField(TIFFTAG_IMAGEWIDTH)     // Line 175
TIFFSetField(TIFFTAG_IMAGELENGTH)    // Line 176
TIFFSetField(TIFFTAG_PHOTOMETRIC)    // Line 177
TIFFSetField(TIFFTAG_PLANARCONFIG)   // Line 178
TIFFSetField(TIFFTAG_SAMPLESPERPIXEL) // Line 179
TIFFSetField(TIFFTAG_EXTRASAMPLES)   // Line 183
TIFFSetField(TIFFTAG_BITSPERSAMPLE)  // Line 187
TIFFSetField(TIFFTAG_SAMPLEFORMAT)   // Line 189 (if 32-bit float)
TIFFSetField(TIFFTAG_ROWSPERSTRIP)   // Line 190
TIFFSetField(TIFFTAG_COMPRESSION)    // Line 191
TIFFSetField(TIFFTAG_ORIENTATION)    // Line 192
TIFFSetField(TIFFTAG_XRESOLUTION)    // Line 193
TIFFSetField(TIFFTAG_YRESOLUTION)    // Line 194
TIFFSetField(TIFFTAG_PREDICTOR)      // Lines 197-200 (if compressed)
TIFFStripSize(m_hTif)                // Lines 215, 237
TIFFWriteEncodedStrip()              // Lines 408, 414
```

#### **Read Path (Open method, lines 244-330)**
```cpp
TIFFOpen(szFname, "r")               // Line 249
TIFFGetField(TIFFTAG_IMAGEWIDTH)     // Line 259
TIFFGetField(TIFFTAG_IMAGELENGTH)    // Line 260
TIFFGetField(TIFFTAG_PHOTOMETRIC)    // Line 261
TIFFGetField(TIFFTAG_PLANARCONFIG)   // Line 262
TIFFGetField(TIFFTAG_SAMPLESPERPIXEL) // Line 263
TIFFGetField(TIFFTAG_EXTRASAMPLES)   // Line 264
TIFFGetField(TIFFTAG_BITSPERSAMPLE)  // Line 265
TIFFGetField(TIFFTAG_SAMPLEFORMAT)   // Line 266
TIFFGetField(TIFFTAG_ROWSPERSTRIP)   // Line 267
TIFFGetField(TIFFTAG_ORIENTATION)    // Line 268
TIFFGetField(TIFFTAG_XRESOLUTION)    // Line 269
TIFFGetField(TIFFTAG_YRESOLUTION)    // Line 270
TIFFGetField(TIFFTAG_COMPRESSION)    // Line 271
TIFFStripSize(m_hTif)                // Line 295
TIFFReadEncodedStrip()               // Lines 350, 357
TIFFGetField(TIFFTAG_ICCPROFILE)     // Line 449
TIFFSetField(TIFFTAG_ICCPROFILE)     // Line 456
```

### **Major Code Branches**

#### **Photometric Interpretation (lines 142-168)**
```cpp
PHOTO_RGB           → PHOTOMETRIC_RGB
PHOTO_MINISBLACK+3  → PHOTOMETRIC_RGB (3-sample = RGB)
PHOTO_MINISBLACK+1  → PHOTOMETRIC_MINISBLACK
PHOTO_MINISWHITE+4  → PHOTOMETRIC_SEPARATED (CMYK)
PHOTO_MINISWHITE+1  → PHOTOMETRIC_MINISWHITE
PHOTO_CIELAB        → PHOTOMETRIC_CIELAB
PHOTO_ICCLAB        → PHOTOMETRIC_ICCLAB
```

#### **Planar Configuration (lines 297-322)**
```cpp
// Separate (planar) mode: samples in separate planes
if (m_nSamples > 1 && m_nPlanar == PLANARCONFIG_SEPARATE) {
  // Multiple passes reading separate planes per strip (lines 346-355)
  // Separate-to-interleaved conversion (lines 362-376)
}

// Contig (interleaved) mode: samples interleaved
else {
  // Single pass reading all samples together
}
```

#### **Bits Per Sample**
```cpp
8-bit   : unsigned int
16-bit  : unsigned int  
32-bit  : IEEE float (SAMPLEFORMAT_IEEEFP)
```

### **Critical Code Paths NOT COVERED**

#### **1. Tiling (LIBTIFF tiling API)**
**Status**: ❌ **NOT IMPLEMENTED**
- No calls to: `TIFFIsTiled()`, `TIFFNumberOfTiles()`, `TIFFComputeTile()`, `TIFFReadTile()`, `TIFFWriteTile()`
- No tags: `TIFFTAG_TILEWIDTH`, `TIFFTAG_TILELENGTH`
- **Impact**: Cannot read/write tiled TIFFs (common in high-performance GIS/imaging)

#### **2. Compression Decompression**
**Status**: ✅ **Set but not explicitly tested**
- Supports: COMPRESSION_NONE, COMPRESSION_LZW, PREDICTOR_HORIZONTAL, PREDICTOR_FLOATINGPOINT
- Coverage: Only indirectly through fuzzer inputs
- **Missing**: Explicit JPEG, DEFLATE codec validation

#### **3. Multi-Strip Validation**
**Status**: ⚠️ **Partially covered**
- `TIFFReadEncodedStrip()` / `TIFFWriteEncodedStrip()` called
- But input validation at line 273: rejects `rowsPerStrip == 0`
- **Missing**: Strips with height not divisible by rowsPerStrip (line 309)

#### **4. Extra Samples**
**Status**: ⚠️ **Partially tested**
- Read at line 264: `TIFFGetField(TIFFTAG_EXTRASAMPLES, &m_nExtraSamples, &nSampleInfo)`
- But nSampleInfo pointer never used for alpha interpretation
- **Missing**: Associated alpha, unassociated alpha, straight alpha handling

#### **5. Resolution Field**
**Status**: ✅ **Read but not validated**
- Lines 269-270: Read XRESOLUTION/YRESOLUTION
- But fuzzer doesn't test: 0 resolution, mismatched resolution, rational encoding

#### **6. Strip Size Overflow**
**Status**: ⚠️ **Protected by SIZE_MAX check**
- Lines 319-322: `if (m_nStripSamples && m_nStripSize > SIZE_MAX / m_nStripSamples) return false;`
- But fuzzer unlikely to trigger pathological strip sizes

---

## 4. Dictionary Analysis

### **icc_tiff_core.dict** (147 lines)
- **TIFF byte order**: II, MM variants
- **TIFF magic**: 0x002a, 0x2a00
- **Essential tags**: Width, height, samples, bits, photometric, compression
- **ICC profile tag**: 0x8773 (TIFFTAG_ICCPROFILE)
- **Coverage**: ⭐⭐⭐⭐ (comprehensive baseline)

### **icc_tiffdump_fuzzer.dict** (308 lines)
- **Generated by**: convert-libfuzzer-dict.py
- **Sources**:
  - Baseline TIFF tokens
  - ICC profile signatures
  - High-frequency patterns from 2.9M+ fuzzing sessions
  - Spectral tag signatures (svcn, pcc0, c2sp, sp2c)
- **Notable entries**:
  ```
  "II*\x00\x08\x00\x00\x00"  (complete little-endian TIFF header)
  "MM\x00*\x00\x00\x00\x08"  (complete big-endian TIFF header)
  "mluc", "sf32", "curv", "mft2"  (ICC tag types)
  "\xff\xff\xff\xff\xff\xff\xff\xff"  (boundary values)
  ```
- **Coverage**: ⭐⭐⭐⭐⭐ (highly optimized from 2M+ corpus)

### **icc_specsep_fuzzer.dict** (80+ lines)
- **Spectral-specific**:
  - Color space signatures: RGB, CMYK, Lab, XYZ, Yxy
  - Spectral tags: svcn, pcc0, c2sp, sp2c
  - Photometric modes: MINISBLACK, MINISWHITE, RGB, ICCLAB, CIELAB
- **Coverage**: ⭐⭐⭐ (good for spectral, but needs ICC profile tokens)

### **Missing Dictionary Entries**

| Category | Missing Entries | Impact |
|----------|-----------------|--------|
| **Compression types** | JPEG (7), DEFLATE (8), ADOBE_DEFLATE (32946) | Can't efficiently generate compressed TIFFs |
| **Predictor types** | PREDICTOR_NONE (1), PREDICTOR_FLOATINGPOINT (3) | Compression validation incomplete |
| **Resolution units** | RESUNIT_NONE (1), INCH (2), CENTIMETER (3) | Resolution parsing untested |
| **Sub-IFD tags** | TIFFTAG_SUBIFD (330), TIFFTAG_JPEGPROC (512) | Hierarchical TIFFs untested |
| **EXIF/ICC metadata** | TIFFTAG_EXIF (34665), TIFFTAG_XMP (700) | Metadata interop untested |
| **Color matrix tags** | TIFFTAG_COLORMATRIX1 (50964) | Advanced color space untested |
| **Bad sector IFD marker** | "FFFF" null terminate patterns | Malformed IFD handling untested |
| **Tile-specific tags** | TILEWIDTH (322), TILELENGTH (323) | Tiling format untested |

---

## 5. Seed Corpus Status

### **icc_tiffdump_fuzzer_seed_corpus**
- **Files**: 578 TIFF images
- **Size**: ~192 MB
- **Naming**: `{BitDepth|Encoding|Width}--{Profile}[--{Crash|Tag}].tiff`
- **Examples**:
  - `16BitDepth-image--Rec2020rgbColorimetric.tiff`
  - `16x16-strip2--Rec2020rgbColorimetric.tiff`
  - `BigEndian-image--crash-pushXYZConvert-heap-oob-.tiff`
- **Characteristics**:
  - All valid TIFFs (file command confirms)
  - Multiple bit depths (8, 16, 32-bit float)
  - Various ICC profiles embedded
  - Real-world crash reproduction cases
- **Coverage Quality**: ⭐⭐⭐⭐⭐ (Excellent)

### **fuzz/graphics/tif/** (Public Test TIFF Set)
- **Files**: 20+ standard TIFF test images
- **Coverage**:
  - `8x8-deflate--sRGB_v4_ICC_preference.tiff` (compressed)
  - `HDRFloatComponents-image--*.tiff` (32-bit float)
  - `PremultipliedFirstAlpha-image--*.tiff` (alpha channel)
  - `BigEndian-image.tiff` (byte order)
  - Stripe vs tile variants
- **Used by**: iccApplyProfiles fuzzer extensively

---

## 6. Code Coverage Analysis: What's NOT Tested

### **Severity: CRITICAL (Security/Stability Risk)**

| Feature | Status | Risk | Why Untested |
|---------|--------|------|--------------|
| **Tiled TIFF format** | ❌ Not implemented | High | No TIFFReadTile/TIFFWriteTile calls; TiffImg.cpp lines 215-237 only handle strips |
| **JPEG/DEFLATE codecs** | ⚠️ Set but not validated | Medium | libtiff handles decompression, but edge cases untested |
| **Planar CMYK (SEPARATED)** | ⚠️ Partial | Medium | Supported (line 156), but fuzzer rarely creates valid 4-plane CMYK |
| **Extra samples (alpha)** | ⚠️ Partial | Medium | Read (line 264) but nSampleInfo never examined for alpha premultiplication |
| **Strip boundary overflow** | ⚠️ Protected | Low | SIZE_MAX check present (line 319) but pathological strip sizes rare |

### **Severity: MEDIUM (Feature Gap)**

| Feature | Status | Gap | Why Untested |
|---------|--------|-----|--------------|
| **Separate plane interleaving** | ⚠️ Code exists | Not systematically tested | Separate flag set randomly in fuzzer, but no explicit branch coverage analysis |
| **Resolution mismatch handling** | ❌ No validation | Silently accepts invalid resolution | Lines 269-270 read but never validate > 0 |
| **TIFF directory chains** | ⚠️ IFD loop exists | No corruption detection | TIFFReadDirectory() called (line 219), but no invalid chain tests |
| **Color space validation** | ⚠️ ICC validation only | TIFF photometric not validated | Accepts any PHOTOMETRIC value; no check for colorimetric consistency |
| **Predictor validation** | ❌ No checking | Wrong predictor silently ignored | TIFFTAG_PREDICTOR set but libtiff auto-detects; no validation of matching data |

### **Severity: LOW (Edge Cases)**

| Feature | Status | Gap |
|---------|--------|-----|
| **Memory pressure** | ⚠️ Partial | 50MB limit on fuzzer input, no allocation failure injection |
| **Corrupted strip offsets** | ⚠️ Implicit detection | Detected by libtiff, not explicit fuzzer tests |
| **Invalid byte order markers** | ⚠️ Rejected early | Lines 96-98 check II/MM, but fuzzer dict doesn't include invalid markers |
| **Negative dimensions** | ⚠️ Implicit detection | Unsigned integers prevent, but signed interpretation untested |
| **Circular IFD references** | ❌ Not tested | Potential infinite loop if TIFF malformed to have IFD2 → IFD1 back-reference |

---

## 7. Recommended Dictionary Additions

### **High Priority**

```
# Compression algorithms (TIFFTAG_COMPRESSION)
"\x01\x00"  # COMPRESSION_NONE (1)
"\x02\x00"  # COMPRESSION_CCITTRLE (2)
"\x03\x00"  # COMPRESSION_CCITTFAX3 (3)
"\x04\x00"  # COMPRESSION_CCITTFAX4 (4)
"\x05\x00"  # COMPRESSION_LZW (5)
"\x06\x00"  # COMPRESSION_OJPEG (6)
"\x07\x00"  # COMPRESSION_JPEG (7)
"\x08\x00"  # COMPRESSION_DEFLATE (8)
"\x32\x80"  # COMPRESSION_ADOBE_DEFLATE (0x80b2)

# Predictors (TIFFTAG_PREDICTOR)
"\x01\x00"  # PREDICTOR_NONE (1)
"\x02\x00"  # PREDICTOR_HORIZONTAL (2)
"\x03\x00"  # PREDICTOR_FLOATINGPOINT (3)

# Resolution units (TIFFTAG_RESOLUTIONUNIT)
"\x01\x00"  # RESUNIT_NONE (1)
"\x02\x00"  # RESUNIT_INCH (2)
"\x03\x00"  # RESUNIT_CENTIMETER (3)

# Extra sample types (TIFFTAG_EXTRASAMPLES values)
"\x00\x00"  # EXTRASAMPLE_UNSPECIFIED (0)
"\x01\x00"  # EXTRASAMPLE_ASSOCALPHA (1)
"\x02\x00"  # EXTRASAMPLE_UNASSALPHA (2)

# Tile dimensions (if implementing tile support)
"\x00\x01"  # 256 pixels (common tile size)
"\x00\x02"  # 512 pixels
"\x00\x04"  # 1024 pixels

# Sample format flags
"\x01\x00"  # SAMPLEFORMAT_UINT (1)
"\x02\x00"  # SAMPLEFORMAT_INT (2)
"\x03\x00"  # SAMPLEFORMAT_IEEEFP (3)
"\x04\x00"  # SAMPLEFORMAT_VOID (4)
```

### **Medium Priority**

```
# Sub-IFD (for hierarchical TIFF support)
"SUBIFD"

# EXIF/XMP markers
"EXIF"
"XMP\x00"

# Floating-point resolution units
"\xcd\xcc\xcc>"  # 1.0f as IEEE float (common resolution)
"\x00\x00\xc8>"  # 100.0f as IEEE float

# Multi-page TIFF markers
"IFD1", "IFD2", "IFD3"  (not actual markers, but doc aids)
```

---

## 8. Comparison: icc_specsep_fuzzer vs icc_tiffdump_fuzzer

| Aspect | Specsep | Tiffdump |
|--------|---------|----------|
| **Primary Goal** | Create multi-channel TIFFs | Extract ICC from TIFF |
| **Data Flow** | Write (Create → WriteLine) | Read (Open, IFD iterate) |
| **Photometric Coverage** | 5 types (MINISBLACK/WHITE, RGB, CIELAB, ICCLAB) | Same (via validation) |
| **Planar Support** | Yes, explicitly tested | Read-only, not validated |
| **Strip Handling** | Write test (TIFFWriteEncodedStrip) | Read test (TIFFReadEncodedStrip) |
| **ICC Profile** | Optional embedding | Required extraction |
| **Bits Per Sample** | 8, 16, 32-bit float | Any (validated for bps==32→float) |
| **Corpus Size** | Not specified | 578 files, 192 MB |
| **Dead Code** | Line 287 MINISWHITE inversion (recently fixed) | Multiple paths below |
| **Strengths** | End-to-end pipeline testing | Diverse corpus, real crash cases |
| **Weaknesses** | No compression testing | No pixel data validation |

---

## 9. Critical Observations

### **Recent Fix (Not Yet Propagated)**
**icc_specsep_fuzzer.cpp, Line 287**: 
```cpp
// MINISWHITE inversion — exercises iccSpecSepToTiff.cpp lines 248-252
// This branch was previously unreachable in the fuzzer
if (nPhoto == PHOTO_MINISWHITE && !bFloat) {
  for (uint8_t j = 0; j < nFiles; j++) {
    // XOR 0xff inversion
  }
}
```
This indicates **fuzzer-driven test improvements are active**, but coverage gaps remain.

### **Infrastructure Disabled in CMakeLists.txt**
**cfl/CMakeLists.txt, Lines 149-159**:
```cmake
# TIFF-based fuzzers disabled:
# add_executable(icc_specsep_fuzzer icc_specsep_fuzzer.cpp)
# add_executable(icc_tiffdump_fuzzer icc_tiffdump_fuzzer.cpp)
# 
# Reason: "requires TiffImg.cpp" compilation
```
**Impact**: TiffImg.o exists (229 KB prebuilt), but fuzzers not in official CMake build. Only run manually or via CI scripts.

### **Tool Fidelity Gap**
- **icc_tiffdump_fuzzer.cpp**: In-memory processing (TIFFClientOpen)
- **Production iccTiffDump**: File-based (TIFFOpen)
- **Impact**: Memory allocation, seek buffering behavior differs from production

---

## 10. Recommended Fuzzing Improvements

### **Phase 1: Immediate Wins**
1. **Add dictionary entries** for compression types (copy from TIFF spec)
2. **Extend tiffdump corpus** with explicit tiled TIFF samples
3. **Enable CMakeLists.txt** fuzzer builds if not already done
4. **Add assertions** for planar CMYK in specsep fuzzer

### **Phase 2: Coverage Expansion**
1. **Implement tile reading** in TiffImg.cpp (`TIFFReadTile()` + buffer management)
2. **Add extra sample validation** in Open() method (check EXTRASAMPLE type)
3. **Create corpus** with:
   - Tiled 256×256, 512×512 layouts
   - JPEG-compressed TIFFs
   - CMYK 4-plane separations
   - Corrupted strip offset chains
4. **Add dictionary fuzzing** for resolution units and predictor types

### **Phase 3: Advanced Testing**
1. **Symbolic execution**: Analyze TIFFStripSize() calculation for overflow
2. **Coverage-guided mutation**: Run afl-tmin on corpus to find minimizers
3. **Memory profiling**: Use Valgrind/ASAN to detect leaks in strip buffer allocation
4. **Comparison testing**: Run icc_tiffdump against ImageMagick `identify` on same inputs

---

## 11. Appendix: TIFF Tag Enumeration

### **Tags Currently Used by CFL**
```
0x0100  IMAGEWIDTH
0x0101  IMAGELENGTH
0x0102  BITSPERSAMPLE
0x0106  PHOTOMETRIC
0x0112  ORIENTATION
0x0115  SAMPLESPERPIXEL
0x0116  ROWSPERSTRIP
0x0153  SAMPLEFORMAT
0x8773  ICCPROFILE (CRITICAL!)
+ implicit: COMPRESSION, PLANARCONFIG, EXTRASAMPLES, XRESOLUTION, YRESOLUTION, PREDICTOR
```

### **Tags NOT Covered**
```
0x010a  FILLORDER
0x010d  DOCUMENTNAME
0x010e  IMAGEDESCRIPTION
0x010f  MAKE
0x0110  MODEL
0x0111  STRIPOFFSETS
0x0115  SAMPLESPERPIXEL (already listed)
0x0119  DATATYPE
0x011a  PREDICTOR (noted as used)
0x011b  WHITEPOINT
0x011c  PRIMARYCHROMATICITIES
0x0122  GRAY*
0x0123  BASEPHOTOMETRIC
0x012d  TRANSFERFUNCTION
0x0134  MODEL
0x013b  ARTIST
0x013c  COPYRIGHT
0x013e  WHITEPOINT
0x013f  TRANSFERRANGE
0x0142  SUBFILETYPE
0x0143  SUBIFD
0x0146  TILEWIDTH
0x0147  TILELENGTH
0x0148  TILEOFFSETS
0x0149  TILEBYTECOUNTS
0x014a  BADFAXLINES
0x014b  CLEANFAXDATA
0x014c  CONSECUTIVEBADFAXLINES
0x014d  SUBIFDS
0x014e  INKNAMESPATTERN
0x0153  SAMPLEFORMAT (already listed)
0x0200+ (many more...)
```

---

## 12. Build Configuration

**Current Status**: Fuzzers disabled in CMakeLists.txt
**Recommended Build**:
```bash
cd cfl
mkdir build && cd build
cmake -DENABLE_FUZZING=ON -DTIFF_FOUND=ON ..
make -j$(nproc)
```

**Resulting Binaries**:
- `bin/icc_tiffdump_fuzzer` (✅ if enabled)
- `bin/icc_specsep_fuzzer` (✅ if enabled)
- Corpus: `corpus-icc_tiffdump_fuzzer/` (578 files)
- Corpus: `corpus-icc_specsep_fuzzer/` (4+ files)

