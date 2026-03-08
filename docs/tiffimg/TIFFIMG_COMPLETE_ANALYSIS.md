# TiffImg Class - Complete Code Path Analysis

## Overview
The `CTiffImg` class is located in `cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/TiffImg.{h,cpp}` and provides a wrapper around the TIFF library for reading/writing TIFF images with ICC profile support.

---

## CLASS DECLARATION (TiffImg.h)

### Public Methods

```cpp
CTiffImg();
virtual ~CTiffImg();

void Close();

bool Create(const char *szFname, unsigned int nWidth, unsigned int nHeight,
            unsigned int nBPS, unsigned int nPhoto, unsigned int nSamples, 
            unsigned int nExtraSamples, float fXRes, float fYRes, 
            bool bCompress=true, bool bSep=false);
bool Open(const char *szFname);

bool ReadLine(unsigned char *pBuf);
bool WriteLine(unsigned char *pBuf);

unsigned int GetWidth() { return m_nWidth; }
unsigned int GetHeight() { return m_nHeight; }
double GetWidthIn() { return (double)m_nWidth / m_fXRes; }
double GetHeightIn() { return (double)m_nHeight / m_fYRes; }
unsigned int GetBitsPerSample() { return m_nBitsPerSample; }
unsigned int GetPhoto();
unsigned int GetSamples() { return m_nSamples; }
unsigned int GetExtraSamples() { return m_nExtraSamples; }
unsigned int GetCompress() { return m_nCompress; }
unsigned int GetPlanar() { return m_nPlanar; }
float GetXRes() { return m_fXRes; }
float GetYRes() { return m_fYRes; }
unsigned int GetBytesPerLine() { return m_nBytesPerLine; }

bool GetIccProfile(unsigned char *&pProfile, unsigned int &nLen);
bool SetIccProfile(unsigned char *pProfile, unsigned int nLen);
```

### Protected Members

```cpp
TIFF *m_hTif;
bool m_bRead;

unsigned int m_nWidth;
unsigned int m_nHeight;
icUInt16Number m_nBitsPerSample;
icUInt16Number m_nBytesPerSample;
icUInt16Number m_nPhoto;           // photometric interpretation
icUInt16Number m_nSamples;
icUInt16Number m_nExtraSamples;
icUInt16Number m_nPlanar;          // PLANARCONFIG_CONTIG or PLANARCONFIG_SEPARATE
icUInt16Number m_nCompress;        // compression method

float m_fXRes, m_fYRes;            // resolution in pixels/inch

unsigned int m_nBytesPerLine;
unsigned int m_nRowsPerStrip;
unsigned int m_nStripSize;
unsigned int m_nStripSamples;
unsigned int m_nStripsPerSample;
unsigned int m_nBytesPerStripLine;

unsigned char *m_pStripBuf;

unsigned int m_nCurLine;
unsigned int m_nCurStrip;

unsigned char *m_pProfile;
unsigned int m_nProfileLength;
```

### Photometric Interpretation Constants (TiffImg.h)

```cpp
#define PHOTO_MINISBLACK  0
#define PHOTO_MINISWHITE  1
#define PHOTO_CIELAB      2
#define PHOTO_ICCLAB      3
#define PHOTO_RGB         4
```

---

## METHOD DETAILS

### 1. Constructor: CTiffImg()
**Lines:** 87-97
**Initialization:**
- m_nWidth = 0
- m_nHeight = 0
- m_nBitsPerSample = 0
- m_nSamples = 0
- m_nExtraSamples = 0
- m_hTif = NULL
- m_pStripBuf = NULL

### 2. Destructor: ~CTiffImg()
**Lines:** 99-102
- Calls Close()

### 3. Close()
**Lines:** 104-122
- Resets all image parameters to 0
- Closes TIFF file via TIFFClose()
- Frees strip buffer (m_pStripBuf)

### 4. Create() - WRITE Mode
**Lines:** 124-242
**Parameters:**
- szFname: output filename
- nWidth, nHeight: image dimensions
- nBPS: bits per sample (8, 16, 32)
- nPhoto: photometric mode (PHOTO_RGB, PHOTO_MINISBLACK, PHOTO_MINISWHITE, PHOTO_CIELAB, PHOTO_ICCLAB)
- nSamples: samples per pixel
- nExtraSamples: alpha/extra channels
- fXRes, fYRes: resolution
- bCompress: LZW compression (default true)
- bSep: planar separation (default false)

**Returns:** bool (success/failure)

**Logic:**
1. Calls Close() to reset state
2. Sets m_bRead = false
3. Validates and converts nPhoto parameter to TIFF photometric values:
   ```
   PHOTO_RGB (4)        -> PHOTOMETRIC_RGB
   PHOTO_MINISBLACK (0) -> if 3 samples: PHOTOMETRIC_RGB, else: PHOTOMETRIC_MINISBLACK
   PHOTO_MINISWHITE (1) -> if 4 samples: PHOTOMETRIC_SEPARATED, else: PHOTOMETRIC_MINISWHITE
   PHOTO_CIELAB (2)     -> PHOTOMETRIC_CIELAB
   PHOTO_ICCLAB (3)     -> PHOTOMETRIC_ICCLAB
   ```

4. Opens file with TIFFOpen(szFname, "w") → **Error Path 1**: returns false if NULL

5. Sets TIFF tags:
   - TIFFTAG_IMAGEWIDTH
   - TIFFTAG_IMAGELENGTH
   - TIFFTAG_PHOTOMETRIC
   - TIFFTAG_PLANARCONFIG (PLANARCONFIG_SEPARATE or PLANARCONFIG_CONTIG)
   - TIFFTAG_SAMPLESPERPIXEL
   - TIFFTAG_EXTRASAMPLES (if nExtraSamples > 0)
   - TIFFTAG_BITSPERSAMPLE
   - TIFFTAG_SAMPLEFORMAT (SAMPLEFORMAT_IEEEFP if nBPS==32)
   - TIFFTAG_ROWSPERSTRIP (set to 1)
   - TIFFTAG_COMPRESSION (COMPRESSION_LZW or COMPRESSION_NONE)
   - TIFFTAG_ORIENTATION (always ORIENTATION_TOPLEFT)
   - TIFFTAG_XRESOLUTION
   - TIFFTAG_YRESOLUTION
   - TIFFTAG_PREDICTOR (if compressed: PREDICTOR_FLOATINGPOINT for 32-bit, PREDICTOR_HORIZONTAL otherwise)

6. Strip/Buffer Calculation:
   - If bSep && nSamples > 1: **Planar Separation Mode**
     - m_nStripSamples = nSamples
     - Validates: nBPS % 8 == 0 → **Error Path 2**
     - Calculates strip sizes and allocated m_pStripBuf
     - Validates: m_nStripSize matches expected byte-per-strip-line → **Error Path 3**
     - Validates: SIZE_MAX overflow check → **Error Path 4**
     - Allocates: m_pStripBuf = malloc(m_nStripSize * m_nStripSamples) → **Error Path 5**
   - Else: **Contiguous Mode**
     - m_nBytesPerLine = m_nStripSize = TIFFStripSize()
     - m_nStripSamples = 1

7. Initializes m_nCurLine = 0, m_nCurStrip = 0

**Error Paths in Create():**
- Line 173: TIFFOpen fails
- Line 211: BPS % 8 != 0 (non-byte-aligned samples in planar mode)
- Line 220: Strip size mismatch
- Line 226: SIZE_MAX overflow
- Line 232: malloc fails

### 5. Open() - READ Mode
**Lines:** 244-331
**Parameters:**
- szFname: input filename

**Returns:** bool (success/failure)

**Logic:**
1. Calls Close() to reset state
2. Sets m_bRead = true
3. Opens file with TIFFOpen(szFname, "r") → **Error Path 1**: returns false if NULL

4. Reads TIFF tags:
   - TIFFTAG_IMAGEWIDTH
   - TIFFTAG_IMAGELENGTH
   - TIFFTAG_PHOTOMETRIC
   - TIFFTAG_PLANARCONFIG
   - TIFFTAG_SAMPLESPERPIXEL
   - TIFFTAG_EXTRASAMPLES
   - TIFFTAG_BITSPERSAMPLE
   - TIFFTAG_SAMPLEFORMAT
   - TIFFTAG_ROWSPERSTRIP
   - TIFFTAG_ORIENTATION
   - TIFFTAG_XRESOLUTION
   - TIFFTAG_YRESOLUTION
   - TIFFTAG_COMPRESSION

5. **Validation (Lines 273-290):**
   - **Error Path 2**: m_nRowsPerStrip == 0 || m_nSamples == 0 || m_nBitsPerSample == 0
   - Line 281: If m_nRowsPerStrip > m_nHeight, clamp to m_nHeight (best guess)
   - **Error Path 3**: 32-bit requires SAMPLEFORMAT_IEEEFP, non-32-bit requires SAMPLEFORMAT_UINT
   - **Error Path 4**: Orientation must be ORIENTATION_TOPLEFT

6. Strip Configuration:
   - If m_nSamples > 1 && m_nPlanar == PLANARCONFIG_SEPARATE: **Planar Mode**
     - m_nStripSamples = m_nSamples
     - m_nBytesPerLine = (m_nWidth * m_nBitsPerSample * m_nSamples + 7) >> 3
     - **Error Path 5**: m_nBitsPerSample % 8 != 0 (non-byte-aligned not supported)
     - m_nStripsPerSample = m_nHeight / m_nRowsPerStrip
     - **Error Path 6**: m_nHeight % m_nRowsPerStrip != 0 (not evenly divisible)
   - Else: **Contiguous Mode**
     - m_nStripSamples = 1
     - m_nBytesPerLine = (m_nWidth * m_nBitsPerSample * m_nSamples + 7) >> 3

7. Memory Allocation:
   - **Error Path 7**: SIZE_MAX overflow check
   - **Error Path 8**: malloc(m_nStripSize * m_nStripSamples) fails

8. Initializes m_nCurStrip = (unsigned int)-1, m_nCurLine = 0

**Error Paths in Open():**
- Line 252: TIFFOpen fails
- Line 278: Invalid/corrupt TIFF tags
- Line 289: Sample format/orientation validation fails
- Line 305: Non-byte-aligned bits in planar mode
- Line 311: Image height not divisible by rows per strip
- Line 321: SIZE_MAX overflow
- Line 327: malloc fails

### 6. ReadLine() - READ Mode
**Lines:** 334-383
**Parameters:**
- pBuf: output buffer for one line of pixels

**Returns:** bool (success/failure)

**Pre-condition:** m_bRead == true, m_nRowsPerStrip > 0

**Logic:**
1. **Validation (Line 336):** → **Error Path 1**
   - if (!m_bRead || m_nRowsPerStrip == 0) return false

2. Calculate strip number and row offset:
   ```cpp
   nStrip = m_nCurLine / m_nRowsPerStrip
   nRowOffset = m_nCurLine % m_nRowsPerStrip
   ```

3. **Strip Loading (Lines 342-360):**
   - If nStrip != m_nCurStrip, load new strip:
     - If m_nStripSamples > 1: **PLANAR MODE** (Separate Planes)
       - For each sample s:
         - TIFFReadEncodedStrip(m_hTif, m_nCurStrip+nStripOffset, pos, m_nStripSize)
         - → **Error Path 2** if < 0
         - Update pos += m_nBytesPerStripLine, nStripOffset += m_nStripsPerSample
     - Else: **CONTIGUOUS MODE**
       - TIFFReadEncodedStrip(m_hTif, m_nCurStrip, m_pStripBuf, m_nStripSize)
       - → **Error Path 3** if < 0

4. **Data Conversion (Lines 362-379):**
   - If m_nStripSamples > 1: **Convert Planar→Contiguous**
     - For each width position w:
       - For each sample s:
         - memcpy(dst, src[pos], m_nBytesPerSample)
         - pos += m_nStripSize (jump to next sample plane)
   - Else: **Copy Contiguous**
     - memcpy(pBuf, m_pStripBuf+nRowOffset*m_nBytesPerLine, m_nBytesPerLine)

5. Increment m_nCurLine++

**Error Paths in ReadLine():**
- Line 337: Not in read mode or invalid strip configuration
- Line 351: TIFFReadEncodedStrip fails (planar mode)
- Line 358: TIFFReadEncodedStrip fails (contiguous mode)

### 7. WriteLine() - WRITE Mode
**Lines:** 385-421
**Parameters:**
- pBuf: input buffer for one line of pixels (contiguous format)

**Returns:** bool (success/failure)

**Pre-condition:** m_bRead == false

**Logic:**
1. **Validation (Line 387):** → **Error Path 1**
   - if (m_bRead) return false

2. **Line Buffering Check (Line 390):**
   - if (m_nCurStrip < m_nHeight)

3. **Data Conversion & Writing (Lines 391-412):**
   - If m_nStripSamples > 1: **Convert Contiguous→Planar**
     - For each width position w:
       - For each sample s:
         - memcpy(pos, src, m_nBytesPerSample)
         - src += m_nBytesPerSample
         - pos += m_nStripSize (jump to next sample plane)
     - For each sample s:
       - TIFFWriteEncodedStrip(m_hTif, m_nCurStrip+offset, src, m_nStripSize)
       - → **Error Path 2** if < 0
       - offset += m_nStripsPerSample, src += m_nStripSize
   - Else: **Write Contiguous**
     - TIFFWriteEncodedStrip(m_hTif, m_nCurStrip, pBuf, m_nBytesPerLine)
     - → **Error Path 3** if < 0

4. Increment m_nCurStrip++

**Error Paths in WriteLine():**
- Line 388: Not in write mode
- Line 409: TIFFWriteEncodedStrip fails (planar mode)
- Line 415: TIFFWriteEncodedStrip fails (contiguous mode)

### 8. GetPhoto() - Photometric Interpretation Mapper
**Lines:** 423-441

**Returns:** Mapped photometric constant

**Conversion Logic:**
```
PHOTOMETRIC_RGB           -> PHOTO_RGB (4)
PHOTOMETRIC_MINISBLACK    -> PHOTO_MINISBLACK (0)
PHOTOMETRIC_MINISWHITE    -> PHOTO_MINISWHITE (1)
PHOTOMETRIC_SEPARATED     -> PHOTO_MINISWHITE (1)
PHOTOMETRIC_CIELAB        -> PHOTO_CIELAB (2)
PHOTOMETRIC_ICCLAB        -> PHOTO_ICCLAB (3)
Any other                 -> PHOTO_MINISWHITE (1) [default]
```

### 9. GetIccProfile() - Read Embedded ICC Profile
**Lines:** 444-452
**Parameters:**
- pProfile: output pointer to profile data
- nLen: output length of profile

**Returns:** bool (profile exists and is valid)

**Logic:**
1. Initialize pProfile = NULL, nLen = 0
2. TIFFGetField(m_hTif, TIFFTAG_ICCPROFILE, &nLen, &pProfile)
3. Return true if pProfile != NULL && nLen > 0

### 10. SetIccProfile() - Embed ICC Profile
**Lines:** 454-459
**Parameters:**
- pProfile: pointer to profile data
- nLen: length of profile

**Returns:** bool (always true)

**Logic:**
1. TIFFSetField(m_hTif, TIFFTAG_ICCPROFILE, nLen, pProfile)
2. Return true

---

## TIFF TAG REFERENCE

### Tags Read in Open():
- **TIFFTAG_IMAGEWIDTH** (256)
- **TIFFTAG_IMAGELENGTH** (257)
- **TIFFTAG_PHOTOMETRIC** (262)
- **TIFFTAG_PLANARCONFIG** (284)
- **TIFFTAG_SAMPLESPERPIXEL** (277)
- **TIFFTAG_EXTRASAMPLES** (338)
- **TIFFTAG_BITSPERSAMPLE** (258)
- **TIFFTAG_SAMPLEFORMAT** (339)
- **TIFFTAG_ROWSPERSTRIP** (278)
- **TIFFTAG_ORIENTATION** (274)
- **TIFFTAG_XRESOLUTION** (282)
- **TIFFTAG_YRESOLUTION** (283)
- **TIFFTAG_COMPRESSION** (259)
- **TIFFTAG_ICCPROFILE** (34675)

### Tags Written in Create():
- **TIFFTAG_IMAGEWIDTH** (256)
- **TIFFTAG_IMAGELENGTH** (257)
- **TIFFTAG_PHOTOMETRIC** (262)
- **TIFFTAG_PLANARCONFIG** (284)
- **TIFFTAG_SAMPLESPERPIXEL** (277)
- **TIFFTAG_EXTRASAMPLES** (338) [optional]
- **TIFFTAG_BITSPERSAMPLE** (258)
- **TIFFTAG_SAMPLEFORMAT** (339) [if BPS==32]
- **TIFFTAG_ROWSPERSTRIP** (278)
- **TIFFTAG_COMPRESSION** (259)
- **TIFFTAG_ORIENTATION** (274)
- **TIFFTAG_XRESOLUTION** (282)
- **TIFFTAG_YRESOLUTION** (283)
- **TIFFTAG_PREDICTOR** (317) [if compressed]
- **TIFFTAG_ICCPROFILE** (34675) [via SetIccProfile()]

---

## COMPRESSION MODES

Supported values:
- **COMPRESSION_NONE** (1): No compression
- **COMPRESSION_LZW** (5): LZW compression (default in Create if bCompress=true)

---

## PLANAR CONFIGURATION MODES

- **PLANARCONFIG_CONTIG** (1): Interleaved samples (default, bSep=false)
- **PLANARCONFIG_SEPARATE** (2): Separate planes (bSep=true)

---

## PHOTOMETRIC INTERPRETATIONS

- **PHOTOMETRIC_MINISBLACK** (1): 0 is black, white is highest value
- **PHOTOMETRIC_MINISWHITE** (0): 0 is white, black is highest value
- **PHOTOMETRIC_RGB** (2): RGB color
- **PHOTOMETRIC_CIELAB** (8): CIE L*a*b* color space
- **PHOTOMETRIC_ICCLAB** (9): ICC L*a*b* color space
- **PHOTOMETRIC_SEPARATED** (5): Color separations (CMYK-like)
- **PHOTOMETRIC_PALETTE** (3): Color palette [checked but rejected in iccSpecSepToTiff]

---

## SAMPLE FORMATS

- **SAMPLEFORMAT_UINT** (1): Unsigned integer (default)
- **SAMPLEFORMAT_IEEEFP** (3): IEEE floating point (32-bit)

---

## ORIENTATION REQUIREMENT

- Only **ORIENTATION_TOPLEFT** (1) is supported
- Any other orientation causes Open() to fail

---

## BITS PER SAMPLE SUPPORT

Supported values:
- **8-bit** (8): unsigned integer
- **16-bit** (16): unsigned integer
- **32-bit** (32): IEEE float (SAMPLEFORMAT_IEEEFP)

In planar mode, bits per sample must be byte-aligned (% 8 == 0).

---

## TOOL-SPECIFIC CODE PATHS

### iccTiffDump.cpp (Read-only tool)
**Lines:** 184-252

**Code Path:**
1. Opens TIFF with Open()
2. Reads all image properties via getter methods
3. Reads embedded ICC profile via GetIccProfile()
4. Optionally exports profile to file
5. Parses and displays profile information

**Exercised Features:**
- GetWidth(), GetHeight()
- GetWidthIn(), GetHeightIn()
- GetPlanar() [PLANARCONFIG_CONTIG/SEPARATE]
- GetBitsPerSample() [8, 16, 32]
- GetSamples(), GetExtraSamples()
- GetPhoto() [PHOTO_MINISBLACK, PHOTO_MINISWHITE, PHOTO_CIELAB, PHOTO_ICCLAB, PHOTO_RGB]
- GetBytesPerLine()
- GetXRes(), GetYRes()
- GetCompress() [COMPRESSION_NONE, COMPRESSION_LZW]
- GetIccProfile()

### iccApplyProfiles.cpp (Read-Modify-Write tool)
**Lines:** 151-638

**Code Paths:**
1. Opens source TIFF with Open()
2. Validates bits-per-sample support (8, 16, 32)
3. Determines destination photometric based on ICC profile color space:
   ```
   icSigRgbData              -> PHOTO_RGB
   icSigCmyData/icSigCmykData/4-8colorData -> PHOTO_MINISWHITE
   icSigXYZData/icSigLabData -> PHOTO_CIELAB
   default                   -> PHOTO_MINISBLACK
   ```
4. Creates destination TIFF with Create()
5. Optionally embeds ICC profile via SetIccProfile()
6. For each line:
   - Reads line with ReadLine()
   - Applies color conversions (including CIELAB/XYZ transformations)
   - Writes line with WriteLine()
7. Closes both images

**Color Space Transformations:**
- **CIELAB (8-bit):** L: 0-255, a/b: -128 to +127 (biased to 128)
- **CIELAB (16-bit):** L: 0-65535, a/b: -32768 to +32767 (biased to 0x8000)
- **CIELAB (32-bit):** Uses icLabToPcs/icLabFromPcs transformations
- **XYZ<->Lab:** icXyzToLab, icLabtoXYZ, icXyzToPcs, icLabToPcs
- **Clip:** UnitClip() guards against NaN and clamps [0,1]

**Exercised Features:**
- Open() with all validation paths
- ReadLine() for all sample configurations
- GetBitsPerSample(), GetSamples(), GetExtraSamples()
- GetPhoto() with photometric mapping
- GetBytesPerLine(), GetWidth(), GetHeight()
- GetXRes(), GetYRes()
- GetCompress(), GetPlanar() for destination configuration
- Create() with all photometric modes and compression options
- WriteLine() for all sample configurations
- SetIccProfile() for embedding
- Close()

### iccSpecSepToTiff.cpp (Spectral concatenation tool)
**Lines:** 119-272

**Code Paths:**
1. Opens N input TIFF files with Open()
2. Validates:
   - All files have 1 sample per pixel
   - No palette-based files (rejects PHOTOMETRIC_PALETTE)
   - All files match format (width, height, BPS, photo, resolution)
3. Supports photometric modes:
   - PHOTO_MINISBLACK (0)
   - PHOTO_MINISWHITE (1) [with inversion logic]
   - Rejects other modes
4. Creates output TIFF with:
   - Multiple samples (N channels concatenated)
   - PHOTO_MINISBLACK photometric
   - Configurable compression and planar separation
5. For each line:
   - Reads line from each input with ReadLine()
   - Inverts if PHOTO_MINISWHITE (XOR with 0xff)
   - Interleaves samples into contiguous output format
   - Writes with WriteLine()
6. Optionally embeds ICC profile via SetIccProfile()

**Exercised Features:**
- Open() for multiple files
- GetSamples() [must be 1]
- GetPhoto() [supports MINISBLACK, MINISWHITE, rejects PALETTE]
- GetWidth(), GetHeight(), GetBitsPerSample()
- GetXRes(), GetYRes()
- GetBytesPerLine()
- Create() with PHOTO_MINISBLACK, multiple samples, planar separation
- ReadLine() for each channel
- WriteLine() for interleaved output
- SetIccProfile()

---

## FUZZER TARGET COVERAGE MATRIX

| Feature | Method | Open | Create | ReadLine | WriteLine | Tools |
|---------|--------|------|--------|----------|-----------|-------|
| 8-bit unsigned | All | ✓ | ✓ | ✓ | ✓ | All |
| 16-bit unsigned | All | ✓ | ✓ | ✓ | ✓ | All |
| 32-bit float | All | ✓ | ✓ | ✓ | ✓ | Apply |
| RGB photometric | Open/Create/GetPhoto | ✓ | ✓ | - | - | Dump, Apply, SpecSep |
| MINISBLACK | Open/Create/GetPhoto | ✓ | ✓ | - | - | All |
| MINISWHITE | Open/Create/GetPhoto | ✓ | ✓ | - | - | All |
| CIELAB | Open/Create/GetPhoto | ✓ | ✓ | - | - | Apply |
| ICCLAB | Open/Create/GetPhoto | ✓ | ✓ | - | - | Apply |
| Contiguous (1-sample) | Open/Create/ReadLine/WriteLine | ✓ | ✓ | ✓ | ✓ | All |
| Contiguous (multi-sample) | Open/Create/ReadLine/WriteLine | ✓ | ✓ | ✓ | ✓ | Apply |
| Planar separated | Open/Create/ReadLine/WriteLine | ✓ | ✓ | ✓ | ✓ | Apply, SpecSep |
| No compression | Create | - | ✓ | ✓ | ✓ | All |
| LZW compression | Create | - | ✓ | ✓ | ✓ | All |
| ICC profile embedding | SetIccProfile | - | ✓ | - | - | Apply, SpecSep |
| ICC profile extraction | GetIccProfile | ✓ | - | - | - | Dump |
| Extra samples | Create | ✓ | ✓ | - | - | Apply |
| Resolution metadata | Create | ✓ | ✓ | - | - | All |
| Strip-based I/O | ReadLine/WriteLine | ✓ | ✓ | ✓ | ✓ | All |
| Orientation validation | Open | ✓ | - | - | - | Implicit |

---

## ERROR PATHS & VALIDATION RULES

### Open() Validation:
1. TIFFOpen() must succeed
2. m_nRowsPerStrip, m_nSamples, m_nBitsPerSample must be > 0
3. If BPS==32: nSampleFormat must be SAMPLEFORMAT_IEEEFP
4. If BPS!=32: nSampleFormat must be SAMPLEFORMAT_UINT
5. Orientation must be ORIENTATION_TOPLEFT
6. If planar + multi-sample: BPS must be byte-aligned (% 8 == 0)
7. If planar + multi-sample: image height must divide evenly by rows-per-strip
8. Memory allocation must not overflow (SIZE_MAX check)
9. malloc(m_pStripBuf) must succeed

### Create() Validation:
1. TIFFOpen() must succeed
2. If planar + multi-sample: BPS must be byte-aligned (% 8 == 0)
3. Strip size calculations must match expectations
4. Memory allocation must not overflow (SIZE_MAX check)
5. malloc(m_pStripBuf) must succeed

### ReadLine() Requirements:
1. m_bRead must be true
2. m_nRowsPerStrip > 0
3. TIFFReadEncodedStrip() must return >= 0

### WriteLine() Requirements:
1. m_bRead must be false
2. m_nCurStrip < m_nHeight
3. TIFFWriteEncodedStrip() must return >= 0

---

## MEMORY SAFETY CONCERNS

1. **Strip Buffer Allocation:** Multiplication overflow check (SIZE_MAX) before malloc
2. **Byte-alignment:** Required for planar mode (BPS % 8 == 0)
3. **Height divisibility:** Planar mode requires height % rows_per_strip == 0
4. **memcpy operations:** Depend on correct calculation of widths/strides
5. **Pointer arithmetic:** In ReadLine/WriteLine for planar↔contiguous conversion
6. **TIFF library calls:** Return value checking for TIFFReadEncodedStrip/TIFFWriteEncodedStrip

---

## BRANCH COVERAGE ANALYSIS

### Total Branches:
1. Create() photometric switch: 5 cases (RGB, MINISBLACK, MINISWHITE, CIELAB, ICCLAB)
2. Create() separation mode: 2 branches (planar vs contiguous)
3. Open() sample format validation: 2 branches (32-bit vs other)
4. Open() planar config: 2 branches (planar vs contiguous)
5. ReadLine() strip loading: 2 branches (planar vs contiguous)
6. ReadLine() data conversion: 2 branches (planar↔contiguous vs copy)
7. WriteLine() data conversion: 2 branches (contiguous→planar vs write)
8. GetPhoto() photometric mapping: 6 branches (RGB, MINISBLACK, MINISWHITE, CIELAB, ICCLAB, default)

**Total Distinct Branches:** ~23+

---

## FUZZER INPUT RECOMMENDATIONS

To exercise all code paths, fuzzer should:
1. Create files with all combinations of:
   - BPS: 8, 16, 32
   - Photometric: RGB, MINISBLACK, MINISWHITE, CIELAB, ICCLAB
   - Samples: 1, 3, 4, N
   - ExtraSamples: 0, 1
   - Planar: CONTIG, SEPARATE
   - Compression: NONE, LZW
2. Vary dimensions: 0, 1, small, large, non-divisible-by-rowsperstrip
3. Vary rowsperstrip values: 0, 1, > height
4. Corrupt tags: missing, invalid values, overflow values
5. Corrupt ICC profiles: present/absent, invalid size
6. Corrupt strips: unreadable, truncated, wrong size
7. Vary resolution values: 0, invalid floating point
8. Orientation: non-TOPLEFT values
9. Sample formats: non-standard combinations

