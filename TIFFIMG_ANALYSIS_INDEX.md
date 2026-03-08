# TiffImg Class - Complete Analysis Index

## 📋 Overview
This directory contains a comprehensive analysis of the **CTiffImg class** used by the TIFF fuzzer target. The class is a wrapper around the libtiff library for reading/writing TIFF images with ICC profile support.

**Location:** `/home/h02332/po/research/cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/TiffImg.{h,cpp}`

---

## 📁 Analysis Documents

### 1. **TIFFIMG_QUICK_REFERENCE.txt** ⭐ START HERE
   - **Purpose:** Quick lookup for common patterns and validation rules
   - **Contents:**
     - All 10 public methods
     - Photometric types (5 types)
     - Sample formats and bits (8, 16, 32-bit)
     - Planar configurations (contiguous vs. separate)
     - Compression modes
     - Validation rules for Open() and Create()
     - All TIFF tags read/written
     - Tool usage patterns
     - Key branch points
     - Fuzzer coverage checklist
   - **Read Time:** 5-10 minutes

### 2. **TIFFIMG_CODE_PATHS.txt** ⭐ FOR DETAILED UNDERSTANDING
   - **Purpose:** Visual tree representation of all code branches
   - **Contents:**
     - Branch trees for Create(), Open(), ReadLine(), WriteLine()
     - Profile methods (GetIccProfile, SetIccProfile)
     - Close() method
     - Photometric mapping (GetPhoto) with all 6 cases
     - Tool-specific code paths (iccTiffDump, iccApplyProfiles, iccSpecSepToTiff)
     - Critical validation points for fuzzer (5 priority levels)
     - Sample format validation table
   - **Read Time:** 15-20 minutes

### 3. **TIFFIMG_COMPLETE_ANALYSIS.md** ⭐ FOR COMPREHENSIVE DETAILS
   - **Purpose:** In-depth technical reference
   - **Contents:**
     - Class declaration with all members (10 public methods, 14 protected members)
     - Detailed method-by-method breakdown (lines, parameters, logic, error paths)
     - All TIFF tags (14 read, 15 written)
     - Compression modes and sample formats
     - Planar configuration modes
     - All error paths with line numbers
     - Tool-specific code paths with exercised features
     - Fuzzer target coverage matrix
     - Branch coverage analysis (23+ branches)
     - Memory safety concerns
     - Fuzzer input recommendations
   - **Read Time:** 30-45 minutes

---

## 🎯 Quick Navigation

### For Fuzzer Development:
1. Read **QUICK_REFERENCE.txt** → "FUZZER COVERAGE CHECKLIST"
2. Read **CODE_PATHS.txt** → "CRITICAL VALIDATION POINTS FOR FUZZER"
3. Check **COMPLETE_ANALYSIS.md** → "ERROR PATHS & VALIDATION RULES"

### For Understanding Specific Methods:
- **Open()**: CODE_PATHS.txt §2, COMPLETE_ANALYSIS.md §5
- **Create()**: CODE_PATHS.txt §1, COMPLETE_ANALYSIS.md §4
- **ReadLine()**: CODE_PATHS.txt §3, COMPLETE_ANALYSIS.md §6
- **WriteLine()**: CODE_PATHS.txt §4, COMPLETE_ANALYSIS.md §7
- **GetPhoto()**: CODE_PATHS.txt §5, COMPLETE_ANALYSIS.md §8

### For Tool Integration:
- **iccTiffDump** (read-only): CODE_PATHS.txt §8, COMPLETE_ANALYSIS.md §11.1
- **iccApplyProfiles** (read-modify-write): CODE_PATHS.txt §8, COMPLETE_ANALYSIS.md §11.2
- **iccSpecSepToTiff** (spectral concatenation): CODE_PATHS.txt §8, COMPLETE_ANALYSIS.md §11.3

---

## 🔧 Key Technical Points

### Validation Rules
```
Open():
  ✓ TIFFOpen succeeds
  ✓ RowsPerStrip > 0, Samples > 0, BPS > 0
  ✓ BPS==32 → SAMPLEFORMAT_IEEEFP
  ✓ BPS!=32 → SAMPLEFORMAT_UINT
  ✓ Orientation == TOPLEFT
  ✓ If PLANAR+MULTI: BPS%8==0 and Height%RowsPerStrip==0
  ✓ No SIZE_MAX overflow on strip allocation

Create():
  ✓ TIFFOpen succeeds
  ✓ If PLANAR+MULTI: BPS%8==0
  ✓ No SIZE_MAX overflow
  ✓ malloc succeeds
```

### Photometric Types (5 total)
- **PHOTO_RGB** (4): RGB color
- **PHOTO_MINISBLACK** (0): Grayscale (0=black)
- **PHOTO_MINISWHITE** (1): Grayscale (0=white)
- **PHOTO_CIELAB** (2): CIE L*a*b* color
- **PHOTO_ICCLAB** (3): ICC L*a*b* color

### Planar Configurations
- **PLANARCONFIG_CONTIG**: Interleaved (RGBRGBRGB...) - default
- **PLANARCONFIG_SEPARATE**: Separated planes (RRR...GGG...BBB...)

### Data Formats
- **8-bit unsigned**: BPS=8, SAMPLEFORMAT_UINT
- **16-bit unsigned**: BPS=16, SAMPLEFORMAT_UINT
- **32-bit float**: BPS=32, SAMPLEFORMAT_IEEEFP

---

## 📊 Code Coverage Breakdown

### Public Methods (10):
1. CTiffImg() - constructor
2. ~CTiffImg() - destructor
3. Close() - cleanup
4. **Open()** - read validation [7 error paths]
5. **Create()** - write setup [5 error paths]
6. **ReadLine()** - read with planar↔contig conversion [2 error paths]
7. **WriteLine()** - write with contig→planar conversion [2 error paths]
8. GetPhoto() - photometric mapping [6 branches]
9. GetIccProfile() - extract profile
10. SetIccProfile() - embed profile

### Branch Count: 23+ distinct branches
- Create() photometric: 5
- Create() separation: 2
- Open() sample format: 2
- Open() planar: 2
- ReadLine() strip: 2
- ReadLine() data: 2
- WriteLine() data: 2
- GetPhoto() mapping: 6

### Error Paths: 26 total
- Create(): 5
- Open(): 8
- ReadLine(): 2
- WriteLine(): 2
- ReadLine/WriteLine mode checks: 2

---

## 🚀 Fuzzer Implementation Hints

### Essential Inputs:
1. **Dimension variations**: 0×0, 1×1, 16×16, large, non-divisible-by-rowsperstrip
2. **Sample configurations**: 1, 3, 4, N samples
3. **Extra samples**: 0, 1+
4. **BPS variations**: 8, 16, 32 (invalid: 4, 24, 31, 33)
5. **Photometric**: RGB, MINISBLACK, MINISWHITE, CIELAB, ICCLAB
6. **Planar**: CONTIG, SEPARATE
7. **Compression**: NONE, LZW
8. **RowsPerStrip**: 0, 1, > height, non-divisors of height

### Critical Edge Cases:
- Planar mode with non-byte-aligned BPS
- Height not divisible by RowsPerStrip in planar mode
- BPS=32 with SAMPLEFORMAT_UINT (invalid)
- BPS=8/16 with SAMPLEFORMAT_IEEEFP (invalid)
- Non-TOPLEFT orientation
- Missing required tags
- RowsPerStrip = 0, Samples = 0, BPS = 0
- SIZE_MAX overflow in strip allocation
- Corrupt ICC profile (present but invalid)

### Tool-Specific Paths:
- **iccTiffDump**: Open + getters + GetIccProfile
- **iccApplyProfiles**: Open + Create + ReadLine/WriteLine loop + SetIccProfile
- **iccSpecSepToTiff**: Multiple Open + Create + interleaved ReadLine/WriteLine + SetIccProfile

---

## 📝 Source Code References

### TiffImg.h (147 lines)
- Lines 74-78: Photometric constants (5 types)
- Lines 80-145: Class declaration (10 public methods, 14 protected members)

### TiffImg.cpp (460 lines)
- **Constructor**: Lines 87-97
- **Destructor**: Lines 99-102
- **Close()**: Lines 104-122
- **Create()**: Lines 124-242 (5 error paths, 2 branches)
- **Open()**: Lines 244-331 (8 error paths, 2 branches)
- **ReadLine()**: Lines 334-383 (2 error paths, 2 branches)
- **WriteLine()**: Lines 385-421 (2 error paths, 2 branches)
- **GetPhoto()**: Lines 423-441 (6 branches)
- **GetIccProfile()**: Lines 444-452
- **SetIccProfile()**: Lines 454-459

### Tool Files:
- **iccTiffDump.cpp**: Lines 184-252 (read-only tool)
- **iccApplyProfiles.cpp**: Lines 151-638 (color space transformation)
- **iccSpecSepToTiff.cpp**: Lines 119-272 (spectral concatenation)

---

## 🔍 Testing Strategy

### Phase 1: Basic Coverage
- [ ] All photometric types
- [ ] All BPS values (8, 16, 32)
- [ ] Both planar configurations
- [ ] Both compression modes

### Phase 2: Validation
- [ ] All error paths in Open()
- [ ] All error paths in Create()
- [ ] All stripe configurations
- [ ] All orientation values (TOPLEFT and others)

### Phase 3: Advanced
- [ ] ICC profile embedding/extraction
- [ ] Extra samples handling
- [ ] Multi-file concurrent operations
- [ ] Tool-specific workflows

### Phase 4: Fuzzing
- [ ] Mutated dimensions
- [ ] Corrupted tags
- [ ] Invalid sample format combinations
- [ ] SIZE_MAX overflow conditions
- [ ] malloc failure simulation

---

## 📦 File Summary

| File | Size | Lines | Purpose |
|------|------|-------|---------|
| TIFFIMG_QUICK_REFERENCE.txt | ~6 KB | 200 | Quick lookup |
| TIFFIMG_CODE_PATHS.txt | ~39 KB | 600 | Visual branch analysis |
| TIFFIMG_COMPLETE_ANALYSIS.md | ~43 KB | 661 | Comprehensive reference |
| TIFFIMG_ANALYSIS_INDEX.md | This file | | Navigation guide |

---

## 🎓 Learning Path

**Beginner (new to TiffImg):**
1. QUICK_REFERENCE.txt (5 min)
2. CODE_PATHS.txt §1-7 (20 min)
3. Create simple test TIFF files

**Intermediate (implementing fuzzer):**
1. CODE_PATHS.txt §8-10 (20 min)
2. COMPLETE_ANALYSIS.md §5-7 (30 min)
3. Implement basic fuzzer with all branches

**Advanced (optimizing coverage):**
1. COMPLETE_ANALYSIS.md §4, §11 (30 min)
2. Study error path coverage (26 paths)
3. Implement adaptive fuzzing strategy

---

## ✅ Validation Checklist for Fuzzer

- [ ] Can create/read all 5 photometric types
- [ ] Can create/read all 3 BPS values (8, 16, 32)
- [ ] Handles both planar configurations
- [ ] Tests all 26 error paths
- [ ] Covers all 23+ branches
- [ ] Validates sample format combinations
- [ ] Tests ICC profile embedding
- [ ] Handles multiple files concurrently
- [ ] Exercises all 3 tool code paths
- [ ] Detects SIZE_MAX overflow
- [ ] Detects malloc failures

---

## 🔗 Related Files

- Source: `/home/h02332/po/research/cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/TiffImg.{h,cpp}`
- Tools:
  - `/home/h02332/po/research/cfl/iccDEV/Tools/CmdLine/IccTiffDump/iccTiffDump.cpp`
  - `/home/h02332/po/research/cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/iccApplyProfiles.cpp`
  - `/home/h02332/po/research/cfl/iccDEV/Tools/CmdLine/IccSpecSepToTiff/iccSpecSepToTiff.cpp`

---

**Generated:** 2025
**Analysis Complete:** All public methods, error paths, branches, and tool integrations documented
