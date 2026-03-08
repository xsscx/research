# TiffImg Class Analysis - START HERE

## 📚 Complete Documentation Package

This directory contains a **comprehensive analysis of the CTiffImg class**, which is the target for TIFF fuzzer development.

### 🎯 Quick Start (Choose Your Path)

**⏱️ Have 5 minutes?**
→ Read: `TIFFIMG_EXECUTIVE_SUMMARY.txt`
- High-level overview of all 10 methods
- 26 error paths summary
- Fuzzer strategy & test matrix
- Critical validation checklist

**⏱️ Have 15 minutes?**
→ Read: `TIFFIMG_QUICK_REFERENCE.txt`
- Quick lookup reference card
- All methods & signatures
- All TIFF tags (29 total)
- All validation rules
- Photometric types, sample formats, planar configs

**⏱️ Have 30 minutes?**
→ Read: `TIFFIMG_CODE_PATHS.txt`
- Visual branch trees for all methods
- Error path mappings
- Tool-specific code paths (3 tools)
- Critical validation points
- Sample format validation table

**⏱️ Have 60+ minutes?**
→ Read: `TIFFIMG_COMPLETE_ANALYSIS.md`
- Detailed method-by-method breakdown
- Line numbers for all code
- All error paths with conditions
- Branch coverage analysis
- Memory safety concerns
- Fuzzer recommendations

**🧭 Need Navigation Help?**
→ Read: `TIFFIMG_ANALYSIS_INDEX.md`
- Document index with descriptions
- Quick navigation by topic
- Learning paths (beginner → advanced)
- Testing strategy (4 phases)

---

## 📊 Key Facts At A Glance

```
Class:              CTiffImg (TIFF I/O wrapper)
Location:           cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/TiffImg.{h,cpp}
Public Methods:     10
Error Paths:        26
Branches:           23+
TIFF Tags:          14 read, 15 written
Photometric Types:  5 (RGB, MINISBLACK, MINISWHITE, CIELAB, ICCLAB)
Sample Formats:     3 (8-bit, 16-bit, 32-bit float)
Planar Configs:     2 (contiguous, separated)
Compression:        2 (none, LZW)
Tool Usage:         3 tools (iccTiffDump, iccApplyProfiles, iccSpecSepToTiff)
```

---

## 🔍 The 10 Public Methods

1. **CTiffImg()** - Constructor
2. **~CTiffImg()** - Destructor
3. **void Close()** - Cleanup
4. **bool Open(const char *szFname)** ⭐ - Read validation (8 error paths)
5. **bool Create(...)** ⭐ - Write setup (5 error paths)
6. **bool ReadLine(unsigned char *pBuf)** ⭐ - Planar↔contiguous conversion
7. **bool WriteLine(unsigned char *pBuf)** ⭐ - Contiguous→planar conversion
8. **unsigned int GetPhoto()** - Photometric mapping (6 branches)
9. **bool GetIccProfile(...)** - Extract ICC profile
10. **bool SetIccProfile(...)** - Embed ICC profile

⭐ = Critical for fuzzer (most complex, most branches)

---

## 🚀 Fuzzer Implementation Strategy

### Phase 1: Basic Coverage
- [ ] All 5 photometric types
- [ ] All 3 BPS values (8, 16, 32)
- [ ] Both planar configurations
- [ ] Both compression modes

### Phase 2: Error Path Testing
- [ ] All 26 error paths
- [ ] Invalid sample format combos
- [ ] Non-TOPLEFT orientation
- [ ] Missing/corrupt TIFF tags

### Phase 3: Advanced Features
- [ ] ICC profile embedding/extraction
- [ ] Multiple file operations
- [ ] Tool-specific workflows

### Phase 4: Fuzzing & Mutation
- [ ] Valid TIFF file seeds
- [ ] Tag/dimension mutation
- [ ] Photometric/BPS mutation
- [ ] File truncation

---

## 📋 Critical Validation Rules

### Open() Must Pass All:
```
✓ TIFFOpen returns non-NULL
✓ RowsPerStrip > 0, Samples > 0, BitsPerSample > 0
✓ BPS==32 → SAMPLEFORMAT_IEEEFP (else SAMPLEFORMAT_UINT)
✓ Orientation must be ORIENTATION_TOPLEFT (1)
✓ If PLANAR+MULTI: BPS%8==0 (byte-aligned)
✓ If PLANAR+MULTI: Height%RowsPerStrip==0
✓ No overflow: m_nStripSize * m_nStripSamples < SIZE_MAX
✓ malloc succeeds
```

### Create() Must Pass All:
```
✓ TIFFOpen returns non-NULL
✓ If PLANAR+MULTI: BPS%8==0
✓ No overflow: m_nStripSize * m_nStripSamples < SIZE_MAX
✓ malloc succeeds
```

---

## 🎯 Sample Format Validation

| BPS | SampleFormat | Status |
|-----|--------------|--------|
| 8 | SAMPLEFORMAT_UINT | ✅ Valid |
| 8 | SAMPLEFORMAT_IEEEFP | ❌ REJECTED |
| 16 | SAMPLEFORMAT_UINT | ✅ Valid |
| 16 | SAMPLEFORMAT_IEEEFP | ❌ REJECTED |
| 32 | SAMPLEFORMAT_UINT | ❌ REJECTED |
| 32 | SAMPLEFORMAT_IEEEFP | ✅ Valid |

---

## 📁 Document Overview

| File | Size | Read Time | Purpose |
|------|------|-----------|---------|
| TIFFIMG_EXECUTIVE_SUMMARY.txt | 10K | 5 min | High-level overview |
| TIFFIMG_QUICK_REFERENCE.txt | 8K | 10 min | Quick lookup card |
| TIFFIMG_CODE_PATHS.txt | 20K | 20 min | Visual branch trees |
| TIFFIMG_COMPLETE_ANALYSIS.md | 22K | 45 min | Detailed reference |
| TIFFIMG_ANALYSIS_INDEX.md | 9K | 10 min | Navigation guide |
| TIFFIMG_FINAL_CHECKLIST.txt | 16K | 15 min | Verification checklist |

**Total:** ~85 KB, ~2400 lines of analysis

---

## 🧠 Learning Paths

### Beginner (Getting Started)
1. TIFFIMG_EXECUTIVE_SUMMARY.txt (5 min)
2. TIFFIMG_QUICK_REFERENCE.txt (10 min)
3. Create simple test TIFF files

### Intermediate (Implementing Fuzzer)
1. TIFFIMG_CODE_PATHS.txt §1-7 (20 min)
2. TIFFIMG_COMPLETE_ANALYSIS.md §4-7 (30 min)
3. Implement basic fuzzer with all branches

### Advanced (Optimizing Coverage)
1. TIFFIMG_COMPLETE_ANALYSIS.md §4, §11 (30 min)
2. Study all 26 error paths
3. Implement adaptive fuzzing

---

## ✅ Verification Checklist

Before implementing your fuzzer, verify coverage of:

- [ ] All 5 photometric types (RGB, MINISBLACK, MINISWHITE, CIELAB, ICCLAB)
- [ ] All 3 BPS values (8, 16, 32)
- [ ] Both planar configurations (CONTIG, SEPARATE)
- [ ] All 26 error paths
- [ ] All 23+ branches
- [ ] ICC profile embedding/extraction
- [ ] Multiple file concurrent operations
- [ ] All 3 tool code paths (iccTiffDump, iccApplyProfiles, iccSpecSepToTiff)
- [ ] SIZE_MAX overflow detection
- [ ] malloc failure handling

---

## 🔗 Source Code Locations

**Main Class:**
- `cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/TiffImg.h` (147 lines)
- `cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/TiffImg.cpp` (460 lines)

**Tool Files Using TiffImg:**
- `cfl/iccDEV/Tools/CmdLine/IccTiffDump/iccTiffDump.cpp`
- `cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/iccApplyProfiles.cpp`
- `cfl/iccDEV/Tools/CmdLine/IccSpecSepToTiff/iccSpecSepToTiff.cpp`

---

## 💡 Pro Tips

1. **Start with QUICK_REFERENCE.txt** - It's the fastest way to understand the scope
2. **Use CODE_PATHS.txt** for visual understanding of branches and error paths
3. **Reference COMPLETE_ANALYSIS.md** for line numbers and detailed logic
4. **Use ANALYSIS_INDEX.md** as your navigation guide
5. **Keep FINAL_CHECKLIST.txt** handy to verify coverage completeness

---

## 🎓 What You'll Learn

✅ Every public method's signature and behavior
✅ Every error path condition and return value
✅ Every branch point in the code
✅ Every TIFF tag read and written
✅ Every validation rule
✅ Every photometric type
✅ Every sample format combination
✅ Every planar configuration
✅ Memory safety considerations
✅ How three different tools use this class

---

## 📞 Question? Check This First:

| Question | Document |
|----------|----------|
| What are all the public methods? | QUICK_REFERENCE.txt |
| What are all the TIFF tags? | QUICK_REFERENCE.txt |
| How does Open() work? | CODE_PATHS.txt §2 or COMPLETE_ANALYSIS.md §5 |
| How does Create() work? | CODE_PATHS.txt §1 or COMPLETE_ANALYSIS.md §4 |
| What are all error paths? | COMPLETE_ANALYSIS.md §14 |
| How do the tools use TiffImg? | CODE_PATHS.txt §8 |
| Where's the best place to start? | You're reading it! |

---

**Ready to implement your fuzzer?** Start with TIFFIMG_QUICK_REFERENCE.txt and work your way through! 🚀

**Analysis Date:** 2025
**Analysis Status:** ✅ Complete (100% coverage of all methods, branches, and error paths)
**Document Package:** 6 files, ~95 KB, ~2400 lines
