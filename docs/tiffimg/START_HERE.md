# TiffImg Class Analysis — START HERE

## Documentation Package

| File | Lines | Purpose |
|------|-------|---------|
| **TIFFIMG_EXECUTIVE_SUMMARY.txt** | ~250 | High-level overview (5 min read) |
| **TIFFIMG_QUICK_REFERENCE.txt** | ~200 | Method signatures, TIFF tags, validation rules |
| **TIFFIMG_CODE_PATHS.txt** | ~500 | Visual branch trees, error path mappings |
| **TIFFIMG_COMPLETE_ANALYSIS.md** | 661 | Definitive reference — line numbers, all 26 error paths |
| **TIFFIMG_ANALYSIS_INDEX.md** | 290 | Navigation guide, learning paths, testing strategy |
| **TIFFIMG_FINAL_CHECKLIST.txt** | ~400 | Verification checklist for fuzzer completeness |

## Quick Start

| Goal | Read This |
|------|-----------|
| Understand scope (5 min) | `TIFFIMG_EXECUTIVE_SUMMARY.txt` |
| Look up a method/tag | `TIFFIMG_QUICK_REFERENCE.txt` |
| Trace code branches | `TIFFIMG_CODE_PATHS.txt` |
| Full implementation reference | `TIFFIMG_COMPLETE_ANALYSIS.md` |
| Verify fuzzer coverage | `TIFFIMG_FINAL_CHECKLIST.txt` |

## Key Facts

- **Class**: `CTiffImg` — `cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/TiffImg.{h,cpp}`
- **10 public methods**, **26 error paths**, **23+ branches**
- **TIFF tags**: 14 read, 15 written
- **Used by**: iccTiffDump, iccApplyProfiles, iccSpecSepToTiff
- **Fuzzers**: `icc_tiffdump_fuzzer`, `icc_specsep_fuzzer`
- **Analyzer heuristics**: H139 (strip geometry), H140 (dimensions), H141 (IFD bounds), H149 (cycle detection), H150 (tile geometry)

## Source Locations

- `cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/TiffImg.h` (147 lines)
- `cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/TiffImg.cpp` (460 lines)
