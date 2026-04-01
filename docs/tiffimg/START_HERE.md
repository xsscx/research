# TiffImg Analysis Start Here

This directory documents the `CTiffImg` class used by the TIFF-related tool
paths in `iccDEV`.

## Read This First

| Goal | File |
|------|------|
| Fast overview | `TIFFIMG_EXECUTIVE_SUMMARY.txt` |
| Method and tag lookup | `TIFFIMG_QUICK_REFERENCE.txt` |
| Branch and error-path tracing | `TIFFIMG_CODE_PATHS.txt` |
| Full technical reference | `TIFFIMG_COMPLETE_ANALYSIS.md` |
| Coverage checklist | `TIFFIMG_FINAL_CHECKLIST.txt` |

## Scope

- Class: `CTiffImg`
- Source: `cfl/iccDEV/Tools/CmdLine/IccApplyProfiles/TiffImg.{h,cpp}`
- Primary tool users: `iccTiffDump`, `iccApplyProfiles`, `iccSpecSepToTiff`
- Related fuzzers: `icc_tiffdump_fuzzer`, `icc_specsep_fuzzer`

## Notes

- This file is the main entry point for the TIFF analysis package.
- `TIFFIMG_ANALYSIS_INDEX.md` is kept only as a short compatibility page for
  older references.
