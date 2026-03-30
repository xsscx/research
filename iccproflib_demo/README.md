# IccProfLib Demo

A standalone demo showing how to use the [iccDEV](https://github.com/InternationalColorConsortium/iccDEV) **IccProfLib2** library to parse, inspect, and validate ICC color profiles against the [ICC.1-2022-05](https://www.color.org/specification/ICC.1-2022-05.pdf) specification.

Originally created for the [BeyondRGB](https://github.com/BeyondRGB) project — *Imaging Art Beyond RGB* — to teach college students how the ICC reference implementation works.

## Build

```bash
cd iccproflib_demo && ./build.sh
```

**Prerequisites:**
- C++17 compiler (clang++ 18 or g++)
- iccDEV built at `../iccDEV/Build/` (the research repo's existing build)

## Run

```bash
# Default profile (auto-detected)
./iccproflib_demo

# Specific profile(s)
./iccproflib_demo ../test-profiles/sRGB_D65_MAT.icc
./iccproflib_demo ../iccDEV/Testing/sRGB_v4_ICC_preference.icc

# Multiple profiles
./iccproflib_demo ../test-profiles/sRGB_D65_MAT.icc ../test-profiles/17ChanPart1.icc
```

## What It Shows

1. **Header parsing** — Profile size, version (v2/v4/v5), class, color space, PCS, rendering intent, D50 illuminant
2. **Tag table** — All tags with their 4-char signatures, C++ type names, file offsets, and sizes
3. **Validation** — Runs the ICC spec validator and reports OK/Warning/NonCompliant/CriticalError
4. **Description** — Extracts the human-readable profile name from the `desc` tag

## Example Output

```
================================================================
  IccProfLib Demo
  Library: iccDEV / IccProfLib2 (ICC.1-2022-05 reference impl)
  Origin:  BeyondRGB — Imaging Art Beyond RGB
================================================================

>> Demo 1: Reading ICC profile from: ../iccDEV/Testing/sRGB_v4_ICC_preference.icc

================================================================
  ICC Profile: ../iccDEV/Testing/sRGB_v4_ICC_preference.icc
================================================================

  -- Header (128 bytes, ICC.1-2022-05 §7.2) ----------------------
  Profile size     : 60960 bytes
  Version          : 4.2.0
  Profile class    : 'spac'  (ColorSpace)
  Color space      : 'RGB '
  PCS              : 'Lab '
  Rendering intent : Perceptual
  Creator          : ''
  Illuminant (D50) : X=0.9642  Y=1.0000  Z=0.8249

  -- Tag Table (9 tags, ICC.1-2022-05 §7.3) ---------------------
  Sig     Type                                Offset        Size
  ------  ------------------------------  ----------  ----------
  'desc'  CIcciSigMultiLocalizedUnicode          240         118
  'A2B0'  CIccTag                                360       29712
  'A2B1'  CIccTag                              30072         436
  'B2A0'  CIccTag                              30508       29748
  'B2A1'  CIccTag                              60256         508
  'rig0'  CIccTagSignature                     60764          12
  'wtpt'  CIccTagXYZ                           60776          20
  'cprt'  CIcciSigMultiLocalizedUnicode        60796         118
  'chad'  CIccTagS15Fixed16                    60916          44

  -- Validation ---------------------------------------------------
  Status: OK (valid)

  -- Profile Description ------------------------------------------
  Language = 'en', Region = 'US'
"sRGB v4 ICC preference perceptual intent beta"

================================================================
  Demo complete.  IccProfLib is linked and working!
================================================================
```

## Learning Resources

| Resource | Description |
|----------|-------------|
| [ICC.1-2022-05](https://www.color.org/specification/ICC.1-2022-05.pdf) | ICC v4.4 profile specification (126 pages) |
| [iccDEV source](https://github.com/InternationalColorConsortium/iccDEV) | Reference implementation of the ICC spec |
| [BeyondRGB](https://github.com/BeyondRGB) | Spectral imaging art analysis project |

## Key IccProfLib APIs Used

| API | Purpose |
|-----|---------|
| `OpenIccProfile(path)` | Load an ICC profile from a `.icc` file |
| `CIccProfile::m_Header` | Access the 128-byte profile header |
| `CIccProfile::m_Tags` | Iterate the tag table entries |
| `CIccProfile::FindTag(sig)` | Look up a tag by its 4-byte signature |
| `CIccProfile::Validate(report)` | Check profile against ICC spec |
| `CIccTag::Describe(str, indent)` | Get human-readable tag description |
| `CIccTag::GetClassName()` | Get the C++ class name for a tag type |
| `icFtoD(fixed)` | Convert ICC s15Fixed16Number to double |
