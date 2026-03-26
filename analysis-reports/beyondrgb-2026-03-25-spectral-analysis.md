# BeyondRGB Spectral Imaging Artifact Analysis

**Date**: 2026-03-26
**Source**: BeyondRGB v2.4.0 (RIT "Imaging Art beyond RGB" project)
**Artifact Directory**: `BeyondRGB_2026-03-25_15-36-48/sony_arw_targets/`
**Analyst**: iccanalyzer-lite v3.6.2 + manual hex/CSV/JSON analysis

---

## Executive Summary

This report covers 12 artifacts (1 ICC profile, 4 TIFFs, 5 CSVs, 1 JSON, 1 set of
Zone.Identifier metadata) produced by the BeyondRGB spectral imaging pipeline.
The ICC profile is a **v4.3/v5.1 hybrid** with an embedded spectral profile — a rare
and complex format that triggered 8 upstream iccDEV bugs (#700, #701, #702, #717-#722).

**Key Findings**:
- **1 ICC hybrid profile** with embedded v5.1 spectral profile via ICC5/ICCp tag
- **H173 WARN**: All 25 FourCC signature conversions trigger UBSAN shift overflow (CWE-190)
- **Library phase skipped**: ICC5/ICCp tag triggers CIccEmbedIO constructor UB (issue #718)
- **4 TIFF files** pass all 5 security heuristics (H139-H141, H149-H150)
- **Injection false positives**: 0xFFFF in 16-bit pixel data matches signature scanner
- **Colorimetry quality**: Mean ΔE00 = 1.646 (good), 1 patch > 5.0 (acceptable for spectral)
- **Spectral coverage**: 380–730nm at 5nm steps, 6-channel camera, 44-band spectral output

---

## 1. File Inventory

| # | File | Format | Size | ICC? | Notes |
|---|------|--------|------|------|-------|
| 1 | `profile.icc` | ICC v4.3 | 2,352 B | ✓ (self) | Hybrid: v4.3 wrapper + v5.1 spectral via ICC5 tag |
| 2 | `BeyondRGB_CM_1774467526.tiff` | TIFF LE | 242.6 MB | ✓ (embedded) | Color-managed output, 7968×5320×3ch×16bit |
| 3 | `BeyondRGB_CM_target_1774467526.tiff` | TIFF LE | 242.6 MB | ✓ (embedded) | Target reference, same dimensions |
| 4 | `BeyondRGB_SP_1774467526.tiff` | TIFF LE | 485.2 MB | ✗ | Spectral output, 7968×5320×**6ch**×16bit |
| 5 | `img_matches.tiff` | TIFF LE | 485.2 MB | ✗ | Side-by-side match, **15936**×5320×3ch×16bit |
| 6 | `BeyondRGB_Colorimetry_*.csv` | CSV | 50 KB | — | ΔE00, CIELAB, XYZ for 141 patches |
| 7 | `BeyondRGB_GeneralInfo_*.csv` | CSV | 789 B | — | Pipeline metadata |
| 8 | `BeyondRGB_M_color_*.csv` | CSV | 17 KB | — | 3×6 color correction matrix + offsets |
| 9 | `BeyondRGB_M_spectral_*.csv` | CSV | 20 KB | — | Spectral reconstruction matrix |
| 10 | `BeyondRGB_R_camera_*.csv` | CSV | 137 KB | — | Camera spectral response, 72 wavelengths × 140 patches |
| 11 | `BeyondRGB_1774467526.btrgb` | JSON | 512 KB | — | Calibration project file |
| 12 | `*:Zone.Identifier` (×11) | ADS | 25 B ea. | — | Windows NTFS ZoneId=3 (Internet zone) |

**Total**: 1.46 GB across 12 primary artifacts + 11 Zone.Identifier ADS files.

---

## 2. ICC Profile Analysis: `profile.icc`

### 2.1 Header Structure

| Field | Value | Spec Reference |
|-------|-------|---------------|
| Size | 2,352 bytes | ICC.1-2022-05 §7.2.2 |
| Version | 4.3.0.0 | ICC.1-2022-05 §7.2.4 |
| Class | `mntr` (Display) | ICC.1-2022-05 §7.2.5 |
| Color Space | `RGB ` (3 channels) | ICC.1-2022-05 §7.2.6 |
| PCS | `XYZ ` | ICC.1-2022-05 §7.2.7 |
| Date | 2026-03-25 19:38:46 | ICC.1-2022-05 §7.2.8 |
| Creator | `ICCD` (iccDEV) | ICC.1-2022-05 §7.2.17 |
| Description | "Hybrid Pro Photo RGB" | — |

### 2.2 Tag Table (10 tags)

| # | Signature | Offset | Size | Type | Notes |
|---|-----------|--------|------|------|-------|
| 0 | `cprt` | 252 | 32 | text | Copyright |
| 1 | `wtpt` | 284 | 20 | XYZ | Media white point (D50) |
| 2 | `desc` | 304 | 127 | mluc | "Hybrid Pro Photo RGB" |
| 3 | `rTRC` | 432 | 14 | curv | **Shared offset** with gTRC, bTRC |
| 4 | `gTRC` | 432 | 14 | curv | Shared with rTRC |
| 5 | `bTRC` | 432 | 14 | curv | Shared with rTRC |
| 6 | `rXYZ` | 448 | 20 | XYZ | Red matrix column |
| 7 | `gXYZ` | 468 | 20 | XYZ | Green matrix column |
| 8 | `bXYZ` | 488 | 20 | XYZ | Blue matrix column |
| 9 | `ICC5` | 524 | 1,828 | ICCp | **Embedded v5.1 spectral profile** |

**Shared TRC**: All three TRC curves share offset 432 — standard practice for gamma=1.8
Pro Photo RGB encoding. This is efficient and spec-compliant.

**ICC5 Tag**: Per *"Embedding an ICC.2 profile in an ICC.1 profile"* spec, this `ICC5`
tag with `ICCp` type signature contains a complete v5.1 profile for spectral-aware
applications. v4 applications silently ignore unknown tags; v5 applications use the
embedded spectral profile for higher-fidelity color management.

### 2.3 Embedded v5.1 Spectral Profile

| Field | Value |
|-------|-------|
| Size | 1,820 bytes |
| Version | 5.1.0.0 |
| Class | `mntr` (Display) |
| Color Space | `nc\x00\x06` (6-channel named color) |
| PCS | null (spectral PCS) |
| Tags | 5: `cprt`, `swpt`, `desc`, `svcn`, `D2B3` |

**Key spectral tags**:
- **`swpt`** (Spectral White Point): D50 illuminant spectral power distribution
- **`svcn`** (Spectral Viewing Conditions): Observer function, illuminant reference
- **`D2B3`** (DToB3): Device-to-PCS spectral transform for intent 3

This profile represents the 6-channel camera system's spectral response,
enabling spectral color management beyond the 3-channel RGB gamut.

### 2.4 Security Findings

| Finding | Severity | CWE | Details |
|---------|----------|-----|---------|
| H173 | WARN | CWE-190 | 25/25 FourCC signatures trigger `sig<<=8` overflow in `icGetSig*()` at IccUtil.cpp:1088,1130,1253 |
| H174 | N/A | — | No half-float values present |
| ICC5/ICCp | DEFENSE | CWE-681 | Library phase skipped — `CIccEmbedIO` constructor has `-1→size_t` implicit conversion (IccIO.cpp:569, issue #718) |

**H173 detail**: Every call to `icGetSigStr()`, `icGetColorSigStr()`, etc. performs
`sig <<= 8` in a loop on `icUInt32Number`. When the first byte of the signature is
non-zero (true for all standard ICC signatures like `mntr`, `RGB `, `XYZ `), the
shift produces a value > UINT32_MAX — undefined behavior under C++17.

**Defense gate**: The analyzer correctly refuses to load this profile through the
unpatched iccDEV library because the ICC5/ICCp tag triggers undefined behavior in
`CIccEmbedIO::CIccEmbedIO()` where `m_nSize` is initialized to `-1` and then
implicitly converted to `size_t` (issue #718, fixed in PR #727).

---

## 3. TIFF Image Analysis

### 3.1 Summary

| TIFF File | Dimensions | Ch | BPS | ICC | Heuristics | Inject Sigs |
|-----------|------------|-----|-----|-----|-----------|-------------|
| CM | 7968×5320 | 3 | 16 | KODA v2.1 (940B) | 5/5 PASS | 1 FP |
| CM_target | 7968×5320 | 3 | 16 | KODA v2.1 (940B) | 5/5 PASS | 1 FP |
| SP | 7968×5320 | **6** | 16 | None | 5/5 PASS | 2 FP |
| img_matches | **15936**×5320 | 3 | 16 | None | 5/5 PASS | 1 FP |

All TIFFs: uncompressed, contiguous (chunky), 1 row/strip, produced by BTRGB v2.4.0.

### 3.2 Security Heuristic Results

All 4 TIFFs pass all 5 TIFF security heuristics cleanly:
- **H139** (Strip Geometry): ✓ — `StripByteCounts ≥ RowsPerStrip × Width × SPP × (BPS/8)`
- **H140** (Dimensions): ✓ — All dimensions within bounds, no overflow
- **H141** (IFD Offsets): ✓ — All offsets within file bounds
- **H149** (IFD Cycles): ✓ — Single IFD, no chain cycles
- **H150** (Tile Geometry): ✓ — Strip-based (N/A for tiles)

### 3.3 Injection Signature False Positives

The injection scanner detected "ICC tag count corruption (0xFFFF)" in pixel data of
all 4 TIFFs and "BigTIFF magic in standard TIFF" in the SP TIFF. These are **false
positives** — the byte patterns `0xFFFF` naturally occur in 16-bit uncompressed pixel
data where channel values approach the maximum (65535). The SP TIFF's "BigTIFF magic"
detection is a coincidental byte pattern `0x002B` at a specific offset in 6-channel
spectral data.

**Recommendation**: Consider adding pixel-data-region exclusion to the injection
scanner to reduce FP rate on high-bit-depth uncompressed TIFFs.

### 3.4 Embedded ICC Profile (CM and CM_target TIFFs)

Both color-managed TIFFs embed the same 940-byte ICC profile:
- **Version**: 2.1.0 (v2 profile)
- **Creator**: `KODA` (Kodak)
- **Class**: `mntr` (Display)
- **Color Space**: RGB → XYZ PCS
- **Description**: (in `desc` tag, 131 bytes)
- **Tags**: 12 — includes `dmnd` (device manufacturer), `dmdd` (device model), `mmod` (make and model)
- **Shared TRC**: `rTRC`/`gTRC`/`bTRC` at same offset (gamma curve)
- **Conformance**: Passes ICC library validation, 5 minor conformance issues

This is a standard Kodak ProPhoto RGB-family profile. It provides the v2 color
management fallback for applications that don't understand the v5.1 spectral
`profile.icc` wrapper.

### 3.5 Spectral TIFF (SP)

The 6-channel spectral TIFF has `Photometric=MinIsBlack` (grayscale interpretation)
with 6 samples per pixel. This is the standard encoding for multispectral images:
each pixel stores 6 spectral band measurements rather than RGB channels.

The 6 channels correspond to the v5.1 embedded profile's `nc\x00\x06` color space.
Together, `profile.icc` (ICC5 tag with DToB3 spectral transform) + `SP.tiff` (6-channel
data) form a complete spectral color management pipeline.

### 3.6 Match Image (img_matches)

The 15936×5320 dimensions (exactly 2× the 7968 width) confirm this is a **side-by-side
visualization** of two images — likely the two input captures (art1 + art2) or
input vs color-managed output, used for visual comparison during calibration.

---

## 4. Calibration Data Analysis

### 4.1 Pipeline Configuration (GeneralInfo CSV + .btrgb JSON)

| Parameter | Value |
|-----------|-------|
| Software | BTRGB v2.4.0 |
| Input Images | 2 art (Sony ARW) + 2 white + 2 dark |
| Image Dimensions | 7968 × 5320 |
| Standard Observer | CIE 1931 2° |
| Illuminant | D50 |
| Target | CCSG (ColorChecker SG, 140 patches) |
| Target Grid | 14 columns × 10 rows |
| Matched Points | 124 (of 140) |
| White Patch | A:1 |
| Y(white) | 90.441827 |
| Camera Make/Model | "unspecified" (Sony RAW input) |

### 4.2 Colorimetric Accuracy (Colorimetry CSV)

| Metric | Value |
|--------|-------|
| Patches analyzed | 141 |
| ΔE00 minimum | 0.000 |
| ΔE00 maximum | 6.837 |
| ΔE00 mean | **1.646** |
| ΔE00 median | 1.399 |
| Patches with ΔE00 > 3.0 | 16 (11.3%) |
| Patches with ΔE00 > 5.0 | 1 (0.7%) |

**Assessment**: Mean ΔE00 of 1.646 indicates good colorimetric accuracy for a
6-channel spectral imaging system. The single patch exceeding ΔE00 = 5.0 is
typical for saturated chromatic samples in spectral-to-colorimetric conversion.
For cultural heritage documentation (the primary BeyondRGB use case), this
accuracy level exceeds the ISO 19264-1 "Class A" threshold (mean ΔE00 ≤ 2.0).

### 4.3 Color Correction Matrix (M_color CSV)

**M_color** (3×6 matrix — camera 6ch → CIE XYZ 3ch):
```
Row 0: [-0.0931  +0.3260  -0.3809  +0.4407  +0.6073  +0.3536]
Row 1: [-0.0589  +0.1376  +0.0946  -0.0321  +2.2167  -0.4036]
Row 2: [-0.0163  +0.0980  +0.2108  -0.0076  -0.3908  +1.1742]
```

**M_color_offset** (1×6 bias vector):
```
[+0.0265  +0.0212  +0.0074  +0.0025  +0.0001  -0.0008]
```

The matrix shows the expected structure: channels 4-5 (green-yellow spectral bands)
have the highest weights for Y (luminance, row 1 coefficient 2.22), while channels
5-6 (red-NIR bands) dominate Z (blue, row 2 coefficient 1.17).

### 4.4 Spectral Reconstruction Matrix (M_spectral CSV)

**Dimensions**: 44 rows × 6 columns (camera 6ch → 44 spectral bands)

This matrix reconstructs 44 spectral bands from the 6-channel camera input.
With the camera covering 380–730nm at 5nm sampling (72 measured wavelengths),
the 44-band output likely represents the spectral range optimized for
colorimetric accuracy and reflectance reconstruction.

### 4.5 Camera Spectral Response (R_camera CSV)

| Parameter | Value |
|-----------|-------|
| Wavelengths | 72 (380nm – 730nm, 5nm step) |
| Patches | 140 (CCSG target, dual exposure: columns per patch) |
| Data type | Reflectance-equivalent camera response |

This data captures the spectral sensitivity of the Sony camera system through
the CCSG target patches, enabling the M_color and M_spectral transformations.

### 4.6 Calibration Quality Metrics (.btrgb JSON)

| Metric | Value | Assessment |
|--------|-------|------------|
| CM DeltaE Mean | 1.646 | Good |
| SP RMSE | 0.337 | Good |
| CM Optimized M | 3×6 matrix | Color correction |
| SP Optimized M_refl | 36×6 matrix | Spectral reconstruction |
| CM Calibrated XYZ | 3×140 | Per-patch XYZ |
| SP R Reference | 36×140 | Reference spectral reflectances |

---

## 5. Cross-Reference with iccDEV Issues

These artifacts triggered or are directly related to 8 upstream iccDEV security issues,
all filed and fixed by the BeyondRGB/RIT research team and maintainer:

| Issue | CWE | Bug | File:Line | Fix PR | Triggered By |
|-------|-----|-----|-----------|--------|-------------|
| #717 | CWE-190 | UB left-shift in `icGetSigStr()` | IccUtil.cpp:1088 | #724 | `iccDumpProfile profile.icc` |
| #718 | CWE-681 | int→size_t implicit -1 in CIccEmbedIO | IccIO.cpp:569 | #727 | `iccDumpProfileGui` on ICC5 profiles |
| #719 | CWE-369 | div-by-zero in TiffImg | TiffImg.h:98 | #723 | `iccTiffDump BeyondRGB_CM.tiff` |
| #720 | CWE-190 | UB left-shift in `icGetColorSigStr()` | IccUtil.cpp:1130 | #724 | `iccDumpProfile -V 100 profile.icc` |
| #721 | CWE-190 | UB left-shift in `icGetColorSig()` | IccUtil.cpp:1253 | #726 | `iccToXml` on extracted ICC |
| #722 | CWE-681 | int→unsigned implicit conversion | IccUtilXml.cpp:1539 | #725 | `iccToXml` on ICC from CM tiff |
| #701 | CWE-476 | Null CIccApplyCLUT in InterpNd | IccTagLut.cpp:3181 | #730 | `iccRoundTrip` on BeyondRGB profiles |
| #702 | CWE-476 | NPD in CIccTagLut16::Write | IccTagLut.cpp:5361 | #728 | `iccTiffDump` on malformed profiles |

### CFL Patch Coverage

| Issue | CFL Patch | iccanalyzer-lite Heuristic |
|-------|-----------|---------------------------|
| #717 | CFL-060 (`icGetSigStr` shift) | H173 ✓ |
| #718 | CFL-058 (`CIccEmbedIO m_nSize`) | ICC5 defense gate ✓ |
| #719 | — (tool-level code) | — |
| #720 | CFL-060 (same patch) | H173 ✓ |
| #721 | CFL-060 (same patch) | H173 ✓ |
| #722 | CFL-066 (`IccUtilXml bitmask`) | — |
| #701 | CFL-025 (`CLUT InterpNd null`) | H167 ✓ |
| #702 | — (upstream fix) | H147 ✓ |

---

## 6. Zone.Identifier Analysis

All 11 primary files have NTFS Alternate Data Stream (ADS) `Zone.Identifier` files
with `ZoneId=3` (Internet zone). This indicates the files were transferred from the
BeyondRGB application through a Windows download path or browser-mediated transfer.
The ADS metadata is informational only — it has no security impact on Linux analysis.

---

## 7. Assessment

### Security Posture

- **ICC profile**: Well-constructed hybrid v4.3/v5.1 profile. The only security
  concerns are upstream iccDEV library bugs triggered by the ICC5/ICCp embedding
  pattern — all now fixed in PRs #723–#730.
- **TIFF files**: All 4 pass all TIFF security heuristics. Clean structure, no
  malformed geometry, no IFD cycles.
- **Data files**: CSV and JSON data is well-formed and contains no injection vectors.

### Colorimetric Quality

- Mean ΔE00 of 1.646 meets ISO 19264-1 Class A digital reproduction standards.
- Only 1 of 141 patches exceeds ΔE00 = 5.0 — excellent for spectral imaging.
- 124/140 target patches matched (89% — 16 unmatched likely due to occlusion or
  edge effects in the physical target).

### Spectral Coverage

- 6-channel camera system covering 380–730nm at 5nm resolution.
- 44-band spectral output from M_spectral reconstruction.
- SP RMSE of 0.337 indicates good spectral fidelity.

### Research Value

These artifacts represent a production-quality spectral imaging pipeline that
successfully exposed 8 iccDEV library bugs through normal usage. The hybrid
v4.3/v5.1 ICC profile format is the canonical test case for the ICC5/ICCp
embedding specification, making it valuable for:

1. **Regression testing**: v5.1 spectral profile parsing and ICC5 tag handling
2. **Fuzzer seeding**: The 2,352-byte hybrid profile exercises rare code paths
3. **Conformance validation**: Tests ICC.1/ICC.2 interoperability
4. **Coverage improvement**: spectral PCS, 6-channel color space, D2B3 transform

---

## 8. Recommendations

1. **Add `profile.icc` to `test-profiles/`** for permanent regression coverage
2. **Add extracted KODA profile** (`/tmp/beyondrgb-cm-embedded.icc`, 940B) as a
   v2.1 Display/RGB reference profile
3. **Seed CFL corpora**: `profile.icc` → `corpus-icc_dump_fuzzer/`,
   `corpus-icc_toxml_fuzzer/`, `corpus-icc_v5dspobs_fuzzer/`
4. **Fix injection scanner FP**: Exclude pixel data regions from signature scanning
   on uncompressed 16-bit TIFFs to reduce false positive rate
5. **Track upstream fixes**: Monitor PRs #723–#730 for merge into iccDEV master

---

*Generated by iccanalyzer-lite v3.6.2 + manual analysis*
*Heuristics: 174 total, H173 WARN on profile.icc, 5/5 TIFF heuristics PASS on all 4 TIFFs*
*0 ASAN/UBSAN errors in analyzer code*
