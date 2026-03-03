# Microsoft Photos Type Confusion

2026-03-02 12:30:20 UTC

## Crash Report for 02 March 2026

This is below the line for Reporting to MSRC. 

## Title
Two vulnerabilities in ImageLib.dll: TIFF StripByteCounts type confusion leading to heap buffer over-read, and unhandled ICC v5.0 profile exception causing application crash

## Summary
A crafted TIFF file containing an ICC v5.0 (Rec. 2100 HLG) color profile triggers an unhandled exception in `ImageLib.dll`, crashing Microsoft Photos. Additionally, the same file exposes a type confusion vulnerability in TIFF `StripByteCounts` parsing that could enable a heap buffer over-read of approximately 24 MB. The ICC profile crash currently masks the type confusion bug; however, if the ICC handling is fixed or a variant file uses a supported ICC profile, the over-read becomes exploitable.

---

## Vulnerability 1: TIFF StripByteCounts Type Confusion (Heap Buffer Over-Read)

### Description
`ImageLib.dll` incorrectly interprets `StripByteCounts` TIFF tag values. The tag is declared with TIFF type `SHORT` (2 bytes per value), but `ImageLib.dll` appears to read the values as type `LONG` (4 bytes per value). This causes adjacent SHORT values to be combined into a single larger integer.

### Technical Details
- **TIFF Tag:** `StripByteCounts` (tag 279), type=SHORT, count=8
- **Raw data at offset 268:** `60 00 60 00 60 00 60 00 60 00 60 00 60 00 60 00`
- **Correct interpretation** (8 × SHORT): `96, 96, 96, 96, 96, 96, 96, 96` (96 bytes per strip)
- **Incorrect interpretation** (4 × LONG): `6,291,552, 6,291,552, 6,291,552, 6,291,552` (0x00600060 per strip)
- **Expected pixel data:** 768 bytes (16×16 pixels × 3 channels × 1 byte)
- **Claimed by ImageLib:** 25,166,212 bytes (~24 MB)
- **Result:** Potential heap buffer over-read of ~24 MB past the allocated pixel buffer

### Impact
- **Information disclosure:** Adjacent heap memory contents could be rendered as pixel data and exfiltrated
- **Denial of Service:** Access violation if the over-read reaches unmapped memory pages
- **Potential remote code execution:** If combined with heap grooming techniques and a write primitive elsewhere in the imaging pipeline

### CVSS 3.1 Estimate
- **Vector:** AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H
- **Score:** ~7.1 (High)
- **Note:** Currently masked by Vulnerability 2. Score applies if ICC handling is fixed or bypassed.

---

## Vulnerability 2: Unhandled ICC v5.0 Profile Exception (Denial of Service)

### Description
When `ImageLib.dll` encounters an ICC v5.0 color profile (specifically Rec. 2100 RGB with HLG transfer function), it raises error `0x800707DB` ("The specified color profile is invalid"). This exception propagates unhandled through the WinRT/XAML rendering pipeline, triggering `FailFastWithStowedExceptions` and terminating the application.

### Technical Details
- **Exception code:** `0xC000027B` (STATUS_STOWED_EXCEPTION)
- **Inner error:** `0x800707DB` ("The specified color profile is invalid")
- **Faulting module:** `ImageLib.dll` at offset `+0x58BF`
- **Call chain:** `ImageLib!+0x58BF` → `ImageLib!+0x5BAD` → `ImageLib!+0x5E44` → `ImageLib!+0x20AF0` → `Microsoft_UI_Xaml!FailFastWithStowedExceptions`
- **ICC profile:** Version 5.0.0, device class `mntr`, color space `RGB`, PCS `XYZ`, description "Rec. 2100 RGB with Hlg"

### Impact
- **Denial of Service:** Microsoft Photos crashes immediately when opening or previewing the file
- **No user warning or graceful degradation** — the application terminates abruptly
- **Zero-click potential:** Windows Explorer thumbnail generation may trigger the same code path without the user explicitly opening the file

### CVSS 3.1 Estimate
- **Vector:** AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H
- **Score:** ~5.5 (Medium)

---

## Affected Components

| Component | Version | Path |
|-----------|---------|------|
| ImageLib.dll | 0.0.0.0 (bundled) | `C:\Program Files\WindowsApps\Microsoft.Windows.Photos_2025.11120.5001.0_x64__8wekyb3d8bbwe\ImageLib.dll` |
| Microsoft Photos | 2025.11120.5001.0 | Microsoft Store app |
| WindowsCodecs.dll | System | `C:\Windows\System32\WindowsCodecs.dll` (potentially affected — uses same WIC TIFF codec) |

### Environment
- **OS:** Windows 10 Pro for Workstations, Build 26200 (24H2)
- **Architecture:** x64

---

## Reproduction Steps

### Prerequisites
- Windows 10/11 with Microsoft Photos installed (default)
- The test file: `16x16-strip2--Rec2100HlgFull.tiff`
  - SHA-256: `4E398015CD443CE35F6E6CABA3B4B064B91A18D5763EAC2E9760647ED24276E9`
  - Size: 5,384 bytes

### Steps to Reproduce
1. Save `16x16-strip2--Rec2100HlgFull.tiff` to any local directory
2. Double-click the file to open it with Microsoft Photos
3. **Result:** Photos crashes with an unhandled exception

---

## File Structure Analysis

The TIFF file is a valid 16×16 RGB image with the following notable characteristics:

### TIFF IFD Entries
```
ImageWidth:         16
ImageLength:        16
BitsPerSample:      8, 8, 8
Compression:        1 (None)
PhotometricInterp:  2 (RGB)
SamplesPerPixel:    3
RowsPerStrip:       2
StripByteCounts:    type=SHORT, count=8
                    Correct values: [96, 96, 96, 96, 96, 96, 96, 96]
                    As read by ImageLib (LONG): [6291552, 6291552, 6291552, 6291552, ...]
ICCProfile:         4,304 bytes, ICC v5.0 "Rec. 2100 RGB with Hlg"
```

### ICC Profile Summary
- **Version:** 5.0.0 (not widely supported)
- **Color space:** RGB → XYZ
- **Description:** "Rec. 2100 RGB with Hlg" (Hybrid Log-Gamma HDR)
- **Copyright:** "Copyright 2026 David H Hoyt LLC"
- **Profile is structurally valid** — the crash is due to lack of v5.0 support, not malformation

---

## Timeline
- **2026-03-02:** Vulnerability discovered and analyzed
- **2026-03-02:** Crash dump captured, root cause identified
- **2026-03-02:** Report Published

---

