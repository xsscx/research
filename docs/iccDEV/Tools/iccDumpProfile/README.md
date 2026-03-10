# iccDumpProfile

Displays ICC profile header, tag table, and tag data in human-readable format.

## Usage

```
iccDumpProfile {-v} {verbosity_int} profile {tagId/"ALL"}
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `-v` | Optional | Enable profile validation |
| `verbosity_int` | Optional | Verbosity level 1–100 (default: 100) |
| `profile` | **Required** | Path to ICC profile (.icc) |
| `tagId` / `"ALL"` | Optional | Dump specific tag by 4-char signature, or `ALL` for every tag |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 255 (-1) | Error (e.g., NamedColor class profiles may trigger this) |

## Examples

### Basic profile dump

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# Dump a v4 Display profile
iccDumpProfile test-profiles/sRGB_D65_MAT.icc
```

### Dump with validation

```bash
iccDumpProfile -v test-profiles/sRGB_D65_MAT.icc
```

### Dump a specific tag

```bash
# Dump only the profile description tag
iccDumpProfile test-profiles/sRGB_D65_MAT.icc desc

# Dump only the media white point tag
iccDumpProfile test-profiles/sRGB_D65_MAT.icc wtpt

# Dump ALL tags individually
iccDumpProfile test-profiles/sRGB_D65_MAT.icc ALL
```

### Control verbosity

```bash
# Low verbosity (summary only)
iccDumpProfile 1 test-profiles/sRGB_D65_MAT.icc

# Medium verbosity
iccDumpProfile 25 test-profiles/sRGB_D65_MAT.icc

# Maximum verbosity (default)
iccDumpProfile 100 test-profiles/sRGB_D65_MAT.icc
```

### Different profile classes

```bash
# CMYK Output/Printer profile
iccDumpProfile test-profiles/CMYK-3DLUTs2.icc

# v5 Spectral profile
iccDumpProfile test-profiles/Rec2020rgbSpectral.icc

# NamedColor profile
iccDumpProfile test-profiles/NamedColor.icc

# 17-channel Input profile
iccDumpProfile test-profiles/17ChanPart1.icc

# MVIS (Multi-Visualization) profile
iccDumpProfile test-profiles/MVIS_Fluorescent_Beads.icc

# CameraModel Input profile
iccDumpProfile test-profiles/CameraModel.icc

# v5 LCDDisplay profile
iccDumpProfile iccDEV/Testing/Display/LCDDisplay.icc

# Spectral profile with Lab PCS
iccDumpProfile test-profiles/Cat8Lab-D65_2degMeta.icc
```

### Dump PoC/Crash profiles (with ASAN)

```bash
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccDumpProfile test-profiles/hbo-CIccCalculatorFunc-ApplySequence-IccMpeCalc_cpp-Line3714.icc
```

## Output Format

The output includes:
1. **Header** — Profile size, version, class, color space, PCS, creation date, flags, rendering intent, illuminant, profile ID
2. **Tag Table** — Tag count, per-tag signature, offset, size, type
3. **Tag Data** — Decoded values for each tag type (curves, matrices, LUTs, text, etc.)

## Profile Classes Tested

| Class | Example Profile | Status |
|-------|----------------|--------|
| Display (mntr) | sRGB_D65_MAT.icc | ✅ PASS |
| Output (prtr) | CMYK-3DLUTs2.icc | ✅ PASS |
| Input (scnr) | 17ChanPart1.icc | ✅ PASS |
| NamedColor (nmcl) | NamedColor.icc | ⚠️ exit 255 |
| ColorSpace (spac) | ICS/*.icc | ✅ PASS |

## Security Testing

Use with ASAN-instrumented build for crash analysis:

```bash
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=0,print_stacktrace=1 \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccDumpProfile malicious_profile.icc
```

## Related Tools

- [iccToXml](../iccToXml/) — Convert profile to XML for deeper inspection
- [iccRoundTrip](../iccRoundTrip/) — Test profile transform accuracy
- [iccanalyzer-lite](../../../../iccanalyzer-lite/) — 150-heuristic security analysis

## Version

Built with IccProfLib version 2.3.1.5
