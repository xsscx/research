# iccRoundTrip

Tests round-trip transform accuracy of ICC profiles by applying forward and inverse
transforms and measuring the error.

## Usage

```
iccRoundTrip profile {rendering_intent=1 {use_mpe=0}}
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `profile` | **Required** | Path to ICC profile (.icc) |
| `rendering_intent` | Optional | 0=Perceptual, 1=Relative (default), 2=Saturation, 3=Absolute |
| `use_mpe` | Optional | 0=Use traditional tables (default), 1=Use MPE (Multi-Process Elements) |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success — round-trip error computed |
| Non-zero | Profile lacks required transform tables |

## Examples

### Basic round-trip test

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# Default: relative colorimetric intent
iccRoundTrip test-profiles/sRGB_D65_MAT.icc
```

### All four rendering intents

```bash
# Perceptual
iccRoundTrip test-profiles/sRGB_D65_MAT.icc 0

# Relative Colorimetric (default)
iccRoundTrip test-profiles/sRGB_D65_MAT.icc 1

# Saturation
iccRoundTrip test-profiles/sRGB_D65_MAT.icc 2

# Absolute Colorimetric
iccRoundTrip test-profiles/sRGB_D65_MAT.icc 3
```

### Use MPE (Multi-Process Elements)

```bash
# Force MPE path instead of traditional LUT tables
iccRoundTrip test-profiles/sRGB_D65_MAT.icc 1 1
```

### Different profile classes

```bash
# CMYK Output profile (has AToB + BToA tables)
iccRoundTrip test-profiles/CMYK-3DLUTs2.icc 1

# Display P3 profile
iccRoundTrip test-profiles/ios-gen-DisplayP3.icc 1

# AdobeRGB profile
iccRoundTrip test-profiles/ios-gen-AdobeRGB1998.icc 1
```

## Output Format

The output shows:
- Profile header info (class, PCS, version)
- Maximum, mean, and RMS round-trip errors in ΔE units
- Per-channel error statistics

## What It Tests

The round-trip test verifies that:
1. AToB (device→PCS) and BToA (PCS→device) transforms are inverses
2. Forward + Inverse = Identity (within numerical precision)
3. LUT precision is sufficient for the declared intent

Profiles that lack both AToB and BToA tables will fail — matrix-only profiles use
the matrix as both forward and inverse.

## Profile Classes Tested

| Class | Example | Intents | Status |
|-------|---------|---------|--------|
| Display (mntr) | sRGB_D65_MAT.icc | 0,1,2,3 | ✅ PASS |
| Display (mntr) | ios-gen-DisplayP3.icc | 1 | ✅ PASS |
| Display (mntr) | ios-gen-AdobeRGB1998.icc | 1 | ✅ PASS |
| Output (prtr) | CMYK-3DLUTs2.icc | 1 | ✅ PASS |

## Related Tools

- [iccApplyNamedCmm](../iccApplyNamedCmm/) — Apply transforms to actual color data
- [iccApplyToLink](../iccApplyToLink/) — Create DeviceLink from chained transforms
- CFL fuzzer: `icc_roundtrip_fuzzer` — Fuzz the round-trip pipeline

## Version

Built with IccProfLib version 2.3.1.5
