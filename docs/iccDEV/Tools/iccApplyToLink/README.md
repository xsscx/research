# iccApplyToLink

Creates a DeviceLink ICC profile or .cube LUT file from a chain of ICC profile transforms.
DeviceLink profiles combine multiple transforms into a single profile for efficient
color conversion.

## Usage

```
iccApplyToLink dst_file link_type lut_size option title range_min range_max first_transform interp {{-ENV:sig value} profile_path rendering_intent {-PCC pcc_path}}
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `dst_file` | **Required** | Output file path (.icc or .cube) |
| `link_type` | **Required** | 0=DeviceLink ICC, 1=.cube text file |
| `lut_size` | **Required** | Grid entries per dimension (e.g., 9, 17, 33) |
| `option` | **Required** | link_type=0: 0=v4 16-bit, 1=v5. link_type=1: precision digits |
| `title` | **Required** | Description string for the profile |
| `range_min` | **Required** | LUT input minimum (typically 0.0) |
| `range_max` | **Required** | LUT input maximum (typically 1.0) |
| `first_transform` | **Required** | 0=Use source space, 1=Use destination space |
| `interp` | **Required** | 0=Linear, 1=Tetrahedral |
| `profile_path` | **Required** | ICC profile path |
| `rendering_intent` | **Required** | 0=Perceptual, 1=Relative, 2=Saturation, 3=Absolute |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | Profile error or incompatible transform chain |

## Examples

### Create DeviceLink (v4, 16-bit LUT)

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# sRGB → sRGB identity DeviceLink, 9×9×9 grid
iccApplyToLink /tmp/link_srgb_9.icc 0 9 0 "sRGB Identity" 0.0 1.0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# Larger LUT (17×17×17) for higher precision
iccApplyToLink /tmp/link_srgb_17.icc 0 17 1 "sRGB v5" 0.0 1.0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# Maximum precision (33×33×33)
iccApplyToLink /tmp/link_srgb_33.icc 0 33 0 "sRGB HiRes" 0.0 1.0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1
```

### Create .cube LUT file

```bash
# Export as .cube with 6 digits of precision
iccApplyToLink /tmp/srgb.cube 1 9 6 "sRGB Cube" 0.0 1.0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1
```

### Tetrahedral interpolation

```bash
iccApplyToLink /tmp/link_tet.icc 0 9 0 "sRGB Tet" 0.0 1.0 0 1 \
  test-profiles/sRGB_D65_MAT.icc 1
```

### Use destination space first

```bash
iccApplyToLink /tmp/link_dest.icc 0 9 0 "sRGB Dest" 0.0 1.0 1 0 \
  test-profiles/sRGB_D65_MAT.icc 1
```

### Cross-gamut DeviceLink

```bash
# sRGB → DisplayP3 conversion
iccApplyToLink /tmp/srgb_to_p3.icc 0 9 0 "sRGB to P3" 0.0 1.0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1 \
  test-profiles/ios-gen-DisplayP3.icc 1
```

### LUT Size Guidelines

| Size | Grid Points | Quality | Speed |
|------|-------------|---------|-------|
| 9 | 729 | Good for proofing | Fast |
| 17 | 4,913 | High quality | Moderate |
| 33 | 35,937 | Maximum quality | Slow generation |
| 65 | 274,625 | Extreme precision | Very slow |

## Tested Configurations

| Link Type | LUT Size | Option | Interp | Status |
|-----------|----------|--------|--------|--------|
| DeviceLink v4 | 9 | 0 | Linear | ✅ PASS |
| DeviceLink v5 | 17 | 1 | Linear | ✅ PASS |
| DeviceLink v4 | 33 | 0 | Linear | ✅ PASS |
| .cube | 9 | 6 (precision) | Linear | ✅ PASS |
| DeviceLink v4 | 9 | 0 | Tetrahedral | ✅ PASS |
| DeviceLink v4 | 9 | 0 | Linear (dest) | ✅ PASS |
| Cross-gamut chain | 9 | 0 | Linear | ✅ PASS |

## Related Tools

- [iccFromCube](../iccFromCube/) — Convert .cube back to ICC profile
- [iccApplyNamedCmm](../iccApplyNamedCmm/) — Apply transforms to data
- [iccDumpProfile](../iccDumpProfile/) — Inspect generated DeviceLink profiles
- CFL fuzzer: `icc_link_fuzzer` — Fuzz the profile linking pipeline

## Version

Built with IccProfLib version 2.3.1.5
