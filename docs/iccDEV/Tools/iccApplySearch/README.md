# iccApplySearch

Applies ICC color transforms and searches for optimal Profile Connection Conditions (PCC)
between two or more profiles. Used for evaluating transform accuracy under different
viewing conditions.

## Usage

```
iccApplySearch {-debugcalc} data_file encoding[:precision[:digits]] interpolation {-ENV:tag value} profile1_path intent1 {{-ENV:tag value} middle_profile_path mid_intent} {-ENV:tag value} profile2_path intent2 -INIT init_intent2 {pcc_path weight ...}
```

Or with a JSON config:

```
iccApplySearch -cfg config_file_path
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `data_file` | **Required** | Path to color data file |
| `encoding` | **Required** | Output encoding (0–6, same as iccApplyNamedCmm) |
| `interpolation` | **Required** | 0=Linear, 1=Tetrahedral |
| `profile1_path` | **Required** | First (source) ICC profile |
| `intent1` | **Required** | Rendering intent for first profile |
| `profile2_path` | **Required** | Last (destination) ICC profile |
| `intent2` | **Required** | Rendering intent for last profile |
| `-INIT init_intent` | **Required** | Initial rendering intent for search |
| `pcc_path weight` | Optional | PCC profile and weight pairs |
| `middle_profile_path` | Optional | Intermediate profile in chain |

### Encoding Values

Same as [iccApplyNamedCmm](../iccApplyNamedCmm/) — see encoding table there.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 255 (-1) | Error 6 — Unable to begin profile application (incompatible profiles) |

## Examples

### Basic search between two sRGB profiles

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# Relative colorimetric
iccApplySearch docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1 \
  test-profiles/sRGB_D65_MAT.icc 1 \
  -INIT 1

# Perceptual
iccApplySearch docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 \
  test-profiles/sRGB_D65_MAT.icc 0 \
  test-profiles/sRGB_D65_MAT.icc 0 \
  -INIT 0
```

### Float encoding output

```bash
iccApplySearch docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 3 0 \
  test-profiles/sRGB_D65_MAT.icc 1 \
  test-profiles/sRGB_D65_MAT.icc 1 \
  -INIT 1
```

### Profile chain (sRGB → DisplayP3 → sRGB)

```bash
# Note: may return exit 255 if profiles are incompatible for chaining
iccApplySearch docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1 \
  test-profiles/ios-gen-DisplayP3.icc 1 \
  test-profiles/sRGB_D65_MAT.icc 1 \
  -INIT 1
```

## Known Limitations

- Profile chain searches (3+ profiles) may fail with "Error 6 — Unable to begin"
  if the profile color spaces are incompatible for chaining
- Chained transforms may trigger upstream memory leak (`CIccPcsStepScale::Mult`)

## Related Tools

- [iccApplyNamedCmm](../iccApplyNamedCmm/) — Apply transforms without PCC search
- [iccApplyToLink](../iccApplyToLink/) — Create DeviceLink from chain
- [iccRoundTrip](../iccRoundTrip/) — Test profile accuracy

## Version

Built with IccProfLib version 2.3.1.5
