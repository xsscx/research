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

## JSON Configuration (`-cfg`)

iccApplySearch accepts a JSON configuration file with a `searchApply` section:

```bash
iccApplySearch -cfg docs/Testing/json-configs/applysearch-basic.json
```

### JSON Schema

```json
{
  "dataFiles": {
    "srcType": "colorData",
    "dstType": "colorData",
    "dstFile": "",
    "dstEncoding": "float",
    "dstPrecision": 4,
    "dstDigits": 9
  },
  "searchApply": {
    "profileSequence": [
      {
        "iccFile": "path/to/profile.icc",
        "intent": 1,
        "useBPC": false,
        "interpolation": "tetrahedral",
        "pccFile": ""
      }
    ],
    "initial": {
      "lab": [50.0, 0.0, 0.0],     // Starting Lab values for search
      "last": false                 // Use last result as starting point
    },
    "pccWeights": {
      "luminance": 1.0,
      "chroma": 1.0,
      "hue": 1.0
    }
  },
  "colorData": {
    "space": "RGB ",
    "encoding": "float",
    "data": [
      { "values": [1.0, 0.0, 0.0] }
    ]
  }
}
```

### Top-Level JSON Structure (vs iccApplyNamedCmm)

| Key | iccApplyNamedCmm | iccApplySearch |
|-----|------------------|----------------|
| `dataFiles` | ✓ | ✓ (identical) |
| `profileSequence` | ✓ (top-level) | ✗ (inside `searchApply`) |
| `searchApply` | ✗ | ✓ (wraps profiles + search params) |
| `colorData` | ✓ | ✓ (identical) |

### CLI Arguments ↔ JSON Field Mapping

| CLI Argument | JSON Path |
|-------------|-----------|
| `data_file_path` | `dataFiles.srcFile` |
| `interpolation` | `searchApply.profileSequence[].interpolation` |
| `profile_file_path` | `searchApply.profileSequence[].iccFile` |
| `rendering_intent` | `searchApply.profileSequence[].intent` |
| `Lab_L Lab_a Lab_b` | `searchApply.initial.lab` |
| `-PCC path` | `searchApply.profileSequence[].pccFile` |
| `-ENV:Name value` | `searchApply.profileSequence[].iccEnvVars` |

### JSON Config Examples

| Config | Description |
|--------|-------------|
| `applysearch-basic.json` | Basic search with sRGB, float encoding |
| `applysearch-perceptual-bpc.json` | Perceptual intent with BPC enabled |

### JSON Test Suite

14 malformed JSON configs + 2 valid configs tested — all handled gracefully,
0 ASAN/UBSAN. See `docs/Testing/README.md` and `docs/Testing/test-json-tools.sh`.

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
