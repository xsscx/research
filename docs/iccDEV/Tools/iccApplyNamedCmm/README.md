# iccApplyNamedCmm

Applies ICC color transforms to color data files using the Named Color Management Module (CMM).
Supports chained profile transforms, multiple encoding formats, and interpolation methods.

## Usage

```
iccApplyNamedCmm {-debugcalc} data_file_path final_data_encoding{:FmtPrecision{:FmtDigits}} interpolation {{-ENV:Name value} profile_file_path Rendering_intent {-PCC connection_conditions_path}}
```

Or with a JSON config file:

```
iccApplyNamedCmm -cfg config_file_path
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `-debugcalc` | Optional | Enable calculator debugging output |
| `data_file_path` | **Required** | Path to color data file |
| `final_data_encoding` | **Required** | Output encoding (see table below) |
| `interpolation` | **Required** | 0=Linear, 1=Tetrahedral |
| `profile_file_path` | **Required** | Path to ICC profile |
| `Rendering_intent` | **Required** | 0=Perceptual, 1=Relative, 2=Saturation, 3=Absolute |
| `-PCC path` | Optional | Profile Connection Conditions file |
| `-ENV:Name value` | Optional | Environment variable for transform |
| `-cfg path` | Optional | JSON configuration file |

### Encoding Values

| Code | Name | Description |
|------|------|-------------|
| 0 | icEncodeValue | Converts to/from Lab encoding when samples=3 |
| 1 | icEncodePercent | Percentage values (0–100) |
| 2 | icEncodeUnitFloat | Unit float (0.0–1.0, may clip) |
| 3 | icEncodeFloat | Unclamped float values |
| 4 | icEncode8Bit | 8-bit integer (0–255) |
| 5 | icEncode16Bit | 16-bit integer (0–65535) |
| 6 | icEncode16BitV2 | 16-bit v2 encoding |

### Encoding Precision Format

`encoding:precision:digits` — e.g., `0:8:12` means encoding=0, 8 digits after decimal, 12 total.

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 255 (-1) | Transform error (incompatible encoding, profile, or data format) |

## Data File Format

```
'RGB '  ; Data Color Space (4-char signature in quotes)
icEncodeValue  ; Encoding enum name

255 255 255
0 0 0
128 128 128
255 0 0
0 255 0
0 0 255
```

- Line 1: 4-character ICC color space signature in single quotes, semicolon comment
- Line 2: Encoding enum name, semicolon comment
- Blank line separator
- Data: space-separated channel values, one sample per line

## Examples

### All encoding types with sRGB

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# Encoding 0: icEncodeValue
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# Encoding 1: icEncodePercent
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 1 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# Encoding 2: icEncodeUnitFloat
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 2 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# Encoding 3: icEncodeFloat
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 3 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# Encoding 5: icEncode16Bit
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 5 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# Encoding with precision format (8 decimal digits, 12 total)
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0:8:12 0 \
  test-profiles/sRGB_D65_MAT.icc 1
```

> **Note**: Encoding 4 (icEncode8Bit) may return exit 255 for some profile/data
> combinations. This is a known tool limitation, not a crash.

### Tetrahedral interpolation

```bash
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 1 \
  test-profiles/sRGB_D65_MAT.icc 1
```

### Different rendering intents

```bash
# Perceptual
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 \
  test-profiles/sRGB_D65_MAT.icc 0

# Saturation
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 \
  test-profiles/sRGB_D65_MAT.icc 2

# Absolute Colorimetric
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 \
  test-profiles/sRGB_D65_MAT.icc 3
```

### Chained profile transforms

```bash
# sRGB → sRGB (identity check with chained transforms)
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1 \
  test-profiles/sRGB_D65_MAT.icc 1
```

### CMYK profile with CMYK data

```bash
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-cmyk-percent.txt 1 0 \
  test-profiles/CMYK-3DLUTs2.icc 1
```

### Float and 16-bit data formats

```bash
# Float data
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-float.txt 3 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# 16-bit data
iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-16bit.txt 5 0 \
  test-profiles/sRGB_D65_MAT.icc 1
```

### Using upstream test data

```bash
# sRGB calculator test data (from iccDEV Testing/)
iccApplyNamedCmm iccDEV/Testing/Calc/srgbCalcTest.txt 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1
```

## Test Data Files

Provided in `docs/iccDEV/Tools/test-data/`:

| File | Color Space | Encoding | Samples |
|------|-------------|----------|---------|
| `test-data-rgb-8bit.txt` | RGB | 8-bit (0–255) | 11 (white, black, grays, primaries, secondaries) |
| `test-data-rgb-16bit.txt` | RGB | 16-bit (0–65535) | 6 |
| `test-data-rgb-float.txt` | RGB | Float (0.0–1.0) | 8 |
| `test-data-cmyk-percent.txt` | CMYK | Percent (0–100) | 10 |
| `test-data-lab-float.txt` | Lab | Float | 9 |

## JSON Configuration (`-cfg`)

Instead of command-line arguments, iccApplyNamedCmm accepts a JSON configuration file:

```bash
iccApplyNamedCmm -cfg docs/Testing/json-configs/applynamedcmm-srgb-basic.json
```

### JSON Schema

```json
{
  "dataFiles": {
    "srcType": "colorData",       // "colorData" | "legacy" | "it8"
    "srcFile": "",                // Path to external data file (when srcType != "colorData")
    "dstType": "colorData",       // "colorData" | "legacy" | "it8"
    "dstFile": "",                // Path to output file (empty = stdout)
    "dstEncoding": "float",       // See encoding strings table below
    "dstPrecision": 4,            // Decimal places in output
    "dstDigits": 9                // Total digits in output
  },
  "profileSequence": [
    {
      "iccFile": "path/to/profile.icc",
      "intent": 1,                // 0=Perceptual, 1=Relative, 2=Saturation, 3=Absolute
      "interpolation": "tetrahedral",  // "linear" | "tetrahedral"
      "useBPC": false,            // Black Point Compensation
      "useD2BxB2Dx": true,        // Use DToB/BToD tags if available
      "adjustPcsLuminance": false, // Adjust PCS luminance
      "useV5SubProfile": false,   // Use v5 sub-profile
      "useHToS": false,           // Use HToS transform
      "pccFile": "",              // Profile Connection Conditions file
      "iccEnvVars": [],           // Environment variables [{name, value}]
      "pccEnvVars": []            // PCC environment variables [{name, value}]
    }
  ],
  "colorData": {
    "space": "RGB ",              // 4-char ICC color space signature (trailing space)
    "encoding": "float",          // Input data encoding string
    "data": [
      { "values": [1.0, 1.0, 1.0] },
      { "values": [0.0, 0.0, 0.0] }
    ]
  }
}
```

### JSON Encoding Strings (CRITICAL)

The JSON parser requires **string** encoding values, NOT numeric enum integers.
Numeric values (0, 1, 2...) are silently rejected as `icEncodeUnknown`.

**Color data encoding** (`colorData.encoding`, `dataFiles.dstEncoding`):

| String | Enum | Range |
|--------|------|-------|
| `"value"` | icEncodeValue | Normalized (Lab conversion for 3-ch) |
| `"percent"` | icEncodePercent | 0–100 |
| `"unitFloat"` | icEncodeUnitFloat | 0.0–1.0 (clips) |
| `"float"` | icEncodeFloat | Unbounded |
| `"8Bit"` | icEncode8Bit | 0–255 |
| `"16Bit"` | icEncode16Bit | 0–65535 |
| `"16BitV2"` | icEncode16BitV2 | 0–65535 |

**Data type** (`dataFiles.srcType`, `dataFiles.dstType`):

| String | Enum |
|--------|------|
| `"colorData"` | icCfgColorData (inline JSON data) |
| `"legacy"` | icCfgLegacy (external file) |
| `"it8"` | icCfgIt8 (IT8 file) |

### CLI Arguments ↔ JSON Field Mapping

| CLI Argument | JSON Path |
|-------------|-----------|
| `data_file_path` | `dataFiles.srcFile` (or inline `colorData`) |
| `final_data_encoding` | `dataFiles.dstEncoding` |
| `interpolation` | `profileSequence[].interpolation` |
| `profile_file_path` | `profileSequence[].iccFile` |
| `Rendering_intent` | `profileSequence[].intent` |
| `-debugcalc` | `profileSequence[].debugCalc` (bool) |
| `-PCC path` | `profileSequence[].pccFile` |
| `-ENV:Name value` | `profileSequence[].iccEnvVars` |
| `FmtPrecision` | `dataFiles.dstPrecision` |
| `FmtDigits` | `dataFiles.dstDigits` |

### JSON Config Examples

Example configs are in `docs/Testing/json-configs/`:

| Config | Description |
|--------|-------------|
| `applynamedcmm-srgb-basic.json` | Single sRGB profile, float encoding, 6 RGB samples |
| `applynamedcmm-chain-two-profiles.json` | Two sRGB profiles chained |
| `applynamedcmm-three-profile-chain.json` | Three profiles with intents 0, 1, 2 |
| `applynamedcmm-debugcalc-bpc.json` | debugCalc + BPC, 8Bit encoding |
| `applynamedcmm-8bit-encoding.json` | 8-bit input encoding |
| `applynamedcmm-16bit-encoding.json` | 16-bit input encoding |
| `applynamedcmm-output-to-file.json` | Output to dstFile |

### JSON Output

When the tool writes results, the output JSON uses `colorData` structure:

```json
{
  "colorData": {
    "data": [{ "v": [0.9642, 1.0, 0.8249] }],
    "encoding": "float",
    "space": "XYZ ",
    "srcEncoding": "float",
    "srcSpace": "RGB "
  }
}
```

### Known JSON Bugs

**Bug 1: `dstDigits]"` key typo** (IccCmmConfig.cpp:~303) — `toJson()` serializes
`dstDigits` as `"dstDigits]"` (bracket inside key string). Breaks round-trip load→save→load.

**Bug 2: `iccFile`/`iccProfile` field mismatch** — `fromJson()` reads `"iccFile"` but
`toJson()` writes `"iccProfile"`. Round-trip serialization loses the profile path.

**Bug 3: `icInterpNames` array assignment** (IccCmmConfig.cpp:~706) — `toJson()` assigns
the entire `icInterpNames` array pointer instead of `icInterpNames[i]`. Interpolation
value is corrupted in output JSON.

### JSON Test Suite

90 automated tests covering valid configs, malformed JSON, edge cases, all intents,
all encodings, profile variants, and crash profiles — 0 ASAN/UBSAN findings.
See `docs/Testing/README.md` and `docs/Testing/test-json-tools.sh`.

## Known Limitations

- Encoding 4 (icEncode8Bit) returns exit 255 with some profiles
- Chained transforms with 2+ profiles may trigger upstream memory leak
  (`CIccPcsStepScale::Mult` at IccCmm.cpp:4325 — 24-byte leak, upstream)
- JSON `toJson()` output has 3 serialization bugs (see Known JSON Bugs above)

## Related Tools

- [iccApplyProfiles](../iccApplyProfiles/) — Apply transforms to TIFF images
- [iccApplySearch](../iccApplySearch/) — Search optimal transforms between profiles
- [iccApplyToLink](../iccApplyToLink/) — Create DeviceLink from profile chain
- CFL fuzzer: `icc_applynamedcmm_fuzzer` — Fuzz the Named CMM

## Version

Built with IccProfLib version 2.3.1.5
