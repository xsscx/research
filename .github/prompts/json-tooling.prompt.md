# iccDEV JSON Configuration Tooling — Workflow Prompt

## When to Use

Use this prompt when:
- Testing or debugging iccDEV's `-cfg <config.json>` feature
- Creating new JSON test configurations
- Triaging JSON-related bugs in IccCmmConfig.cpp
- Reviewing CFL-027 patch status or upstream merge readiness
- Running the JSON test suites (187 total tests)

## JSON-Enabled Tools (3 of 15)

| Tool | Binary | JSON Top-Level Keys |
|------|--------|-------------------|
| iccApplyNamedCmm | `iccDEV/Build/Tools/IccApplyNamedCmm/iccApplyNamedCmm` | `dataFiles`, `profileSequence`, `colorData` |
| iccApplyProfiles | `iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles` | `imageFiles`, `profileSequence` |
| iccApplySearch | `iccDEV/Build/Tools/IccApplySearch/iccApplySearch` | `dataFiles`, `searchApply`, `colorData` |

**iccApplyToLink does NOT support JSON** (args-only).

## Quick Start

```bash
# Set environment (run from research repo root)
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML
export ASAN_OPTIONS=halt_on_error=0,detect_leaks=0

# Run a single JSON config
iccDEV/Build/Tools/IccApplyNamedCmm/iccApplyNamedCmm -cfg docs/Testing/json-configs/applynamedcmm-srgb-basic.json

# Run full test suites
bash docs/Testing/test-json-tools.sh              # 90 tests
bash docs/Testing/json-cli-exercise/json-cli-exercise.sh  # 97 tests

# Run from iccDEV paths (same tests, adapted paths)
bash iccDEV/Testing/Fuzzing/scripts/test-json-tools.sh              # 90 tests
bash iccDEV/Testing/Fuzzing/scripts/json-cli-exercise.sh            # 97 tests
```

## JSON Encoding Values (CRITICAL — strings, NOT integers)

The JSON configs use **string** encoding names. Passing numeric enums silently fails.

### Color Encoding (`srcEncoding`, `encoding`)
| String Value | Enum | Meaning |
|-------------|------|---------|
| `"value"` | `icEncodeValue` | Raw ICC internal values |
| `"float"` | `icEncodeFloat` | Floating point [0.0-1.0] |
| `"unitFloat"` | `icEncodeUnitFloat` | Unit float [0.0-1.0] |
| `"percent"` | `icEncodePercent` | Percentage [0-100] |
| `"8Bit"` | `icEncode8Bit` | 8-bit integer [0-255] |
| `"16Bit"` | `icEncode16Bit` | 16-bit integer [0-65535] |
| `"16BitV2"` | `icEncode16BitV2` | Legacy v2 16-bit |

### File Encoding (`dstEncoding` in imageFiles)
| String Value | Meaning |
|-------------|---------|
| `"8Bit"` | 8-bit output |
| `"16Bit"` | 16-bit output |
| `"float"` | Float output |
| `"sameAsSource"` | Match input encoding |

### Data Type (`srcType`)
| String Value | Meaning |
|-------------|---------|
| `"colorData"` | ICC color data format |
| `"legacy"` | Legacy format |
| `"it8"` | IT8 chart format |

## Complete JSON Field Inventory (38 fields)

```
adjustPcsLuminance, debugCalc, dstCompression, dstDigits, dstEmbedIcc,
dstEncoding, dstFile, dstImageFile, dstPlanar, dstPrecision, dstType,
encoding, i, iccEnvVars, iccFile, l, linkFile, linkGridSize, linkMaxRange,
linkMinRange, linkPrecision, linkTitle, linkType, n, pccEnvVars, pccFile,
sn, srcEncoding, srcFile, srcImageFile, srcType, sv, transform, useBPC,
useHToS, useSourceTransform, useV5SubProfile, v, weight
```

## Known Bugs (Fixed by CFL-027)

| Line | Bug | Fix |
|------|-----|-----|
| 303 | `j["dstDigits]"]` — stray `]` in key | `j["dstDigits"]` |
| 422 | `j["srcImgFile"]` — key mismatch vs fromJson | `j["srcImageFile"]` |
| 424 | `j["dstImgFile"]` — key mismatch vs fromJson | `j["dstImageFile"]` |
| 681 | `j["iccProfile"]` — key mismatch vs fromJson | `j["iccFile"]` |
| 705,1092 | `= icInterpNames` — assigns array pointer | `= icInterpNames[i]` |

Patch: `cfl/patches/027-json-tojson-key-typos.patch`
Upstream submission: `~/typos.patch` (standalone, `-p0` format)

## Test Configs Reference

### Valid Configs (9) — in `docs/Testing/json-configs/` and `iccDEV/Testing/Fuzzing/seeds/json/configs/`

| Config | Tool | Tests |
|--------|------|-------|
| `applynamedcmm-srgb-basic.json` | ApplyNamedCmm | Basic sRGB float→XYZ |
| `applynamedcmm-chain-two-profiles.json` | ApplyNamedCmm | Two-profile RGB→XYZ→RGB |
| `applynamedcmm-8bit-encoding.json` | ApplyNamedCmm | 8-bit [0-255] input |
| `applynamedcmm-16bit-encoding.json` | ApplyNamedCmm | 16-bit [0-65535] input |
| `applynamedcmm-debugcalc-bpc.json` | ApplyNamedCmm | debugCalc + BPC flags |
| `applynamedcmm-output-to-file.json` | ApplyNamedCmm | File output mode |
| `applynamedcmm-saturation-intent.json` | ApplyNamedCmm | Saturation rendering intent |
| `applysearch-basic.json` | ApplySearch | 2-profile search optimization |
| `applysearch-perceptual-bpc.json` | ApplySearch | Perceptual + BPC search |

### Malformed Configs (14) — in `docs/Testing/malformed-json/` and `iccDEV/Testing/Fuzzing/seeds/json/malformed/`

All must be rejected gracefully (exit ≠ 0, 0 ASAN/UBSAN):
`invalid-syntax`, `missing-profiles`, `empty-object`, `null-values`, `wrong-types`,
`huge-values`, `path-traversal-dotdot`, `negative-values`, `binary-inject`,
`unicode-inject`, `duplicate-keys`, `deeply-nested`, `array-instead-object`, `missing-data`

## CLI Exercise Groups (22 — json-cli-exercise.sh)

1. srcEncoding sweep (7 values)
2. dstEncoding sweep
3. Rendering intent sweep (4 intents × 3 interpolation)
4. debugCalc toggle (true/false)
5. useBPC toggle
6. useD2BxB2Dx toggle
7. adjustPcsLuminance toggle
8. useHToS toggle
9. dstDigits sweep (1-8)
10. Multi-profile chains (2-3 profiles)
11. PCS space tests (Lab, XYZ)
12. Transform type sweep
13. Profile boolean combinations
14. ApplySearch basic
15. ApplySearch with BPC
16. ApplySearch rendering intents
17. ApplySearch debugCalc
18. ApplySearch dstDigits
19. ApplySearch multi-profile
20. ApplyProfiles TIFF basic
21. ApplyProfiles encoding sweep
22. Error handling edge cases

## Architecture Notes

- **Infrastructure**: `IccJsonUtil.{h,cpp}` (nlohmann/json wrappers) + `IccCmmConfig.{h,cpp}` (9 config classes)
- **Parsing**: `icSetJsonColorEncoding()` at IccCmmConfig.cpp:112-122 — case-insensitive `stricmp`
- **9 config classes**: CIccCfgDataApply, CIccCfgImageApply, CIccCfgProfile, CIccCfgProfileArray,
  CIccCfgProfileSequence, CIccCfgColorData, CIccCfgDataEntry, CIccCfgSearchApply, CIccCfgSearchWeights
- **Call path**: main() → loadJsonFrom() → nlohmann::json::parse() → CIccCfg*::fromJson()
- **Round-trip**: fromJson() → [execute] → toJson() → saveJsonAs()

## See Also

- `docs/Testing/README.md` — Full test results documentation
- `docs/iccDEV/Tools/README.md` — JSON feature overview with bug table
- `docs/iccDEV/Tools/iccApplyNamedCmm/README.md` — Per-tool JSON schema
- `docs/iccDEV/Tools/iccApplyProfiles/README.md` — Per-tool JSON schema
- `docs/iccDEV/Tools/iccApplySearch/README.md` — Per-tool JSON schema
- `~/typo-bug.txt` — Bug reproduction writeup
- `~/json-1-liners.txt` — 14 quick test commands
