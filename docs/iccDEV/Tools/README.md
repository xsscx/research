# iccDEV Tool Reference

Command-line tools built from `iccDEV/Tools/CmdLine/`.

## Build and Runtime

```bash
cd iccDEV/Build
cmake Cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_TOOLS=ON -DENABLE_SANITIZERS=ON
make -j32

export LD_LIBRARY_PATH=$PWD/IccProfLib:$PWD/IccXML
export ASAN_OPTIONS=detect_leaks=0
```

## Quick Reference

| Tool | JSON | Purpose | Exit 0 |
|------|------|---------|--------|
| iccDumpProfile | - | Dump header, tags, data | Valid profile |
| iccToXml | - | ICC binary to XML | Conversion OK |
| iccFromXml | - | XML to ICC binary | Conversion OK |
| [iccToJson](iccToJson/README.md) | - | ICC binary to JSON | Conversion OK |
| iccFromJson | - | JSON to ICC binary | Conversion OK |
| iccRoundTrip | - | Forward+inverse error | Transform OK |
| iccFromCube | - | .cube LUT to ICC DeviceLink | Conversion OK |
| iccApplyNamedCmm | -cfg | Apply profile chain to data | Transform OK |
| iccApplyProfiles | - | Apply profiles to TIFF | Transform OK |
| iccApplySearch | -cfg | PCC search across profiles | Search OK |
| iccApplyToLink | - | Build DeviceLink or .cube | Link OK |
| iccTiffDump | - | TIFF metadata + ICC extract | Valid TIFF |
| iccJpegDump | - | JPEG ICC extract or inject | Valid JPEG |
| iccPngDump | - | PNG ICC extract or inject | Valid PNG |
| iccProfilePlot | stdout | List or render profile visualization data | Valid mode and descriptor |
| iccV5DspObsToV4Dsp | - | v5 display+observer to v4 | Conversion OK |
| iccSpecSepToTiff | - | Merge spectral TIFF channels | Merge OK |

## Tool Usage

### iccDumpProfile

```
iccDumpProfile {-v} {int} profile {tagId/"ALL"}
```

| Arg | Values | Default |
|-----|--------|---------|
| -v | Enable validation | off |
| int | Verbosity 1-100 | 100 |
| tagId | 4-char tag sig or "ALL" | header only |

```bash
iccDumpProfile Testing/sRGB_v4_ICC_preference.icc ALL
iccDumpProfile -v 50 profile.icc desc
```

### iccToXml / iccFromXml

```
iccToXml src.icc dst.xml
iccFromXml src.xml dst.icc {-noid -v{=[relax_ng_schema]}}
```

| Flag | Purpose |
|------|---------|
| -noid | Skip Profile ID computation |
| -v | Validate output profile |
| -v=schema.rng | Validate against RelaxNG schema |

```bash
iccToXml profile.icc /tmp/profile.xml
iccFromXml /tmp/profile.xml /tmp/roundtrip.icc
```

### iccToJson / iccFromJson

```
iccToJson src.icc dst.json {-indent=N -sort}
iccFromJson src.json dst.icc {-noid}
```

```bash
iccToJson profile.icc /tmp/profile.json
iccFromJson /tmp/profile.json /tmp/roundtrip-json.icc
```

### iccRoundTrip

```
iccRoundTrip profile {rendering_intent=1 {use_mpe=0}}
```

| Arg | Values |
|-----|--------|
| rendering_intent | 0=perceptual, 1=relative, 2=saturation, 3=absolute |
| use_mpe | 0=LUT tags, 1=MPE (DToB/BToD) |

```bash
iccRoundTrip profile.icc 1 0   # relative, LUT
iccRoundTrip profile.icc 0 1   # perceptual, MPE
```

### iccFromCube

```
iccFromCube cube_file output.icc
```

Converts a .cube 3D LUT file to an ICC DeviceLink profile.

### iccApplyNamedCmm

```
# JSON mode (preferred for testing):
iccApplyNamedCmm -cfg config.json

# Export config from CLI args:
iccApplyNamedCmm -exportcfg out.json data.txt encoding interp profile.icc intent

# CLI mode:
iccApplyNamedCmm {-debugcalc} data.txt encoding{:precision{:digits}} interp
    {{-ENV:Name value} profile.icc intent {-PCC pcc.icc}}
```

| Arg | Values |
|-----|--------|
| encoding | 0=value, 1=percent, 2=unitFloat, 3=float, 4=8bit, 5=16bit, 6=16bitV2 |
| interp | 0=linear, 1=tetrahedral |
| intent | 0=perceptual, 1=relative, 2=saturation, 3=absolute |
| | 10+=no D2Bx/B2Dx, 20+=preview, 30=gamut, 40+=BPC |
| | 90+=colorimetric only, 100+=spectral only |
| | +1000=luminance PCS adjust |

### iccApplySearch

```
# JSON mode:
iccApplySearch -cfg config.json

# CLI mode:
iccApplySearch {-debugcalc} data.txt encoding[:prec[:dig]] interp
    {-ENV:tag val} profile1 intent1
    {{-ENV:tag val} mid_profile mid_intent}
    {-ENV:tag val} profile2 intent2
    -INIT init_intent {pcc1 weight1 ...}
```

Intents same as iccApplyNamedCmm, plus +10000 for V5 sub-profile.

### iccApplyProfiles

```
iccApplyProfiles src.tif dst.tif encoding compression planar embed interp
    {{-ENV:sig val} profile.icc intent {-PCC pcc.icc}}
```

| Arg | Values |
|-----|--------|
| encoding | 0=same, 1=8bit, 2=16bit, 4=float |
| compression | 0=none, 1=LZW |
| planar | 0=contig, 1=separate |
| embed | 0=no, 1=embed last ICC |
| interp | 0=linear, 1=tetrahedral |

### iccApplyToLink

```
iccApplyToLink dst type lut_size option title range_min range_max
    first_transform interp {{-ENV:sig val} profile.icc intent {-PCC pcc.icc}}
```

| Arg | Values |
|-----|--------|
| type | 0=DeviceLink, 1=.cube |
| option (type=0) | 0=v4 16-bit, 1=v5 |
| option (type=1) | precision digits |
| first_transform | 0=source, 1=destination |

### iccTiffDump

```
iccTiffDump tiff_file {exported.icc}
```

Dumps TIFF metadata. Optionally extracts embedded ICC profile.

### iccJpegDump

```
# Extract:
iccJpegDump input.jpg {output.icc}

# Inject:
iccJpegDump input.jpg --write-icc profile.icc --output output.jpg
```

Handles APP2 ICC_PROFILE markers and multi-segment reassembly.

### iccPngDump

```
# Extract:
iccPngDump input.png {output.icc}

# Inject:
iccPngDump input.png --write-icc profile.icc --output output.png
```

Reads iCCP chunk from PNG files.

### iccProfilePlot

```
iccProfilePlot profile.icc list
iccProfilePlot profile.icc graph descriptor_id
iccProfilePlot profile.icc raster descriptor_id {output.raw}
```

`list` emits descriptor JSON. `graph` emits point-series JSON. `raster` emits
CLUT geometry and optionally writes normalized, interleaved samples. Enumerate
first because descriptor IDs depend on profile tags.

```bash
iccProfilePlot Testing/sRGB_v4_ICC_preference.icc list
iccProfilePlot Testing/sRGB_v4_ICC_preference.icc graph chroma:xy
iccProfilePlot Testing/sRGB_v4_ICC_preference.icc raster clut:A2B0 /tmp/a2b0.raw
```

### iccV5DspObsToV4Dsp

```
iccV5DspObsToV4Dsp inputV5.icc inputObserverV5.icc outputV4.icc
```

Converts ICCv5 display + observer pair to v4 display for legacy apps.

### iccSpecSepToTiff

```
iccSpecSepToTiff output compress sep fmt start end incr {profile}
```

| Arg | Values |
|-----|--------|
| compress | 0=no, 1=yes |
| sep | 0=contig, 1=separate planes |
| fmt | printf format for input files |
| start/end/incr | Channel range |
| profile | Optional ICC to embed |

## JSON Configuration Schema

Tools with `-cfg` support accept this structure:

```json
{
  "colorData": {
    "data": [{"v": [50.0, 40.0, 40.0, 0.0]}],
    "encoding": "percent",
    "srcEncoding": "value",
    "srcSpace": "CMYK"
  },
  "dataFiles": {
    "dstEncoding": "float",
    "dstType": "legacy",
    "srcFile": null,
    "srcType": "colorData"
  },
  "profileSequence": [
    {
      "iccFile": "path/to/profile.icc",
      "intent": "absolute",
      "transform": "default",
      "useV5SubProfile": true
    }
  ]
}
```

Key fields:

| Field | Values |
|-------|--------|
| encoding | value, percent, unitFloat, float, 8bit, 16bit, 16bitV2 |
| intent | perceptual, relative, saturation, absolute |
| transform | default, colorimetric, spectral, MCS, preview, gamut |
| dstType | legacy, text |

## Rendering Intent Reference

| Code | Intent | Notes |
|------|--------|-------|
| 0 | Perceptual | |
| 1 | Relative Colorimetric | |
| 2 | Saturation | |
| 3 | Absolute Colorimetric | |
| 10-13 | Without D2Bx/B2Dx | Base + 10 |
| 20-23 | Preview | Base + 20 |
| 30 | Gamut | |
| 33 | Gamut Absolute | |
| 40-43 | With BPC | Base + 40 |
| 50 | BDRF Parameters | |
| 60 | BDRF Direct | |
| 70 | BDRF MCS Parameters | |
| 80 | MCS Connection | |
| 90-93 | Colorimetric Only | Base + 90 |
| 100-103 | Spectral Only | Base + 100 |
| +1000 | Luminance PCS adjust | Added to any intent |
| +10000 | V5 sub-profile | iccApplySearch only |

## Encoding Reference

| Code | Name | Description |
|------|------|-------------|
| 0 | icEncodeValue | Native; lab encoding when samples=3 |
| 1 | icEncodePercent | 0-100 range |
| 2 | icEncodeUnitFloat | 0.0-1.0 (may clip) |
| 3 | icEncodeFloat | Unclamped float |
| 4 | icEncode8Bit | 0-255 |
| 5 | icEncode16Bit | 0-65535 |
| 6 | icEncode16BitV2 | v2 16-bit encoding |

## Cross-References

- Per-tool details: subdirectories in this folder
- JSON config testing: `docs/Testing/test-json-tools.sh`
- CLI exercise script: `docs/Testing/json-cli-exercise/`
- Regression tests: `iccDEV/.github/ci/`
- Test data: `test-data/` (sample profiles + color data + .cube LUTs)
