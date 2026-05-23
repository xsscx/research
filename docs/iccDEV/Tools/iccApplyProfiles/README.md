# iccApplyProfiles

Apply one or more ICC profiles to TIFF images and write a transformed TIFF.

## Usage

```text
iccApplyProfiles {-threads N} -cfg config_file

iccApplyProfiles {-threads N} {-exportcfg config_file} \
  src_tiff dst_tiff dst_encoding dst_compression dst_planar \
  dst_embed_icc interpolation {{-ENV:sig value} profile_path rendering_intent \
  {-PCC pcc_path}}
```

The legacy positional form is:

```text
iccApplyProfiles src_tiff dst_tiff dst_encoding dst_compression dst_planar \
  dst_embed_icc interpolation {{-ENV:sig value} profile_path rendering_intent \
  {-PCC pcc_path}}
```

## Arguments

| Argument | Required | Notes |
|----------|----------|-------|
| `src_tiff` | Yes | Input TIFF path |
| `dst_tiff` | Yes | Output TIFF path |
| `dst_encoding` | Yes | `0` same as source, `1` 8-bit, `2` 16-bit, `4` float |
| `dst_compression` | Yes | `0` none, `1` LZW |
| `dst_planar` | Yes | `0` contiguous, `1` separate |
| `dst_embed_icc` | Yes | `0` no embed, `1` embed output profile |
| `interpolation` | Yes | `0` linear, `1` tetrahedral |
| `profile_path` | Yes | ICC profile in the transform chain |
| `rendering_intent` | Yes | `0` perceptual, `1` relative, `2` saturation, `3` absolute |
| `-threads N` | No | Worker count; `0` uses hardware concurrency, `1` uses single-pixel apply |
| `-exportcfg path` | No | Write a JSON config from the remaining positional arguments |
| `-PCC path` | No | Profile connection conditions file |
| `-ENV:sig value` | No | Environment variable override |

## Basic Example

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

iccApplyProfiles input.tiff /tmp/output.tiff 1 0 0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1
```

## Common Variants

```bash
# Write 16-bit output with LZW
iccApplyProfiles input.tiff /tmp/output_16.tiff 2 1 0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# Write float output
iccApplyProfiles input.tiff /tmp/output_float.tiff 4 0 0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 0

# Embed the output profile
iccApplyProfiles input.tiff /tmp/output_embed.tiff 1 0 0 1 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# Exercise the row-apply path used by threaded operation
iccApplyProfiles -threads 0 input.tiff /tmp/output_threads.tiff 1 0 0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1

# Export the equivalent JSON configuration
iccApplyProfiles -exportcfg /tmp/applyprofiles.json \
  input.tiff /tmp/output_cfg.tiff 1 0 0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1
```

## JSON Mode

The tool also accepts:

```bash
iccApplyProfiles -cfg config.json
iccApplyProfiles -threads 1 -cfg config.json
```

Minimal JSON shape:

```json
{
  "imageFiles": {
    "srcImageFile": "input.tiff",
    "dstImageFile": "output.tiff",
    "dstEncoding": "8Bit",
    "dstCompression": false,
    "dstPlanar": false,
    "dstEmbedIcc": false
  },
  "profileSequence": [
    {
      "iccFile": "path/to/profile.icc",
      "intent": 1,
      "interpolation": "tetrahedral"
    }
  ],
  "connect": {
    "threads": 1
  }
}
```

## JSON Caveat

Older summaries documented a `srcImageFile` versus `srcImgFile` round-trip
serialization mismatch in upstream `toJson()` output. Use `srcImageFile` and
`dstImageFile` in input configs and verify behavior against the current build.

## TIFF Requirements

- valid TIFF input
- supported sample formats: 8-bit, 16-bit, or 32-bit float
- supported photometric layouts that match the chosen profile chain
- TIFF pixel values are treated as device encodings; integers map linearly to
  `[0, 1]`, and 32-bit float values pass through unchanged.

## Notes

- For metadata-only inspection or ICC extraction, use `../iccTiffDump/README.md`.
- For JSON fixtures and saved test checkpoints, use `docs/Testing/README.md`.
- For untrusted TIFFs, prefer the ASAN/UBSAN build because strip and tile
  geometry handling is part of the attack surface.
