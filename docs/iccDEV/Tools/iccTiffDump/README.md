# iccTiffDump

Inspect TIFF metadata and optionally extract the embedded ICC profile.

## Usage

```text
iccTiffDump tiff_file {exported_icc_file}
```

## Arguments

| Argument | Required | Notes |
|----------|----------|-------|
| `tiff_file` | Yes | Input TIFF path |
| `exported_icc_file` | No | Output path for the extracted profile |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| Non-zero | TIFF open failure, malformed metadata, or missing ICC export target |

## Common Examples

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# Dump TIFF metadata
iccTiffDump test-profiles/catalyst-8bit-ACESCG.tiff

# Extract the embedded profile
iccTiffDump test-profiles/catalyst-8bit-ACESCG.tiff /tmp/extracted.icc

# Inspect the extracted profile
iccDumpProfile /tmp/extracted.icc
```

## Output

Typical output includes:

- image dimensions
- bits per sample
- samples per pixel
- photometric interpretation
- compression and planar layout
- ICC profile presence and size

## Notes

- This tool focuses on TIFF metadata and ICC extraction, not color transforms.
- For pixel-transform workflows, use `../iccApplyProfiles/README.md`.
- For hostile TIFFs, prefer an ASAN build. Metadata parsing can still exercise
  offset, geometry, and IFD-chain bugs.
