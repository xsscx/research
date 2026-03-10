# iccSpecSepToTiff

Concatenates several spectral separation TIFF files into a single multi-channel TIFF,
with optional embedded ICC profile.

## Usage

```
iccSpecSepToTiff output compress sep infile_fmt start end incr {profile}
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `output` | **Required** | Path for output TIFF file |
| `compress` | **Required** | 0=No compression, 1=Compressed |
| `sep` | **Required** | 0=Contiguous, 1=Separated planes |
| `infile_fmt` | **Required** | printf format string for input files (e.g., `spec_%06d.tiff`) |
| `start` | **Required** | First channel number |
| `end` | **Required** | Last channel number |
| `incr` | **Required** | Increment between channels |
| `profile` | Optional | ICC profile to embed in output TIFF |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 255 (-1) | Input file not found or invalid TIFF format |

## Examples

### Merge spectral TIFF sequence

Given spectral separation TIFFs named `spec_000380.tiff` through `spec_000780.tiff`
at 5nm intervals:

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# Merge 380nm–780nm at 5nm steps (81 channels)
iccSpecSepToTiff /tmp/spectral_merged.tiff 0 0 \
  "spec_%06d.tiff" 380 780 5

# With compression and embedded spectral ICC profile
iccSpecSepToTiff /tmp/spectral_merged.tiff 1 0 \
  "spec_%06d.tiff" 380 780 5 \
  test-profiles/Rec2020rgbSpectral.icc
```

### Using iccDEV test data

```bash
# The iccDEV Testing/ directory has spectral TIFF test data
# Check what's available
ls iccDEV/Testing/hybrid/Data/

# Note: smCows380_5_780.tif is already a merged spectral TIFF (81 channels)
# SpecSepToTiff expects separated single-channel TIFFs as input
```

### Separated planes output

```bash
iccSpecSepToTiff /tmp/spectral_sep.tiff 0 1 \
  "spec_%06d.tiff" 380 780 5
```

## Spectral TIFF Pipeline

```
Individual spectral TIFFs          Multi-channel TIFF
  spec_000380.tiff ─┐
  spec_000385.tiff  ├──→ iccSpecSepToTiff ──→ spectral_merged.tiff (81 channels)
  spec_000390.tiff  │
  ...               │
  spec_000780.tiff ─┘
```

## Creating Test Input

To create sequential spectral TIFFs for testing, use any tool that generates
single-channel TIFF images. The channel number in the filename (via the printf format)
determines the spectral band assignment.

## Known Limitations

- Requires sequential TIFF files matching the printf format exactly
- All input TIFFs must have identical dimensions and 1 sample per pixel
- The spectral TIFF at `iccDEV/Testing/hybrid/Data/smCows380_5_780.tif` has
  81 SPP — it cannot be used as input (it's the expected output format)

## Security Notes

CFL-082 patches the `CTiffImg::Open()` strip buffer validation that this tool uses.
For untrusted input TIFFs:

```bash
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccSpecSepToTiff /tmp/out.tiff 0 0 "malicious_%06d.tiff" 1 10 1
```

## Related Tools

- [iccTiffDump](../iccTiffDump/) — Inspect the merged spectral TIFF
- [iccApplyProfiles](../iccApplyProfiles/) — Apply ICC transforms to TIFF images
- CFL fuzzer: `icc_specsep_fuzzer` — Fuzz the spectral separation pipeline

## Version

Built with IccProfLib version 2.3.1.5
