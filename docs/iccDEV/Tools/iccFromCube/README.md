# iccFromCube

Creates an ICC DeviceLink profile from a .cube LUT (Look-Up Table) file.

## Usage

```
iccFromCube cube_file output_icc_file
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `cube_file` | **Required** | Path to .cube LUT file |
| `output_icc_file` | **Required** | Path for output ICC profile (.icc) |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| Non-zero | Parse error or invalid .cube format |

## .cube File Format

The .cube format is a simple text-based 3D LUT format:

```
TITLE "My LUT"
LUT_3D_SIZE 2
DOMAIN_MIN 0.0 0.0 0.0
DOMAIN_MAX 1.0 1.0 1.0

0.0 0.0 0.0
1.0 0.0 0.0
0.0 1.0 0.0
1.0 1.0 0.0
0.0 0.0 1.0
1.0 0.0 1.0
0.0 1.0 1.0
1.0 1.0 1.0
```

- `LUT_3D_SIZE N` — Grid dimension (N×N×N entries required)
- `DOMAIN_MIN` / `DOMAIN_MAX` — Input range (default 0.0–1.0)
- Data lines: space-separated RGB float triplets

## Examples

### Identity LUT (2×2×2)

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

iccFromCube docs/iccDEV/Tools/test-data/test-identity.cube /tmp/identity.icc
iccDumpProfile /tmp/identity.icc
```

### Warm film LUT (5×5×5)

```bash
iccFromCube docs/iccDEV/Tools/test-data/test-warmfilm-5x5x5.cube /tmp/warmfilm.icc
iccDumpProfile /tmp/warmfilm.icc
```

### From CFL corpus .cube files

```bash
# Use existing corpus cubes
iccFromCube cfl/corpus-icc_fromcube_fuzzer/warm_film_2x2x2.cube /tmp/warm.icc
iccFromCube cfl/corpus-icc_fromcube_fuzzer/domain_with_input_range_2x2x2.cube /tmp/domain.icc
iccFromCube cfl/corpus-icc_fromcube_fuzzer/negative_domain_3x3x3.cube /tmp/negative.icc
```

### Generate a .cube from profile chain

Use [iccApplyToLink](../iccApplyToLink/) with `link_type=1` to create .cube files:

```bash
iccApplyToLink /tmp/output.cube 1 9 6 "sRGB" 0.0 1.0 0 0 \
  test-profiles/sRGB_D65_MAT.icc 1
```

## Test Data

Provided test .cube files in `docs/iccDEV/Tools/test-data/`:

| File | Size | Description |
|------|------|-------------|
| `test-identity.cube` | 2×2×2 | Identity (passthrough) LUT |
| `test-warmfilm-5x5x5.cube` | 5×5×5 | Warm film color grade with 125 entries |

## Profile Classes Tested

All output profiles are DeviceLink class. Tested with:

| Input | Grid Size | Status |
|-------|-----------|--------|
| Identity 2×2×2 | 8 entries | ✅ PASS |
| Warm film 5×5×5 | 125 entries | ✅ PASS |
| Corpus cubes (3 files) | Various | ✅ PASS |

## Related Tools

- [iccApplyToLink](../iccApplyToLink/) — Create .cube files from profile chains
- [iccDumpProfile](../iccDumpProfile/) — Inspect generated profiles
- CFL fuzzer: `icc_fromcube_fuzzer` — Fuzz the .cube parser (100% tool fidelity)

## Version

Built with IccProfLib version 2.3.1.5
