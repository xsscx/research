# iccV5DspObsToV4Dsp

Converts an ICC v5 (iccMAX) display profile paired with a v5 observer profile into a
legacy ICC v4 display profile. This enables v5 spectral profiles to be used by
applications that only support v4.

## Usage

```
iccV5DspObsToV4Dsp inputV5.icc inputObserverV5.icc outputV4.icc
```

### Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `inputV5.icc` | **Required** | Input v5 display profile |
| `inputObserverV5.icc` | **Required** | Input v5 observer profile (ColorSpace class) |
| `outputV4.icc` | **Required** | Output v4 display profile |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 254 (-2) | "bad transform matrix" — incompatible display/observer pairing |

## Profile Requirements

### Display Profile (inputV5.icc)
- Must be ICC v5 (iccMAX) Display class (`mntr`)
- Must contain spectral data (e.g., `Rec2020rgbSpectral.icc`)
- The profile at `iccDEV/Testing/Display/LCDDisplay.icc` is the canonical test profile

### Observer Profile (inputObserverV5.icc)
- Must be ICC v5 ColorSpace class (`spac`)
- Located in `iccDEV/Testing/ICS/` (Input Color Space)
- Available observers:

| Observer File | PCS | Description |
|---------------|-----|-------------|
| `XYZ_float-D65_2deg-Part1.icc` | XYZ Float | CIE 1931 2° observer, D65 |
| `Lab_float-D65_2deg-Part1.icc` | Lab Float | CIE 1931 2° observer, D65, Lab |
| `Spec400_10_700-D50_2deg-Part1.icc` | Spectral | 400–700nm, 10nm steps, D50 |

## Examples

### Basic v5 → v4 conversion

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# v5 Display + XYZ observer → v4 Display
iccV5DspObsToV4Dsp \
  iccDEV/Testing/Display/LCDDisplay.icc \
  iccDEV/Testing/ICS/XYZ_float-D65_2deg-Part1.icc \
  /tmp/v4_display.icc
```

### Different observer profiles

```bash
# Lab-based observer
iccV5DspObsToV4Dsp \
  iccDEV/Testing/Display/LCDDisplay.icc \
  iccDEV/Testing/ICS/Lab_float-D65_2deg-Part1.icc \
  /tmp/v4_lab_obs.icc

# Spectral observer
iccV5DspObsToV4Dsp \
  iccDEV/Testing/Display/LCDDisplay.icc \
  iccDEV/Testing/ICS/Spec400_10_700-D50_2deg-Part1.icc \
  /tmp/v4_spec_obs.icc
```

### Verify output

```bash
# Check the output is a valid v4 profile
iccDumpProfile /tmp/v4_display.icc
```

## Known Issues

- Currently returns exit 254 ("bad transform matrix") with all tested observer pairings
  from `iccDEV/Testing/ICS/`. The profiles in this directory may require specific
  Part2/Part3 counterparts or updated observer data.
- The v5DspObs conversion requires precise spectral range alignment between the display
  and observer profiles

## Security Notes

The CFL fuzzer `icc_v5dspobs_fuzzer` uses a concatenated input format:
`[4B BE size][display.icc][observer.icc]`. Use `.github/scripts/unbundle-fuzzer-input.sh`
to extract profiles from crash files:

```bash
.github/scripts/unbundle-fuzzer-input.sh v5dspobs crash-file
```

## Related Tools

- [iccDumpProfile](../iccDumpProfile/) — Inspect v5 and v4 profiles
- [iccRoundTrip](../iccRoundTrip/) — Test v4 output accuracy
- CFL fuzzer: `icc_v5dspobs_fuzzer` — Fuzz the v5→v4 conversion

## Version

Built with IccProfLib version 2.3.1.5
