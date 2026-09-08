# iccApplyNamedCmm V5 PCC seed inventory

Date: 2026-09-08

## Failure reproduced

The original `applynamedcmm-hybrid-pcc --fresh --mode rare` staging pass had no
`SEED_FILE_TYPE_REGEX`. It offered every sub-1 MiB file from five broad roots to
an ICC-only `-PCC @@` argument. The reported pass rejected 1,145 mixed-format
files and left an empty input directory.

The same resolved command returned exit 0 with the generated D50 PCC profile
when replayed directly. This isolated the defect to seed selection and the lack
of a guaranteed bootstrap seed, not to the 17-argument command shape.

## Corrected V5 inventory

Command:

```bash
./afl/start.sh applynamedcmm-hybrid-pcc --fresh --mode rare --seed-only --seed-order sorted
```

The corrected pass requires `file(1)` to report an ICC V5 profile, always adds
the generated D50 PCC profile through `SEED_FILES`, and discovers the five
package ICC directories under `ICS-POC/` when that separate checkout exists.

| Source | Eligible V5 ICC files | Staging policy |
|---|---:|---|
| `iccDEV/Testing` | 207 | all |
| generated hybrid support | 7 | all, plus one guaranteed D50 seed |
| `fuzz/graphics/icc` | 239 | all |
| `test-profiles` | 773 | first 300 in sorted seed order |
| `extended-test-profiles` | 78 | all |
| ICS Colorimetric Encoding | 37 | all |
| ICS Hybrid MultiSpectral Encoding | 6 | all |
| ICS Hybrid Printer Overprint | 6 | all |
| ICS Hybrid Printer Reflectance | 5 | all |
| ICS Spectral Encoding | 7 | all |

Result: 893 seeds staged, zero dry-run rejections, and seed-only mode completed
successfully. Directory counts are measurements from this checkout, not target
contracts; the runtime continues to discover the current inventory.

The ICS package inventory contains 61 V5 ICC files. None was byte-identical to
the 207 upstream `iccDEV/Testing` V5 profiles by SHA-256, so the optional source
adds distinct binary fixtures rather than exact copies.

## ICS media inventory

Outside its embedded `iccDEV/` dependency checkout, `ICS-POC/` also contains 70
TIFF files and one PNG plot. Of those 71 media files, 52 contain an embedded ICC
profile according to ExifTool. The largest TIFF is about 30 MiB, well above the
current AFL hybrid TIFF testcase ceiling. These media files are therefore not
fed to the NamedCMM PCC lane. They remain candidates for separately bounded
TIFF/embedded-profile campaigns after size, codec, and semantic screening.

## Validation evidence

The shared tool-test setup initially reported 26 soft failures because the
tracked research-corpus path named `sRGB_D65_MAT.icc` contained JSON in this
dirty checkout. The common fixture resolver now checks the ICC `acsp` signature
and falls back to the generated upstream Testing profile. The same sanitizer
envelope then passed all 27 NamedCMM cases.

```text
ApplyNamedCmm AFL target validation passed: 4 target contracts.
AFL target configuration validation passed: 60 targets.
applynamedcmm intents 0, 1, 2, and 3 with known RGB profiles: exit 0.
iccApplyNamedCmm quick ASAN envelope: 27 passed, 0 failed, 0 crashes.
applynamedcmm-hybrid-pcc V5 seed-only pass: 893 seeds, 0 rejected.
```
