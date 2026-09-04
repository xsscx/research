# iccDEV Issue 2385 Local TIFF Audit

Date: 2026-09-04

Upstream issue:
<https://github.com/InternationalColorConsortium/iccDEV/issues/2385>

Follow-up comment:
<https://github.com/InternationalColorConsortium/iccDEV/issues/2385#issuecomment-5540273455>

## Scope

The local upstream checkout was inspected at commit
`913a9dc4a923322914dd3a677287743d497e4f51`. The tracked image inventory was:

| Format | Files |
| --- | ---: |
| TIFF | 10 |
| GIF | 25 |
| JPEG | 4 |
| PNG | 4 |

The audit used `git ls-files` so that the hidden TIFF regression fixture under
`.github/ci/test-data` was included. Untracked `iccProfileVisualize` outputs
were assessed separately and were not counted as tracked fixtures.

## Finding 1: issue 2385 is present in the upstream fixture set

`Testing/hybrid/Data/smCows380_5_780.tif` stores:

- `Photometric=MinIsBlack`
- `SamplesPerPixel=81`
- 81 16-bit samples
- an embedded ICC profile
- no `ExtraSamples` tag

Raw metadata reproduction from the iccDEV checkout root:

```bash
tiffdump Testing/hybrid/Data/smCows380_5_780.tif 2>&1 | grep -E 'Photometric|SamplesPerPixel|ExtraSamples|ICC Profile'
```

Libtiff-backed reproduction:

```bash
Build/Tools/IccTiffDump/iccTiffDump Testing/hybrid/Data/smCows380_5_780.tif 2>&1 | grep 'Sum of Photometric'
```

Both `tiffinfo` and `iccTiffDump` reported:

```text
TIFFReadDirectory: Warning, Sum of Photometric type-related color channels and ExtraSamples doesn't match SamplesPerPixel. Defining non-color channels as ExtraSamples.
```

`iccTiffDump` exited 0. This is a TIFF container-conformance and
interoperability defect, not a demonstrated security crash.

Suggested resolution: include this tracked upstream path in the issue 2385
fixture set, regenerate it using the agreed spectral TIFF container contract,
and cover it with raw-tag and no-libtiff-warning assertions.

## Finding 2: the checked-in 16-bit fixture is 8-bit

`docs/Testing/test-data/rgb-4x4-16bit.tif` reports:

```text
BitsPerSample:     8 (unsigned integer)
SamplesPerPixel:   3
BytesPerLine:      12
```

Reproduction:

```bash
Build/Tools/IccTiffDump/iccTiffDump docs/Testing/test-data/rgb-4x4-16bit.tif 2>&1 | grep -E 'BitsPerSample|SamplesPerPixel|BytesPerLine'
```

`.github/scripts/json-cli-exercise.sh` uses this file in both JSON and CLI
tests described as 16-bit-source coverage, but those cases assert command
success rather than the input bit depth. Its fallback Pillow generator also
converts each `I;16` channel to `L` before merging RGB, which produces 8-bit
RGB.

Suggested resolution: replace the fixture with true 16-bit RGB, make the
fallback generator preserve 16-bit RGB samples, and assert
`BitsPerSample=16` before running either source-depth test. Treat this as an
independent fixture and coverage correction.

## Finding 3: MiniTIFF writes SHORT-only fields as LONG

Eight untracked TIFFs generated locally by the current
`iccProfileVisualize` binary stored:

```text
Predictor (317) LONG (4) 1<1>
```

Libtiff reported:

```text
TIFFReadDirectory: Warning, Unknown field with tag 317 (0x13d) encountered.
```

Fresh-output reproduction from the iccDEV checkout root:

```bash
r=$PWD; d=$(mktemp -d); (cd "$d" && "$r/Build/Tools/IccProfileVisualize/iccProfileVisualize" "$r/Testing/sRGB_v4_ICC_preference.icc" >/dev/null 2>&1 && for f in *.tif; do printf '%s: ' "$f"; tiffdump "$f" 2>&1 | grep 'Predictor'; done)
```

Both writer copies encode Predictor and several other TIFF fields with
`TIFF_LONG`:

- `Tools/CmdLine/IccProfileVisualize/MiniTIFF.cpp:274-331`
- `Tools/CmdLine/IccProfilePlot/MiniTIFF.cpp:320-384`

The affected SHORT fields include Compression, PhotometricInterpretation,
SamplesPerPixel, PlanarConfiguration, ResolutionUnit, Predictor, and
SampleFormat. The current profile-visualization regression verifies only TIFF
magic, so it does not detect the invalid IFD types or the libtiff warning.

Suggested resolution: use TIFF 6.0 field types and counts in both MiniTIFF
copies. Add raw IFD type assertions and a no-libtiff-warning read test for the
generated TIFFs. Treat this as an independent writer correction.

TIFF 6.0 reference:
<https://www.itu.int/itudoc/itu-t/com16/tiff-fx/docs/tiff6.pdf>

## Other local images

The other nine tracked TIFFs did not produce the issue 2385 metadata warning.
The tracked PNG, JPEG, and GIF files passed ImageMagick identification. The
intentional issue 1932 regression TIFF returned a soft embedded-profile parse
failure, but its RGB plus five-extra-sample TIFF metadata was internally
consistent.

## Upstream work split

Keep the changes independently reviewable:

1. Issue 2385 spectral and direct-N-channel `ExtraSamples` contract, fixture,
   and regression coverage.
2. True 16-bit RGB fixture, fallback generator, and source-depth assertions.
3. MiniTIFF IFD field types and generated-output validation.
