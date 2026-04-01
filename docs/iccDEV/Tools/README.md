# iccDEV Tool Reference

This directory is the stable entry point for the upstream `iccDEV` command-line
tools used throughout the repository.

## Start Here

- Shared build and runtime setup: `docs/iccDEV/shell-helpers/README.md`
- JSON config testing and saved results: `docs/Testing/README.md`
- Upstream build and static-analysis workflow: `docs/iccDEV/codeql/README.md`

## Tool Catalog

| Tool | Purpose | Page |
|------|---------|------|
| `iccDumpProfile` | Dump profile header, tags, and data | `iccDumpProfile/README.md` |
| `iccToXml` | Convert ICC to XML | `iccToXml/README.md` |
| `iccFromXml` | Convert XML to ICC | `iccFromXml/README.md` |
| `iccRoundTrip` | Measure transform round-trip behavior | `iccRoundTrip/README.md` |
| `iccFromCube` | Build profiles from `.cube` LUTs | `iccFromCube/README.md` |
| `iccApplyNamedCmm` | Apply profile chains to color data | `iccApplyNamedCmm/README.md` |
| `iccApplyProfiles` | Apply profiles to TIFF images | `iccApplyProfiles/README.md` |
| `iccApplySearch` | Search PCC behavior across profiles | `iccApplySearch/README.md` |
| `iccApplyToLink` | Build DeviceLink or `.cube` output | `iccApplyToLink/README.md` |
| `iccTiffDump` | Inspect TIFF metadata and ICC tags | `iccTiffDump/README.md` |
| `iccJpegDump` | Extract or inject JPEG ICC data | `iccJpegDump/README.md` |
| `iccPngDump` | Extract or inject PNG ICC data | `iccPngDump/README.md` |
| `iccV5DspObsToV4Dsp` | Convert v5 display and observer pairs | `iccV5DspObsToV4Dsp/README.md` |
| `iccSpecSepToTiff` | Merge spectral TIFF channels | `iccSpecSepToTiff/README.md` |

## Shared Notes

- Set `LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML` before
  running the upstream binaries from a local build.
- Keep volatile test counts, corpus sizes, and patch totals out of this file.
  Those belong in dated reports or component-specific READMEs.
- The per-tool pages are the right place for arguments, examples, and
  tool-specific caveats.

## JSON-Capable Tools

These tools accept `-cfg` JSON input and are covered by the testing assets under
`docs/Testing/`:

- `iccApplyNamedCmm`
- `iccApplyProfiles`
- `iccApplySearch`

## Test Data

Small sample files used by the examples in this directory live under
`docs/iccDEV/Tools/test-data/`.
