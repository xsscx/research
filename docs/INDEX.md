# Documentation Start Here

Use this file when you know what you want to do and need the shortest path to
the right part of `docs/`.

## Common Tasks

### Build or Run Tools

- Upstream `iccDEV` build recipes: `iccDEV/shell-helpers/README.md`
- Per-tool usage pages: `iccDEV/Tools/README.md`
- Repo-level build entry points: `../README.md`
- Apple Silicon host setup (Linux container host flow): `LOCAL_MACOS_ARM64_ONBOARDING.md`

### Investigate a Bug or Security Issue

- Vulnerability taxonomy: `iccDEV/vulnerability-taxonomy.md`
- CVE inventory: `cve/iccDEV-CVE-Report.md`
- PoC notes and reproductions: `pocs/`
- Static-analysis workflow: `iccDEV/codeql/README.md`
- Runtime analyzer findings: `analysis/`
- Three-layer HTML overlay for conformance vs bug patterns:
  `iccDEV/specifications/html/icc-profile-conformance-and-vulnerability-overlay.html`
- Annotated byte-level specimen page for a minimal iccMAX profile:
  `iccDEV/specifications/html/iccmax-srgbencoding-annotated-dump.html`
- Static PNG poster for the same minimal iccMAX specimen:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump.png`
- High-resolution table-first PNG v2 for the same specimen:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v2.png`
- ICC-homepage-branded PNG v3 for the same specimen:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v3.png`
- GIF-style PNG v4 for the same specimen:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v4.png`
- TIFF-style PNG v5 for the same specimen:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v5.png`
- No-logo `ico_png`-style PNG v6 for the same specimen:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v6.png`
- No-logo `bmp5`-style PNG v7 for the same specimen:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v7.png`

### Run or Review Tests

- Testing index: `Testing/README.md`
- Saved parity and release checkpoint:
  `analysis/ICCANALYZER_PARITY_AND_MCP_RELEASE_STATUS_2026-03-29.md`
- ICC binary format notes: `icc-format/ICC-Binary-Format-Reference.md`
- ICC poster example: `icc-format/icc-sRgbEncoding-poster.html`
- ICC poster example v2: `icc-format/icc-sRgbEncoding-poster-v2.html`

### Understand Generated Research Artifacts

- Call graph notes: `callgraph/CALLGRAPH_EXAMINATION_INDEX.md`
- TIFF analysis package: `tiffimg/START_HERE.md`
- XNU image fuzzer notes: `xnuimagefuzzer/ICC_PROFILE_ANALYSIS.md`

### Study ICC Design And Parsing

- ICC specifications and technotes: `iccDEV/specifications/README.md`
- HTML overlay for issue #599 and the `gbd ` signed-overflow PoC:
  `iccDEV/specifications/html/icc-profile-conformance-and-vulnerability-overlay.html`
- Corkami-style HTML dump poster for `test-profiles/sRgbEncoding.icc`:
  `iccDEV/specifications/html/iccmax-srgbencoding-annotated-dump.html`
- Matching PNG poster for `test-profiles/sRgbEncoding.icc`:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump.png`
- Matching high-resolution PNG v2 for `test-profiles/sRgbEncoding.icc`:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v2.png`
- Matching ICC-homepage-branded PNG v3 for `test-profiles/sRgbEncoding.icc`:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v3.png`
- Matching GIF-style PNG v4 for `test-profiles/sRgbEncoding.icc`:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v4.png`
- Matching TIFF-style PNG v5 for `test-profiles/sRgbEncoding.icc`:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v5.png`
- Matching no-logo `ico_png`-style PNG v6 for `test-profiles/sRgbEncoding.icc`:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v6.png`
- Matching no-logo `bmp5`-style PNG v7 for `test-profiles/sRgbEncoding.icc`:
  `iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v7.png`

## Notes

- Prefer authored entry docs over raw logs and saved results.
- Treat `Testing/results/` and similar artifact folders as evidence, not
  onboarding material.
