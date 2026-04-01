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

### Run or Review Tests

- Testing index: `Testing/README.md`
- Saved parity and release checkpoint:
  `analysis/ICCANALYZER_PARITY_AND_MCP_RELEASE_STATUS_2026-03-29.md`
- ICC binary format notes: `icc-format/ICC-Binary-Format-Reference.md`

### Understand Generated Research Artifacts

- Call graph notes: `callgraph/CALLGRAPH_EXAMINATION_INDEX.md`
- TIFF analysis package: `tiffimg/START_HERE.md`
- XNU image fuzzer notes: `xnuimagefuzzer/ICC_PROFILE_ANALYSIS.md`

## Notes

- Prefer authored entry docs over raw logs and saved results.
- Treat `Testing/results/` and similar artifact folders as evidence, not
  onboarding material.
