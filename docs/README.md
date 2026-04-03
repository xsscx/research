# Documentation Map

This directory mixes authored references, research notes, fixtures, and saved
evidence. Start with `INDEX.md` for task-based navigation. Use this file when
you want a quick map of the major subtrees.

## Reference Material

| Path | Purpose |
|------|---------|
| `iccDEV/Tools/` | Upstream CLI tool pages and examples |
| `iccDEV/shell-helpers/` | Build, sanitizer, and platform workflows |
| `iccDEV/codeql/` | Query catalog and maintainer workflow |
| `iccDEV/specifications/` | ICC specifications and technotes |
| `iccDEV/specifications/html/` | Standalone HTML overlays tying spec clauses to concrete profile examples and parser risks |
| `icc-format/` | ICC binary format notes and CWE mapping |

Current HTML overlays include the three-layer conformance/vulnerability page for
`sRGB_v4_ICC_preference.icc` and the annotated `xxd` poster for the compact
iccMAX specimen `test-profiles/sRgbEncoding.icc`.

The same iccMAX specimen also has a generated PNG poster at
`iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump.png`.

There is also a higher-resolution table-first variant at
`iccDEV/specifications/png/iccmax-srgbencoding-annotated-dump-v2.png`.

## Research and Evidence

| Path | Purpose |
|------|---------|
| `analysis/` | Analyzer findings, policy notes, and patch coverage |
| `Testing/` | Test scripts, fixtures, and saved reports |
| `cve/` | Consolidated CVE and GHSA material |
| `pocs/` | Reproduction notes and exploit techniques |
| `callgraph/` | Call graph generation notes |
| `tiffimg/` | TIFF-specific analysis package |
| `xnuimagefuzzer/` | ICC notes for the sibling XNU image fuzzer work |

## Maintenance Rules

- Keep broad onboarding in the repo-root `README.md`.
- Keep this directory focused on reference material and saved research.
- Put volatile counts and one-off test outcomes in dated reports, not hub docs.
