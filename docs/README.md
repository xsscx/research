# Documentation Map

This directory mixes authored references, research notes, fixtures, and saved
evidence. Start with `INDEX.md` for task-based navigation. Use this file for a
compact map of the major subtrees.

## Reference Material

| Path | Purpose |
|------|---------|
| `iccDEV/Tools/` | Upstream CLI tool pages and examples |
| `iccDEV/shell-helpers/` | Build, sanitizer, and platform workflows |
| `iccDEV/specifications/` | ICC specifications, technotes, overlays, and posters |
| `icc-format/` | ICC binary format notes and CWE mapping |
| `afl/` | AFL++ tool-level fuzzing reference |
| `Testing/CFL_MANUAL_FUZZER_COMMANDS.md` | Per-fuzzer CFL maintainer command one-liners |
| `Testing/FUZZ_CFL_INVENTORY.md` | Fuzzing asset map and tracking policy |

## Research And Evidence

| Path | Purpose |
|------|---------|
| `Testing/` | Test scripts, fixtures, and saved reports |
| `cve/` | Consolidated CVE and GHSA material |
| `pocs/` | Reproduction notes and exploit techniques |
| `callgraph/` | Call graph generation notes |
| `tiffimg/` | TIFF-specific analysis package |
| `xnuimagefuzzer/` | ICC notes for sibling image-fuzzer work |

## Maintenance Rules

- Keep broad onboarding in the repo-root `README.md`.
- Keep task routing in `INDEX.md`.
- Keep volatile counts and one-off test outcomes in dated reports.
- Promote only durable fuzzing evidence into docs; leave raw run output in
  ignored runtime directories.
