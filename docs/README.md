# Documentation Index

Research documentation organized by topic. 65 documents across 12 subdirectories.

## iccDEV Library

| Directory | Contents | Files |
|-----------|----------|-------|
| [iccDEV/Tools/](iccDEV/Tools/) | 14 CLI tool references, baseline results, test data | 16+ |
| [iccDEV/shell-helpers/](iccDEV/shell-helpers/) | Build, test, ASAN/UBSAN commands (Unix + Windows) | 3 |
| [iccDEV/codeql/](iccDEV/codeql/) | 7 maintainer CodeQL queries, how-to-run, workflow guide | 4 |
| [iccDEV/afl/](iccDEV/afl/) | AFL++ tool-level fuzzing index (9 targets, 14 binaries) | 1 |

## Security Research

| Directory | Contents | Files |
|-----------|----------|-------|
| [cve/](cve/) | iccDEV CVE report — 87 CVEs + 95 GHSAs across 93 advisories | 1 |
| [pocs/](pocs/) | 64 PoC reproductions, 12 technique categories, upstream reporting standard ([iccDEV#700](https://github.com/InternationalColorConsortium/iccDEV/issues/700)) | 2 |
| [analysis/](analysis/) | iccanalyzer-lite code review, concrete findings, summary, `mluc` parity note, instrumented build policy, PAWG quality coverage, upstream-UB hardening policy, resource-bomb quarantine policy | 8 |

## Testing / Fuzzing

| Directory | Contents | Files |
|-----------|----------|-------|
| [Testing/](Testing/) | CFL corpus inventory, TIFF fuzzer analysis, JSON config test suite (215 tests) | 8+ |
| [tiffimg/](tiffimg/) | CTiffImg code paths, analysis index, executive summary, checklists | 7 |
| [xnuimagefuzzer/](xnuimagefuzzer/) | ICC profile injection analysis, function reference | 2 |

## ICC Format Reference

| Directory | Contents | Files |
|-----------|----------|-------|
| [icc-format/](icc-format/) | ICC binary format specification, security patterns, CWE catalog | 1 |

## Infrastructure

| Directory | Contents | Files |
|-----------|----------|-------|
| [callgraph/](callgraph/) | LLVM call graph infrastructure, examination index | 3 |
| [doxygen/](doxygen/) | Doxyfile for interactive SVG class graphs (all research components) | 1 |

## Quick Links

### Build & Test
- **Build helpers (Unix)**: [iccDEV/shell-helpers/unix.md](iccDEV/shell-helpers/unix.md)
- **Build helpers (Windows)**: [iccDEV/shell-helpers/windows.md](iccDEV/shell-helpers/windows.md)
- **JSON config test suite**: [Testing/README.md](Testing/README.md)

### Tool Reference
- **iccDEV tool reference**: [iccDEV/Tools/README.md](iccDEV/Tools/README.md)
- **ICC binary format reference**: [icc-format/ICC-Binary-Format-Reference.md](icc-format/ICC-Binary-Format-Reference.md)

### Security Analysis
- **CVE report**: [cve/iccDEV-CVE-Report.md](cve/iccDEV-CVE-Report.md)
- **64 PoC reproductions**: [pocs/iccdev-issue-reproductions.md](pocs/iccdev-issue-reproductions.md)
- **PoC techniques (12 categories)**: [pocs/iccdev-poc-techniques.md](pocs/iccdev-poc-techniques.md)
- **CodeQL maintainer queries**: [iccDEV/codeql/query-catalog.md](iccDEV/codeql/query-catalog.md)
- **iccanalyzer-lite findings**: [analysis/ICCANALYZER_LITE_CONCRETE_REVIEW.txt](analysis/ICCANALYZER_LITE_CONCRETE_REVIEW.txt)
- **`mluc` placeholder parity note**: [analysis/ICCANALYZER_MLUC_PLACEHOLDER_PARITY.md](analysis/ICCANALYZER_MLUC_PLACEHOLDER_PARITY.md)
- **Instrumented build / artifact policy**: [analysis/ICCANALYZER_INSTRUMENTED_BUILD_POLICY.md](analysis/ICCANALYZER_INSTRUMENTED_BUILD_POLICY.md)
- **Upstream UB hardening policy**: [analysis/ICCANALYZER_UPSTREAM_UB_HARDENING.md](analysis/ICCANALYZER_UPSTREAM_UB_HARDENING.md)
- **PAWG quality coverage**: [analysis/ICCANALYZER_PAWG_QUALITY_COVERAGE.md](analysis/ICCANALYZER_PAWG_QUALITY_COVERAGE.md)
- **Resource-bomb quarantine policy**: [analysis/ICCANALYZER_RESOURCE_BOMB_QUARANTINE.md](analysis/ICCANALYZER_RESOURCE_BOMB_QUARANTINE.md)

### Fuzzing
- **CFL corpus inventory**: [Testing/FUZZ_CFL_INVENTORY.md](Testing/FUZZ_CFL_INVENTORY.md)
- **TIFF fuzzer analysis**: [Testing/TIFF_FUZZER_COMPREHENSIVE_ANALYSIS.md](Testing/TIFF_FUZZER_COMPREHENSIVE_ANALYSIS.md)
- **TIFF code paths**: [tiffimg/START_HERE.md](tiffimg/START_HERE.md)
- **AFL++ fuzzing index**: [iccDEV/afl/index.md](iccDEV/afl/index.md)

### Infrastructure
- **Call graph overview**: [callgraph/CALLGRAPH_EXAMINATION_INDEX.md](callgraph/CALLGRAPH_EXAMINATION_INDEX.md)
- **Doxygen config**: [doxygen/Doxyfile](doxygen/Doxyfile) — `doxygen docs/doxygen/Doxyfile`

## Related

- [analysis-reports/](../analysis-reports/) — Per-profile iccanalyzer-lite reports
- [call-graph/](../call-graph/) — Generated DOT/SVG call graphs (103 targets)
- [.github/instructions/](../.github/instructions/) — Copilot agent instructions
- [.github/prompts/](../.github/prompts/) — Copilot reusable prompts (19 workflows)
