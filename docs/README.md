# Documentation Index

Research documentation organized by topic.

## iccDEV

| Directory | Contents | Files |
|-----------|----------|-------|
| [iccDEV/Tools/](iccDEV/Tools/) | 14 CLI tool references, baseline results, test data | 16+ |
| [iccDEV/shell-helpers/](iccDEV/shell-helpers/) | Build, test, ASAN/UBSAN commands (Unix + Windows) | 3 |
| [cve/](cve/) | iccDEV CVE report | 1 |
| [pocs/](pocs/) | Issue reproductions (63 PoCs) and techniques | 2 |

## Testing / Fuzzing

| Directory | Contents | Files |
|-----------|----------|-------|
| [Testing/](Testing/) | CFL corpus inventory, TIFF fuzzer analysis, JSON config test suite | 4+ |
| [tiffimg/](tiffimg/) | CTiffImg code paths, analysis index, checklists | 7 |
| [xnuimagefuzzer/](xnuimagefuzzer/) | ICC profile injection analysis, function reference | 2 |

## ICC Format Reference

| Directory | Contents | Files |
|-----------|----------|-------|
| [icc-format/](icc-format/) | ICC binary format specification, security patterns, CWE catalog | 1 |

## Analysis

| Directory | Contents | Files |
|-----------|----------|-------|
| [analysis/](analysis/) | iccanalyzer-lite code review and findings | 3 |
| [callgraph/](callgraph/) | LLVM call graph infrastructure, examination index | 3 |

## Quick Links

- **ICC binary format reference**: [icc-format/ICC-Binary-Format-Reference.md](icc-format/ICC-Binary-Format-Reference.md)
- **iccDEV tool reference**: [iccDEV/Tools/README.md](iccDEV/Tools/README.md)
- **Build helpers (Unix)**: [iccDEV/shell-helpers/unix.md](iccDEV/shell-helpers/unix.md)
- **Build helpers (Windows)**: [iccDEV/shell-helpers/windows.md](iccDEV/shell-helpers/windows.md)
- **JSON config test suite**: [Testing/README.md](Testing/README.md)
- **CFL corpus inventory**: [Testing/FUZZ_CFL_INVENTORY.md](Testing/FUZZ_CFL_INVENTORY.md)
- **TIFF fuzzer analysis**: [Testing/TIFF_FUZZER_COMPREHENSIVE_ANALYSIS.md](Testing/TIFF_FUZZER_COMPREHENSIVE_ANALYSIS.md)
- **Start with TIFF code paths**: [tiffimg/START_HERE.md](tiffimg/START_HERE.md)
- **Call graph overview**: [callgraph/CALLGRAPH_EXAMINATION_INDEX.md](callgraph/CALLGRAPH_EXAMINATION_INDEX.md)
- **iccanalyzer-lite findings**: [analysis/ICCANALYZER_LITE_CONCRETE_REVIEW.txt](analysis/ICCANALYZER_LITE_CONCRETE_REVIEW.txt)

## Related

- [analysis-reports/](../analysis-reports/) — Per-profile iccanalyzer-lite reports
- [call-graph/](../call-graph/) — Generated DOT/SVG call graphs
- [.github/instructions/](../.github/instructions/) — Copilot agent instructions
- [.github/prompts/](../.github/prompts/) — Copilot reusable prompts
