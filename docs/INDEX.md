# Documentation Start Here

Use this file as the fast path into `docs/`. For a fuller directory guide, see [README.md](README.md).

## Start With

- Tool usage and CLI examples: [iccDEV/Tools/README.md](iccDEV/Tools/README.md)
- Build, sanitizer, coverage, and shell workflows: [iccDEV/shell-helpers/README.md](iccDEV/shell-helpers/README.md)
- CodeQL query inventory and maintainer workflow: [iccDEV/codeql/README.md](iccDEV/codeql/README.md)
- Analyzer runtime findings and policy notes: [analysis/](analysis/)
- JSON config and TIFF-focused test work: [Testing/README.md](Testing/README.md)
- ICC binary format and CWE cross-reference: [icc-format/ICC-Binary-Format-Reference.md](icc-format/ICC-Binary-Format-Reference.md)
- CI governance hardening (bash + PowerShell): [ci-governance-hardening.md](ci-governance-hardening.md)

## By Task

### Build or Run Something

- Upstream `iccDEV` build recipes: [iccDEV/shell-helpers/unix.md](iccDEV/shell-helpers/unix.md)
- Tool-specific invocation examples: [iccDEV/Tools/](iccDEV/Tools/)
- Repo-level build entry points: project `README.md` in the repository root

### Investigate a Bug or Security Finding

- CVE inventory: [cve/iccDEV-CVE-Report.md](cve/iccDEV-CVE-Report.md)
- Reproduction notes and PoC techniques: [pocs/](pocs/)
- Static-analysis workflow: [iccDEV/codeql/maintainer-workflow.md](iccDEV/codeql/maintainer-workflow.md)
- Runtime analyzer notes: [analysis/ICCANALYZER_LITE_ANALYSIS.md](analysis/ICCANALYZER_LITE_ANALYSIS.md)

### Understand Generated Research Artifacts

- LLVM call graph notes: [callgraph/CALLGRAPH_EXAMINATION_INDEX.md](callgraph/CALLGRAPH_EXAMINATION_INDEX.md)
- Doxygen config for graph generation: [doxygen/Doxyfile](doxygen/Doxyfile)
- XNU image fuzzer ICC analysis: [xnuimagefuzzer/ICC_PROFILE_ANALYSIS.md](xnuimagefuzzer/ICC_PROFILE_ANALYSIS.md)

## Notes

- `docs/Testing/results/` and similar log-heavy folders are evidence artifacts, not the best onboarding starting point.
- `docs/xnuimagefuzzer/` contains XNU image-fuzzer-specific analysis; it is not the primary index for this repository.
