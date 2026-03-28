# Documentation Guide

This directory mixes authored references, research writeups, test fixtures, and generated evidence. If you are new to the repository, start with [INDEX.md](INDEX.md) for task-based navigation, then use the sections below to drill into the relevant subtree.

## Core References

| Path | What it covers |
|------|----------------|
| [iccDEV/Tools/](iccDEV/Tools/) | Reference docs and examples for the upstream CLI tools |
| [iccDEV/shell-helpers/](iccDEV/shell-helpers/) | Linux, macOS, WSL, and Windows build and debug commands |
| [iccDEV/codeql/](iccDEV/codeql/) | CodeQL query catalog, how-to-run steps, and maintainer workflow |
| [iccDEV/specifications/](iccDEV/specifications/) | ICC specifications, technotes, and supporting reference material |
| [icc-format/](icc-format/) | ICC binary format notes, security patterns, and CWE mapping |

## Security Reference

| Path | What it covers |
|------|----------------|
| [iccDEV/vulnerability-taxonomy.md](iccDEV/vulnerability-taxonomy.md) | CWE/CVE/CVSS vulnerability classification, attack surface map, SCAP identifiers, exploit primitives, detection coverage matrix |

## Research and Testing

| Path | What it covers |
|------|----------------|
| [analysis/](analysis/) | iccanalyzer-lite findings, policy notes, and patch coverage analysis |
| [Testing/](Testing/) | JSON-config tests, TIFF investigations, fixtures, and result logs |
| [cve/](cve/) | Consolidated iccDEV CVE and GHSA reporting |
| [pocs/](pocs/) | Reproduction notes and exploit-technique writeups |
| [callgraph/](callgraph/) | Call-graph generation notes and examination index |
| [xnuimagefuzzer/](xnuimagefuzzer/) | ICC-specific analysis for the XNU image-fuzzer sibling project |

## Maintenance Notes

- Prefer linking readers to authored entry docs such as `README.md`, `INDEX.md`, or per-tool references instead of raw log files.
- Treat `Testing/results/`, `Testing/json-configs/`, and similar subtrees as supporting artifacts for tests, not primary overview documents.
- Keep broad repository onboarding in the root `README.md` and contributor guidance in `AGENTS.md`; keep `docs/` focused on reference and research material.
