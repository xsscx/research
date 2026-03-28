# Call Graph Infrastructure — Documentation Index

## Documentation Files

### 1. CALLGRAPH_INFRASTRUCTURE_ANALYSIS.md (455 lines)
Comprehensive technical analysis — 3-layer architecture, implementation details, code references.

### 2. CALLGRAPH_INFRASTRUCTURE_SUMMARY.txt (259 lines)
Quick reference — metrics, data model, regex patterns, fidelity results.

## Key Facts

| Metric | Value |
|--------|-------|
| iccDEV tools analyzed | 11 |
| Average call sites per tool | 54 |
| Average AST gates per tool | 24 |
| Security-relevant gates per tool | 12 |
| Aggregate fuzzer fidelity | 90% (270/300) |

## Where to Find Information

| Topic | Location |
|-------|----------|
| Architecture overview | ANALYSIS.md §1-3 |
| Data structures | ANALYSIS.md Layer 2 + SUMMARY.txt "DATA MODEL" |
| Regex patterns | SUMMARY.txt "REGEX PATTERNS" |
| Security hardening | SUMMARY.txt "IMPLEMENTATION HIGHLIGHTS" |
| Fidelity metrics | SUMMARY.txt "FIDELITY METRICS" + ANALYSIS.md Layer 3 |
| Enhancement ideas | ANALYSIS.md final section |

## Related Source

| Component | Path |
|-----------|------|
| Python scripts (11) | `.github/scripts/callgraphs/` |
| C++ runtime library | `iccanalyzer-lite/IccAnalyzerCallGraph.{h,cpp}` |
| Generated reports | `analysis-reports/callgraph-*/` |
| Automated call graphs | `call-graph/` (37 targets, 103 DOT/SVG) |

## Quick Commands

```bash
# Render a call graph
dot -Tsvg analysis-reports/callgraph-iccDumpProfile/tool-callgraph.dot -o graph.svg

# Regenerate automated call graphs (all 37 targets)
python3 call-graph/scripts/generate-callgraphs.py
python3 call-graph/scripts/improve-callgraphs.py --filter-std
```

---
**Last Updated:** 2026-03-08 | **Scope:** 11 tools + 19 fuzzers | **Fidelity:** 90%
