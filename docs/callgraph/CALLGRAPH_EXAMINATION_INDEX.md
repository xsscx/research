# Call Graph Infrastructure - Documentation Index

## Documentation Files

### 1. CALLGRAPH_INFRASTRUCTURE_ANALYSIS.md (455 lines)
Comprehensive technical analysis - 3-layer architecture, implementation details, code references.

### 2. CALLGRAPH_INFRASTRUCTURE_SUMMARY.txt (259 lines)
Quick reference - metrics, data model, regex patterns, fidelity results.

## Key Facts

| Metric | Value |
|--------|-------|
| Knowledge graph nodes | 525 |
| Knowledge graph edges | 585 |
| Registry-derived heuristics | 181 |
| Generated call-graph components | 9 |
| Fuzzer target edges | 7 |
| Generated component fuzzer coverage | 6/9 |

The latest local rebuild reused the committed heuristic registry data because
`iccanalyzer-lite/iccanalyzer-lite` was not present. Call-graph components were
refreshed from generated `*-summary.json` files because `call-graph/index.json`
is generated and ignored.

## Where to Find Information

| Topic | Location |
|-------|----------|
| Architecture overview | ANALYSIS.md sections 1-3 |
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
| Automated call graphs | `call-graph/` |
| Knowledge graph | `call-graph/knowledge-graph.json` |
| Mermaid diagrams | `call-graph/mermaid/` |

## Quick Commands

```bash
# Render a call graph
dot -Tsvg analysis-reports/callgraph-iccDumpProfile/tool-callgraph.dot -o graph.svg

# Regenerate automated call graphs
python3 call-graph/scripts/generate-callgraphs.py
python3 call-graph/scripts/improve-callgraphs.py

# Rebuild the report layer
python3 call-graph/scripts/generate-callgraphs.py --summary
python3 call-graph/scripts/build-knowledge-graph.py
python3 call-graph/scripts/query-graph.py stats
python3 call-graph/scripts/generate-mermaid.py all
```

---
**Last Updated:** 2026-07-05 | **Scope:** generated local artifacts + knowledge graph
