# Call Graph & AST Analysis

LLVM-based call graphs and Clang AST dumps for all ICC security research components.

## Contents

| Directory | Scope | Method |
|-----------|-------|--------|
| `iccdev/tools/` | iccDEV and IccJSON CLI tools | LLVM IR |
| `iccdev/proflib/` | IccProfLib library | LLVM IR |
| `iccdev/xml/` | IccLibXML library | LLVM IR |
| `iccdev/json/` | IccLibJSON library | LLVM IR |
| `iccdev/connect/` | IccLibConnect library | LLVM IR |
| `cfl/` | CFL fuzzers | LLVM IR |
| `colorbleed/` | colorbleed tools | LLVM IR |
| `analyzer/` | iccanalyzer-lite | LLVM IR |

Use `python3 call-graph/scripts/generate-callgraphs.py --summary` or
`call-graph/index.json` for current target, function, and edge counts.
When `index.json` is absent, `--summary` scans generated `*-summary.json`
files so partial local runs are still reportable.

## Generated Artifacts

For each compilation unit:

| File | Description |
|------|-------------|
| `*-callgraph.dot` | Graphviz DOT call graph (LLVM IR edges) |
| `*-callgraph.svg` | SVG rendering of call graph |
| `*-ast.json` | Clang AST summary: functions, classes, inheritance |
| `*-summary.json` | Combined AST + call graph metadata |
| `index.json` | Master index of all targets and metrics |

## Generation

```bash
# Generate everything
python3 call-graph/scripts/generate-callgraphs.py

# Single component
python3 call-graph/scripts/generate-callgraphs.py --component iccdev
python3 call-graph/scripts/generate-callgraphs.py --component cfl
python3 call-graph/scripts/generate-callgraphs.py --component colorbleed
python3 call-graph/scripts/generate-callgraphs.py --component analyzer

# Single target, preserving existing index entries
python3 call-graph/scripts/generate-callgraphs.py --component cfl --target icc_fromjson_fuzzer
python3 call-graph/scripts/generate-callgraphs.py --component iccdev --target IccLibConnect

# AST or call graph only
python3 call-graph/scripts/generate-callgraphs.py --ast-only
python3 call-graph/scripts/generate-callgraphs.py --callgraph-only

# Print summary of existing outputs
python3 call-graph/scripts/generate-callgraphs.py --summary

# Rebuild the unified security graph and derived Mermaid diagrams
python3 call-graph/scripts/build-knowledge-graph.py
python3 call-graph/scripts/query-graph.py stats
python3 call-graph/scripts/generate-mermaid.py all
```

## Current Local Report

The latest local rebuild did not have `iccanalyzer-lite/iccanalyzer-lite`
available, so `build-knowledge-graph.py` reused the existing committed
registry-derived heuristic nodes and refreshed the call-graph component layer
from generated `*-summary.json` files.

Observed command results:

| Command | Result |
|---------|--------|
| `python3 call-graph/scripts/generate-callgraphs.py` | 46 targets processed |
| `python3 call-graph/scripts/improve-callgraphs.py` | 146 SVGs regenerated, 0 failed |
| `python3 call-graph/scripts/generate-callgraphs.py --summary` | 46 targets, 1159816 AST functions, 105087 call edges |
| `python3 call-graph/scripts/build-knowledge-graph.py` | 562 nodes, 602 edges |
| `python3 call-graph/scripts/query-graph.py stats` | 181 heuristics, 98 CVEs, 106 GHSAs, 57 CWEs, 61 patches, 46 components, 13 fuzzers |
| `python3 call-graph/scripts/query-graph.py attack` | 10/46 generated components have fuzzer target edges |

During raw generation, Graphviz timed out on two large IccLibJSON SVGs at the
generator's 120-second per-render limit. The required post-processing pass
rerendered the complete SVG set successfully.

## Method

1. **AST**: `clang++-18 -Xclang -ast-dump=json -fsyntax-only` extracts function declarations,
   class hierarchies, and method signatures from each source file.
2. **Call Graph**: `clang++-18 -S -emit-llvm` compiles to LLVM IR, then
   `opt-18 -passes=dot-callgraph` extracts caller->callee edges as DOT.
3. **Rendering**: Graphviz `dot -Tsvg` produces SVG visualizations.
4. **Demangling**: `c++filt` converts LLVM mangled names to human-readable C++.

If LLVM IR compilation fails (missing deps), a regex-based fallback extracts
call sites from source directly.

## Requirements

- `clang-18` / `clang++-18` - LLVM IR and AST generation
- `opt-18` - LLVM call graph pass
- `dot` (Graphviz) - SVG rendering
- `c++filt` - name demangling

## Relationship to Hand-Verified Call Graphs

The existing Python scripts in `.github/scripts/callgraphs/` provide
**hand-verified** call graphs with AST gate analysis and fuzzer fidelity mapping.
Those are manually maintained and provide security-focused annotations
(gate conditions, exploitability, CLI-only vs fuzzer paths).

This directory provides **automated LLVM-based** call graphs that are
machine-generated and cover the full codebase. The two approaches are complementary:

| Aspect | Hand-Verified (`.github/scripts/`) | Automated (`call-graph/`) |
|--------|-------------------------------------|---------------------------|
| Scope | 11 iccDEV tools | Current generated targets |
| Method | Manual source reading | LLVM IR analysis |
| Accuracy | Verified per-call-site | Complete but includes templates |
| Annotations | Gates, fidelity, security | Raw caller->callee edges |
| Maintenance | Manual updates required | Re-run script to refresh |
