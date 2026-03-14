# Call Graph & AST Analysis

LLVM-based call graphs and Clang AST dumps for all ICC security research components.

## Contents

| Directory | Targets | Functions | Call Edges | Method |
|-----------|---------|-----------|------------|--------|
| `iccdev/tools/` | 13 iccDEV CLI tools | ~130K | ~14K | LLVM IR |
| `iccdev/proflib/` | IccProfLib (36 files) | ~300K | ~30K | LLVM IR |
| `iccdev/xml/` | IccLibXML (7 files) | ~20K | ~4K | LLVM IR |
| `cfl/` | 12 CFL fuzzers | ~113K | ~2.3K | LLVM IR |
| `colorbleed/` | 3 colorbleed tools | ~14K | ~735 | LLVM IR |
| `analyzer/` | iccanalyzer-lite (24 files) | ~190K | ~21.5K | LLVM IR |

**Total: 37 targets, 729K+ AST functions, 57K+ call graph edges**

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

# AST or call graph only
python3 call-graph/scripts/generate-callgraphs.py --ast-only
python3 call-graph/scripts/generate-callgraphs.py --callgraph-only

# Print summary of existing outputs
python3 call-graph/scripts/generate-callgraphs.py --summary
```

## Method

1. **AST**: `clang++-18 -Xclang -ast-dump=json -fsyntax-only` extracts function declarations,
   class hierarchies, and method signatures from each source file.
2. **Call Graph**: `clang++-18 -S -emit-llvm` compiles to LLVM IR, then
   `opt-18 -passes=dot-callgraph` extracts caller→callee edges as DOT.
3. **Rendering**: Graphviz `dot -Tsvg` produces SVG visualizations.
4. **Demangling**: `c++filt` converts LLVM mangled names to human-readable C++.

If LLVM IR compilation fails (missing deps), a regex-based fallback extracts
call sites from source directly.

## Requirements

- `clang-18` / `clang++-18` — LLVM IR and AST generation
- `opt-18` — LLVM call graph pass
- `dot` (Graphviz) — SVG rendering
- `c++filt` — name demangling

## Relationship to Hand-Verified Call Graphs

The existing Python scripts in `.github/scripts/callgraphs/` provide
**hand-verified** call graphs with AST gate analysis and fuzzer fidelity mapping.
Those are manually maintained and provide security-focused annotations
(gate conditions, exploitability, CLI-only vs fuzzer paths).

This directory provides **automated LLVM-based** call graphs that are
machine-generated and cover the full codebase. The two approaches are complementary:

| Aspect | Hand-Verified (`.github/scripts/`) | Automated (`call-graph/`) |
|--------|-------------------------------------|---------------------------|
| Scope | 11 iccDEV tools | All 37 targets |
| Method | Manual source reading | LLVM IR analysis |
| Accuracy | Verified per-call-site | Complete but includes templates |
| Annotations | Gates, fidelity, security | Raw caller→callee edges |
| Maintenance | Manual updates required | Re-run script to refresh |
