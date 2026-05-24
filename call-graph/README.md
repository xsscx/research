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
```

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
