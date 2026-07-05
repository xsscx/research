# call-graph/ - Path-Specific Instructions

## What This Is

LLVM-based call graphs and Clang AST dumps for all ICC security research components.
The generator produces DOT/SVG call graphs, AST summaries, and a master index for
the current checkout. Used for fuzzer coverage analysis, attack surface mapping,
and code navigation.

Use `python3 call-graph/scripts/generate-callgraphs.py --summary` or
`call-graph/index.json` for current target, function, and edge counts.
If `index.json` is not present, `--summary` now scans generated
`*-summary.json` files and prints the partial local artifact set.

## Directory Structure

```
call-graph/
|-- README.md                        # Overview and usage
|-- index.json                       # Master index (targets, function counts, edge counts)
|-- scripts/
|   |-- generate-callgraphs.py       # Generator (clang->LLVM IR->DOT->SVG)
|   `-- improve-callgraphs.py        # Post-processor (demangle, simplify, filter, restyle)
|-- iccdev/
|   |-- tools/                       # DOT+SVG+AST+summary for iccDEV CLI tools
|   |-- proflib/                     # DOT+SVG+AST+summary for IccProfLib
|   |-- xml/                         # DOT+SVG+AST+summary for IccLibXML
|   |-- json/                        # DOT+SVG+AST+summary for IccLibJSON
|   `-- connect/                     # DOT+SVG+AST+summary for IccLibConnect
|-- cfl/                             # DOT+SVG+AST+summary for CFL fuzzers
|-- colorbleed/                      # DOT+SVG+AST+summary for colorbleed_tools
`-- analyzer/                        # DOT+SVG+AST+summary for iccanalyzer-lite
```

## Generated Artifacts Per Target

| File | Description |
|------|-------------|
| `*-callgraph.dot` | Graphviz DOT call graph (LLVM IR edges, demangled) |
| `*-callgraph.svg` | SVG rendering - properly sized for browser pan/zoom |
| `*-ast.json` | Clang AST summary: functions, classes, inheritance |
| `*-summary.json` | Combined AST + call graph metadata |
| `index.json` | Master index of all targets and metrics |

## Generation Pipeline

### Step 1: Generate raw call graphs and ASTs

```bash
python3 call-graph/scripts/generate-callgraphs.py           # all 37 targets
python3 call-graph/scripts/generate-callgraphs.py --component iccdev
python3 call-graph/scripts/generate-callgraphs.py --component cfl
python3 call-graph/scripts/generate-callgraphs.py --component colorbleed
python3 call-graph/scripts/generate-callgraphs.py --component analyzer
python3 call-graph/scripts/generate-callgraphs.py --component cfl --target icc_fromjson_fuzzer
python3 call-graph/scripts/generate-callgraphs.py --component iccdev --target IccLibConnect
python3 call-graph/scripts/generate-callgraphs.py --ast-only
python3 call-graph/scripts/generate-callgraphs.py --callgraph-only
python3 call-graph/scripts/generate-callgraphs.py --summary  # print existing stats
```

### Step 2: Improve SVG quality (demangle, filter, restyle)

```bash
python3 call-graph/scripts/improve-callgraphs.py              # process all
python3 call-graph/scripts/improve-callgraphs.py --dry-run     # preview only
python3 call-graph/scripts/improve-callgraphs.py --component cfl
```

**IMPORTANT**: Always run `improve-callgraphs.py` after `generate-callgraphs.py`.
Noise filtering is default; use `--keep-noise` only when you need raw libc,
LLVM, or STL nodes. Raw LLVM output contains mangled C++ names and std:: template
noise that makes SVGs unreadable.

### Method

1. **AST**: `clang++-18 -Xclang -ast-dump=json -fsyntax-only` - function declarations,
   class hierarchies, method signatures
2. **Call Graph**: `clang++-18 -S -emit-llvm` -> `opt-18 -passes=dot-callgraph` - caller->callee
   edges as DOT format
3. **Demangling**: `c++filt` batch demangling (93%+ success) with regex fallback for
   symbols c++filt cannot handle
4. **Simplification**: Strip `std::allocator` noise, truncate deep template args,
   extract `Class::Method()` from verbose signatures
5. **Filtering**: Remove 100+ noise patterns: STL internals, libc, libpng/libjpeg/libtiff/
   libxml2/OpenSSL nodes. Default-on (use `--keep-noise` to disable)
6. **Rendering**: Graphviz `dot -Tsvg` with attributes: `rankdir=LR`,
   auto-sized canvas, Courier font, rounded box nodes, blue edges

If LLVM IR compilation fails (missing deps), a regex-based fallback extracts call sites
from source directly.

## Requirements

- `clang-18` / `clang++-18` - LLVM IR and AST generation
- `opt-18` - LLVM call graph pass
- `dot` (Graphviz 2.43+) - SVG rendering
- `c++filt` - C++ name demangling
- Python 3.10+

## SVG Quality Standards

SVGs must be readable when opened in a browser with pan/zoom:

- **Dimensions**: Auto-sized canvas (no forced `size` attribute - let graphviz compute)
- **Layout**: `rankdir=LR` (left-to-right) for wide graphs, `TB` for deep call trees
- **Labels**: Demangled C++ names, simplified to `Class::Method()` format
- **Nodes**: Rounded boxes with light fill (`#f0f4ff`), Courier 9pt font
- **Edges**: Blue arrows (`#4a6fa5`), `arrowsize=0.7`
- **Filtering**: 100+ noise patterns removed by default (STL, libc, libpng, libjpeg,
  libtiff, libxml2, OpenSSL, compiler intrinsics). Use `--keep-noise` to disable.
- **No mangled names**: `_ZN8CIccCmm4ReadEP8CIccIO` -> `CIccCmm::Read()`

## Relationship to Hand-Verified Call Graphs

| Aspect | Hand-Verified (`.github/scripts/callgraphs/`) | Automated (`call-graph/`) |
|--------|---------------------------------------------|---------------------------|
| Scope | 11 iccDEV tools | All 37 targets |
| Method | Manual source reading | LLVM IR analysis |
| Accuracy | Verified per-call-site | Complete but includes templates |
| Annotations | Gates, fidelity, security | Raw caller->callee edges |
| Maintenance | Manual updates required | Re-run scripts to refresh |

Both approaches are complementary. The hand-verified graphs provide security-focused
annotations (gate conditions, exploitability). The automated graphs provide complete
coverage across all compilation units.

## When to Regenerate

Regenerate call graphs after:
- iccDEV upstream sync (`cd cfl/iccDEV && git pull`)
- New CFL fuzzer added
- New iccanalyzer-lite heuristic module added
- Significant refactoring of any component

## Component Coverage

Current coverage is generated into `call-graph/index.json`. Do not hand-maintain
target, function, or edge counts in this instruction file.

## Error Files

If LLVM IR compilation fails for a target (e.g., missing headers), an `*-error.json`
file is created with the compiler error output. These are NOT committed - fix the
compilation issue and re-run. Common causes:
- Missing `libxml2-dev` or `libtiff-dev` headers
- iccDEV not built yet (`cd iccDEV/Build && cmake Cmake && make -j32`)
- Wrong include paths (check `COMMON_INCLUDES` in `generate-callgraphs.py`)

## Adding a New Component

1. Add a `SourceTarget` entry in `generate-callgraphs.py` with sources and includes
2. Create the output subdirectory under `call-graph/`
3. Run `generate-callgraphs.py --component <name>`
4. Run `improve-callgraphs.py --component <name>`
5. Run `build-knowledge-graph.py`, `query-graph.py stats`, and
   `generate-mermaid.py all` to refresh the report layer
6. Commit DOT + SVG + AST + summary files

## Common Pitfalls

- **Mangled names in SVGs** - Always run `improve-callgraphs.py` after generation.
  Raw `opt-18` output uses LLVM IR mangled names that are unreadable.
- **Stale graphs** - After upstream sync, regenerate to pick up new/changed functions.
  Old call graphs may show deleted functions or miss new call edges.
- **Missing index.json** - `index.json` is generated and ignored. Summary/report
  commands fall back to generated `*-summary.json` files, but a full generation
  run is still required before treating totals as authoritative.
- **Missing analyzer binary** - `build-knowledge-graph.py` reuses the existing
  committed registry-derived heuristic layer when `iccanalyzer-lite/iccanalyzer-lite`
  is unavailable, then refreshes patches, advisories, components, and fuzzer
  mappings from local sources.
- **Large SVGs** - IccCmmConfig has 1800+ nodes. These are correct but complex.
  Noise filtering is default; use `--keep-noise` only when debugging raw output.
- **c++filt failures** - ~7% of mangled symbols use LLVM-internal conventions that
  c++filt cannot demangle. The regex fallback extracts class::method but loses
  parameter types.
