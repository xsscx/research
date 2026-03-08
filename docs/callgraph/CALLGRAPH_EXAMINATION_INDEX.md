# Call Graph Infrastructure Examination - Documentation Index

## 📚 Documentation Files

### 1. **CALLGRAPH_INFRASTRUCTURE_ANALYSIS.md** (455 lines, 14 KB)
Comprehensive technical analysis with code references and implementation details.

**Contents:**
- Overview of 3-layer architecture
- **Layer 1: Python Static Analysis** (11 scripts, data model, metrics)
- **Layer 2: C++ Runtime Library** (API, implementation per function, regexes)
- **Layer 3: Generated Reports** (files, README structure, metrics)
- Key characteristics and design patterns
- Limitations and observations
- Improvement opportunities

**Best for:** Deep technical understanding, implementation reference

---

### 2. **CALLGRAPH_INFRASTRUCTURE_SUMMARY.txt** (259 lines, 13 KB)
Quick reference guide with structured overview and key metrics.

**Contents:**
- Three-layer architecture visualization
- Metrics tracked (all 11 tools)
- Data model details (all classes/structs)
- Output formats explanation
- Regex patterns used in parsing
- Implementation highlights
- Fidelity metrics with tool×fuzzer matrix
- Limitations and design notes

**Best for:** Quick lookup, reference during development

---

## 🎯 Quick Facts

### Architecture Layers
1. **Python** - Static analysis scripts (11 tools)
2. **C++** - Runtime ASAN/UBSAN log parsing library
3. **Reports** - Generated analysis output (DOT, JSON, SVG)

### Key Numbers
- **11** iccDEV tools analyzed
- **54** average call sites per tool
- **24** average AST gates per tool
- **12** security-relevant gates per tool
- **90%** aggregate fuzzer fidelity (270/300 matched)

### Data Model Components
- **CallSite**: callee, line, caller, gate, cli_only
- **ASTGate**: condition, gate_type, true_calls[], false_calls[], security_relevant
- **FunctionDef**: name, lines, params, return_type, calls[], gates[]
- **VulnMetadata**: error_type, access_type, access_size, overflow_bytes

### Output Formats
- **DOT** (Graphviz) - Visualizable graph
- **JSON** - Detailed metadata & fidelity
- **SVG/PNG** - Rendered visualization
- **Tree** - ASCII art call chain

---

## 🔍 Where to Find Information

### To understand the overall approach:
→ See **ANALYSIS.md** sections 1-3 (Overview + Layers 1-3)

### To understand data structures:
→ See **ANALYSIS.md** Layer 2 section + **SUMMARY.txt** "🔐 DATA MODEL DETAILS"

### To find specific regex patterns:
→ See **SUMMARY.txt** "🔍 REGEX PATTERNS" section

### To understand security hardening:
→ See **SUMMARY.txt** "⚙️ IMPLEMENTATION HIGHLIGHTS"

### To see fidelity metrics:
→ See **SUMMARY.txt** "📈 FIDELITY METRICS" + **ANALYSIS.md** Layer 3

### To understand code flow:
→ See **ANALYSIS.md** Layer 2 function-by-function breakdown

### To identify limitations:
→ See **ANALYSIS.md** end section + **SUMMARY.txt** "⚠️ LIMITATIONS"

---

## 📂 Related Source Files

### Python Scripts
```
.github/scripts/callgraphs/
├─ iccDumpProfile-callgraph.py (main reference)
├─ iccApplyProfiles-callgraph.py
├─ iccFromXml-callgraph.py
└─ ... (8 more)
```

### C++ Implementation
```
iccanalyzer-lite/
├─ IccAnalyzerCallGraph.h (121 lines)
└─ IccAnalyzerCallGraph.cpp (698 lines)
```

### Generated Reports
```
analysis-reports/
├─ callgraph-iccDumpProfile/
│  ├─ README.md (detailed fidelity analysis)
│  ├─ tool-callgraph.dot (graphviz)
│  ├─ tool-callgraph.json (metadata)
│  ├─ tool-callgraph.svg (rendered)
│  └─ fuzzer-callgraph.json (fuzzer-specific)
├─ callgraph-iccApplyProfiles/
└─ ... (9 more tools)
```

---

## 🚀 Key Insights from Analysis

### Strengths
✓ **Hand-verified accuracy** - Not regex parsing, actual source verification
✓ **Comprehensive tracking** - All 11 tools with consistent methodology  
✓ **Gate-aware** - Every call tracked with controlling condition
✓ **Multi-format** - DOT (viz), JSON (data), SVG/PNG (rendering)
✓ **Security-focused** - NULL guards, validation paths, exploitability classification
✓ **High fidelity** - 90% aggregate (some tools 100%)

### Limitations
✗ Manual updates required when source changes
✗ No incremental re-analysis capability
✗ Indirect calls not fully utilized
✗ No cross-tool dependency graph
✗ No automated fuzzer alignment validation

### Design Patterns
- **Explicit over implicit** - Every call/gate documented with gates
- **Dual-path tracking** - Both true & false branches of conditionals
- **Security relevance** - Gates marked for vulnerability analysis
- **Fidelity metrics** - Quantified fuzzer coverage per tool

---

## 💡 For Enhancement Opportunities

See **ANALYSIS.md** final section for improvement ideas:
1. Automated extraction from source
2. Incremental update mechanism
3. API consistency checking
4. Cross-tool dependency analysis
5. Fuzzer alignment validation
6. Indirect call resolution

---

## 🔄 Common Usage Patterns

### Render a call graph
```bash
cd analysis-reports/callgraph-iccDumpProfile/
dot -Tpng tool-callgraph.dot -o tool-callgraph.png
dot -Tsvg tool-callgraph.dot -o tool-callgraph.svg
```

### Regenerate from source
```bash
python3 .github/scripts/callgraphs/iccDumpProfile-callgraph.py \
  --dot graph.dot --format json
```

### Parse ASAN crash logs
```bash
iccAnalyzer-lite -cg crash.log output.png
# Generates: output.png, output.png.dot, output.png.json
```

---

## 📖 Reading Recommendations

1. **First time?** → Read SUMMARY.txt top-to-bottom
2. **Need implementation details?** → Read ANALYSIS.md Layer 2
3. **Looking for specific info?** → Use "Where to Find Information" section above
4. **Want to enhance?** → Read ANALYSIS.md limitations section
5. **Need to update?** → Reference the Python script structure in ANALYSIS.md

---

**Last Updated:** 2026-03-08  
**Analysis Scope:** 11 iccDEV CLI tools + 19 CFL fuzzers  
**Fidelity Status:** 90.0% aggregate (270/300 calls matched)
