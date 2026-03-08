#!/usr/bin/env python3
"""
Call Graph & AST Generator for ICC Security Research
=====================================================

Generates LLVM-based call graphs and Clang AST dumps for all project components:
  - iccDEV tools (16 tools) + IccProfLib + IccXML libraries
  - CFL fuzzers (18 harnesses)
  - colorbleed_tools (2 tools)
  - iccanalyzer-lite (24 source files)

Uses:
  - clang-18 -emit-llvm → opt-18 -dot-callgraph  (LLVM call graphs)
  - clang-18 -ast-dump=json                        (Clang AST)
  - Graphviz dot → SVG/PNG                          (visualization)

Usage:
  python3 generate-callgraphs.py                    # generate all
  python3 generate-callgraphs.py --component iccdev # just iccDEV
  python3 generate-callgraphs.py --component cfl    # just CFL fuzzers
  python3 generate-callgraphs.py --component colorbleed
  python3 generate-callgraphs.py --component analyzer
  python3 generate-callgraphs.py --ast-only         # AST dumps only
  python3 generate-callgraphs.py --callgraph-only   # call graphs only
  python3 generate-callgraphs.py --summary          # print summary of outputs

Copyright (c) 2026 David H Hoyt LLC. All Rights Reserved.
"""

import argparse
import json
import os
import subprocess
import sys
import glob
import shutil
import re
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── Configuration ───

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
CALL_GRAPH_DIR = REPO_ROOT / "call-graph"
CLANG = "clang-18"
CLANGXX = "clang++-18"
OPT = "opt-18"
DOT = "dot"

ICCDEV_ROOT = REPO_ROOT / "iccDEV"
ICCPROFLIB = ICCDEV_ROOT / "IccProfLib"
ICCXML_LIB = ICCDEV_ROOT / "IccXML" / "IccLibXML"
ICCXML_TOOLS = ICCDEV_ROOT / "IccXML"
ICCDEV_TOOLS = ICCDEV_ROOT / "Build" / "Cmake"
CFL_DIR = REPO_ROOT / "cfl"
COLORBLEED_DIR = REPO_ROOT / "colorbleed_tools"
ANALYZER_DIR = REPO_ROOT / "iccanalyzer-lite"

COMMON_INCLUDES = [
    f"-I{ICCPROFLIB}",
    f"-I{ICCXML_LIB}",
    f"-I{ICCDEV_ROOT / 'IccXML' / 'IccLibXML'}",
    "-I/usr/include/libxml2",
    "-std=c++17",
    "-DUSEREFICCMAXPATHLEN",
]

# ─── Data Structures ───

@dataclass
class SourceTarget:
    """A compilation unit to analyze."""
    name: str
    sources: List[str]
    includes: List[str] = field(default_factory=list)
    component: str = ""
    extra_flags: List[str] = field(default_factory=list)

@dataclass
class CallGraphEdge:
    """An edge in the call graph."""
    caller: str
    callee: str
    file: str = ""
    line: int = 0

@dataclass
class ASTFunction:
    """A function extracted from the AST."""
    name: str
    file: str
    line: int
    return_type: str = ""
    params: List[str] = field(default_factory=list)
    is_virtual: bool = False
    class_name: str = ""

# ─── Tool Discovery ───

def find_iccdev_tools() -> List[SourceTarget]:
    """Discover all iccDEV command-line tools and their source files."""
    tools_base = ICCDEV_ROOT / "Tools" / "CmdLine"
    targets = []

    if not tools_base.exists():
        print(f"  [WARN] {tools_base} not found, skipping iccDEV tools")
        return targets

    for tool_dir in sorted(tools_base.iterdir()):
        if not tool_dir.is_dir():
            continue
        sources = sorted(str(s) for s in tool_dir.glob("*.cpp"))
        if not sources:
            continue

        extra_inc = [f"-I{tool_dir}"]
        # TiffImg.h lives in IccApplyProfiles — TIFF tools need that path
        tiff_tools = {"IccSpecSepToTiff", "IccTiffDump"}
        extra_flags = []
        if tool_dir.name in tiff_tools:
            extra_inc.append(f"-I{tools_base / 'IccApplyProfiles'}")

        targets.append(SourceTarget(
            name=tool_dir.name,
            sources=sources,
            includes=COMMON_INCLUDES + extra_inc,
            component="iccdev/tools",
            extra_flags=extra_flags,
        ))

    return targets


def find_iccdev_libraries() -> List[SourceTarget]:
    """Discover iccDEV library source files."""
    targets = []

    # IccProfLib
    proflib_sources = sorted(str(s) for s in ICCPROFLIB.glob("*.cpp"))
    if proflib_sources:
        targets.append(SourceTarget(
            name="IccProfLib",
            sources=proflib_sources,
            includes=COMMON_INCLUDES,
            component="iccdev/proflib",
        ))

    # IccLibXML
    xml_sources = sorted(str(s) for s in ICCXML_LIB.glob("*.cpp"))
    if xml_sources:
        targets.append(SourceTarget(
            name="IccLibXML",
            sources=xml_sources,
            includes=COMMON_INCLUDES,
            component="iccdev/xml",
        ))

    return targets


def find_cfl_fuzzers() -> List[SourceTarget]:
    """Discover CFL fuzzer harnesses."""
    targets = []
    fuzzer_dir = CFL_DIR

    # CFL fuzzers link against cfl/iccDEV, not the main iccDEV
    cfl_iccdev = CFL_DIR / "iccDEV"
    cfl_includes = [
        f"-I{cfl_iccdev / 'IccProfLib'}",
        f"-I{cfl_iccdev / 'IccXML' / 'IccLibXML'}",
        "-I/usr/include/libxml2",
        "-std=c++17",
        "-DUSEREFICCMAXPATHLEN",
    ]

    for src in sorted(fuzzer_dir.glob("icc_*_fuzzer.cpp")):
        name = src.stem
        extra_inc = []
        # TIFF fuzzers need TiffImg.h from tools
        if "tiff" in name or "specsep" in name or "applyprofiles" in name:
            tiff_tool = cfl_iccdev / "Tools" / "CmdLine" / "IccApplyProfiles"
            if tiff_tool.exists():
                extra_inc.append(f"-I{tiff_tool}")

        targets.append(SourceTarget(
            name=name,
            sources=[str(src)],
            includes=cfl_includes + extra_inc,
            component="cfl",
            extra_flags=["-fsyntax-only"],
        ))

    return targets


def find_colorbleed_tools() -> List[SourceTarget]:
    """Discover colorbleed_tools source files."""
    targets = []

    for src_name in ["IccToXml_unsafe.cpp", "IccFromXml_unsafe.cpp", "ColorBleedAlloc.cpp"]:
        src = COLORBLEED_DIR / src_name
        if src.exists():
            cb_includes = COMMON_INCLUDES + [
                f"-I{COLORBLEED_DIR}",
                f"-I{COLORBLEED_DIR / 'iccDEV' / 'IccProfLib'}",
            ]
            targets.append(SourceTarget(
                name=src.stem,
                sources=[str(src)],
                includes=cb_includes,
                component="colorbleed",
            ))

    return targets


def find_analyzer_sources() -> List[SourceTarget]:
    """Discover iccanalyzer-lite source files."""
    sources = sorted(str(s) for s in ANALYZER_DIR.glob("*.cpp"))
    if not sources:
        return []

    analyzer_includes = COMMON_INCLUDES + [
        f"-I{ANALYZER_DIR}",
        "-DICCANALYZER_LITE",
    ]

    # Group as single compilation unit for whole-program call graph
    return [SourceTarget(
        name="iccanalyzer-lite",
        sources=sources,
        includes=analyzer_includes,
        component="analyzer",
    )]


# ─── AST Generation ───

def generate_ast_dump(target: SourceTarget, output_dir: Path) -> Dict:
    """Generate clang AST dump (JSON) for a compilation target."""
    output_dir.mkdir(parents=True, exist_ok=True)
    results = {"target": target.name, "files": [], "functions": [], "classes": []}

    for src in target.sources:
        src_name = Path(src).stem
        ast_file = output_dir / f"{src_name}-ast.json"

        cmd = [
            CLANGXX, "-Xclang", "-ast-dump=json",
            "-fsyntax-only",
            *target.includes,
            *target.extra_flags,
            src
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and result.stdout.strip():
                # Parse the AST JSON to extract function/class info
                try:
                    ast = json.loads(result.stdout)
                    funcs, classes = extract_ast_info(ast, src)
                    results["functions"].extend(funcs)
                    results["classes"].extend(classes)

                    # Save compact summary (not full AST — too large)
                    summary = {
                        "source": src,
                        "functions": [asdict(f) for f in funcs],
                        "classes": classes,
                        "function_count": len(funcs),
                        "class_count": len(classes),
                    }
                    with open(ast_file, "w") as f:
                        json.dump(summary, f, indent=2)
                    results["files"].append(str(ast_file))
                except json.JSONDecodeError:
                    # AST output too large or malformed — save raw
                    with open(ast_file, "w") as f:
                        f.write(result.stdout[:500000])
                    results["files"].append(str(ast_file))
            else:
                # Log errors but continue
                err_file = output_dir / f"{src_name}-ast-errors.txt"
                with open(err_file, "w") as f:
                    f.write(f"Command: {' '.join(cmd)}\n")
                    f.write(f"Exit code: {result.returncode}\n")
                    f.write(f"Stderr:\n{result.stderr[:5000]}\n")
        except subprocess.TimeoutExpired:
            print(f"    [TIMEOUT] AST dump for {src_name}")
        except Exception as e:
            print(f"    [ERROR] AST dump for {src_name}: {e}")

    return results


def extract_ast_info(ast_node: dict, source_file: str) -> Tuple[List[ASTFunction], List[dict]]:
    """Extract function declarations and class definitions from AST JSON."""
    functions = []
    classes = []
    _extract_recursive(ast_node, source_file, functions, classes, "")
    return functions, classes


def _extract_recursive(node: dict, source_file: str, functions: list,
                       classes: list, current_class: str):
    """Recursively walk AST nodes to find functions and classes."""
    if not isinstance(node, dict):
        return

    kind = node.get("kind", "")
    loc = node.get("loc", {})
    file_in_loc = loc.get("file", loc.get("expansionLoc", {}).get("file", ""))

    # Only process nodes from our source file (not system headers)
    is_our_file = (not file_in_loc) or (Path(source_file).name in file_in_loc)

    if kind == "FunctionDecl" and is_our_file:
        name = node.get("name", "")
        if name and not name.startswith("__"):
            line = loc.get("line", node.get("range", {}).get("begin", {}).get("line", 0))
            rtype = node.get("type", {}).get("qualType", "")
            # Extract return type (before first '(')
            ret = rtype.split("(")[0].strip() if "(" in rtype else rtype
            functions.append(ASTFunction(
                name=name,
                file=source_file,
                line=line,
                return_type=ret,
                class_name=current_class,
            ))

    elif kind == "CXXMethodDecl" and is_our_file:
        name = node.get("name", "")
        if name and not name.startswith("~") and not name.startswith("operator"):
            line = loc.get("line", 0)
            rtype = node.get("type", {}).get("qualType", "")
            ret = rtype.split("(")[0].strip() if "(" in rtype else rtype
            is_virtual = node.get("virtual", False)
            functions.append(ASTFunction(
                name=name,
                file=source_file,
                line=line,
                return_type=ret,
                is_virtual=is_virtual,
                class_name=current_class,
            ))

    elif kind == "CXXRecordDecl" and is_our_file:
        name = node.get("name", "")
        if name:
            bases = []
            for inner in node.get("inner", []):
                if inner.get("kind") == "CXXBaseSpecifier":
                    base_type = inner.get("type", {}).get("qualType", "")
                    if base_type:
                        bases.append(base_type)
            classes.append({
                "name": name,
                "file": source_file,
                "line": loc.get("line", 0),
                "bases": bases,
                "tag_used": node.get("tagUsed", "class"),
            })
            current_class = name

    # Recurse into children
    for child in node.get("inner", []):
        _extract_recursive(child, source_file, functions, classes, current_class)


# ─── Call Graph Generation ───

def generate_llvm_callgraph(target: SourceTarget, output_dir: Path) -> Dict:
    """Generate LLVM IR call graph using clang + opt."""
    output_dir.mkdir(parents=True, exist_ok=True)
    results = {"target": target.name, "dot_files": [], "svg_files": [], "edges": []}
    ir_files = []

    for src in target.sources:
        src_name = Path(src).stem
        ir_file = output_dir / f"{src_name}.ll"

        # Step 1: Compile to LLVM IR
        cmd = [
            CLANGXX, "-S", "-emit-llvm",
            "-g",  # debug info for line numbers
            "-O0",  # no optimization (preserve call structure)
            *target.includes,
            "-o", str(ir_file),
            src
        ]

        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if result.returncode == 0 and ir_file.exists():
                ir_files.append(ir_file)
            else:
                # If full compile fails, try syntax-only AST approach
                err_file = output_dir / f"{src_name}-ir-errors.txt"
                with open(err_file, "w") as f:
                    f.write(f"Command: {' '.join(cmd)}\n")
                    f.write(f"Exit code: {result.returncode}\n")
                    f.write(f"Stderr:\n{result.stderr[:5000]}\n")
        except subprocess.TimeoutExpired:
            print(f"    [TIMEOUT] IR generation for {src_name}")
        except Exception as e:
            print(f"    [ERROR] IR generation for {src_name}: {e}")

    if not ir_files:
        # Fallback: use regex-based call graph extraction
        results["method"] = "regex-fallback"
        edges = extract_calls_regex(target.sources)
        results["edges"] = [asdict(e) for e in edges]
        dot_content = edges_to_dot(target.name, edges)
        dot_file = output_dir / f"{target.name}-callgraph.dot"
        with open(dot_file, "w") as f:
            f.write(dot_content)
        results["dot_files"].append(str(dot_file))
        render_dot(dot_file, output_dir / f"{target.name}-callgraph.svg")
        results["svg_files"].append(str(output_dir / f"{target.name}-callgraph.svg"))
        return results

    # Step 2: Generate call graph from IR using opt
    results["method"] = "llvm-ir"
    for ir_file in ir_files:
        src_name = ir_file.stem
        # opt -dot-callgraph writes .callgraph.dot in CWD
        try:
            result = subprocess.run(
                [OPT, "-passes=dot-callgraph", "-disable-output", str(ir_file)],
                capture_output=True, text=True, timeout=60,
                cwd=str(output_dir)
            )

            # opt-18 writes "{ir_filename}.callgraph.dot" in CWD
            expected_dot = output_dir / f"{src_name}.ll.callgraph.dot"
            if expected_dot.exists():
                final_dot = output_dir / f"{src_name}-callgraph.dot"
                shutil.move(str(expected_dot), str(final_dot))
                results["dot_files"].append(str(final_dot))

                edges = parse_dot_edges(final_dot)
                results["edges"].extend([asdict(e) for e in edges])

                svg_file = final_dot.with_suffix(".svg")
                render_dot(final_dot, svg_file)
                if svg_file.exists():
                    results["svg_files"].append(str(svg_file))

            # Fallback: check for any .callgraph.dot files
            for dot in output_dir.glob("*.callgraph.dot"):
                final_dot = output_dir / f"{src_name}-callgraph.dot"
                if not final_dot.exists():
                    shutil.move(str(dot), str(final_dot))
                    results["dot_files"].append(str(final_dot))
                    edges = parse_dot_edges(final_dot)
                    results["edges"].extend([asdict(e) for e in edges])
                    svg_file = final_dot.with_suffix(".svg")
                    render_dot(final_dot, svg_file)
                    if svg_file.exists():
                        results["svg_files"].append(str(svg_file))
                else:
                    dot.unlink()

        except subprocess.TimeoutExpired:
            print(f"    [TIMEOUT] opt callgraph for {src_name}")
        except Exception as e:
            print(f"    [ERROR] opt callgraph for {src_name}: {e}")

    # Clean up IR files (large)
    for ir_file in ir_files:
        ir_file.unlink(missing_ok=True)

    return results


def extract_calls_regex(sources: List[str]) -> List[CallGraphEdge]:
    """Fallback: extract function calls using regex analysis."""
    edges = []
    func_pattern = re.compile(
        r'^\s*(?:(?:static|inline|virtual|explicit|extern)\s+)*'
        r'(?:[\w:*&<>,\s]+?)\s+'
        r'((?:\w+::)*\w+)\s*\('
    )
    call_pattern = re.compile(r'(\w+(?:::\w+)*)\s*\(')

    for src in sources:
        try:
            with open(src, "r", errors="replace") as f:
                lines = f.readlines()
        except Exception:
            continue

        current_func = ""
        brace_depth = 0

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("//") or stripped.startswith("/*"):
                continue

            # Track function boundaries
            m = func_pattern.match(line)
            if m and "{" in line:
                current_func = m.group(1)
                brace_depth = line.count("{") - line.count("}")
                continue

            brace_depth += line.count("{") - line.count("}")
            if brace_depth <= 0:
                current_func = ""

            # Find calls
            if current_func:
                for cm in call_pattern.finditer(stripped):
                    callee = cm.group(1)
                    # Skip keywords and common macros
                    skip = {"if", "else", "for", "while", "switch", "case", "return",
                            "sizeof", "static_cast", "dynamic_cast", "reinterpret_cast",
                            "const_cast", "throw", "catch", "try", "delete", "new",
                            "printf", "fprintf", "snprintf", "sprintf", "memcpy",
                            "memset", "strlen", "strcmp", "strncmp", "malloc", "free",
                            "calloc", "realloc"}
                    if callee not in skip and not callee.startswith("__"):
                        edges.append(CallGraphEdge(
                            caller=current_func,
                            callee=callee,
                            file=src,
                            line=i,
                        ))

    return edges


def parse_dot_edges(dot_file: Path) -> List[CallGraphEdge]:
    """Parse edges from LLVM-generated DOT call graph file."""
    edges = []
    # LLVM DOT format: NodeHEXADDR -> NodeHEXADDR;
    # Node labels: NodeHEXADDR [shape=record,label="{_Z3foov}"];
    node_labels = {}
    label_pattern = re.compile(r'(Node0x[0-9a-f]+)\s*\[.*label="[{]?([^}"]+)[}]?"')
    edge_pattern = re.compile(r'(Node0x[0-9a-f]+)\s*->\s*(Node0x[0-9a-f]+)')

    try:
        with open(dot_file, "r") as f:
            content = f.read()

        # First pass: collect node labels
        for m in label_pattern.finditer(content):
            node_id = m.group(1)
            label = m.group(2).strip()
            node_labels[node_id] = demangle_name(label)

        # Second pass: collect edges
        for m in edge_pattern.finditer(content):
            caller_id = m.group(1)
            callee_id = m.group(2)
            caller = node_labels.get(caller_id, caller_id)
            callee = node_labels.get(callee_id, callee_id)
            edges.append(CallGraphEdge(caller=caller, callee=callee))
    except Exception:
        pass

    return edges


def demangle_name(name: str) -> str:
    """Demangle LLVM mangled names to human-readable form."""
    if not name.startswith("_Z"):
        return name
    try:
        result = subprocess.run(
            ["c++filt", name], capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except Exception:
        pass
    return name


def edges_to_dot(name: str, edges: List[CallGraphEdge]) -> str:
    """Convert edges list to DOT format."""
    lines = [
        f'digraph "{name}" {{',
        '  rankdir=LR;',
        '  node [shape=box, style="rounded,filled", fillcolor="#2d2d2d", '
        'fontcolor="white", fontname="Consolas"];',
        '  edge [color="#666666"];',
        '',
    ]

    # Collect unique nodes
    nodes = set()
    for e in edges:
        nodes.add(e.caller)
        nodes.add(e.callee)

    # Add nodes
    for n in sorted(nodes):
        safe_id = n.replace('"', '\\"')
        lines.append(f'  "{safe_id}";')

    lines.append('')

    # Add edges (deduplicated)
    seen = set()
    for e in edges:
        key = (e.caller, e.callee)
        if key not in seen:
            seen.add(key)
            c1 = e.caller.replace('"', '\\"')
            c2 = e.callee.replace('"', '\\"')
            lines.append(f'  "{c1}" -> "{c2}";')

    lines.append('}')
    return '\n'.join(lines)


def render_dot(dot_file: Path, output_file: Path, fmt: str = "svg"):
    """Render DOT file to SVG/PNG using Graphviz."""
    try:
        subprocess.run(
            [DOT, f"-T{fmt}", str(dot_file), "-o", str(output_file)],
            capture_output=True, timeout=120
        )
    except Exception as e:
        print(f"    [WARN] Graphviz render failed: {e}")


# ─── Combined Analysis ───

def generate_combined_summary(target: SourceTarget, ast_results: Dict,
                               cg_results: Dict, output_dir: Path):
    """Generate a combined JSON summary with AST + call graph data."""
    summary = {
        "component": target.component,
        "target": target.name,
        "sources": target.sources,
        "ast": {
            "function_count": len(ast_results.get("functions", [])),
            "class_count": len(ast_results.get("classes", [])),
            "functions": [asdict(f) if hasattr(f, '__dataclass_fields__') else f
                         for f in ast_results.get("functions", [])],
            "classes": ast_results.get("classes", []),
        },
        "callgraph": {
            "method": cg_results.get("method", "unknown"),
            "edge_count": len(cg_results.get("edges", [])),
            "dot_files": cg_results.get("dot_files", []),
            "svg_files": cg_results.get("svg_files", []),
        },
    }

    summary_file = output_dir / f"{target.name}-summary.json"
    with open(summary_file, "w") as f:
        json.dump(summary, f, indent=2, default=str)

    return summary_file


# ─── Main Orchestrator ───

def process_target(target: SourceTarget, ast_only: bool = False,
                   cg_only: bool = False) -> Dict:
    """Process a single target: generate AST and/or call graph."""
    output_dir = CALL_GRAPH_DIR / target.component
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"  [{target.component}] {target.name} ({len(target.sources)} files)")

    ast_results = {}
    cg_results = {}

    if not cg_only:
        ast_results = generate_ast_dump(target, output_dir)
        if ast_results.get("functions"):
            print(f"    AST: {len(ast_results['functions'])} functions, "
                  f"{len(ast_results.get('classes', []))} classes")

    if not ast_only:
        cg_results = generate_llvm_callgraph(target, output_dir)
        method = cg_results.get("method", "none")
        edge_count = len(cg_results.get("edges", []))
        print(f"    CallGraph: {edge_count} edges ({method})")

    # Combined summary
    summary_file = generate_combined_summary(target, ast_results, cg_results, output_dir)
    print(f"    Summary: {summary_file.name}")

    return {
        "target": target.name,
        "component": target.component,
        "ast_functions": len(ast_results.get("functions", [])),
        "cg_edges": len(cg_results.get("edges", [])),
        "cg_method": cg_results.get("method", "none"),
    }


def generate_master_index(all_results: List[Dict]):
    """Generate a master index JSON of all generated artifacts."""
    index = {
        "generated_by": "generate-callgraphs.py",
        "components": {},
        "totals": {
            "targets": len(all_results),
            "total_functions": sum(r["ast_functions"] for r in all_results),
            "total_edges": sum(r["cg_edges"] for r in all_results),
        },
    }

    for r in all_results:
        comp = r["component"]
        if comp not in index["components"]:
            index["components"][comp] = []
        index["components"][comp].append({
            "name": r["target"],
            "ast_functions": r["ast_functions"],
            "cg_edges": r["cg_edges"],
            "cg_method": r["cg_method"],
        })

    index_file = CALL_GRAPH_DIR / "index.json"
    with open(index_file, "w") as f:
        json.dump(index, f, indent=2)
    print(f"\n  Master index: {index_file}")
    return index


def print_summary():
    """Print summary of existing call-graph artifacts."""
    index_file = CALL_GRAPH_DIR / "index.json"
    if not index_file.exists():
        print("No index.json found. Run generation first.")
        return

    with open(index_file) as f:
        index = json.load(f)

    print("\n═══ Call Graph & AST Summary ═══\n")
    print(f"  Targets: {index['totals']['targets']}")
    print(f"  Total functions: {index['totals']['total_functions']}")
    print(f"  Total call edges: {index['totals']['total_edges']}")

    for comp, targets in index.get("components", {}).items():
        print(f"\n  [{comp}]")
        for t in targets:
            print(f"    {t['name']}: {t['ast_functions']} funcs, "
                  f"{t['cg_edges']} edges ({t['cg_method']})")

    # Count files
    for subdir in ["iccdev/tools", "iccdev/proflib", "iccdev/xml", "cfl",
                    "colorbleed", "analyzer"]:
        d = CALL_GRAPH_DIR / subdir
        if d.exists():
            dots = list(d.glob("*.dot"))
            svgs = list(d.glob("*.svg"))
            jsons = list(d.glob("*.json"))
            print(f"\n  {subdir}/: {len(dots)} DOT, {len(svgs)} SVG, {len(jsons)} JSON")


def main():
    parser = argparse.ArgumentParser(description="Generate LLVM call graphs and ASTs")
    parser.add_argument("--component", choices=["iccdev", "cfl", "colorbleed", "analyzer"],
                        help="Generate for specific component only")
    parser.add_argument("--ast-only", action="store_true", help="AST dumps only")
    parser.add_argument("--callgraph-only", action="store_true", help="Call graphs only")
    parser.add_argument("--summary", action="store_true", help="Print summary")
    parser.add_argument("--parallel", type=int, default=1,
                        help="Number of parallel compilations (default: 1)")
    args = parser.parse_args()

    if args.summary:
        print_summary()
        return

    print("═══ Call Graph & AST Generator ═══\n")

    # Discover targets
    targets = []
    if args.component is None or args.component == "iccdev":
        print("[iccDEV] Discovering tools and libraries...")
        targets.extend(find_iccdev_tools())
        targets.extend(find_iccdev_libraries())

    if args.component is None or args.component == "cfl":
        print("[CFL] Discovering fuzzers...")
        targets.extend(find_cfl_fuzzers())

    if args.component is None or args.component == "colorbleed":
        print("[colorbleed] Discovering tools...")
        targets.extend(find_colorbleed_tools())

    if args.component is None or args.component == "analyzer":
        print("[analyzer] Discovering sources...")
        targets.extend(find_analyzer_sources())

    if not targets:
        print("No targets found!")
        return

    print(f"\nFound {len(targets)} targets\n")

    # Process each target
    all_results = []
    for target in targets:
        result = process_target(target, ast_only=args.ast_only, cg_only=args.callgraph_only)
        all_results.append(result)

    # Generate master index
    index = generate_master_index(all_results)

    print(f"\n═══ Complete: {len(all_results)} targets processed ═══")
    print(f"  Functions: {index['totals']['total_functions']}")
    print(f"  Call edges: {index['totals']['total_edges']}")
    print(f"  Output: {CALL_GRAPH_DIR}/")


if __name__ == "__main__":
    main()
