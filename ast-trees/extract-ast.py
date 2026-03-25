#!/usr/bin/env python3
"""
extract-ast.py — Extract structured AST from Clang JSON dump
=============================================================

Filters the raw Clang AST JSON to only nodes originating from the target
source file, then extracts:
  1. Function definitions (name, params, return type, line range)
  2. Call expressions (callee, line, caller context)
  3. AST gates (if/else/switch/ternary controlling reachability)
  4. Variable declarations with security-relevant types

Outputs:
  - <name>-ast.json          Structured analysis JSON
  - <name>-callgraph.dot     Graphviz DOT call graph with gate annotations
  - <name>-ast-summary.txt   Human-readable summary

Usage:
    python3 extract-ast.py <raw-ast.json> <source-filename> [--output-prefix PREFIX]
"""

import json
import sys
import os
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Optional


@dataclass
class Param:
    name: str
    type: str


@dataclass
class CallExpr:
    callee: str
    line: int
    col: int
    parent_func: str
    is_member: bool = False
    is_operator: bool = False


@dataclass
class ASTGate:
    condition_text: str
    line: int
    gate_type: str  # if, else-if, switch, ternary, for, while
    parent_func: str
    depth: int = 0
    calls_in_true: list = field(default_factory=list)
    calls_in_false: list = field(default_factory=list)


@dataclass
class VarDecl:
    name: str
    type: str
    line: int
    parent_func: str
    is_pointer: bool = False
    is_array: bool = False


@dataclass
class FunctionDef:
    name: str
    return_type: str
    params: list
    line_start: int
    line_end: int
    calls: list = field(default_factory=list)
    gates: list = field(default_factory=list)
    vars: list = field(default_factory=list)
    is_main: bool = False


def get_loc_file(node):
    """Extract source filename from a node's location info."""
    if "loc" in node:
        loc = node["loc"]
        if "file" in loc:
            return loc["file"]
        if "expansionLoc" in loc and "file" in loc["expansionLoc"]:
            return loc["expansionLoc"]["file"]
        if "spellingLoc" in loc and "file" in loc["spellingLoc"]:
            return loc["spellingLoc"]["file"]
    if "range" in node:
        rng = node["range"]
        for key in ("begin", "end"):
            if key in rng:
                r = rng[key]
                if "file" in r:
                    return r["file"]
                if "expansionLoc" in r and "file" in r["expansionLoc"]:
                    return r["expansionLoc"]["file"]
    return None


def get_line(node):
    """Extract line number from node."""
    if "loc" in node and "line" in node["loc"]:
        return node["loc"]["line"]
    if "range" in node and "begin" in node["range"]:
        b = node["range"]["begin"]
        if "line" in b:
            return b["line"]
        if "expansionLoc" in b and "line" in b["expansionLoc"]:
            return b["expansionLoc"]["line"]
    return 0


def get_end_line(node):
    """Extract end line number."""
    if "range" in node and "end" in node["range"]:
        e = node["range"]["end"]
        if "line" in e:
            return e["line"]
        if "expansionLoc" in e and "line" in e["expansionLoc"]:
            return e["expansionLoc"]["line"]
    return get_line(node)


def get_col(node):
    if "loc" in node and "col" in node["loc"]:
        return node["loc"]["col"]
    return 0


def extract_condition_text(node):
    """Try to reconstruct condition text from AST nodes."""
    kind = node.get("kind", "")

    if kind == "BinaryOperator":
        op = node.get("opcode", "?")
        children = node.get("inner", [])
        if len(children) >= 2:
            lhs = extract_condition_text(children[0])
            rhs = extract_condition_text(children[1])
            return f"{lhs} {op} {rhs}"

    if kind == "UnaryOperator":
        op = node.get("opcode", "?")
        children = node.get("inner", [])
        if children:
            operand = extract_condition_text(children[0])
            return f"{op}{operand}"

    if kind == "DeclRefExpr":
        ref = node.get("referencedDecl", {})
        return ref.get("name", "?")

    if kind == "MemberExpr":
        return node.get("name", "?member")

    if kind == "ImplicitCastExpr":
        children = node.get("inner", [])
        if children:
            return extract_condition_text(children[0])

    if kind == "IntegerLiteral":
        return str(node.get("value", "?"))

    if kind == "StringLiteral":
        return node.get("value", '""')

    if kind == "CallExpr":
        children = node.get("inner", [])
        if children:
            callee = extract_condition_text(children[0])
            return f"{callee}(...)"

    if kind == "CXXMemberCallExpr":
        children = node.get("inner", [])
        if children:
            callee = extract_condition_text(children[0])
            return f"{callee}(...)"

    if kind == "ParenExpr":
        children = node.get("inner", [])
        if children:
            inner = extract_condition_text(children[0])
            return f"({inner})"

    if kind == "CStyleCastExpr" or kind == "CXXStaticCastExpr":
        children = node.get("inner", [])
        if children:
            return extract_condition_text(children[-1])

    return f"<{kind}>"


def collect_calls_in_subtree(node, target_file, current_file_stack):
    """Collect all call expressions in a subtree."""
    calls = []
    kind = node.get("kind", "")
    
    nf = get_loc_file(node)
    if nf:
        current_file_stack = nf

    if kind in ("CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr"):
        children = node.get("inner", [])
        callee_name = "?"
        if children:
            c0 = children[0]
            if c0.get("kind") == "DeclRefExpr":
                ref = c0.get("referencedDecl", {})
                callee_name = ref.get("name", "?")
            elif c0.get("kind") == "MemberExpr":
                callee_name = c0.get("name", "?member")
            elif c0.get("kind") == "ImplicitCastExpr":
                inner = c0.get("inner", [])
                if inner and inner[0].get("kind") == "DeclRefExpr":
                    ref = inner[0].get("referencedDecl", {})
                    callee_name = ref.get("name", "?")
        calls.append(callee_name)

    for child in node.get("inner", []):
        calls.extend(collect_calls_in_subtree(child, target_file, current_file_stack))

    return calls


def walk_function_body(node, func_name, target_basename, results, depth=0, current_file=None):
    """Walk a function body extracting calls, gates, and vars."""
    kind = node.get("kind", "")

    nf = get_loc_file(node)
    if nf:
        current_file = nf

    # Call expressions
    if kind in ("CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr"):
        children = node.get("inner", [])
        callee_name = "?"
        is_member = kind == "CXXMemberCallExpr"
        is_operator = kind == "CXXOperatorCallExpr"
        if children:
            c0 = children[0]
            if c0.get("kind") == "DeclRefExpr":
                ref = c0.get("referencedDecl", {})
                callee_name = ref.get("name", "?")
            elif c0.get("kind") == "MemberExpr":
                callee_name = c0.get("name", "?member")
            elif c0.get("kind") == "ImplicitCastExpr":
                inner = c0.get("inner", [])
                if inner:
                    if inner[0].get("kind") == "DeclRefExpr":
                        ref = inner[0].get("referencedDecl", {})
                        callee_name = ref.get("name", "?")
                    elif inner[0].get("kind") == "MemberExpr":
                        callee_name = inner[0].get("name", "?member")

        ce = CallExpr(
            callee=callee_name,
            line=get_line(node),
            col=get_col(node),
            parent_func=func_name,
            is_member=is_member,
            is_operator=is_operator,
        )
        results["calls"].append(ce)

    # Gates: if, for, while, switch, ternary
    if kind == "IfStmt":
        children = node.get("inner", [])
        cond_text = "<complex>"
        if children:
            cond_text = extract_condition_text(children[0])

        true_calls = []
        false_calls = []
        if len(children) > 1:
            true_calls = collect_calls_in_subtree(children[1], target_basename, current_file)
        if len(children) > 2:
            false_calls = collect_calls_in_subtree(children[2], target_basename, current_file)

        gate = ASTGate(
            condition_text=cond_text,
            line=get_line(node),
            gate_type="if",
            parent_func=func_name,
            depth=depth,
            calls_in_true=true_calls,
            calls_in_false=false_calls,
        )
        results["gates"].append(gate)

    elif kind == "ForStmt":
        children = node.get("inner", [])
        cond_text = "<for-loop>"
        if len(children) > 1 and children[1]:
            cond_text = extract_condition_text(children[1])
        gate = ASTGate(
            condition_text=cond_text,
            line=get_line(node),
            gate_type="for",
            parent_func=func_name,
            depth=depth,
        )
        results["gates"].append(gate)

    elif kind == "WhileStmt":
        children = node.get("inner", [])
        cond_text = "<while-loop>"
        if children:
            cond_text = extract_condition_text(children[0])
        gate = ASTGate(
            condition_text=cond_text,
            line=get_line(node),
            gate_type="while",
            parent_func=func_name,
            depth=depth,
        )
        results["gates"].append(gate)

    elif kind == "SwitchStmt":
        children = node.get("inner", [])
        cond_text = "<switch>"
        if children:
            cond_text = extract_condition_text(children[0])
        gate = ASTGate(
            condition_text=cond_text,
            line=get_line(node),
            gate_type="switch",
            parent_func=func_name,
            depth=depth,
        )
        results["gates"].append(gate)

    elif kind == "ConditionalOperator":
        children = node.get("inner", [])
        cond_text = "<ternary>"
        if children:
            cond_text = extract_condition_text(children[0])
        gate = ASTGate(
            condition_text=cond_text,
            line=get_line(node),
            gate_type="ternary",
            parent_func=func_name,
            depth=depth,
        )
        results["gates"].append(gate)

    # Variable declarations
    if kind == "VarDecl":
        vtype = node.get("type", {}).get("qualType", "?")
        vname = node.get("name", "?")
        is_ptr = "*" in vtype or "unique_ptr" in vtype or "shared_ptr" in vtype
        is_arr = "[" in vtype or "vector" in vtype
        vd = VarDecl(
            name=vname,
            type=vtype,
            line=get_line(node),
            parent_func=func_name,
            is_pointer=is_ptr,
            is_array=is_arr,
        )
        results["vars"].append(vd)

    # Recurse
    for child in node.get("inner", []):
        walk_function_body(child, func_name, target_basename, results, depth + 1, current_file)


def generate_dot(functions, output_path):
    """Generate Graphviz DOT call graph with gate annotations."""
    lines = []
    lines.append("digraph iccDumpProfile {")
    lines.append('  rankdir=LR;')
    lines.append('  node [shape=box, style="rounded,filled", fillcolor="#f0f4ff",')
    lines.append('        fontname="Courier", fontsize=9];')
    lines.append('  edge [color="#4a6fa5", arrowsize=0.7];')
    lines.append("")

    # Collect all unique callee names for node definitions
    all_callees = set()
    func_names = set()
    for f in functions:
        func_names.add(f.name)
        for c in f.calls:
            all_callees.add(c.callee)

    # Define function nodes
    for f in functions:
        label = f"{f.return_type} {f.name}()"
        color = "#d4edda" if f.is_main else "#f0f4ff"
        lines.append(f'  "{f.name}" [label="{label}", fillcolor="{color}"];')

    # Define external callee nodes
    for callee in sorted(all_callees - func_names):
        if callee == "?" or callee.startswith("operator"):
            continue
        lines.append(f'  "{callee}" [label="{callee}", fillcolor="#fff3cd", style="rounded,filled,dashed"];')

    lines.append("")

    # Edges with gate annotations
    for f in functions:
        seen_edges = set()
        for c in f.calls:
            if c.callee == "?" or c.callee.startswith("operator"):
                continue
            edge_key = (f.name, c.callee)
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)

            # Find if this call is inside a gate
            gate_label = ""
            for g in f.gates:
                if c.callee in g.calls_in_true:
                    gate_label = f"  [gate: {g.condition_text[:40]}]"
                    break
                if c.callee in g.calls_in_false:
                    gate_label = f"  [else: {g.condition_text[:40]}]"
                    break

            label = f"L{c.line}{gate_label}"
            lines.append(f'  "{f.name}" -> "{c.callee}" [label="  {label}  ", fontsize=7];')

    lines.append("}")

    with open(output_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")


def generate_summary(functions, source_file, output_path):
    """Generate human-readable AST summary."""
    lines = []
    lines.append("=" * 76)
    lines.append(f"  AST Analysis: {os.path.basename(source_file)}")
    lines.append("=" * 76)
    lines.append("")

    total_calls = sum(len(f.calls) for f in functions)
    total_gates = sum(len(f.gates) for f in functions)
    total_vars = sum(len(f.vars) for f in functions)

    lines.append(f"  Functions:  {len(functions)}")
    lines.append(f"  Call sites: {total_calls}")
    lines.append(f"  AST gates:  {total_gates}")
    lines.append(f"  Variables:  {total_vars}")
    lines.append("")

    for f in functions:
        marker = " [ENTRY]" if f.is_main else ""
        lines.append("-" * 76)
        lines.append(f"  {f.return_type} {f.name}({', '.join(p['type']+' '+p['name'] for p in f.params)}){marker}")
        lines.append(f"  Lines {f.line_start}–{f.line_end}   |   {len(f.calls)} calls   |   {len(f.gates)} gates   |   {len(f.vars)} vars")
        lines.append("")

        if f.gates:
            lines.append("  AST Gates:")
            for g in f.gates:
                indent = "    " + "  " * min(g.depth, 4)
                lines.append(f"{indent}⊳ {g.gate_type} ({g.condition_text[:60]})  L{g.line}")
                if g.calls_in_true:
                    lines.append(f"{indent}  → true:  {', '.join(g.calls_in_true[:8])}")
                if g.calls_in_false:
                    lines.append(f"{indent}  → false: {', '.join(g.calls_in_false[:8])}")
            lines.append("")

        if f.calls:
            lines.append("  Call Graph:")
            # Group by callee, show first occurrence
            seen = {}
            for c in f.calls:
                if c.callee == "?" or c.callee.startswith("operator"):
                    continue
                if c.callee not in seen:
                    seen[c.callee] = c
            for callee, c in sorted(seen.items(), key=lambda x: x[1].line):
                member = " (member)" if c.is_member else ""
                lines.append(f"    L{c.line:4d}  {callee}{member}")
            lines.append("")

        # Security-relevant variables (pointers, arrays, file-controlled)
        sec_vars = [v for v in f.vars if v.is_pointer or v.is_array
                    or any(kw in v.type.lower() for kw in ("char", "uint", "int", "size_t", "float"))]
        if sec_vars:
            lines.append("  Security-Relevant Variables:")
            for v in sec_vars[:20]:
                flags = []
                if v.is_pointer:
                    flags.append("PTR")
                if v.is_array:
                    flags.append("ARR")
                flag_str = f" [{','.join(flags)}]" if flags else ""
                lines.append(f"    L{v.line:4d}  {v.type:40s} {v.name}{flag_str}")
            lines.append("")

    with open(output_path, "w") as fh:
        fh.write("\n".join(lines) + "\n")
    return "\n".join(lines)


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <raw-ast.json> <source-basename> [--output-prefix PREFIX]")
        sys.exit(1)

    raw_ast_path = sys.argv[1]
    target_basename = sys.argv[2]
    prefix = sys.argv[4] if len(sys.argv) > 4 and sys.argv[3] == "--output-prefix" else None

    if not prefix:
        prefix = os.path.splitext(target_basename)[0]

    print(f"Loading {raw_ast_path} ...")
    with open(raw_ast_path, "r") as f:
        ast = json.load(f)

    print(f"Filtering for nodes from: {target_basename}")

    # Find top-level function definitions from the target file
    # Clang AST uses "inherited" locations — only the first node in a file
    # has an explicit "file" field. Subsequent nodes inherit it implicitly.
    # We track the current file as we walk top-level declarations.
    functions = []
    top_inner = ast.get("inner", [])
    inherited_file = ""

    for node in top_inner:
        kind = node.get("kind", "")

        # Track inherited file context from ANY top-level node
        nf = get_loc_file(node)
        if nf:
            inherited_file = nf

        if kind != "FunctionDecl":
            continue

        # Check if this function is from our target file
        # Use explicit file if present, otherwise use inherited
        effective_file = nf if nf else inherited_file
        if not effective_file or target_basename not in effective_file:
            continue

        # Skip declarations without bodies
        inner = node.get("inner", [])
        has_body = any(c.get("kind") == "CompoundStmt" for c in inner)
        if not has_body:
            continue

        func_name = node.get("name", "?")
        ret_type = node.get("type", {}).get("qualType", "?")
        # Extract return type (before the '(')
        if "(" in ret_type:
            ret_type = ret_type[:ret_type.index("(")].strip()

        params = []
        for child in inner:
            if child.get("kind") == "ParmVarDecl":
                params.append({
                    "name": child.get("name", ""),
                    "type": child.get("type", {}).get("qualType", "?")
                })

        results = {"calls": [], "gates": [], "vars": []}

        # Walk the compound statement (function body)
        for child in inner:
            if child.get("kind") == "CompoundStmt":
                walk_function_body(child, func_name, target_basename, results)

        fdef = FunctionDef(
            name=func_name,
            return_type=ret_type,
            params=params,
            line_start=get_line(node),
            line_end=get_end_line(node),
            calls=results["calls"],
            gates=results["gates"],
            vars=results["vars"],
            is_main=(func_name == "main"),
        )
        functions.append(fdef)

    print(f"Found {len(functions)} function definitions")

    # Sort by line number
    functions.sort(key=lambda f: f.line_start)

    # Output directory
    out_dir = os.path.dirname(raw_ast_path) or "."

    # 1. Structured JSON
    json_path = os.path.join(out_dir, f"{prefix}-ast.json")
    json_data = {
        "source": target_basename,
        "generator": "extract-ast.py (clang-18 AST)",
        "functions": len(functions),
        "total_calls": sum(len(f.calls) for f in functions),
        "total_gates": sum(len(f.gates) for f in functions),
        "total_vars": sum(len(f.vars) for f in functions),
        "definitions": []
    }
    for f in functions:
        fdict = {
            "name": f.name,
            "return_type": f.return_type,
            "params": f.params,
            "line_start": f.line_start,
            "line_end": f.line_end,
            "is_main": f.is_main,
            "calls": [asdict(c) for c in f.calls],
            "gates": [asdict(g) for g in f.gates],
            "vars": [asdict(v) for v in f.vars],
        }
        json_data["definitions"].append(fdict)

    with open(json_path, "w") as fh:
        json.dump(json_data, fh, indent=2)
    print(f"  → {json_path} ({os.path.getsize(json_path)} bytes)")

    # 2. DOT call graph
    dot_path = os.path.join(out_dir, f"{prefix}-callgraph.dot")
    generate_dot(functions, dot_path)
    print(f"  → {dot_path}")

    # 3. Human-readable summary
    summary_path = os.path.join(out_dir, f"{prefix}-ast-summary.txt")
    summary = generate_summary(functions, target_basename, summary_path)
    print(f"  → {summary_path}")

    # 4. Try to render SVG
    import shutil
    if shutil.which("dot"):
        svg_path = os.path.join(out_dir, f"{prefix}-callgraph.svg")
        os.system(f'dot -Tsvg "{dot_path}" -o "{svg_path}" 2>/dev/null')
        if os.path.exists(svg_path) and os.path.getsize(svg_path) > 100:
            print(f"  → {svg_path}")
        else:
            print("  → SVG rendering skipped (graphviz error)")

    # Print summary to stdout
    print("")
    print(summary)


if __name__ == "__main__":
    main()
