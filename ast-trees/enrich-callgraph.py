#!/usr/bin/env python3
"""Enrich call-graph/ DOT files with security gate annotations from ast-trees/ JSON.

Reads ast-trees/*-ast.json for gate/condition data, then annotates matching nodes
and edges in call-graph/iccdev/tools/*-callgraph.dot with:
  - Gate conditions on edges (e.g., [gate: pTag])
  - Security-relevant variable annotations on nodes (e.g., [PTR] pIcc)
  - Color-coded nodes: red=security-sensitive, orange=gated, green=entry

Usage:
  python3 enrich-callgraph.py                          # enrich all tools
  python3 enrich-callgraph.py --tool iccDumpProfile    # single tool
  python3 enrich-callgraph.py --dry-run                # preview changes
"""

import json
import os
import re
import sys
import argparse
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
AST_DIR = REPO / "ast-trees"
CG_DIR = REPO / "call-graph" / "iccdev" / "tools"

# Map tool binary names to ast-trees prefixes
TOOL_MAP = {
    "iccDumpProfile": "iccDumpProfile",
    "iccApplyNamedCmm": "iccApplyNamedCmm",
    "iccApplyProfiles": "iccApplyProfiles",
    "iccApplySearch": "iccApplySearch",
    "iccApplyToLink": "iccApplyToLink",
    "iccFromCube": "iccFromCube",
    "iccFromXml": "iccFromXml",
    "iccJpegDump": "iccJpegDump",
    "iccPngDump": "iccPngDump",
    "iccRoundTrip": "iccRoundTrip",
    "iccSpecSepToTiff": "iccSpecSepToTiff",
    "IccSpecSepToTiff": "iccSpecSepToTiff",
    "iccTiffDump": "iccTiffDump",
    "IccTiffDump": "iccTiffDump",
    "iccToXml": "iccToXml",
    "iccV5DspObsToV4Dsp": "iccV5DspObsToV4Dsp",
}


def load_ast_data(tool_name):
    """Load gate and variable data from ast-trees JSON."""
    ast_prefix = TOOL_MAP.get(tool_name, tool_name)
    ast_path = AST_DIR / f"{ast_prefix}-ast.json"
    if not ast_path.exists():
        return None
    with open(ast_path) as f:
        return json.load(f)


def extract_gates_by_function(ast_data):
    """Build a map: function_name -> list of gates with call info."""
    gates_map = {}
    for defn in ast_data.get("definitions", []):
        fn_name = defn["name"]
        gates = defn.get("gates", [])
        if gates:
            gates_map[fn_name] = gates
    return gates_map


def extract_security_vars(ast_data):
    """Build a map: function_name -> list of security-relevant variables."""
    vars_map = {}
    for defn in ast_data.get("definitions", []):
        fn_name = defn["name"]
        sec_vars = []
        for v in defn.get("vars", []):
            flags = []
            if v.get("is_pointer"):
                flags.append("PTR")
            if v.get("is_array"):
                flags.append("ARR")
            vtype = v.get("type", "")
            if "size_t" in vtype or "uint" in vtype.lower():
                flags.append("SIZE")
            if flags:
                v["security_flags"] = flags
                sec_vars.append(v)
        if sec_vars:
            vars_map[fn_name] = sec_vars
    return vars_map


def find_gate_for_call(gates, callee_name):
    """Find the gate condition that guards a specific callee call."""
    for gate in gates:
        if callee_name in gate.get("calls_in_true", []):
            cond = gate.get("condition_text", "?")
            return f"if({cond})"
        if callee_name in gate.get("calls_in_false", []):
            cond = gate.get("condition_text", "?")
            return f"else({cond})"
    return None


def extract_node_name(label):
    """Extract the function name from a DOT node label."""
    # Handle formats like: "CIccInfo::GetTagSigName()" or "DumpTagCore()"
    m = re.search(r'"([^"]+)"', label)
    if m:
        name = m.group(1)
        # Strip class prefix for matching
        if "::" in name:
            name = name.split("::")[-1]
        # Strip parentheses and params
        name = re.sub(r'\(.*\)', '', name)
        return name.strip()
    return None


def enrich_dot(dot_path, ast_data, dry_run=False):
    """Enrich a single DOT file with gate annotations."""
    gates_map = extract_gates_by_function(ast_data)
    vars_map = extract_security_vars(ast_data)

    with open(dot_path) as f:
        content = f.read()

    lines = content.split('\n')
    new_lines = []

    # Build node-id -> function-name map from existing labels
    node_name_map = {}
    for line in lines:
        m = re.match(r'\s*(Node\w+)\s+\[label="([^"]+)"', line)
        if m:
            node_id = m.group(1)
            label = m.group(2)
            name = extract_node_name(f'"{label}"')
            if name:
                node_name_map[node_id] = name

    # Track enrichments
    enriched_edges = 0
    enriched_nodes = 0
    security_nodes = set()

    # Identify security-sensitive functions (have gates or security vars)
    for fn_name in set(list(gates_map.keys()) + list(vars_map.keys())):
        for node_id, name in node_name_map.items():
            if name == fn_name or fn_name.endswith(name):
                security_nodes.add(node_id)

    for line in lines:
        # Enrich node declarations with security annotations
        m = re.match(r'(\s*)(Node\w+)\s+\[label="([^"]+)"(.*)\];', line)
        if m:
            indent, node_id, label, rest = m.groups()
            name = extract_node_name(f'"{label}"')

            if node_id in security_nodes and name:
                # Add security var tooltip
                sec_vars = vars_map.get(name, [])
                if sec_vars:
                    tooltip_parts = []
                    for v in sec_vars[:5]:
                        flags = ",".join(v.get("security_flags", []))
                        tooltip_parts.append(f"[{flags}] {v.get('name', '?')}")
                    tooltip = "\\n".join(tooltip_parts)
                    new_label = f"{label}\\n---\\n{tooltip}"
                    # Color security-sensitive nodes
                    rest_clean = re.sub(r'fillcolor="[^"]*"', 'fillcolor="#ffcccc"', rest)
                    if 'fillcolor' not in rest:
                        rest_clean = rest + ', fillcolor="#ffcccc"'
                    line = f'{indent}{node_id} [label="{new_label}"{rest_clean}];'
                    enriched_nodes += 1
                elif name in gates_map:
                    # Node has gates but no security vars — mark as gated
                    rest_clean = re.sub(r'fillcolor="[^"]*"', 'fillcolor="#fff3cd"', rest)
                    line = f'{indent}{node_id} [label="{label}"{rest_clean}];'

        # Enrich edges with gate annotations
        m = re.match(r'(\s*)(Node\w+)\s*->\s*(Node\w+)\s*(.*);', line)
        if m:
            indent, src_id, dst_id, attrs = m.groups()
            src_name = node_name_map.get(src_id, "")
            dst_name = node_name_map.get(dst_id, "")

            if src_name and src_name in gates_map:
                gate = find_gate_for_call(gates_map[src_name], dst_name)
                if gate:
                    if 'label=' in attrs:
                        # Append gate to existing label
                        attrs = re.sub(r'label="([^"]*)"',
                                       f'label="\\1 {gate}"', attrs)
                    else:
                        attrs_inner = attrs.strip()
                        if attrs_inner.startswith('[') and attrs_inner.endswith(']'):
                            attrs = f'[label="{gate}", fontsize=7, ' + attrs_inner[1:]
                        else:
                            attrs = f'[label="{gate}", fontsize=7, fontcolor="#cc0000"]'
                    enriched_edges += 1

        new_lines.append(line)

    enriched_content = '\n'.join(new_lines)

    # Add legend
    legend = '''
  subgraph cluster_legend {
    label="Security Gate Legend";
    style=dashed;
    color="#999999";
    fontsize=8;
    fontname="Courier";
    leg_sec [label="Security-sensitive\\n(has ptr/array vars)", fillcolor="#ffcccc",
             shape=box, style="rounded,filled", fontsize=7];
    leg_gated [label="Gated function\\n(has if/else branches)", fillcolor="#fff3cd",
               shape=box, style="rounded,filled", fontsize=7];
    leg_normal [label="Normal function", fillcolor="#f0f4ff",
                shape=box, style="rounded,filled", fontsize=7];
  }
'''
    # Insert legend before closing brace
    enriched_content = enriched_content.rstrip()
    if enriched_content.endswith('}'):
        enriched_content = enriched_content[:-1] + legend + '}\n'

    tool_name = dot_path.stem.replace("-callgraph", "")
    print(f"  {tool_name}: +{enriched_edges} gate edges, +{enriched_nodes} security nodes")

    if not dry_run:
        # Write enriched version alongside original
        out_path = dot_path.parent / dot_path.name.replace("-callgraph.dot",
                                                           "-callgraph-enriched.dot")
        with open(out_path, 'w') as f:
            f.write(enriched_content)

        # Render SVG
        svg_path = out_path.with_suffix('.svg')
        os.system(f'dot -Tsvg "{out_path}" -o "{svg_path}" 2>/dev/null')
        if svg_path.exists():
            sz = svg_path.stat().st_size
            print(f"    → {svg_path.name} ({sz:,} bytes)")

    return enriched_edges, enriched_nodes


def main():
    parser = argparse.ArgumentParser(description="Enrich call-graph DOTs with AST gates")
    parser.add_argument("--tool", help="Process single tool")
    parser.add_argument("--dry-run", action="store_true", help="Preview only")
    args = parser.parse_args()

    if not CG_DIR.exists():
        print(f"ERROR: {CG_DIR} not found")
        sys.exit(1)

    # Find all call-graph DOT files
    dot_files = sorted(CG_DIR.glob("*-callgraph.dot"))
    if not dot_files:
        print("No DOT files found in call-graph/iccdev/tools/")
        sys.exit(1)

    if args.tool:
        dot_files = [d for d in dot_files if args.tool.lower() in d.name.lower()]

    total_edges = 0
    total_nodes = 0
    processed = 0

    print(f"Enriching {len(dot_files)} call-graph DOT files with AST gate data...")
    print()

    for dot_path in dot_files:
        # Extract tool name from filename
        tool_name = dot_path.stem.replace("-callgraph", "")

        ast_data = load_ast_data(tool_name)
        if not ast_data:
            print(f"  {tool_name}: no AST data, skipping")
            continue

        edges, nodes = enrich_dot(dot_path, ast_data, dry_run=args.dry_run)
        total_edges += edges
        total_nodes += nodes
        processed += 1

    print()
    print(f"Done: {processed} tools enriched, "
          f"+{total_edges} gate edges, +{total_nodes} security nodes")


if __name__ == "__main__":
    main()
