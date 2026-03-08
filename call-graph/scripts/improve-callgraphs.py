#!/usr/bin/env python3
"""
Improve call graph DOT files and regenerate SVGs.

Transforms:
  1. Demangle C++ symbols via c++filt
  2. Simplify long template names for readability
  3. Add graph attributes for proper SVG sizing/zooming
  4. Filter out std:: / __cxx / compiler-internal nodes (optional)
  5. Regenerate SVGs with graphviz dot

Usage:
  python3 improve-callgraphs.py                    # process all
  python3 improve-callgraphs.py --filter-std       # remove std:: nodes
  python3 improve-callgraphs.py --dry-run          # show changes without writing

Copyright (c) 2026 David H Hoyt LLC. All Rights Reserved.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

CALL_GRAPH_DIR = Path(__file__).resolve().parent.parent


def demangle_batch(mangled_names: list) -> dict:
    """Demangle a batch of C++ symbols via c++filt."""
    if not mangled_names:
        return {}
    input_text = "\n".join(mangled_names)
    result = subprocess.run(
        ["c++filt"], input=input_text, capture_output=True, text=True
    )
    demangled = result.stdout.strip().split("\n")
    mapping = {}
    for m, d in zip(mangled_names, demangled):
        mapping[m] = d if d != m else None
    return mapping


def simplify_name(demangled: str) -> str:
    """Simplify a demangled C++ name for graph readability."""
    name = demangled

    # Remove std::allocator noise
    name = re.sub(r",\s*std::allocator<[^>]*>", "", name)
    name = re.sub(r"std::__cxx11::", "std::", name)

    # Simplify deep templates: keep outermost type
    # std::vector<std::pair<unsigned int const, CIccTag*>> -> std::vector<...>
    depth = 0
    simplified = []
    skip_depth = 0
    for ch in name:
        if ch == "<":
            depth += 1
            if depth == 1:
                simplified.append("<")
                skip_depth = 0
            elif depth == 2:
                skip_depth = depth
        elif ch == ">":
            if depth == skip_depth:
                pass
            if depth == 1:
                simplified.append(">")
            depth -= 1
        elif depth <= 1:
            simplified.append(ch)
        elif depth == 2 and skip_depth == 0:
            simplified.append(ch)
    name = "".join(simplified)

    # Clean up empty angle brackets and extra commas
    name = re.sub(r"<\s*>", "", name)
    name = re.sub(r",\s*>", ">", name)

    # Extract meaningful function name
    # Pattern: ReturnType Class::Method(Args) -> Class::Method()
    match = re.search(
        r"([A-Za-z_][A-Za-z0-9_]*(?:<[^>]*>)?(?:::[~A-Za-z_][A-Za-z0-9_]*(?:<[^>]*>)?)*)\s*\(",
        name,
    )
    if match:
        func = match.group(1)
        # Keep class::method but drop leading qualifiers for deeply nested stuff
        parts = func.split("::")
        if len(parts) > 3:
            parts = parts[-3:]
            func = "::".join(parts)
        name = func + "()"

    # Truncate if still too long
    if len(name) > 70:
        name = name[:67] + "..."

    return name


def extract_mangled_from_label(label: str) -> str:
    """Extract the mangled symbol from a DOT label field."""
    # label="{_ZN8CIccCmmC2E...}" or label="{funcname}"
    match = re.search(r"\{([^}]+)\}", label)
    return match.group(1) if match else label


def fallback_demangle(mangled: str) -> str:
    """Regex-based demangling for symbols c++filt can't handle."""
    # _ZN<len>Class<len>MethodE... -> Class::Method
    parts = re.findall(r"(\d+)([A-Za-z_][A-Za-z0-9_]*)", mangled)
    if parts and mangled.startswith("_Z"):
        names = []
        for length_str, name in parts:
            length = int(length_str)
            if len(name) == length:
                names.append(name)
            elif len(name) > length:
                names.append(name[:length])
        if names:
            result = "::".join(names)
            if result and not result.startswith("std"):
                return result + "()"
    return mangled


def is_std_node(label: str) -> bool:
    """Check if a node represents a std:: library function."""
    return any(
        label.startswith(prefix)
        for prefix in [
            "std::",
            "__cxa_",
            "__gxx_",
            "_Unwind_",
            "__clang_",
            "operator new",
            "operator delete",
            "__cxx_global",
            "llvm.",
            "memcpy",
            "memset",
            "memmove",
            "strlen",
            "strcmp",
            "strcpy",
            "strncmp",
            "malloc",
            "calloc",
            "realloc",
            "free",
        ]
    )


def process_dot_file(dot_path: Path, filter_std: bool = False, dry_run: bool = False) -> dict:
    """Process a single DOT file: demangle, simplify, improve attributes."""
    with open(dot_path) as f:
        content = f.read()

    # Extract all mangled symbols from labels
    label_pattern = re.compile(r'label="\{([^}]+)\}"')
    mangled_symbols = set()
    for match in label_pattern.finditer(content):
        sym = match.group(1)
        if sym.startswith("_Z") or sym.startswith("_GLOBAL"):
            mangled_symbols.add(sym)

    # Batch demangle
    demangle_map = demangle_batch(list(mangled_symbols))

    # Build final label mapping
    label_map = {}
    std_nodes = set()

    for sym in mangled_symbols:
        demangled = demangle_map.get(sym)
        if demangled:
            simplified = simplify_name(demangled)
        else:
            simplified = fallback_demangle(sym)
        label_map[sym] = simplified

        if filter_std and is_std_node(simplified):
            std_nodes.add(sym)

    # Also handle non-mangled labels (plain C functions)
    for match in label_pattern.finditer(content):
        sym = match.group(1)
        if sym not in mangled_symbols and not sym.startswith("_Z"):
            label_map[sym] = sym  # Keep as-is

    # Replace labels in content
    def replace_label(m):
        old = m.group(1)
        new = label_map.get(old, old)
        # Escape special DOT chars
        new = new.replace("\\", "\\\\").replace('"', '\\"')
        return f'label="{{{new}}}"'

    new_content = label_pattern.sub(replace_label, content)

    # Filter std:: nodes if requested
    if filter_std and std_nodes:
        # Find node IDs for std:: symbols
        node_id_map = {}
        for line in new_content.split("\n"):
            for sym in std_nodes:
                escaped = sym.replace("\\", "\\\\")
                if escaped in line or sym in line:
                    nid_match = re.match(r"\s*(Node0x[a-f0-9]+)\s", line)
                    if nid_match:
                        node_id_map[nid_match.group(1)] = sym

        # Remove lines with std:: node definitions and edges
        if node_id_map:
            filtered_lines = []
            for line in new_content.split("\n"):
                skip = False
                for nid in node_id_map:
                    if nid in line:
                        skip = True
                        break
                if not skip:
                    filtered_lines.append(line)
            new_content = "\n".join(filtered_lines)

    # Improve graph attributes for SVG rendering
    # Add after the opening brace of the digraph
    graph_attrs = """
\t// Graph attributes for readable SVG output
\tgraph [
\t\trankdir=LR,
\t\tnodesep=0.4,
\t\tranksep=1.2,
\t\tfontname="Helvetica",
\t\tfontsize=11,
\t\tbgcolor="white",
\t\tpad=0.5,
\t\tmargin=0,
\t\tsize="200,200!",
\t\tratio="compress"
\t];
\tnode [
\t\tshape=box,
\t\tstyle="rounded,filled",
\t\tfillcolor="#f0f4ff",
\t\tfontname="Courier",
\t\tfontsize=9,
\t\tmargin="0.1,0.05"
\t];
\tedge [
\t\tcolor="#4a6fa5",
\t\tarrowsize=0.7
\t];
"""

    # Remove old label= line at top and insert new attributes
    new_content = re.sub(
        r'(digraph "[^"]*" \{)\s*\n\tlabel="[^"]*";\n',
        lambda m: m.group(1) + "\n" + graph_attrs,
        new_content,
    )

    # Also replace shape=record with improved styling
    new_content = new_content.replace("shape=record,", "")

    stats = {
        "file": str(dot_path),
        "total_nodes": len(mangled_symbols) + len(
            [1 for m in label_pattern.finditer(content) if m.group(1) not in mangled_symbols]
        ),
        "demangled": sum(1 for v in demangle_map.values() if v is not None),
        "fallback": sum(1 for sym in mangled_symbols if demangle_map.get(sym) is None),
        "filtered_std": len(std_nodes) if filter_std else 0,
    }

    if not dry_run:
        with open(dot_path, "w") as f:
            f.write(new_content)

    return stats


def regenerate_svg(dot_path: Path, dry_run: bool = False) -> bool:
    """Regenerate SVG from DOT file."""
    svg_path = dot_path.with_suffix(".svg")
    if dry_run:
        return True

    try:
        result = subprocess.run(
            ["dot", "-Tsvg", "-o", str(svg_path), str(dot_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"  TIMEOUT: {dot_path.name} (>120s)")
        return False


def main():
    parser = argparse.ArgumentParser(description="Improve call graph DOT files")
    parser.add_argument("--filter-std", action="store_true", help="Remove std:: nodes")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without writing")
    parser.add_argument("--component", help="Process only this component (iccdev, cfl, analyzer, colorbleed)")
    args = parser.parse_args()

    dot_files = sorted(CALL_GRAPH_DIR.rglob("*.dot"))
    if args.component:
        dot_files = [f for f in dot_files if args.component in str(f)]

    print(f"Processing {len(dot_files)} DOT files...")
    if args.filter_std:
        print("  Filtering std:: nodes")
    if args.dry_run:
        print("  DRY RUN — no files will be modified")

    total_stats = {"demangled": 0, "fallback": 0, "filtered_std": 0, "total_nodes": 0}

    for dot_file in dot_files:
        rel = dot_file.relative_to(CALL_GRAPH_DIR)
        stats = process_dot_file(dot_file, filter_std=args.filter_std, dry_run=args.dry_run)
        total_stats["demangled"] += stats["demangled"]
        total_stats["fallback"] += stats["fallback"]
        total_stats["filtered_std"] += stats["filtered_std"]
        total_stats["total_nodes"] += stats["total_nodes"]
        print(f"  {rel}: {stats['demangled']} demangled, {stats['fallback']} fallback"
              + (f", {stats['filtered_std']} std filtered" if stats['filtered_std'] else ""))

    print(f"\nTotals: {total_stats['total_nodes']} nodes, "
          f"{total_stats['demangled']} demangled, "
          f"{total_stats['fallback']} fallback")

    if args.dry_run:
        print("\nDry run complete. No files modified.")
        return

    # Regenerate SVGs
    print(f"\nRegenerating {len(dot_files)} SVGs...")
    success = 0
    fail = 0
    for dot_file in dot_files:
        rel = dot_file.relative_to(CALL_GRAPH_DIR)
        if regenerate_svg(dot_file, dry_run=args.dry_run):
            success += 1
        else:
            fail += 1
            print(f"  FAILED: {rel}")

    print(f"\nSVG generation: {success} succeeded, {fail} failed")


if __name__ == "__main__":
    main()
