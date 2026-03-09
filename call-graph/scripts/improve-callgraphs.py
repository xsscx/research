#!/usr/bin/env python3
"""
Improve call graph DOT files and regenerate SVGs.

Transforms:
  1. Demangle C++ symbols via c++filt
  2. Simplify long template names for readability
  3. Remove record-style {braces} from labels (use plain labels)
  4. Strip graph attribute blocks and replace with clean styling
  5. Filter noise nodes: std::, libc, LLVM intrinsics, compiler helpers
  6. Regenerate SVGs with graphviz dot (auto-sized, not forced 200×200in)

Usage:
  python3 improve-callgraphs.py                    # process all (always filters noise)
  python3 improve-callgraphs.py --keep-noise       # keep libc/LLVM nodes
  python3 improve-callgraphs.py --dry-run          # show changes without writing
  python3 improve-callgraphs.py --component cfl    # process only CFL

Copyright (c) 2026 David H Hoyt LLC. All Rights Reserved.
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

CALL_GRAPH_DIR = Path(__file__).resolve().parent.parent

# Noise node prefixes — these add clutter without analytical value
NOISE_PREFIXES = [
    # C++ runtime
    "std::", "__cxa_", "__gxx_", "_Unwind_", "__clang_", "__cxx_global",
    "operator new", "operator delete",
    # LLVM intrinsics
    "llvm.", "llvm.memset", "llvm.memcpy", "llvm.lifetime", "llvm.dbg",
    # libc memory
    "memcpy", "memset", "memmove", "malloc", "calloc", "realloc", "free",
    # libc string
    "strlen", "strcmp", "strcpy", "strncmp", "strncpy", "strcat", "strncat",
    "strstr", "strchr", "strrchr", "strtol", "strtod", "strtoul", "atoi",
    "sscanf", "sprintf",
    # libc I/O
    "printf", "fprintf", "snprintf", "vsnprintf", "puts", "putchar",
    "fread", "fwrite", "fopen", "fclose", "fseek", "ftell", "fgets",
    "fflush", "ferror", "feof", "fileno", "fdopen", "freopen",
    # libc misc
    "stat", "lstat", "fstat", "access", "getenv", "setenv",
    "exit", "abort", "_exit", "atexit",
    "close", "read", "write", "open", "unlink", "remove",
    "time", "clock", "difftime", "mktime",
    "qsort", "bsort",
    # Signal/longjmp
    "_setjmp", "setjmp", "longjmp", "siglongjmp", "sigsetjmp",
    "signal", "sigaction", "alarm",
    # libpng
    "png_", "PNG_",
    # libjpeg
    "jpeg_", "JPEG_",
    # libtiff
    "TIFF", "Tiff", "_TIFF", "TIFFGetField", "TIFFOpen", "TIFFClose",
    "TIFFReadScanline", "TIFFStripSize", "TIFFNumberOfStrips",
    "TIFFNumberOfTiles", "TIFFSetField", "TIFFWriteScanline",
    "TIFFReadEncodedStrip", "TIFFScanlineSize", "TIFFTileSize",
    # libxml2
    "xml", "XML", "xmlSAX", "xmlParse", "xmlChar",
    # OpenSSL
    "EVP_", "SHA256", "OPENSSL_",
    # STL internals (tree, allocator, string)
    "_S_right", "_S_left", "_S_key", "_S_value", "_S_minimum", "_S_maximum",
    "_M_drop", "_M_clone", "_M_get_insert", "_M_lower_bound", "_M_upper_bound",
    "_M_begin", "_M_end", "_M_insert", "_M_erase", "_M_emplace", "_M_create",
    "_M_construct", "_M_dispose", "_M_assign", "_M_mutate", "_M_replace",
    "_M_append", "_M_destroy", "_M_deallocate", "_M_allocate", "_M_fill",
    "basic_string::", "basic_ostream::", "basic_istream::",
    # Trivial patterns
    "bool()", "__assert",
]

# Exact-match noise labels
NOISE_EXACT = {
    "bool()", "int()", "void()", "char()", "unsigned()", "float()", "double()",
    "__gxx_personality_v0", "_Unwind_Resume",
    # STL container internals
    "set()", "map()", "list()", "vector()", "pair()", "tuple()",
    "insert()", "erase()", "find()", "count()", "begin()", "end()",
    "size()", "empty()", "clear()", "push_back()", "pop_back()",
    "front()", "back()", "emplace()", "emplace_back()",
    "_S_right()", "_S_left()", "_S_key()", "_S_value()", "_S_minimum()",
    "_S_maximum()", "_M_drop_node()", "_M_clone_node()", "_M_insert_",
    "_M_erase()", "_M_get_insert_unique_pos()", "_M_get_insert_equal_pos()",
    "_M_lower_bound()", "_M_upper_bound()", "_M_begin()", "_M_end()",
    "_M_insert_()", "_M_emplace_unique()",
    "basic_string()", "string()", "wstring()",
}

# Graph attributes for clean, browser-viewable SVGs
GRAPH_ATTRS = """\
\t// Clean graph styling — auto-sized for browser viewing
\tgraph [
\t\trankdir=LR,
\t\tnodesep=0.3,
\t\tranksep=0.8,
\t\tfontname="Helvetica",
\t\tfontsize=10,
\t\tbgcolor="white",
\t\tpad=0.3
\t];
\tnode [
\t\tshape=box,
\t\tstyle="rounded,filled",
\t\tfillcolor="#f0f4ff",
\t\tfontname="Courier",
\t\tfontsize=9,
\t\tmargin="0.08,0.04"
\t];
\tedge [
\t\tcolor="#4a6fa5",
\t\tarrowsize=0.6
\t];
"""


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

    # Simplify deep templates: collapse nested template args
    depth = 0
    simplified = []
    for ch in name:
        if ch == "<":
            depth += 1
            if depth == 1:
                simplified.append("<")
        elif ch == ">":
            if depth == 1:
                simplified.append(">")
            depth -= 1
        elif depth <= 1:
            simplified.append(ch)
    name = "".join(simplified)

    # Clean up empty angle brackets
    name = re.sub(r"<\s*>", "", name)

    # Extract Class::Method() from full signature
    match = re.search(
        r"([A-Za-z_][A-Za-z0-9_]*(?:::[~A-Za-z_][A-Za-z0-9_]*)*)\s*\(",
        name,
    )
    if match:
        func = match.group(1)
        parts = func.split("::")
        if len(parts) > 3:
            parts = parts[-3:]
            func = "::".join(parts)
        name = func + "()"

    if len(name) > 60:
        name = name[:57] + "..."

    return name


def fallback_demangle(mangled: str) -> str:
    """Regex-based demangling for symbols c++filt can't handle."""
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


def is_noise_node(label: str) -> bool:
    """Check if a label represents a noise node that should be filtered."""
    stripped = label.strip()
    if stripped in NOISE_EXACT:
        return True
    if any(stripped.startswith(prefix) for prefix in NOISE_PREFIXES):
        return True
    # Catch-all: STL/libstdc++ internals (_M_*, _S_*, _Rb_tree*, _Vector_*, _Alloc_*, __new_*)
    if re.match(r'^_[A-Z]_\w+', stripped):
        return True
    if re.match(r'^_[A-Z][a-z]+_', stripped):  # _Rb_tree, _Vector_base, _Alloc_node
        return True
    if stripped.startswith("__gnu_cxx::") or stripped.startswith("__new_"):
        return True
    # Bare operator() is noise (STL functors)
    if stripped == "operator()":
        return True
    # std:: qualified anything
    if "std::" in stripped:
        return True
    # Trivial single-word functions (allocator internals, libc bare names)
    trivial = {"allocate()", "deallocate()", "data()", "new()", "delete()",
               "getpid", "memcmp", "memcpy", "memset", "memmove", "rewind",
               "fread", "fwrite", "fclose", "fopen", "ftell", "fseek",
               "strlen", "strcmp", "strncmp", "strcpy", "strncpy", "strcat",
               "abort", "exit", "_exit"}
    if stripped in trivial:
        return True
    return False


def strip_braces(label: str) -> str:
    """Remove graphviz record-style {braces} from a label."""
    if label.startswith("{") and label.endswith("}"):
        return label[1:-1]
    return label


def process_dot_file(dot_path: Path, filter_noise: bool = True, dry_run: bool = False) -> dict:
    """Process a single DOT file: demangle, clean labels, filter noise, restyle."""
    with open(dot_path) as f:
        content = f.read()

    # Match both braced and plain label formats
    label_pattern = re.compile(r'label="(?:\{([^}]+)\}|([^"]+))"')
    mangled_symbols = set()
    for match in label_pattern.finditer(content):
        sym = match.group(1) or match.group(2)
        if sym and (sym.startswith("_Z") or sym.startswith("_GLOBAL")):
            mangled_symbols.add(sym)

    demangle_map = demangle_batch(list(mangled_symbols))

    label_map = {}
    noise_labels = set()

    for sym in mangled_symbols:
        demangled = demangle_map.get(sym)
        simplified = simplify_name(demangled) if demangled else fallback_demangle(sym)
        label_map[sym] = simplified
        if filter_noise and is_noise_node(simplified):
            noise_labels.add(sym)

    # Handle non-mangled labels (plain C functions, already-demangled)
    for match in label_pattern.finditer(content):
        sym = match.group(1) or match.group(2)
        if sym and sym not in mangled_symbols and not sym.startswith("_Z"):
            clean = strip_braces(sym)
            label_map[sym] = clean
            if filter_noise and is_noise_node(clean):
                noise_labels.add(sym)

    # Build set of node IDs to remove
    noise_node_ids = set()
    if filter_noise and noise_labels:
        for line in content.split("\n"):
            for sym in noise_labels:
                if sym in line:
                    nid_match = re.match(r"\s*(Node0x[a-f0-9]+)\s", line)
                    if nid_match:
                        noise_node_ids.add(nid_match.group(1))

    # Replace labels: remove braces, use demangled names
    def replace_label(m):
        old = m.group(1) or m.group(2)
        new = label_map.get(old, strip_braces(old))
        new = new.replace("\\", "\\\\").replace('"', '\\"')
        return f'label="{new}"'

    new_content = label_pattern.sub(replace_label, content)

    # Filter noise node lines (definitions and edges)
    if noise_node_ids:
        filtered_lines = []
        for line in new_content.split("\n"):
            skip = any(nid in line for nid in noise_node_ids)
            if not skip:
                filtered_lines.append(line)
        new_content = "\n".join(filtered_lines)

    # Strip ALL existing graph/node/edge attribute blocks and old size/ratio settings
    # Remove any existing attribute blocks between digraph opening and first Node
    new_content = re.sub(
        r'(digraph "[^"]*" \{)\s*\n'
        r'(?:\s*//[^\n]*\n)*'          # comment lines
        r'(?:\s*graph\s*\[[^\]]*\];\s*\n)*'   # graph [] blocks
        r'(?:\s*node\s*\[[^\]]*\];\s*\n)*'    # node [] blocks
        r'(?:\s*edge\s*\[[^\]]*\];\s*\n)*',   # edge [] blocks
        lambda m: m.group(1) + "\n" + GRAPH_ATTRS,
        new_content,
    )

    # Remove stale label= at digraph level
    new_content = re.sub(r'\tlabel="[^"]*";\n', '', new_content)
    # Remove shape=record remnants
    new_content = new_content.replace("shape=record,", "")
    # Remove forced size/ratio that create absurd SVG dimensions
    new_content = re.sub(r'\s*size="[^"]*",?\n?', '\n', new_content)
    new_content = re.sub(r'\s*ratio="[^"]*",?\n?', '\n', new_content)

    remaining_nodes = new_content.count("label=")
    stats = {
        "file": str(dot_path),
        "total_nodes": len(label_map),
        "demangled": sum(1 for v in demangle_map.values() if v is not None),
        "fallback": sum(1 for sym in mangled_symbols if demangle_map.get(sym) is None),
        "noise_filtered": len(noise_node_ids),
        "remaining": remaining_nodes,
    }

    if not dry_run:
        with open(dot_path, "w") as f:
            f.write(new_content)

    return stats


def regenerate_svg(dot_path: Path, dry_run: bool = False) -> bool:
    """Regenerate SVG from DOT file using graphviz auto-sizing."""
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
    parser = argparse.ArgumentParser(description="Improve call graph DOT files and SVGs")
    parser.add_argument("--keep-noise", action="store_true",
                        help="Keep libc/LLVM/compiler noise nodes (default: filter them)")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without writing")
    parser.add_argument("--component",
                        help="Process only this component (iccdev, cfl, analyzer, colorbleed)")
    args = parser.parse_args()

    filter_noise = not args.keep_noise

    dot_files = sorted(CALL_GRAPH_DIR.rglob("*.dot"))
    if args.component:
        dot_files = [f for f in dot_files if args.component in str(f)]

    print(f"Processing {len(dot_files)} DOT files...")
    if filter_noise:
        print("  Filtering noise nodes (libc, LLVM, std::, compiler helpers)")
    if args.dry_run:
        print("  DRY RUN — no files will be modified")

    total = {"demangled": 0, "fallback": 0, "noise_filtered": 0, "total_nodes": 0, "remaining": 0}

    for dot_file in dot_files:
        rel = dot_file.relative_to(CALL_GRAPH_DIR)
        stats = process_dot_file(dot_file, filter_noise=filter_noise, dry_run=args.dry_run)
        for k in total:
            total[k] += stats[k]
        noise_msg = f", {stats['noise_filtered']} noise removed" if stats['noise_filtered'] else ""
        print(f"  {rel}: {stats['remaining']} nodes{noise_msg}")

    print(f"\nTotals: {total['total_nodes']} processed, "
          f"{total['noise_filtered']} noise removed, "
          f"{total['remaining']} remaining")

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
