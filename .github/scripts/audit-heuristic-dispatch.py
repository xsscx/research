#!/usr/bin/env python3
"""Audit heuristic registry entries against dispatch calls.

Cross-references IccHeuristicsRegistry.h entries with RunHeuristic_H*
calls across all dispatcher files. Reports missing or orphaned heuristics.

Usage:
    python3 .github/scripts/audit-heuristic-dispatch.py
    python3 .github/scripts/audit-heuristic-dispatch.py --verbose
"""

import re
import sys
import os

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ANALYZER_DIR = os.path.join(REPO_ROOT, "iccanalyzer-lite")

REGISTRY_FILE = os.path.join(ANALYZER_DIR, "IccHeuristicsRegistry.h")

DISPATCH_FILES = [
    os.path.join(ANALYZER_DIR, "IccHeuristicsHeader.cpp"),
    os.path.join(ANALYZER_DIR, "IccHeuristicsLibrary.cpp"),
    os.path.join(ANALYZER_DIR, "IccHeuristicsRawPost.cpp"),
    os.path.join(ANALYZER_DIR, "IccAnalyzerSecurity.cpp"),
    os.path.join(ANALYZER_DIR, "IccImageAnalyzer.cpp"),
]

def extract_registry_ids(filepath):
    """Extract H-IDs from kHeuristicRegistry[] entries (numeric id field)."""
    ids = set()
    # Match lines like: {  1, "Profile Size", ... or {149, "IFD Chain...
    pattern = re.compile(r'^\s*\{\s*(\d+)\s*,\s*"')
    with open(filepath, "r") as f:
        in_registry = False
        for line in f:
            if "kHeuristicRegistry" in line and "[" in line:
                in_registry = True
                continue
            if in_registry:
                if line.strip().startswith("};"):
                    break
                m = pattern.match(line)
                if m:
                    ids.add(f"H{m.group(1)}")
    return ids

def extract_dispatch_ids(filepath):
    """Extract H-IDs from RunHeuristic_H* function calls."""
    ids = {}
    pattern = re.compile(r'RunHeuristic_(H\d+)_')
    with open(filepath, "r") as f:
        for lineno, line in enumerate(f, 1):
            for m in pattern.finditer(line):
                hid = m.group(1)
                if hid not in ids:
                    ids[hid] = (filepath, lineno)
    return ids

def main():
    verbose = "--verbose" in sys.argv or "-v" in sys.argv

    if not os.path.exists(REGISTRY_FILE):
        print(f"ERROR: Registry file not found: {REGISTRY_FILE}")
        sys.exit(2)

    registry_ids = extract_registry_ids(REGISTRY_FILE)
    if not registry_ids:
        print("ERROR: No heuristic IDs found in registry")
        sys.exit(2)

    all_dispatched = {}
    for df in DISPATCH_FILES:
        if not os.path.exists(df):
            print(f"WARNING: Dispatch file not found: {df}")
            continue
        dispatched = extract_dispatch_ids(df)
        for hid, loc in dispatched.items():
            if hid not in all_dispatched:
                all_dispatched[hid] = loc

    dispatched_ids = set(all_dispatched.keys())

    missing = sorted(registry_ids - dispatched_ids, key=lambda x: int(x[1:]))
    orphaned = sorted(dispatched_ids - registry_ids, key=lambda x: int(x[1:]))

    if verbose:
        print(f"Registry entries: {len(registry_ids)}")
        print(f"Dispatch calls:   {len(dispatched_ids)}")
        print(f"Matched:          {len(registry_ids & dispatched_ids)}")
        print()
        for hid in sorted(dispatched_ids & registry_ids, key=lambda x: int(x[1:])):
            fpath, line = all_dispatched[hid]
            fname = os.path.basename(fpath)
            print(f"  [OK] {hid} → {fname}:{line}")
        print()

    errors = 0
    if missing:
        print(f"MISSING DISPATCH ({len(missing)} heuristic(s) in registry but not dispatched):")
        for hid in missing:
            print(f"  [FAIL] {hid} — registered but no RunHeuristic_{hid}_* call found")
        errors += len(missing)
    if orphaned:
        print(f"ORPHANED DISPATCH ({len(orphaned)} dispatched but not in registry):")
        for hid in orphaned:
            fpath, line = all_dispatched[hid]
            fname = os.path.basename(fpath)
            print(f"  [WARN] {hid} — dispatched at {fname}:{line} but not in registry")
        errors += len(orphaned)

    if errors == 0:
        print(f"[OK] All {len(registry_ids)} heuristics have matching dispatch calls")
        sys.exit(0)
    else:
        sys.exit(1)

if __name__ == "__main__":
    main()
