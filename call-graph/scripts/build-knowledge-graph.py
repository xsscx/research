#!/usr/bin/env python3
"""Build a unified knowledge graph from all ICC security research data sources.

Parses:
  1. iccanalyzer-lite --registry JSON -> heuristic, CVE, CWE nodes
  2. Patch coverage CSV -> patch nodes + coverage edges
  3. call-graph/index.json -> component nodes + edge counts
  4. CVE report markdown -> advisory nodes with severity/CVSS
  5. Fuzzer-tool mappings -> fuzzer nodes + target edges

Output: call-graph/knowledge-graph.json
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# --- Data source paths ---
REGISTRY_BIN = REPO_ROOT / "iccanalyzer-lite" / "iccanalyzer-lite"
PATCH_CSV = REPO_ROOT / "docs" / "analysis" / "ICCANALYZER_CFL_PATCH_COVERAGE_MATRIX.csv"
CALLGRAPH_INDEX = REPO_ROOT / "call-graph" / "index.json"
CVE_REPORT = REPO_ROOT / "docs" / "cve" / "iccDEV-CVE-Report.md"
OUTPUT = REPO_ROOT / "call-graph" / "knowledge-graph.json"

# Fuzzer to upstream tool mapping (from CFL instructions)
FUZZER_TOOL_MAP = {
    "icc_dump_fuzzer": "IccDumpProfile",
    "icc_toxml_fuzzer": "IccToXml",
    "icc_fromxml_fuzzer": "IccFromXml",
    "icc_roundtrip_fuzzer": "IccRoundTrip",
    "icc_fromcube_fuzzer": "IccFromCube",
    "icc_tiffdump_fuzzer": "IccTiffDump",
    "icc_applynamedcmm_fuzzer": "IccApplyNamedCmm",
    "icc_applyprofiles_fuzzer": "IccApplyProfiles",
    "icc_link_fuzzer": "IccApplyToLink",
    "icc_v5dspobs_fuzzer": "IccV5DspObsToV4Dsp",
    "icc_specsep_fuzzer": "IccSpecSepToTiff",
    "icc_applysearch_fuzzer": "IccApplySearch",
    "icc_cfg_fuzzer": "IccApplyNamedCmm",  # JSON config fuzzer
}

# Fuzzer fidelity percentages (from coverage analysis)
FUZZER_FIDELITY = {
    "icc_fromcube_fuzzer": 100,
    "icc_dump_fuzzer": 100,  # >100% but cap at 100
    "icc_roundtrip_fuzzer": 95,
    "icc_specsep_fuzzer": 85,
    "icc_applynamedcmm_fuzzer": 75,
    "icc_link_fuzzer": 65,
}


def parse_registry(bin_path: Path) -> dict:
    """Run --registry and parse JSON output."""
    if not bin_path.exists():
        print(f"  WARN: {bin_path} not found, reusing existing graph registry", file=sys.stderr)
        return parse_existing_registry(OUTPUT)
    try:
        result = subprocess.run(
            [str(bin_path), "--registry"],
            capture_output=True, text=True, timeout=10
        )
        return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError) as e:
        print(f"  WARN: --registry failed: {e}; reusing existing graph registry", file=sys.stderr)
        return parse_existing_registry(OUTPUT)


def parse_existing_registry(graph_path: Path) -> dict:
    """Recover registry-shaped data from an existing knowledge graph."""
    if not graph_path.exists():
        return {"heuristics": [], "totalHeuristics": 0, "severity": {}}

    try:
        with open(graph_path) as f:
            graph = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {"heuristics": [], "totalHeuristics": 0, "severity": {}}

    node_by_id = {n.get("id"): n for n in graph.get("nodes", [])}
    heuristic_nodes = [n for n in graph.get("nodes", []) if n.get("type") == "heuristic"]

    refs_by_heuristic = {}
    cwe_by_heuristic = {}
    for edge in graph.get("edges", []):
        source = edge.get("source")
        target = edge.get("target")
        rel = edge.get("relationship")
        if source not in node_by_id:
            continue
        if rel == "DETECTS":
            refs_by_heuristic.setdefault(source, []).append(target)
        elif rel == "CLASSIFIES":
            cwe_by_heuristic[source] = target

    severity = {}
    heuristics = []
    for node in heuristic_nodes:
        hid = str(node.get("id", "H0"))
        numeric_id = int(hid[1:]) if hid.startswith("H") and hid[1:].isdigit() else 0
        sev = node.get("severity", "INFO")
        severity[sev] = severity.get(sev, 0) + 1
        heuristics.append({
            "id": numeric_id,
            "name": node.get("name", ""),
            "specRef": node.get("specRef", ""),
            "phase": node.get("phase", ""),
            "severity": sev,
            "cwe": cwe_by_heuristic.get(hid, ""),
            "cveRefs": ", ".join(refs_by_heuristic.get(hid, [])),
        })

    heuristics.sort(key=lambda h: h["id"])
    return {
        "heuristics": heuristics,
        "totalHeuristics": len(heuristics),
        "severity": severity,
    }


def parse_patch_csv(csv_path: Path) -> list[dict]:
    """Parse the patch coverage matrix CSV."""
    patches = []
    if not csv_path.exists():
        print(f"  WARN: {csv_path} not found", file=sys.stderr)
        return patches
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            patches.append(row)
    return patches


def parse_callgraph_index(idx_path: Path) -> dict:
    """Parse call-graph/index.json."""
    if idx_path.exists():
        with open(idx_path) as f:
            return json.load(f)

    print(f"  WARN: {idx_path} not found; scanning summary files", file=sys.stderr)
    components = {}
    for summary_path in sorted(idx_path.parent.rglob("*-summary.json")):
        try:
            with open(summary_path) as f:
                summary = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue

        component = summary.get("component")
        target = summary.get("target")
        if not component or not target:
            continue

        ast = summary.get("ast", {})
        callgraph = summary.get("callgraph", {})
        components.setdefault(component, []).append({
            "name": target,
            "ast_functions": ast.get("function_count", 0),
            "cg_edges": callgraph.get("edge_count", 0),
            "cg_method": callgraph.get("method", "unknown"),
        })

    for targets in components.values():
        targets.sort(key=lambda t: t.get("name", ""))

    return {"generated_by": "summary-files", "components": components}


def parse_cve_report(md_path: Path) -> list[dict]:
    """Parse the CVE report markdown table."""
    advisories = []
    if not md_path.exists():
        print(f"  WARN: {md_path} not found", file=sys.stderr)
        return advisories

    with open(md_path) as f:
        lines = f.readlines()

    # Find table rows: | # | CVE ID | GHSA ID | Severity | CVSS | Summary |
    in_table = False
    for line in lines:
        line = line.strip()
        if line.startswith("| #"):
            in_table = True
            continue
        if in_table and line.startswith("|---"):
            continue
        if in_table and line.startswith("|"):
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 6:
                # Extract GHSA ID from markdown link
                ghsa_match = re.search(r"GHSA-[\w-]+", parts[2])
                ghsa_id = ghsa_match.group(0) if ghsa_match else parts[2]
                cve_id = parts[1] if parts[1] != "Pending" else None
                advisories.append({
                    "num": parts[0],
                    "cve_id": cve_id,
                    "ghsa_id": ghsa_id,
                    "severity": parts[3],
                    "cvss": parts[4],
                    "summary": parts[5],
                })
        elif in_table and not line.startswith("|"):
            in_table = False

    return advisories


def parse_cwe_distribution(md_path: Path) -> dict[str, int]:
    """Parse CWE distribution from the CVE report."""
    cwe_dist = {}
    if not md_path.exists():
        return cwe_dist
    with open(md_path) as f:
        content = f.read()
    # Pattern: - **CWE-NNN: Description** - N advisory(ies)
    for m in re.finditer(r"- \*\*CWE-(\d+):[^*]+\*\*\s*[-\u2013\u2014]+\s*(\d+)\s*advisory", content):
        cwe_dist[f"CWE-{m.group(1)}"] = int(m.group(2))
    return cwe_dist


def build_graph(registry: dict, patches: list, cg_index: dict,
                advisories: list, cwe_dist: dict) -> dict:
    """Build the unified knowledge graph."""
    nodes = []
    edges = []
    node_ids = set()

    def add_node(nid: str, ntype: str, **attrs):
        if nid not in node_ids:
            node_ids.add(nid)
            nodes.append({"id": nid, "type": ntype, **attrs})

    def add_edge(src: str, tgt: str, rel: str, **attrs):
        edges.append({"source": src, "target": tgt, "relationship": rel, **attrs})

    # --- 1. Heuristics + CVE/CWE edges ---
    for h in registry.get("heuristics", []):
        hid = f"H{h['id']}"
        add_node(hid, "heuristic",
                 name=h["name"], specRef=h["specRef"],
                 phase=h["phase"], severity=h["severity"])

        # CWE edge
        cwe = h.get("cwe", "")
        if cwe:
            add_node(cwe, "cwe", name=cwe)
            add_edge(hid, cwe, "CLASSIFIES")

        # CVE/GHSA edges
        refs = h.get("cveRefs") or ""
        for ref in re.split(r"[,;]\s*", refs):
            ref = ref.strip()
            if ref.startswith("CVE-"):
                add_node(ref, "cve")
                add_edge(hid, ref, "DETECTS")
            elif ref.startswith("GHSA-"):
                add_node(ref, "ghsa")
                add_edge(hid, ref, "DETECTS")

    # --- 2. Patches + coverage edges ---
    for p in patches:
        pid = f"CFL-{p['patch_id']}"
        add_node(pid, "patch",
                 file=p.get("patch_file", ""),
                 reachability=p.get("reachability", ""),
                 priority=p.get("priority", ""),
                 v1_defense=p.get("v1_defense", ""),
                 v2_defense=p.get("v2_defense", ""),
                 review_state=p.get("review_state", ""))

        # Extract CWE from notes if present
        notes = p.get("notes", "")
        for cwe_m in re.finditer(r"CWE-\d+", notes):
            cwe_id = cwe_m.group(0)
            add_node(cwe_id, "cwe", name=cwe_id)
            add_edge(pid, cwe_id, "ADDRESSES")

        # Extract heuristic references from notes (H##)
        for h_m in re.finditer(r"\bH(\d+)\b", notes):
            hid = f"H{h_m.group(1)}"
            if hid in node_ids:
                add_edge(pid, hid, "COVERED_BY")

    # --- 3. Components from call graph ---
    for comp_name, targets in cg_index.get("components", {}).items():
        for target in targets:
            tid = f"comp:{comp_name}/{target['name']}"
            add_node(tid, "component",
                     component=comp_name,
                     name=target["name"],
                     ast_functions=target.get("ast_functions", 0),
                     cg_edges=target.get("cg_edges", 0),
                     cg_method=target.get("cg_method", ""))

    # --- 4. Advisories ---
    for adv in advisories:
        if adv.get("cve_id"):
            add_node(adv["cve_id"], "cve",
                     severity=adv["severity"],
                     cvss=adv["cvss"],
                     summary=adv["summary"])
        if adv.get("ghsa_id"):
            add_node(adv["ghsa_id"], "ghsa",
                     severity=adv["severity"],
                     cvss=adv["cvss"],
                     summary=adv["summary"])
            if adv.get("cve_id"):
                add_edge(adv["cve_id"], adv["ghsa_id"], "ALIAS")

    # CWE distribution from report
    for cwe_id, count in cwe_dist.items():
        add_node(cwe_id, "cwe", name=cwe_id, advisory_count=count)

    # --- 5. Fuzzer nodes + tool target edges ---
    for fuzzer, tool in FUZZER_TOOL_MAP.items():
        fid = f"fuzzer:{fuzzer}"
        add_node(fid, "fuzzer", name=fuzzer)

        # Link to component if it exists
        tool_id = f"comp:iccdev/tools/{tool}"
        if tool_id in node_ids:
            fidelity = FUZZER_FIDELITY.get(fuzzer)
            attrs = {}
            if fidelity is not None:
                attrs["fidelity_pct"] = fidelity
            add_edge(fid, tool_id, "TARGETS", **attrs)

        # Link CFL fuzzer component if it exists
        cfl_id = f"comp:cfl/{fuzzer}"
        if cfl_id in node_ids:
            add_edge(fid, cfl_id, "IMPLEMENTED_BY")

    # --- Severity distribution summary ---
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    severity_dist = {
        level: registry.get("severity", {}).get(level, 0)
        for level in severity_order
        if registry.get("severity", {}).get(level, 0)
    }

    return {
        "version": "1.0.0",
        "generated_by": "build-knowledge-graph.py",
        "stats": {
            "nodes": len(nodes),
            "edges": len(edges),
            "heuristics": registry.get("totalHeuristics", 0),
            "cves": sum(1 for n in nodes if n["type"] == "cve"),
            "ghsas": sum(1 for n in nodes if n["type"] == "ghsa"),
            "cwes": sum(1 for n in nodes if n["type"] == "cwe"),
            "patches": sum(1 for n in nodes if n["type"] == "patch"),
            "components": sum(1 for n in nodes if n["type"] == "component"),
            "fuzzers": sum(1 for n in nodes if n["type"] == "fuzzer"),
            "severity_distribution": severity_dist,
        },
        "nodes": nodes,
        "edges": edges,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("-o", "--output", default=str(OUTPUT),
                        help="Output JSON path (default: call-graph/knowledge-graph.json)")
    parser.add_argument("--registry-bin", default=str(REGISTRY_BIN),
                        help="Path to iccanalyzer-lite binary")
    parser.add_argument("--no-registry", action="store_true",
                        help="Skip running --registry (use when binary unavailable)")
    parser.add_argument("--summary", action="store_true",
                        help="Print summary stats and exit")
    args = parser.parse_args()

    print("Building knowledge graph...")

    # Parse all sources
    print("  [1/5] Heuristic registry...", end=" ", flush=True)
    if args.no_registry:
        registry = {"heuristics": [], "totalHeuristics": 0, "severity": {}}
        print("skipped")
    else:
        registry = parse_registry(Path(args.registry_bin))
        print(f"{registry.get('totalHeuristics', 0)} heuristics")

    print("  [2/5] Patch coverage CSV...", end=" ", flush=True)
    patches = parse_patch_csv(PATCH_CSV)
    print(f"{len(patches)} patches")

    print("  [3/5] Call graph index...", end=" ", flush=True)
    cg_index = parse_callgraph_index(CALLGRAPH_INDEX)
    n_targets = sum(len(v) for v in cg_index.get("components", {}).values())
    print(f"{n_targets} targets")

    print("  [4/5] CVE report...", end=" ", flush=True)
    advisories = parse_cve_report(CVE_REPORT)
    cwe_dist = parse_cwe_distribution(CVE_REPORT)
    print(f"{len(advisories)} advisories, {len(cwe_dist)} CWEs")

    print("  [5/5] Fuzzer mappings...", end=" ", flush=True)
    print(f"{len(FUZZER_TOOL_MAP)} fuzzers")

    # Build unified graph
    graph = build_graph(registry, patches, cg_index, advisories, cwe_dist)

    if args.summary:
        print(f"\n--- Knowledge Graph Summary ---")
        for k, v in graph["stats"].items():
            if isinstance(v, dict):
                print(f"  {k}:")
                for sk, sv in v.items():
                    print(f"    {sk}: {sv}")
            else:
                print(f"  {k}: {v}")
        return

    # Write output
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(graph, f, indent=2)
    print(f"\nWrote {out_path} ({out_path.stat().st_size:,} bytes)")
    print(f"  {graph['stats']['nodes']} nodes, {graph['stats']['edges']} edges")


if __name__ == "__main__":
    main()
