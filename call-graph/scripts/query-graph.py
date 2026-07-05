#!/usr/bin/env python3
"""Query the ICC security research knowledge graph.

Usage:
  query-graph.py gaps          # Uncovered CVEs (no heuristic detection)
  query-graph.py patches       # Patch coverage status by priority
  query-graph.py cwes          # CWE distribution across heuristics
  query-graph.py attack        # Attack surface analysis
  query-graph.py orphans       # Nodes with no edges
  query-graph.py path H42 CVE-2024-38427  # Path between two nodes
  query-graph.py neighbors H42            # All neighbors of a node
  query-graph.py stats         # Full graph statistics
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

GRAPH_PATH = Path(__file__).resolve().parent.parent / "knowledge-graph.json"


def load_graph(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def build_adjacency(graph: dict) -> tuple[dict, dict]:
    """Build adjacency lists (outgoing and incoming)."""
    out_adj = defaultdict(list)
    in_adj = defaultdict(list)
    for e in graph["edges"]:
        out_adj[e["source"]].append(e)
        in_adj[e["target"]].append(e)
    return out_adj, in_adj


def node_map(graph: dict) -> dict:
    return {n["id"]: n for n in graph["nodes"]}


def cmd_gaps(graph: dict):
    """Find CVEs/GHSAs not detected by any heuristic."""
    nmap = node_map(graph)
    _, in_adj = build_adjacency(graph)

    detected = set()
    for e in graph["edges"]:
        if e["relationship"] == "DETECTS":
            detected.add(e["target"])

    vuln_nodes = [n for n in graph["nodes"] if n["type"] in ("cve", "ghsa")]
    undetected = [n for n in vuln_nodes if n["id"] not in detected]

    if not undetected:
        print("All CVEs/GHSAs are covered by at least one heuristic.")
        return

    print(f"{'ID':<30} {'Type':<6} {'Severity':<10} {'Summary'}")
    print("-" * 90)
    for n in sorted(undetected, key=lambda x: x.get("severity", ""), reverse=True):
        sev = n.get("severity", "?")
        summary = n.get("summary", "")[:50]
        print(f"{n['id']:<30} {n['type']:<6} {sev:<10} {summary}")
    print(f"\nTotal undetected: {len(undetected)} / {len(vuln_nodes)}")


def cmd_patches(graph: dict):
    """Show patch coverage status by priority."""
    patches = [n for n in graph["nodes"] if n["type"] == "patch"]
    patches.sort(key=lambda p: p.get("priority", "P9"))

    print(f"{'Patch':<12} {'Priority':<10} {'V1 Defense':<14} {'V2 Defense':<14} {'Reachability':<18} {'State'}")
    print("-" * 90)
    for p in patches:
        print(f"{p['id']:<12} {p.get('priority','?'):<10} "
              f"{p.get('v1_defense','?'):<14} {p.get('v2_defense','?'):<14} "
              f"{p.get('reachability','?'):<18} {p.get('review_state','?')}")

    # Summary by priority
    by_priority = defaultdict(list)
    for p in patches:
        by_priority[p.get("priority", "?")].append(p)
    print(f"\nBy priority:")
    for pri in sorted(by_priority):
        total = len(by_priority[pri])
        covered = sum(1 for p in by_priority[pri] if p.get("v1_defense") == "covered")
        print(f"  {pri}: {covered}/{total} covered")


def cmd_cwes(graph: dict):
    """CWE distribution across heuristics."""
    out_adj, _ = build_adjacency(graph)
    cwe_heuristics = defaultdict(list)

    for e in graph["edges"]:
        if e["relationship"] == "CLASSIFIES":
            cwe_heuristics[e["target"]].append(e["source"])

    nmap = node_map(graph)
    print(f"{'CWE':<16} {'Heuristics':<6} {'Advisory Count':<16} {'Heuristic IDs'}")
    print("-" * 80)
    for cwe in sorted(cwe_heuristics, key=lambda c: len(cwe_heuristics[c]), reverse=True):
        h_count = len(cwe_heuristics[cwe])
        adv_count = nmap.get(cwe, {}).get("advisory_count", "")
        h_ids = ", ".join(sorted(cwe_heuristics[cwe],
                                 key=lambda h: int(h[1:]) if h[1:].isdigit() else 0)[:8])
        if h_count > 8:
            h_ids += f" (+{h_count - 8} more)"
        print(f"{cwe:<16} {h_count:<6} {str(adv_count):<16} {h_ids}")


def cmd_attack(graph: dict):
    """Attack surface analysis by component exposure."""
    nmap = node_map(graph)
    out_adj, in_adj = build_adjacency(graph)

    # Components targeted by fuzzers
    fuzzed = set()
    for e in graph["edges"]:
        if e["relationship"] == "TARGETS":
            fuzzed.add(e["target"])

    components = [n for n in graph["nodes"] if n["type"] == "component"]
    print(f"{'Component':<45} {'AST Funcs':>10} {'CG Edges':>10} {'Fuzzed?'}")
    print("-" * 80)
    for c in sorted(components, key=lambda x: x.get("ast_functions", 0), reverse=True):
        is_fuzzed = "yes" if c["id"] in fuzzed else ""
        print(f"{c['id']:<45} {c.get('ast_functions',0):>10,} "
              f"{c.get('cg_edges',0):>10,} {is_fuzzed:>7}")

    fuzzed_count = sum(1 for c in components if c["id"] in fuzzed)
    print(f"\nFuzz coverage: {fuzzed_count}/{len(components)} components targeted")


def cmd_orphans(graph: dict):
    """Find nodes with no edges."""
    out_adj, in_adj = build_adjacency(graph)
    connected = set()
    for e in graph["edges"]:
        connected.add(e["source"])
        connected.add(e["target"])

    orphans = [n for n in graph["nodes"] if n["id"] not in connected]
    if not orphans:
        print("No orphan nodes found.")
        return

    by_type = defaultdict(list)
    for n in orphans:
        by_type[n["type"]].append(n)

    for ntype, nodes in sorted(by_type.items()):
        print(f"\n{ntype} ({len(nodes)}):")
        for n in nodes[:10]:
            name = n.get("name", n["id"])
            print(f"  {n['id']}: {name}")
        if len(nodes) > 10:
            print(f"  ... and {len(nodes) - 10} more")


def cmd_path(graph: dict, src: str, tgt: str):
    """BFS shortest path between two nodes."""
    out_adj, _ = build_adjacency(graph)
    nmap = node_map(graph)

    if src not in nmap:
        print(f"Node '{src}' not found")
        return
    if tgt not in nmap:
        print(f"Node '{tgt}' not found")
        return

    # BFS (undirected)
    adj = defaultdict(set)
    for e in graph["edges"]:
        adj[e["source"]].add((e["target"], e["relationship"]))
        adj[e["target"]].add((e["source"], e["relationship"]))

    visited = {src}
    queue = [(src, [(src, "")])]
    while queue:
        node, path = queue.pop(0)
        if node == tgt:
            print(f"Path ({len(path) - 1} hops):")
            for i, (n, rel) in enumerate(path):
                prefix = "  " * i
                ntype = nmap.get(n, {}).get("type", "?")
                if rel:
                    print(f"{prefix}--[{rel}]--> {n} ({ntype})")
                else:
                    print(f"{prefix}{n} ({ntype})")
            return
        for neighbor, rel in adj.get(node, set()):
            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, path + [(neighbor, rel)]))

    print(f"No path found between {src} and {tgt}")


def cmd_neighbors(graph: dict, node_id: str):
    """Show all neighbors of a node."""
    nmap = node_map(graph)
    if node_id not in nmap:
        print(f"Node '{node_id}' not found")
        return

    n = nmap[node_id]
    print(f"Node: {n['id']} (type: {n['type']})")
    for k, v in n.items():
        if k not in ("id", "type"):
            print(f"  {k}: {v}")

    out_edges = [e for e in graph["edges"] if e["source"] == node_id]
    in_edges = [e for e in graph["edges"] if e["target"] == node_id]

    if out_edges:
        print(f"\nOutgoing ({len(out_edges)}):")
        for e in out_edges:
            tgt_type = nmap.get(e["target"], {}).get("type", "?")
            extra = ""
            if "fidelity_pct" in e:
                extra = f" (fidelity: {e['fidelity_pct']}%)"
            print(f"  --[{e['relationship']}]--> {e['target']} ({tgt_type}){extra}")

    if in_edges:
        print(f"\nIncoming ({len(in_edges)}):")
        for e in in_edges:
            src_type = nmap.get(e["source"], {}).get("type", "?")
            print(f"  <--[{e['relationship']}]-- {e['source']} ({src_type})")


def cmd_stats(graph: dict):
    """Print full statistics."""
    s = graph["stats"]
    print("=== Knowledge Graph Statistics ===")
    for k, v in s.items():
        if isinstance(v, dict):
            print(f"  {k}:")
            for sk, sv in v.items():
                print(f"    {sk}: {sv}")
        else:
            print(f"  {k}: {v}")

    # Edge type distribution
    edge_types = defaultdict(int)
    for e in graph["edges"]:
        edge_types[e["relationship"]] += 1
    print("\n  edge_types:")
    for rel, count in sorted(edge_types.items(), key=lambda x: -x[1]):
        print(f"    {rel}: {count}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["gaps", "patches", "cwes", "attack",
                                            "orphans", "path", "neighbors", "stats"],
                        help="Query command")
    parser.add_argument("args", nargs="*", help="Command arguments")
    parser.add_argument("-g", "--graph", default=str(GRAPH_PATH),
                        help="Knowledge graph JSON path")
    args = parser.parse_args()

    graph = load_graph(Path(args.graph))

    if args.command == "gaps":
        cmd_gaps(graph)
    elif args.command == "patches":
        cmd_patches(graph)
    elif args.command == "cwes":
        cmd_cwes(graph)
    elif args.command == "attack":
        cmd_attack(graph)
    elif args.command == "orphans":
        cmd_orphans(graph)
    elif args.command == "path":
        if len(args.args) != 2:
            print("Usage: query-graph.py path <source> <target>")
            sys.exit(1)
        cmd_path(graph, args.args[0], args.args[1])
    elif args.command == "neighbors":
        if len(args.args) != 1:
            print("Usage: query-graph.py neighbors <node_id>")
            sys.exit(1)
        cmd_neighbors(graph, args.args[0])
    elif args.command == "stats":
        cmd_stats(graph)


if __name__ == "__main__":
    main()
