#!/usr/bin/env python3
"""Generate Mermaid diagrams from the ICC security knowledge graph.

Usage:
  generate-mermaid.py cve-flow       # CVE → Heuristic → CWE flow
  generate-mermaid.py patch-impact   # Patch impact diagram
  generate-mermaid.py fuzzer-map     # Fuzzer → Tool mapping
  generate-mermaid.py severity       # Severity pie chart
  generate-mermaid.py all            # All diagrams to call-graph/mermaid/
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

GRAPH_PATH = Path(__file__).resolve().parent.parent / "knowledge-graph.json"
MERMAID_DIR = Path(__file__).resolve().parent.parent / "mermaid"


def load_graph(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def node_map(graph: dict) -> dict:
    return {n["id"]: n for n in graph["nodes"]}


def sanitize_id(s: str) -> str:
    """Make string safe for Mermaid node IDs."""
    return s.replace("-", "_").replace(":", "_").replace("/", "_").replace(" ", "_")


def sanitize_label(s: str) -> str:
    """Escape quotes in labels."""
    return s.replace('"', "'").replace("\n", " ")[:60]


def diagram_cve_flow(graph: dict) -> str:
    """Generate CVE → Heuristic → CWE flow diagram."""
    lines = ["graph LR"]
    nmap = node_map(graph)

    # Collect DETECTS and CLASSIFIES edges
    detects = defaultdict(list)  # heuristic → [cve/ghsa]
    classifies = {}  # heuristic → cwe

    for e in graph["edges"]:
        if e["relationship"] == "DETECTS":
            detects[e["source"]].append(e["target"])
        elif e["relationship"] == "CLASSIFIES":
            classifies[e["source"]] = e["target"]

    # Only show heuristics with CVE links (keep diagram readable)
    shown_cves = set()
    shown_cwes = set()

    for hid, cves in sorted(detects.items()):
        h_node = nmap.get(hid, {})
        severity = h_node.get("severity", "INFO")
        style = {"CRITICAL": ":::critical", "HIGH": ":::high",
                 "MEDIUM": ":::medium"}.get(severity, "")

        h_safe = sanitize_id(hid)
        h_label = f"{hid}: {h_node.get('name', '')[:30]}"
        lines.append(f"    {h_safe}[\"{sanitize_label(h_label)}\"]")

        for cve in cves[:3]:  # Limit edges per heuristic
            c_safe = sanitize_id(cve)
            if cve not in shown_cves:
                sev = nmap.get(cve, {}).get("severity", "")
                lines.append(f"    {c_safe}((\"{cve}\"))")
                shown_cves.add(cve)
            lines.append(f"    {c_safe} -->|detects| {h_safe}")

        cwe = classifies.get(hid)
        if cwe:
            cwe_safe = sanitize_id(cwe)
            if cwe not in shown_cwes:
                lines.append(f"    {cwe_safe}[/\"{cwe}\"/]")
                shown_cwes.add(cwe)
            lines.append(f"    {h_safe} -->|classifies| {cwe_safe}")

    # Styles
    lines.append("")
    lines.append("    classDef critical fill:#d32f2f,color:#fff,stroke:#b71c1c")
    lines.append("    classDef high fill:#f57c00,color:#fff,stroke:#e65100")
    lines.append("    classDef medium fill:#fbc02d,color:#000,stroke:#f9a825")

    return "\n".join(lines)


def diagram_patch_impact(graph: dict) -> str:
    """Generate patch impact diagram."""
    lines = ["graph TD"]
    nmap = node_map(graph)

    patches = [n for n in graph["nodes"] if n["type"] == "patch"]
    patches.sort(key=lambda p: p.get("priority", "P9"))

    # Group by priority
    by_priority = defaultdict(list)
    for p in patches:
        by_priority[p.get("priority", "?")].append(p)

    for pri in sorted(by_priority):
        pri_safe = sanitize_id(pri)
        pri_label = "{" + f'"{pri}"' + "}"
        lines.append(f"    {pri_safe}{pri_label}")

        for p in by_priority[pri][:8]:
            p_safe = sanitize_id(p["id"])
            defense = p.get("v1_defense", "?")
            style = ":::covered" if defense == "covered" else ":::uncovered"
            lines.append(f"    {p_safe}[\"{p['id']}: {p.get('reachability', '')[:20]}\"]")
            lines.append(f"    {pri_safe} --> {p_safe}")

            # Link to CWEs
            for e in graph["edges"]:
                if e["source"] == p["id"] and e["relationship"] == "ADDRESSES":
                    cwe_safe = sanitize_id(e["target"])
                    lines.append(f"    {p_safe} -.->|addresses| {cwe_safe}")

    lines.append("")
    lines.append("    classDef covered fill:#4caf50,color:#fff")
    lines.append("    classDef uncovered fill:#f44336,color:#fff")

    return "\n".join(lines)


def diagram_fuzzer_map(graph: dict) -> str:
    """Generate fuzzer → tool mapping diagram."""
    lines = ["graph LR"]
    nmap = node_map(graph)

    fuzzers = [n for n in graph["nodes"] if n["type"] == "fuzzer"]

    for f in sorted(fuzzers, key=lambda x: x["id"]):
        f_safe = sanitize_id(f["id"])
        f_name = f.get("name", f["id"]).replace("icc_", "").replace("_fuzzer", "")
        lines.append(f"    {f_safe}[\"{f_name}\"]:::fuzzer")

        for e in graph["edges"]:
            if e["source"] == f["id"] and e["relationship"] == "TARGETS":
                t_safe = sanitize_id(e["target"])
                t_name = nmap.get(e["target"], {}).get("name", e["target"])
                fidelity = e.get("fidelity_pct", "")
                label = f"|{fidelity}%|" if fidelity else ""
                lines.append(f"    {t_safe}([\"{t_name}\"]):::tool")
                lines.append(f"    {f_safe} -->{label} {t_safe}")

    lines.append("")
    lines.append("    classDef fuzzer fill:#1565c0,color:#fff,stroke:#0d47a1")
    lines.append("    classDef tool fill:#2e7d32,color:#fff,stroke:#1b5e20")

    return "\n".join(lines)


def diagram_severity(graph: dict) -> str:
    """Generate severity pie chart."""
    sev = graph["stats"].get("severity_distribution", {})
    lines = ["pie title Heuristic Severity Distribution"]
    for level, count in sev.items():
        lines.append(f'    "{level}" : {count}')
    return "\n".join(lines)


def write_diagram(name: str, content: str, out_dir: Path):
    """Write a Mermaid diagram to file."""
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{name}.md"
    with open(path, "w") as f:
        f.write(f"# {name.replace('-', ' ').title()}\n\n")
        f.write("```mermaid\n")
        f.write(content)
        f.write("\n```\n")
    print(f"  Wrote {path}")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("diagram", choices=["cve-flow", "patch-impact",
                                            "fuzzer-map", "severity", "all"],
                        help="Diagram to generate")
    parser.add_argument("-g", "--graph", default=str(GRAPH_PATH),
                        help="Knowledge graph JSON path")
    parser.add_argument("-o", "--output-dir", default=str(MERMAID_DIR),
                        help="Output directory for markdown files")
    parser.add_argument("--stdout", action="store_true",
                        help="Print to stdout instead of file")
    args = parser.parse_args()

    graph = load_graph(Path(args.graph))
    out_dir = Path(args.output_dir)

    generators = {
        "cve-flow": ("cve-flow", diagram_cve_flow),
        "patch-impact": ("patch-impact", diagram_patch_impact),
        "fuzzer-map": ("fuzzer-map", diagram_fuzzer_map),
        "severity": ("severity", diagram_severity),
    }

    if args.diagram == "all":
        targets = list(generators.values())
    else:
        targets = [generators[args.diagram]]

    for name, gen_fn in targets:
        content = gen_fn(graph)
        if args.stdout:
            print(f"--- {name} ---")
            print(content)
            print()
        else:
            write_diagram(name, content, out_dir)


if __name__ == "__main__":
    main()
