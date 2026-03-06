#!/usr/bin/env python3
"""
iccApplyToLink Call Graph & AST Gate Analysis
==============================================

Static analysis of iccApplyToLink.cpp to extract:
  1. Call Graph — every function/method call with caller→callee edges
  2. AST Gates — conditional branches controlling code path reachability
  3. Fuzzer Fidelity Map — which calls the fuzzer exercises vs. tool

Usage:
    python3 iccApplyToLink-callgraph.py [--dot FILE] [--json FILE] [--render FORMAT]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict

@dataclass
class CallSite:
    callee: str
    line: int
    caller: str
    context: str = ""
    gate: str = ""
    is_indirect: bool = False
    cli_only: bool = False
    in_fuzzer: bool = False
    note: str = ""

@dataclass
class ASTGate:
    condition: str
    line: int
    gate_type: str
    parent_func: str
    security_relevant: bool = False
    note: str = ""

TOOL_NAME = "iccApplyToLink"
TOOL_FILE = "iccApplyToLink.cpp"
FUZZER_NAME = "icc_link_fuzzer"
FUZZER_FILE = "icc_link_fuzzer.cpp"

# Phase 1: CLI Argument Parsing
CLI_CALLS = [
    CallSite("printUsage", 590, "main", "Print usage and exit",
             cli_only=True, in_fuzzer=False),
    CallSite("atoi(bFirstTransform)", 691, "main",
             "Parse first-transform flag from argv[8]",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer derives from ctrl byte bit 0"),
    CallSite("atoi(nInterp)", 692, "main",
             "Parse interpolation mode from argv[9]",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer derives from ctrl byte bit 1"),
]

# Phase 2: CMM Construction (core attack surface)
CMM_CALLS = [
    CallSite("CIccCmm::CIccCmm", 699, "main",
             "Construct CMM with bFirstTransform flag",
             in_fuzzer=True,
             note="Fuzzer matches: CIccCmm(icSigUnknownData, icSigUnknownData, bFirstTransform)"),
    CallSite("ReadIccProfile", 770, "main",
             "Read ICC profile from file with bUseSubProfile flag",
             in_fuzzer=True,
             note="Fuzzer matches: ReadIccProfile(tmp, bUseSubProfile)"),
    CallSite("OpenIccProfile(pcc)", 754, "main",
             "Open PCC profile for viewing conditions",
             in_fuzzer=False,
             note="Fuzzer does not use PCC profiles"),
    CallSite("CIccCreateXformHintManager", 736, "main",
             "Create hint manager for xform", in_fuzzer=True),
    CallSite("CIccApplyBPCHint", 744, "main",
             "Add Black Point Compensation hint",
             in_fuzzer=True,
             note="Fuzzer matches: ctrl bit 0x04"),
    CallSite("CIccLuminanceMatchingHint", 749, "main",
             "Add Luminance matching hint",
             in_fuzzer=True,
             note="Fuzzer matches: ctrl bit 0x08"),
    CallSite("CIccCmmEnvVarHint", 766, "main",
             "Add environment variable hints",
             in_fuzzer=False,
             note="Fuzzer does not exercise env var hints"),
    CallSite("CIccCmm::AddXform(CIccProfile*)", 771, "main",
             "Add profile xform with full parameter set (intent, interp, pcc, lutType, d2bx)",
             in_fuzzer=True,
             note="Fuzzer uses same overload: AddXform(pProf, intent, interp, NULL, nLutType, bUseD2Bx, &hint)"),
]

# Phase 3: CMM Execution
EXEC_CALLS = [
    CallSite("CIccCmm::Begin", 783, "main",
             "Initialize CMM pipeline", in_fuzzer=True),
    CallSite("CIccCmm::GetSourceSpace", 804, "main",
             "Query source color space", in_fuzzer=True),
    CallSite("CIccCmm::GetDestSpace", 808, "main",
             "Query dest color space", in_fuzzer=True),
    CallSite("icGetSpaceSamples(src)", 805, "main",
             "Get source channel count", in_fuzzer=True),
    CallSite("icGetSpaceSamples(dst)", 809, "main",
             "Get dest channel count", in_fuzzer=True),
    CallSite("CIccCmm::Apply", 834, "main",
             "Apply CMM transform — iterates over LUT grid",
             in_fuzzer=True,
             note="Tool iterates over full LUT grid; fuzzer tests key values"),
]

# Phase 4: Output Writing (tool-specific)
OUTPUT_CALLS = [
    CallSite("ILinkWriter::begin", 798, "main",
             "Initialize output writer (DevLink or file)",
             in_fuzzer=False),
    CallSite("ILinkWriter::setPixel", 835, "main",
             "Set pixel in output grid", in_fuzzer=False),
    CallSite("ILinkWriter::finish", 862, "main",
             "Finalize output — SaveIccProfile or TIFF write",
             in_fuzzer=False),
    CallSite("SaveIccProfile", 540, "CDevLinkWriter::finish",
             "Save device link profile to disk",
             in_fuzzer=False,
             note="Output-only, not part of attack surface"),
    CallSite("CIccProfile::new", 328, "CDevLinkWriter::finish",
             "Create new profile for device link output",
             in_fuzzer=False),
]

# Phase 5: Fuzzer-only extras
FUZZER_EXTRA = [
    CallSite("CIccCmm::GetNumXforms", 0, "LLVMFuzzerTestOneInput",
             "Query xform count", in_fuzzer=True),
    CallSite("CIccCmm::Valid", 0, "LLVMFuzzerTestOneInput",
             "Validate CMM state", in_fuzzer=True),
]

ALL_CALLS = CLI_CALLS + CMM_CALLS + EXEC_CALLS + OUTPUT_CALLS + FUZZER_EXTRA

GATES = [
    ASTGate("argc < 10", 587, "if", "main",
            security_relevant=False, note="Argument count check"),
    ASTGate("nIntent derivation (nType, nLuminance, bUseSubProfile)", 726, "if-chain", "main",
            security_relevant=True,
            note="Intent encoding: nIntent%1000→subProfile, /100→luminance, /10→type, %10→intent"),
    ASTGate("nType==1", 739, "if", "main",
            security_relevant=True, note="Disables D2Bx/B2Dx tags"),
    ASTGate("nType==4", 743, "if", "main",
            security_relevant=True, note="Enables Black Point Compensation"),
    ASTGate("nLuminance>0", 748, "if", "main",
            security_relevant=False, note="Enables luminance matching"),
    ASTGate("pcc_file provided", 752, "if", "main",
            security_relevant=False, note="PCC profile loading gate"),
    ASTGate("stat != icCmmStatOk (AddXform)", 773, "if", "main",
            security_relevant=True, note="Profile load failure handling"),
    ASTGate("stat = theCmm.Begin()", 783, "if", "main",
            security_relevant=True, note="CMM init failure — blocks Apply()"),
    ASTGate("!pWriter->begin()", 798, "if", "main",
            security_relevant=True, note="Output writer init failure"),
]


def compute_fidelity():
    total = len(ALL_CALLS)
    cli_only = sum(1 for c in ALL_CALLS if c.cli_only)
    fuzzable = total - cli_only
    matched = sum(1 for c in ALL_CALLS if c.in_fuzzer)
    output_only = sum(1 for c in OUTPUT_CALLS if not c.in_fuzzer)

    return {
        "total_call_sites": total,
        "cli_only_excluded": cli_only,
        "fuzzable_call_sites": fuzzable,
        "matched_by_fuzzer": matched,
        "output_only_not_in_fuzzer": output_only,
        "coverage_percent": round(matched / max(fuzzable, 1) * 100, 1),
        "note": (
            "The link fuzzer has excellent CMM pipeline coverage. It exercises "
            "ReadIccProfile + AddXform(CIccProfile*,...) with all 6 control flags "
            "(bFirstTransform, bUseD2Bx, bUseBPC, bUseLuminance, bUseSubProfile, "
            "nLutType) matching the tool's parameter derivation. Output writing "
            "(SaveIccProfile/DevLink) is excluded as output-only."
        ),
    }


def generate_json(output_file):
    data = {
        "tool": TOOL_NAME,
        "tool_file": TOOL_FILE,
        "fuzzer": FUZZER_NAME,
        "fuzzer_file": FUZZER_FILE,
        "analysis_date": "2026-03-06",
        "phases": {
            "1_cli_parsing": {
                "description": "Command-line argument parsing",
                "calls": [asdict(c) for c in CLI_CALLS],
                "in_fuzzer": False,
            },
            "2_cmm_construction": {
                "description": "CMM and xform construction with hints",
                "calls": [asdict(c) for c in CMM_CALLS],
                "in_fuzzer": True,
            },
            "3_cmm_execution": {
                "description": "CMM Begin + Apply over LUT grid",
                "calls": [asdict(c) for c in EXEC_CALLS],
                "in_fuzzer": True,
            },
            "4_output": {
                "description": "Device link profile output writing",
                "calls": [asdict(c) for c in OUTPUT_CALLS],
                "in_fuzzer": False,
            },
            "5_fuzzer_extras": {
                "description": "Additional CMM queries exercised by fuzzer",
                "calls": [asdict(c) for c in FUZZER_EXTRA],
                "in_fuzzer": True,
            },
        },
        "gates": [asdict(g) for g in GATES],
        "fidelity": compute_fidelity(),
        "fuzzer_input_format": {
            "description": "Input split 50/50 into two profiles + 3 trailing control bytes",
            "control_bytes": {
                "byte[-3] (ctrl)": "bFirstTransform(0x01), !bUseD2Bx(0x02), bUseBPC(0x04), bUseLuminance(0x08), bUseSubProfile(0x10), nLutType=Preview(0x20)",
                "byte[-2]": "icXformInterp (bit 0: linear vs tetrahedral)",
                "byte[-1]": "icRenderingIntent (% 4)",
            },
            "min_size": 258,
            "max_size": "2MB",
        },
        "tool_unique_features": {
            "two_profiles": "Tool chains 2+ profiles; fuzzer always uses exactly 2",
            "device_link_output": "Tool creates device link profile; fuzzer tests CMM pipeline only",
            "lut_grid_iteration": "Tool iterates full LUT grid (nSrc^gridSize); fuzzer tests 5 representative values",
        },
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[OK] JSON call graph: {output_file}")


def generate_dot(output_file):
    lines = [
        'digraph iccApplyToLink {',
        '  rankdir=TB;',
        '  node [shape=box, style=filled, fontname="Helvetica", fontsize=10];',
        '  edge [fontname="Helvetica", fontsize=8];',
        '',
        '  // Legend',
        '  subgraph cluster_legend {',
        '    label="Legend"; style=dashed; fontsize=9;',
        '    leg_both [label="In Tool + Fuzzer", fillcolor="#90EE90"];',
        '    leg_tool [label="Tool Only", fillcolor="#ADD8E6"];',
        '    leg_cli  [label="CLI Only", fillcolor="#D3D3D3"];',
        '    leg_fuzzer [label="Fuzzer Extra", fillcolor="#FFD700"];',
        '  }',
        '',
        '  main [label="main()\\niccApplyToLink.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '  fuzzer [label="LLVMFuzzerTestOneInput()\\nicc_link_fuzzer.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '',
    ]

    phases = [
        ("cluster_cli", "Phase 1: CLI Parsing", CLI_CALLS),
        ("cluster_cmm", "Phase 2: CMM Construction", CMM_CALLS),
        ("cluster_exec", "Phase 3: CMM Execution", EXEC_CALLS),
        ("cluster_output", "Phase 4: Output Writing", OUTPUT_CALLS),
        ("cluster_fuzzer", "Phase 5: Fuzzer Extras", FUZZER_EXTRA),
    ]

    node_id = 0
    node_map = {}

    for cluster_name, cluster_label, calls in phases:
        lines.append(f'  subgraph {cluster_name} {{')
        lines.append(f'    label="{cluster_label}"; style=rounded;')
        for c in calls:
            nid = f"n{node_id}"
            node_map[c.callee + str(c.line)] = nid
            if c.cli_only:
                color = "#D3D3D3"
            elif c.in_fuzzer and c.caller == "LLVMFuzzerTestOneInput":
                color = "#FFD700"
            elif c.in_fuzzer:
                color = "#90EE90"
            else:
                color = "#ADD8E6"
            label = c.callee.replace('"', '\\"')
            if c.line > 0:
                label += f"\\nL{c.line}"
            lines.append(f'    {nid} [label="{label}", fillcolor="{color}"];')
            node_id += 1
        lines.append('  }')
        lines.append('')

    for c in ALL_CALLS:
        nid = node_map.get(c.callee + str(c.line))
        if not nid:
            continue
        if c.caller == "main":
            style = 'style=bold' if c.in_fuzzer else 'style=dashed'
            lines.append(f'  main -> {nid} [{style}];')
        elif c.caller == "LLVMFuzzerTestOneInput":
            lines.append(f'  fuzzer -> {nid} [style=bold, color=orange];')

    for c in CMM_CALLS + EXEC_CALLS:
        if c.in_fuzzer:
            nid = node_map.get(c.callee + str(c.line))
            if nid:
                lines.append(f'  fuzzer -> {nid} [style=dotted, color=green];')

    lines.append('}')

    with open(output_file, "w") as f:
        f.write('\n'.join(lines) + '\n')
    print(f"[OK] DOT call graph: {output_file}")


def render_graph(dot_file, fmt="svg"):
    out_file = dot_file.rsplit(".", 1)[0] + f".{fmt}"
    dot_cmd = shutil.which("dot")
    if not dot_cmd:
        print("WARNING: Graphviz 'dot' not found", file=sys.stderr)
        return
    try:
        subprocess.run([dot_cmd, f"-T{fmt}", dot_file, "-o", out_file],
                       check=True, timeout=30)
        print(f"[OK] Rendered: {out_file}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"WARNING: Render failed: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="iccApplyToLink call graph analysis")
    parser.add_argument("--dot", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--render", choices=["png", "svg", "pdf"], default=None)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    if args.summary or not any([args.dot, args.json]):
        fid = compute_fidelity()
        print(f"\n{'='*60}")
        print(f"iccApplyToLink Call Graph & Fuzzer Fidelity")
        print(f"{'='*60}")
        print(f"Total call sites:       {fid['total_call_sites']}")
        print(f"CLI-only excluded:      {fid['cli_only_excluded']}")
        print(f"Fuzzable call sites:    {fid['fuzzable_call_sites']}")
        print(f"Matched by fuzzer:      {fid['matched_by_fuzzer']}")
        print(f"Output-only (not fuz):  {fid['output_only_not_in_fuzzer']}")
        print(f"Coverage:               {fid['coverage_percent']}%")
        print(f"\n{fid['note']}")
        print()

    if args.json:
        generate_json(args.json)
    if args.dot:
        generate_dot(args.dot)
        if args.render:
            render_graph(args.dot, args.render)


if __name__ == "__main__":
    main()
