#!/usr/bin/env python3
"""
iccRoundTrip Call Graph & AST Gate Analysis
============================================

Static analysis of iccRoundTrip.cpp to extract call graph, AST gates,
and fuzzer fidelity mapping for the icc_roundtrip_fuzzer.

This tool is notable for:
  - Deep CMM evaluation via EvaluateProfile() (constructs internal CMM pipeline)
  - PRMG (Perceptual Reference Medium Gamut) analysis
  - CIccMinMaxEval callback — exercises Compare() with DeltaE computations
  - Very high fuzzer fidelity — fuzzer copies the CIccMinMaxEval class verbatim

Usage:
    python3 iccRoundTrip-callgraph.py [--dot FILE] [--json FILE] [--render FORMAT]
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

TOOL_NAME = "iccRoundTrip"
TOOL_FILE = "iccRoundTrip.cpp"
FUZZER_NAME = "icc_roundtrip_fuzzer"
FUZZER_FILE = "icc_roundtrip_fuzzer.cpp"

# Phase 1: CLI Argument Parsing
CLI_CALLS = [
    CallSite("printf(usage)", 152, "main",
             "Print usage and exit", cli_only=True, in_fuzzer=False),
    CallSite("atoi(argv[2])", 162, "main",
             "Parse rendering intent from CLI arg",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer derives intent from trailing byte: data[size-1] % 4"),
    CallSite("atoi(argv[3])", 164, "main",
             "Parse use_mpe flag from CLI arg",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer derives from trailing byte: data[size-2] % 2"),
]

# Phase 2: Round-Trip Evaluation (core attack surface)
EVAL_CALLS = [
    CallSite("CIccMinMaxEval::CIccMinMaxEval", 168, "main",
             "Construct min/max evaluation object",
             in_fuzzer=True,
             note="Fuzzer copies the full CIccMinMaxEval class verbatim"),
    CallSite("CIccEvalCompare::EvaluateProfile", 170, "main",
             "Evaluate profile round-trip accuracy — MAIN ATTACK SURFACE",
             in_fuzzer=True,
             note="Exact 1:1 match: eval.EvaluateProfile(file, 0, intent, interp, useMPE)"),
]

# Phase 3: PRMG Analysis
PRMG_CALLS = [
    CallSite("CIccPRMG::CIccPRMG", 177, "main",
             "Construct PRMG analysis object", in_fuzzer=True),
    CallSite("CIccPRMG::EvaluateProfile", 179, "main",
             "Evaluate PRMG interoperability — second attack surface",
             in_fuzzer=True,
             note="Exact 1:1 match: prmg.EvaluateProfile(file, intent, interp, useMPE)"),
]

# Phase 4: Result Access (exercises member reads)
RESULT_CALLS = [
    CallSite("CIccInfo::GetRenderingIntentName", 189, "main",
             "Get human-readable intent name", in_fuzzer=False,
             note="Tool-only: printf output"),
    CallSite("eval.GetMean1", 195, "main",
             "Get mean DeltaE for round-trip 1", in_fuzzer=True,
             note="Fuzzer accesses via (void)eval.GetMean1()"),
    CallSite("eval.GetMean2", 203, "main",
             "Get mean DeltaE for round-trip 2", in_fuzzer=True),
    CallSite("eval.minDE1/maxDE1", 194, "main",
             "Access min/max DeltaE round-trip 1", in_fuzzer=True),
    CallSite("eval.minDE2/maxDE2", 202, "main",
             "Access min/max DeltaE round-trip 2", in_fuzzer=True),
    CallSite("eval.maxLab1/maxLab2", 198, "main",
             "Access max Lab values for worst-case samples", in_fuzzer=True),
    CallSite("prmg.m_bPrmgImplied", 190, "main",
             "Check if PRMG gamut is implied", in_fuzzer=True),
    CallSite("prmg.m_nDE1..m_nDE10", 212, "main",
             "Access PRMG DeltaE distribution bins", in_fuzzer=True),
    CallSite("prmg.m_nTotal", 208, "main",
             "Access PRMG total sample count", in_fuzzer=True),
]

# Phase 5: Deep call chains from EvaluateProfile
DEEP_CALLS = [
    CallSite("OpenIccProfile", 0, "CIccEvalCompare::EvaluateProfile",
             "Open ICC profile from file path", in_fuzzer=True),
    CallSite("CIccCmm::AddXform (forward)", 0, "EvaluateProfile",
             "Add forward transform to CMM pipeline", in_fuzzer=True),
    CallSite("CIccCmm::AddXform (inverse)", 0, "EvaluateProfile",
             "Add inverse transform for round-trip", in_fuzzer=True,
             note="Round-trip requires forward+inverse pipeline"),
    CallSite("CIccCmm::Begin", 0, "EvaluateProfile",
             "Initialize round-trip CMM pipeline", in_fuzzer=True),
    CallSite("CIccCmm::Apply", 0, "EvaluateProfile",
             "Apply round-trip transform to test samples", in_fuzzer=True),
    CallSite("CIccMinMaxEval::Compare", 0, "EvaluateProfile",
             "Compare results via icDeltaE — callback for each sample",
             in_fuzzer=True,
             note="Fuzzer copies this class verbatim from tool source"),
    CallSite("icDeltaE", 0, "CIccMinMaxEval::Compare",
             "Compute CIE Delta E between Lab values", in_fuzzer=True),
]

ALL_CALLS = CLI_CALLS + EVAL_CALLS + PRMG_CALLS + RESULT_CALLS + DEEP_CALLS

GATES = [
    ASTGate("argc <= 1", 151, "if", "main",
            security_relevant=False, note="Usage message guard"),
    ASTGate("argc > 2", 161, "if", "main",
            security_relevant=False, note="Optional intent argument"),
    ASTGate("argc > 3", 163, "if", "main",
            security_relevant=False, note="Optional use_mpe argument"),
    ASTGate("stat != icCmmStatOk (EvaluateProfile)", 172, "if", "main",
            security_relevant=True,
            note="Round-trip evaluation failure — prevents result access"),
    ASTGate("stat != icCmmStatOk (PRMG)", 181, "if", "main",
            security_relevant=True,
            note="PRMG analysis failure — prevents PRMG result output"),
    ASTGate("prmg.m_nTotal > 0", 208, "if", "main",
            security_relevant=False,
            note="Guards PRMG output — division by m_nTotal"),
    ASTGate("DE1 < minDE1", 118, "if", "CIccMinMaxEval::Compare",
            security_relevant=False, note="Min tracking in Compare callback"),
    ASTGate("DE1 > maxDE1", 122, "if", "CIccMinMaxEval::Compare",
            security_relevant=False, note="Max tracking with memcpy of Lab values"),
    ASTGate("DE2 <= 1.0", 136, "if", "CIccMinMaxEval::Compare",
            security_relevant=False, note="Count samples within 1.0 DeltaE"),
]


def compute_fidelity():
    total = len(ALL_CALLS)
    cli_only = sum(1 for c in ALL_CALLS if c.cli_only)
    fuzzable = total - cli_only
    matched = sum(1 for c in ALL_CALLS if c.in_fuzzer)

    return {
        "total_call_sites": total,
        "cli_only_excluded": cli_only,
        "fuzzable_call_sites": fuzzable,
        "matched_by_fuzzer": matched,
        "coverage_percent": round(matched / max(fuzzable, 1) * 100, 1),
        "fidelity_note": "NEAR-PERFECT",
        "note": (
            "The roundtrip fuzzer has near-perfect fidelity. It copies the "
            "CIccMinMaxEval class verbatim from the tool source (lines 79-146), "
            "calls EvaluateProfile and PRMG EvaluateProfile with the same API, "
            "and accesses all result members. The only differences are: "
            "(1) intent/useMPE derived from trailing bytes instead of CLI args, "
            "(2) profile written to temp file from fuzzer input, "
            "(3) printf output is suppressed."
        ),
    }


def generate_json(output_file):
    data = {
        "tool": TOOL_NAME,
        "tool_file": TOOL_FILE,
        "fuzzer": FUZZER_NAME,
        "fuzzer_file": FUZZER_FILE,
        "analysis_date": "2026-07-20",
        "phases": {
            "1_cli_parsing": {
                "description": "Command-line argument parsing",
                "calls": [asdict(c) for c in CLI_CALLS],
                "in_fuzzer": False,
            },
            "2_roundtrip_eval": {
                "description": "Round-trip evaluation — main attack surface",
                "calls": [asdict(c) for c in EVAL_CALLS],
                "in_fuzzer": True,
            },
            "3_prmg_analysis": {
                "description": "PRMG interoperability analysis",
                "calls": [asdict(c) for c in PRMG_CALLS],
                "in_fuzzer": True,
            },
            "4_result_access": {
                "description": "Access evaluation result members",
                "calls": [asdict(c) for c in RESULT_CALLS],
                "in_fuzzer": True,
            },
            "5_deep_calls": {
                "description": "Deep call chains within EvaluateProfile",
                "calls": [asdict(c) for c in DEEP_CALLS],
                "in_fuzzer": True,
            },
        },
        "gates": [asdict(g) for g in GATES],
        "fidelity": compute_fidelity(),
        "attack_surface_notes": {
            "evaluate_profile": (
                "EvaluateProfile internally constructs a CIccCmm with forward+inverse "
                "transforms. It iterates over a grid of test values, applying the round-trip "
                "and calling Compare() for each sample. This exercises the full CMM pipeline "
                "including LUT interpolation, curves, and matrix operations."
            ),
            "prmg_analysis": (
                "CIccPRMG::EvaluateProfile tests the profile against the Perceptual "
                "Reference Medium Gamut. It uses a fixed set of PRMG colors and computes "
                "DeltaE distributions."
            ),
        },
        "fuzzer_input_format": {
            "description": "ICC profile data with 2 trailing control bytes",
            "control_bytes": {
                "data[size-1]": "icRenderingIntent (% 4)",
                "data[size-2]": "nUseMPE flag (% 2)",
            },
            "min_size": 130,
            "max_size": "1MB",
        },
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[OK] JSON call graph: {output_file}")


def generate_dot(output_file):
    lines = [
        'digraph iccRoundTrip {',
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
        '  }',
        '',
        '  tool [label="main()\\niccRoundTrip.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '  fuzzer [label="LLVMFuzzerTestOneInput()\\nicc_roundtrip_fuzzer.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '',
        '  // CLI',
        '  subgraph cluster_cli {',
        '    label="Phase 1: CLI Parsing"; style=rounded;',
        '    usage [label="printf(usage)", fillcolor="#D3D3D3"];',
        '    parse_intent [label="atoi(intent)", fillcolor="#D3D3D3"];',
        '    parse_mpe [label="atoi(use_mpe)", fillcolor="#D3D3D3"];',
        '  }',
        '',
        '  // Round-trip eval',
        '  subgraph cluster_eval {',
        '    label="Phase 2: Round-Trip Evaluation (Attack Surface)"; style=rounded; color=red;',
        '    eval_ctor [label="CIccMinMaxEval()", fillcolor="#90EE90"];',
        '    eval_profile [label="EvaluateProfile()\\nMAIN ENTRY", fillcolor="#90EE90", penwidth=3];',
        '  }',
        '',
        '  // PRMG',
        '  subgraph cluster_prmg {',
        '    label="Phase 3: PRMG Analysis"; style=rounded; color=red;',
        '    prmg_ctor [label="CIccPRMG()", fillcolor="#90EE90"];',
        '    prmg_eval [label="CIccPRMG::EvaluateProfile", fillcolor="#90EE90", penwidth=3];',
        '  }',
        '',
        '  // Results',
        '  subgraph cluster_results {',
        '    label="Phase 4: Result Access"; style=rounded;',
        '    get_mean [label="GetMean1/GetMean2", fillcolor="#90EE90"];',
        '    get_minmax [label="minDE/maxDE", fillcolor="#90EE90"];',
        '    get_lab [label="maxLab1/maxLab2", fillcolor="#90EE90"];',
        '    prmg_results [label="PRMG DE bins\\nm_nDE1..m_nDE10", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Deep calls',
        '  subgraph cluster_deep {',
        '    label="Phase 5: Internal CMM Pipeline"; style=rounded; color=red;',
        '    open_profile [label="OpenIccProfile", fillcolor="#90EE90"];',
        '    add_fwd [label="AddXform\\n(forward)", fillcolor="#90EE90"];',
        '    add_inv [label="AddXform\\n(inverse)", fillcolor="#90EE90"];',
        '    cmm_begin [label="CIccCmm::Begin", fillcolor="#90EE90"];',
        '    cmm_apply [label="CIccCmm::Apply", fillcolor="#90EE90"];',
        '    compare [label="Compare()\\nicDeltaE", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Tool edges',
        '  tool -> usage [style=dashed];',
        '  tool -> parse_intent [style=dashed];',
        '  tool -> parse_mpe [style=dashed];',
        '  tool -> eval_ctor;',
        '  tool -> eval_profile [style=bold, penwidth=2];',
        '  tool -> prmg_ctor;',
        '  tool -> prmg_eval [style=bold, penwidth=2];',
        '  tool -> get_mean;',
        '  tool -> get_minmax;',
        '  tool -> get_lab;',
        '  tool -> prmg_results;',
        '',
        '  // Fuzzer edges',
        '  fuzzer -> eval_ctor [style=dotted, color=green];',
        '  fuzzer -> eval_profile [style=bold, color=green, penwidth=2];',
        '  fuzzer -> prmg_ctor [style=dotted, color=green];',
        '  fuzzer -> prmg_eval [style=bold, color=green, penwidth=2];',
        '  fuzzer -> get_mean [style=dotted, color=green];',
        '  fuzzer -> get_minmax [style=dotted, color=green];',
        '  fuzzer -> get_lab [style=dotted, color=green];',
        '  fuzzer -> prmg_results [style=dotted, color=green];',
        '',
        '  // Deep call chain',
        '  eval_profile -> open_profile [style=bold];',
        '  eval_profile -> add_fwd [style=bold];',
        '  eval_profile -> add_inv [style=bold];',
        '  eval_profile -> cmm_begin [style=bold];',
        '  eval_profile -> cmm_apply [style=bold];',
        '  cmm_apply -> compare [style=bold, color=red];',
        '',
        '}',
    ]

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
    parser = argparse.ArgumentParser(description="iccRoundTrip call graph analysis")
    parser.add_argument("--dot", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--render", choices=["png", "svg", "pdf"], default=None)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    if args.summary or not any([args.dot, args.json]):
        fid = compute_fidelity()
        print(f"\n{'='*60}")
        print(f"iccRoundTrip Call Graph & Fuzzer Fidelity")
        print(f"{'='*60}")
        print(f"Total call sites:      {fid['total_call_sites']}")
        print(f"CLI-only excluded:     {fid['cli_only_excluded']}")
        print(f"Fuzzable call sites:   {fid['fuzzable_call_sites']}")
        print(f"Matched by fuzzer:     {fid['matched_by_fuzzer']}")
        print(f"Coverage:              {fid['coverage_percent']}%")
        print(f"Fidelity:              {fid['fidelity_note']}")
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
