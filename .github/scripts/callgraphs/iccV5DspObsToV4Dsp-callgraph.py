#!/usr/bin/env python3
"""
iccV5DspObsToV4Dsp Call Graph & AST Gate Analysis
===================================================

Static analysis of IccV5DspObsToV4Dsp.cpp to extract call graph, AST gates,
and fuzzer fidelity mapping for the icc_v5dspobs_fuzzer (primary),
icc_spectral_fuzzer.

This tool is notable for:
  - V5→V4 display profile conversion using MPE pipeline
  - Direct tag-level MPE processing (no CIccCmm abstraction)
  - CurveSet + EmissionMatrix MPE element Apply
  - customToStandardPcc tag processing
  - TRC curve generation (2048 samples per channel)
  - Colorant XYZ computation from spectral data

Usage:
    python3 iccV5DspObsToV4Dsp-callgraph.py [--dot FILE] [--json FILE] [--render FORMAT]
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

TOOL_NAME = "iccV5DspObsToV4Dsp"
TOOL_FILE = "IccV5DspObsToV4Dsp.cpp"
FUZZER_NAME = "icc_v5dspobs_fuzzer"
FUZZER_FILE = "icc_v5dspobs_fuzzer.cpp"

# Phase 1: CLI and Display Profile Loading
LOAD_DSP_CALLS = [
    CallSite("Usage()", 103, "main",
             "Print usage and exit", cli_only=True, in_fuzzer=False),
    CallSite("ReadIccProfile(dsp, true)", 108, "main",
             "Read V5 display profile with sub-profile support",
             in_fuzzer=True,
             note="Fuzzer matches: ReadIccProfile(dspTmpFile, true)"),
]

# Phase 2: Display Profile Validation
VALIDATE_DSP_CALLS = [
    CallSite("dspIcc->m_Header.version check", 115, "main",
             "Verify profile is V5 or later",
             in_fuzzer=True,
             note="Fuzzer checks same version constraint"),
    CallSite("dspIcc->m_Header.deviceClass check", 116, "main",
             "Verify profile is display class (icSigDisplayClass)",
             in_fuzzer=True),
    CallSite("dspIcc->FindTagOfType(AToB1, MPE)", 121, "main",
             "Find AToB1 tag as MultiProcessElement type",
             in_fuzzer=True,
             note="Critical gate — profile must have spectral emission AToB1"),
]

# Phase 3: MPE Structure Validation
MPE_VALIDATE_CALLS = [
    CallSite("pTagIn->NumElements()", 130, "main",
             "Verify AToB1 has exactly 2 MPE elements",
             in_fuzzer=True),
    CallSite("pTagIn->NumInputChannels()", 131, "main",
             "Verify 3 input channels", in_fuzzer=True),
    CallSite("pTagIn->NumOutputChannels()", 132, "main",
             "Verify 3 output channels", in_fuzzer=True),
    CallSite("pTagIn->GetElement(0) [CurveSet]", 133, "main",
             "Get first MPE element — must be CurveSet type",
             in_fuzzer=True),
    CallSite("pTagIn->GetElement(1) [EmissionMatrix]", 135, "main",
             "Get second MPE element — must be EmissionMatrix type",
             in_fuzzer=True),
]

# Phase 4: Observer/PCC Profile Loading
LOAD_PCC_CALLS = [
    CallSite("ReadIccProfile(pcc)", 141, "main",
             "Read observer/PCC V5 profile",
             in_fuzzer=True,
             note="Fuzzer matches: ReadIccProfile(obsTmpFile)"),
    CallSite("pccIcc->m_Header.version check", 148, "main",
             "Verify PCC profile is V5", in_fuzzer=True),
    CallSite("FindTagOfType(svcn)", 153, "main",
             "Find spectralViewingConditions tag in PCC profile",
             in_fuzzer=True),
    CallSite("FindTagOfType(c2sp, MPE)", 154, "main",
             "Find customToStandardPcc tag as MPE type",
             in_fuzzer=True),
    CallSite("pTagC2S->NumInputChannels()", 158, "main",
             "Verify C2S has 3 input channels", in_fuzzer=True),
    CallSite("pTagC2S->NumOutputChannels()", 159, "main",
             "Verify C2S has 3 output channels", in_fuzzer=True),
]

# Phase 5: MPE Pipeline Initialization
MPE_INIT_CALLS = [
    CallSite("pTagIn->Begin(icElemInterpLinear, dspIcc, pccIcc)", 164, "main",
             "Initialize display AToB1 MPE pipeline with PCC context",
             in_fuzzer=True,
             note="Critical: links display profile MPE with observer PCC"),
    CallSite("pTagIn->GetNewApply()", 166, "main",
             "Create apply context for AToB1 MPE pipeline",
             in_fuzzer=True),
    CallSite("pApplyMpe->GetList() [iterate]", 168, "main",
             "Get apply list and extract curve/matrix apply contexts",
             in_fuzzer=True),
    CallSite("pTagC2S->Begin(icElemInterpLinear, pccIcc)", 174, "main",
             "Initialize C2S PCC tag MPE pipeline",
             in_fuzzer=True),
    CallSite("pTagC2S->GetNewApply()", 176, "main",
             "Create apply context for C2S MPE pipeline",
             in_fuzzer=True),
]

# Phase 6: V4 Profile Construction
V4_BUILD_CALLS = [
    CallSite("CIccProfile::InitHeader()", 180, "main",
             "Initialize V4 output profile header", in_fuzzer=True),
    CallSite("icGetTagText(desc)", 188, "main",
             "Get description text from source profile", in_fuzzer=True),
    CallSite("CIccTagMultiLocalizedUnicode::SetText", 190, "main",
             "Set description tag text in V4 profile", in_fuzzer=True),
    CallSite("pIcc->AttachTag(desc)", 193, "main",
             "Attach description tag to V4 profile", in_fuzzer=True),
    CallSite("pIcc->AttachTag(copyright)", 199, "main",
             "Attach copyright tag to V4 profile", in_fuzzer=True),
]

# Phase 7: TRC Curve Generation (MPE Apply loop)
TRC_CALLS = [
    CallSite("CIccTagCurve::new(2048)", 201, "main",
             "Create TRC curve with 2048 entries per channel",
             in_fuzzer=True),
    CallSite("curveMpe->Apply(curveApply, out, in) [loop 2048]", 208, "main",
             "Apply CurveSet MPE element for each of 2048 samples",
             in_fuzzer=True,
             note="CRITICAL: 2048 iterations through MPE Apply — attack surface"),
    CallSite("pIcc->AttachTag(RedTRC/GreenTRC/BlueTRC)", 214, "main",
             "Attach TRC curves to V4 profile", in_fuzzer=True),
]

# Phase 8: Colorant XYZ Computation
COLORANT_CALLS = [
    CallSite("matrixMpe->Apply(mtxApply, in, rRGB)", 222, "main",
             "Apply EmissionMatrix for red primary", in_fuzzer=True),
    CallSite("pTagC2S->Apply(pApplyC2S, out, in) [red]", 223, "main",
             "Apply C2S PCC transform for red XYZ", in_fuzzer=True),
    CallSite("icDtoF(out[]) [red]", 226, "main",
             "Convert double to s15Fixed16 for red colorant", in_fuzzer=True),
    CallSite("pIcc->AttachTag(redColorant)", 227, "main",
             "Attach red colorant XYZ tag", in_fuzzer=True),
    CallSite("matrixMpe->Apply(mtxApply, in, gRGB)", 229, "main",
             "Apply EmissionMatrix for green primary", in_fuzzer=True),
    CallSite("pTagC2S->Apply(pApplyC2S, out, in) [green]", 230, "main",
             "Apply C2S PCC transform for green XYZ", in_fuzzer=True),
    CallSite("pIcc->AttachTag(greenColorant)", 234, "main",
             "Attach green colorant XYZ tag", in_fuzzer=True),
    CallSite("matrixMpe->Apply(mtxApply, in, bRGB)", 236, "main",
             "Apply EmissionMatrix for blue primary", in_fuzzer=True),
    CallSite("pTagC2S->Apply(pApplyC2S, out, in) [blue]", 237, "main",
             "Apply C2S PCC transform for blue XYZ", in_fuzzer=True),
    CallSite("pIcc->AttachTag(blueColorant)", 241, "main",
             "Attach blue colorant XYZ tag", in_fuzzer=True),
]

# Phase 9: Output
OUTPUT_CALLS = [
    CallSite("SaveIccProfile(output)", 243, "main",
             "Save V4 profile to output file",
             in_fuzzer=True,
             note="Fuzzer saves to temp file then deletes"),
]

ALL_CALLS = (LOAD_DSP_CALLS + VALIDATE_DSP_CALLS + MPE_VALIDATE_CALLS +
             LOAD_PCC_CALLS + MPE_INIT_CALLS + V4_BUILD_CALLS + TRC_CALLS +
             COLORANT_CALLS + OUTPUT_CALLS)

GATES = [
    ASTGate("argc < 4", 103, "if", "main",
            security_relevant=False, note="Argument count check"),
    ASTGate("!dspIcc", 110, "if", "main",
            security_relevant=True, note="Display profile parse failure"),
    ASTGate("version < V5 || class != Display", 115, "if", "main",
            security_relevant=True,
            note="Profile version and class validation gate"),
    ASTGate("!pTagIn (AToB1 MPE)", 123, "if", "main",
            security_relevant=True,
            note="AToB1 tag must exist as MultiProcessElement"),
    ASTGate("NumElements!=2 || channels!=3 || wrong types", 130, "if", "main",
            security_relevant=True,
            note="MPE structure validation — must be CurveSet+EmissionMatrix"),
    ASTGate("!pccIcc", 143, "if", "main",
            security_relevant=True, note="Observer profile parse failure"),
    ASTGate("pccIcc version < V5", 148, "if", "main",
            security_relevant=True, note="PCC profile version check"),
    ASTGate("!pTagSvcn || !pTagC2S || channels!=3", 156, "if", "main",
            security_relevant=True,
            note="PCC profile must have spectralViewingConditions and C2S tags"),
    ASTGate("i < 2048 (TRC loop)", 206, "for", "main",
            security_relevant=True,
            note="Fixed 2048 iteration loop — bounded, no OOM risk from loop itself"),
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
        "fidelity_note": "VERY HIGH",
        "note": (
            "The v5dspobs fuzzer has very high fidelity with the tool. It exercises "
            "the complete V5→V4 conversion pipeline: ReadIccProfile for both display "
            "and observer profiles, MPE tag validation, CurveSet/EmissionMatrix Apply "
            "for TRC generation, C2S PCC transforms for colorant XYZ computation, "
            "and SaveIccProfile for output. The fuzzer uses a split input format "
            "(4-byte size prefix + two profile blobs) matching the tool's two-file "
            "input. Secondary fuzzer (icc_spectral_fuzzer) "
            "cover individual spectral tag parsing paths."
        ),
        "related_fuzzers": [
            "icc_spectral_fuzzer — spectral tag Read/Write/Validate paths",
            "icc_v5dspobs_fuzzer — full V5→V4 conversion pipeline (primary)",
        ],
    }


def generate_json(output_file):
    data = {
        "tool": TOOL_NAME,
        "tool_file": TOOL_FILE,
        "fuzzer": FUZZER_NAME,
        "fuzzer_file": FUZZER_FILE,
        "related_fuzzers": [
            {"name": "icc_spectral_fuzzer", "file": "icc_spectral_fuzzer.cpp",
             "focus": "Spectral tag Read/Write/Validate"},
        ],
        "analysis_date": "2026-07-20",
        "phases": {
            "1_load_display": {
                "description": "Load V5 display profile",
                "calls": [asdict(c) for c in LOAD_DSP_CALLS],
                "in_fuzzer": True,
            },
            "2_validate_display": {
                "description": "Validate display profile version, class, and tags",
                "calls": [asdict(c) for c in VALIDATE_DSP_CALLS],
                "in_fuzzer": True,
            },
            "3_mpe_validation": {
                "description": "Validate AToB1 MPE structure (CurveSet+EmissionMatrix)",
                "calls": [asdict(c) for c in MPE_VALIDATE_CALLS],
                "in_fuzzer": True,
            },
            "4_load_pcc": {
                "description": "Load observer/PCC V5 profile with C2S tag",
                "calls": [asdict(c) for c in LOAD_PCC_CALLS],
                "in_fuzzer": True,
            },
            "5_mpe_init": {
                "description": "Initialize MPE pipelines (Begin + GetNewApply)",
                "calls": [asdict(c) for c in MPE_INIT_CALLS],
                "in_fuzzer": True,
            },
            "6_v4_build": {
                "description": "Construct V4 profile header, description, copyright",
                "calls": [asdict(c) for c in V4_BUILD_CALLS],
                "in_fuzzer": True,
            },
            "7_trc_generation": {
                "description": "Generate TRC curves (2048 samples × 3 channels)",
                "calls": [asdict(c) for c in TRC_CALLS],
                "in_fuzzer": True,
            },
            "8_colorant_xyz": {
                "description": "Compute RGB colorant XYZ via MPE + C2S pipeline",
                "calls": [asdict(c) for c in COLORANT_CALLS],
                "in_fuzzer": True,
            },
            "9_output": {
                "description": "Save V4 profile",
                "calls": [asdict(c) for c in OUTPUT_CALLS],
                "in_fuzzer": True,
            },
        },
        "gates": [asdict(g) for g in GATES],
        "fidelity": compute_fidelity(),
        "mpe_pipeline_notes": {
            "display_pipeline": "CurveSet(3→3) → EmissionMatrix(3→spectra) — linearizes RGB then maps to spectral emission",
            "pcc_pipeline": "customToStandardPcc(3→3) — converts custom PCS to standard PCS (XYZ)",
            "combined": "For each primary: EmissionMatrix(RGB) → C2S(spectral→XYZ) → icDtoF → s15Fixed16 colorant",
        },
        "fuzzer_input_format": {
            "description": "Split input: [4-byte BE size][display_profile][observer_profile]",
            "fields": {
                "bytes[0-3]": "Big-endian uint32 size of display profile",
                "bytes[4..4+N-1]": "Display profile data (V5 display class)",
                "bytes[4+N..]": "Observer/PCC profile data (V5 with svcn+c2sp tags)",
            },
            "min_size": 264,
            "max_size": "10MB",
        },
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[OK] JSON call graph: {output_file}")


def generate_dot(output_file):
    lines = [
        'digraph iccV5DspObsToV4Dsp {',
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
        '  tool [label="main()\\nIccV5DspObsToV4Dsp.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '  fuzzer [label="LLVMFuzzerTestOneInput()\\nicc_v5dspobs_fuzzer.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '',
        '  // Load profiles',
        '  subgraph cluster_load {',
        '    label="Phase 1-2: Load & Validate Profiles"; style=rounded;',
        '    read_dsp [label="ReadIccProfile\\n(display V5)", fillcolor="#90EE90"];',
        '    validate_dsp [label="Version/Class\\ncheck", fillcolor="#90EE90"];',
        '    find_atob1 [label="FindTagOfType\\n(AToB1 MPE)", fillcolor="#90EE90"];',
        '    read_pcc [label="ReadIccProfile\\n(observer V5)", fillcolor="#90EE90"];',
        '    find_svcn [label="FindTagOfType\\n(svcn)", fillcolor="#90EE90"];',
        '    find_c2s [label="FindTagOfType\\n(c2sp MPE)", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // MPE validation',
        '  subgraph cluster_mpe_val {',
        '    label="Phase 3: MPE Structure Validation"; style=rounded; color=red;',
        '    num_elem [label="NumElements==2", fillcolor="#90EE90"];',
        '    get_curve [label="GetElement(0)\\nCurveSet", fillcolor="#90EE90"];',
        '    get_matrix [label="GetElement(1)\\nEmissionMatrix", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // MPE init',
        '  subgraph cluster_mpe_init {',
        '    label="Phase 5: MPE Pipeline Init"; style=rounded; color=red;',
        '    mpe_begin [label="pTagIn->Begin\\n(dspIcc, pccIcc)", fillcolor="#90EE90", penwidth=3];',
        '    mpe_apply_ctx [label="GetNewApply\\nGetList", fillcolor="#90EE90"];',
        '    c2s_begin [label="pTagC2S->Begin\\n(pccIcc)", fillcolor="#90EE90"];',
        '    c2s_apply_ctx [label="C2S GetNewApply", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // TRC generation',
        '  subgraph cluster_trc {',
        '    label="Phase 7: TRC Curve Generation"; style=rounded; color=red;',
        '    curve_alloc [label="CIccTagCurve\\n(2048)", fillcolor="#90EE90"];',
        '    curve_apply [label="curveMpe->Apply\\n×2048", fillcolor="#90EE90", penwidth=3];',
        '    attach_trc [label="AttachTag\\n(R/G/B TRC)", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Colorant XYZ',
        '  subgraph cluster_colorant {',
        '    label="Phase 8: Colorant XYZ Computation"; style=rounded; color=red;',
        '    mtx_apply_r [label="matrixMpe->Apply\\n(red RGB)", fillcolor="#90EE90"];',
        '    c2s_apply_r [label="C2S->Apply\\n(red→XYZ)", fillcolor="#90EE90"];',
        '    mtx_apply_g [label="matrixMpe->Apply\\n(green RGB)", fillcolor="#90EE90"];',
        '    c2s_apply_g [label="C2S->Apply\\n(green→XYZ)", fillcolor="#90EE90"];',
        '    mtx_apply_b [label="matrixMpe->Apply\\n(blue RGB)", fillcolor="#90EE90"];',
        '    c2s_apply_b [label="C2S->Apply\\n(blue→XYZ)", fillcolor="#90EE90"];',
        '    attach_xyz [label="AttachTag\\n(R/G/B Colorant)", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Output',
        '  subgraph cluster_output {',
        '    label="Phase 9: Output"; style=rounded;',
        '    save_profile [label="SaveIccProfile\\n(V4 output)", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Tool edges',
        '  tool -> read_dsp [style=bold, penwidth=2];',
        '  tool -> validate_dsp;',
        '  tool -> find_atob1;',
        '  tool -> read_pcc [style=bold];',
        '  tool -> find_svcn;',
        '  tool -> find_c2s;',
        '  tool -> num_elem;',
        '  tool -> get_curve;',
        '  tool -> get_matrix;',
        '  tool -> mpe_begin [style=bold, penwidth=2];',
        '  tool -> mpe_apply_ctx;',
        '  tool -> c2s_begin;',
        '  tool -> c2s_apply_ctx;',
        '  tool -> curve_alloc;',
        '  tool -> curve_apply [style=bold, penwidth=2];',
        '  tool -> attach_trc;',
        '  tool -> mtx_apply_r;',
        '  tool -> c2s_apply_r;',
        '  tool -> mtx_apply_g;',
        '  tool -> c2s_apply_g;',
        '  tool -> mtx_apply_b;',
        '  tool -> c2s_apply_b;',
        '  tool -> attach_xyz;',
        '  tool -> save_profile;',
        '',
        '  // Fuzzer edges',
        '  fuzzer -> read_dsp [style=bold, color=green, penwidth=2];',
        '  fuzzer -> validate_dsp [style=dotted, color=green];',
        '  fuzzer -> find_atob1 [style=dotted, color=green];',
        '  fuzzer -> read_pcc [style=bold, color=green];',
        '  fuzzer -> find_svcn [style=dotted, color=green];',
        '  fuzzer -> find_c2s [style=dotted, color=green];',
        '  fuzzer -> num_elem [style=dotted, color=green];',
        '  fuzzer -> get_curve [style=dotted, color=green];',
        '  fuzzer -> get_matrix [style=dotted, color=green];',
        '  fuzzer -> mpe_begin [style=bold, color=green, penwidth=2];',
        '  fuzzer -> mpe_apply_ctx [style=dotted, color=green];',
        '  fuzzer -> c2s_begin [style=dotted, color=green];',
        '  fuzzer -> c2s_apply_ctx [style=dotted, color=green];',
        '  fuzzer -> curve_alloc [style=dotted, color=green];',
        '  fuzzer -> curve_apply [style=bold, color=green, penwidth=2];',
        '  fuzzer -> attach_trc [style=dotted, color=green];',
        '  fuzzer -> mtx_apply_r [style=dotted, color=green];',
        '  fuzzer -> c2s_apply_r [style=dotted, color=green];',
        '  fuzzer -> mtx_apply_g [style=dotted, color=green];',
        '  fuzzer -> c2s_apply_g [style=dotted, color=green];',
        '  fuzzer -> mtx_apply_b [style=dotted, color=green];',
        '  fuzzer -> c2s_apply_b [style=dotted, color=green];',
        '  fuzzer -> attach_xyz [style=dotted, color=green];',
        '  fuzzer -> save_profile [style=dotted, color=green];',
        '',
        '  // Pipeline flow',
        '  find_atob1 -> num_elem;',
        '  num_elem -> get_curve;',
        '  num_elem -> get_matrix;',
        '  mpe_begin -> curve_apply;',
        '  mpe_begin -> mtx_apply_r;',
        '  curve_apply -> attach_trc;',
        '  mtx_apply_r -> c2s_apply_r;',
        '  mtx_apply_g -> c2s_apply_g;',
        '  mtx_apply_b -> c2s_apply_b;',
        '  c2s_apply_r -> attach_xyz;',
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
    parser = argparse.ArgumentParser(description="iccV5DspObsToV4Dsp call graph analysis")
    parser.add_argument("--dot", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--render", choices=["png", "svg", "pdf"], default=None)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    if args.summary or not any([args.dot, args.json]):
        fid = compute_fidelity()
        print(f"\n{'='*60}")
        print(f"iccV5DspObsToV4Dsp Call Graph & Fuzzer Fidelity")
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
