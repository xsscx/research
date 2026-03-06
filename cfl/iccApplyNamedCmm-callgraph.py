#!/usr/bin/env python3
"""
iccApplyNamedCmm Call Graph & AST Gate Analysis
=================================================

Static analysis of iccApplyNamedCmm.cpp to extract call graph, AST gates,
and fuzzer fidelity mapping for the icc_applynamedcmm_fuzzer.

This tool is notable for:
  - CIccNamedColorCmm — supports named color, pixel, and mixed interfaces
  - 4 distinct Apply() overloads (Named2Pixel, Pixel2Pixel, Named2Named, Pixel2Named)
  - JSON and legacy configuration parsing
  - Encoding conversion via ToInternalEncoding/FromInternalEncoding
  - Debug calculator support (CIccLogDebugger)

Usage:
    python3 iccApplyNamedCmm-callgraph.py [--dot FILE] [--json FILE] [--render FORMAT]
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

TOOL_NAME = "iccApplyNamedCmm"
TOOL_FILE = "iccApplyNamedCmm.cpp"
FUZZER_NAME = "icc_applynamedcmm_fuzzer"
FUZZER_FILE = "icc_applynamedcmm_fuzzer.cpp"

# Phase 1: Configuration Parsing
CONFIG_CALLS = [
    CallSite("CIccCfgDataApply::fromJson", 254, "main",
             "Parse JSON configuration for data application",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer uses hardcoded params, not JSON config"),
    CallSite("CIccCfgProfileSequence::fromJson", 259, "main",
             "Parse JSON profile sequence configuration",
             cli_only=True, in_fuzzer=False),
    CallSite("CIccCfgColorData::fromJson", 266, "main",
             "Parse JSON color data from config",
             cli_only=True, in_fuzzer=False),
    CallSite("CIccCfgDataApply::fromArgs", 290, "main",
             "Parse legacy command-line arguments",
             cli_only=True, in_fuzzer=False),
    CallSite("CIccCfgProfileSequence::fromArgs", 298, "main",
             "Parse legacy profile sequence from args",
             cli_only=True, in_fuzzer=False),
    CallSite("CIccCfgColorData::fromLegacy", 304, "main",
             "Parse legacy color data file",
             cli_only=True, in_fuzzer=False),
]

# Phase 2: Profile Loading and CMM Setup
CMM_CALLS = [
    CallSite("OpenIccProfile(first)", 330, "main",
             "Open first profile to determine source color space",
             in_fuzzer=True,
             note="Fuzzer matches: OpenIccProfile(tmp_profile)"),
    CallSite("CIccNamedColorCmm::CIccNamedColorCmm", 339, "main",
             "Construct named color CMM with source/dest spaces",
             in_fuzzer=True,
             note="Fuzzer matches: CIccNamedColorCmm(srcSpace, icSigUnknownData, bInputProfile)"),
    CallSite("CIccCreateXformHintManager", 353, "main",
             "Create hint manager for xform", in_fuzzer=True),
    CallSite("CIccApplyBPCHint", 355, "main",
             "Add Black Point Compensation hint", in_fuzzer=True),
    CallSite("CIccLuminanceMatchingHint", 358, "main",
             "Add luminance matching hint", in_fuzzer=True),
    CallSite("OpenIccProfile(pcc)", 362, "main",
             "Open PCC profile for viewing conditions",
             in_fuzzer=False,
             note="Fuzzer does not use PCC profiles"),
    CallSite("CIccCmmEnvVarHint", 373, "main",
             "Add environment variable hints",
             in_fuzzer=True,
             note="Fuzzer exercises env var path when flags bit 7 set"),
    CallSite("CIccCmmPccEnvVarHint", 377, "main",
             "Add PCC environment variable hints",
             in_fuzzer=False),
    CallSite("CIccNamedColorCmm::AddXform", 381, "main",
             "Add profile xform to named color CMM pipeline",
             in_fuzzer=True,
             note="Exact match: namedCmm.AddXform(file, intent, interp, pcc, xformType, useD2Bx, &Hint, useV5Sub)"),
]

# Phase 3: CMM Execution
EXEC_CALLS = [
    CallSite("CIccNamedColorCmm::Begin", 397, "main",
             "Initialize named color CMM pipeline", in_fuzzer=True),
    CallSite("CIccNamedColorCmm::GetInterface", 479, "main",
             "Get CMM interface type (Named2Pixel, Pixel2Pixel, etc.)",
             in_fuzzer=True),
    CallSite("CIccNamedColorCmm::GetSourceSpace", 413, "main",
             "Query source color space from CMM", in_fuzzer=True),
    CallSite("icGetSpaceSamples(src)", 414, "main",
             "Get source channel count", in_fuzzer=True),
    CallSite("CIccNamedColorCmm::GetDestSpace", 429, "main",
             "Query destination color space", in_fuzzer=True),
    CallSite("icGetSpaceSamples(dst)", 430, "main",
             "Get destination channel count", in_fuzzer=True),
]

# Phase 4: Apply (4 interface types)
APPLY_CALLS = [
    CallSite("CIccNamedColorCmm::Apply(Named2Pixel)", 483, "main",
             "Apply named color → pixel transform",
             in_fuzzer=True,
             note="Fuzzer tests 9 named colors × 3 tint values"),
    CallSite("CIccNamedColorCmm::Apply(Pixel2Pixel)", 536, "main",
             "Apply pixel → pixel transform — MOST COMMON",
             in_fuzzer=True,
             note="Fuzzer tests black/white/gray/primaries/edge cases/NaN/Inf/batch"),
    CallSite("CIccNamedColorCmm::Apply(Named2Named)", 500, "main",
             "Apply named color → named color transform",
             in_fuzzer=True),
    CallSite("CIccNamedColorCmm::Apply(Pixel2Named)", 552, "main",
             "Apply pixel → named color transform",
             in_fuzzer=True),
    CallSite("CIccNamedColorCmm::Apply(batch)", 0, "LLVMFuzzerTestOneInput",
             "Apply batch pixel transform (3 pixels)",
             in_fuzzer=True,
             note="Fuzzer-only: tests multi-pixel Apply overload"),
]

# Phase 5: Encoding Conversion
ENCODING_CALLS = [
    CallSite("CIccCmm::ToInternalEncoding", 522, "main",
             "Convert source data to internal encoding",
             in_fuzzer=True,
             note="Fuzzer tests 6 encoding types: Value, Percent, UnitFloat, Float, 16Bit, 16BitV2"),
    CallSite("CIccCmm::FromInternalEncoding", 540, "main",
             "Convert internal encoding to destination format",
             in_fuzzer=True,
             note="Fuzzer tests same 6 encoding types"),
]

# Phase 6: Output (tool-only)
OUTPUT_CALLS = [
    CallSite("CIccCfgColorData::toLegacy", 580, "main",
             "Write legacy output format", in_fuzzer=False),
    CallSite("CIccCfgColorData::toJson", 590, "main",
             "Write JSON output format", in_fuzzer=False),
    CallSite("CIccCfgColorData::toIt8", 598, "main",
             "Write IT8 output format", in_fuzzer=False),
]

# Phase 7: Fuzzer-only extras
FUZZER_EXTRA = [
    CallSite("CIccNamedColorCmm::GetNumXforms", 0, "LLVMFuzzerTestOneInput",
             "Query xform count", in_fuzzer=True),
    CallSite("CIccNamedColorCmm::Valid", 0, "LLVMFuzzerTestOneInput",
             "Validate CMM state", in_fuzzer=True),
    CallSite("CIccNamedColorCmm::GetLastSpace", 0, "LLVMFuzzerTestOneInput",
             "Query last color space", in_fuzzer=True),
    CallSite("CIccNamedColorCmm::GetLastParentSpace", 0, "LLVMFuzzerTestOneInput",
             "Query last parent color space", in_fuzzer=True),
]

ALL_CALLS = (CONFIG_CALLS + CMM_CALLS + EXEC_CALLS + APPLY_CALLS +
             ENCODING_CALLS + OUTPUT_CALLS + FUZZER_EXTRA)

GATES = [
    ASTGate("argc < 2", 238, "if", "main",
            security_relevant=False, note="Usage message guard"),
    ASTGate("!stricmp(argv[1], '-cfg')", 247, "if", "main",
            security_relevant=False, note="JSON vs legacy config mode"),
    ASTGate("!stricmp(argv[0], '-debugcalc')", 283, "if", "main",
            security_relevant=False, note="Debug calculator mode"),
    ASTGate("!bInputProfile (IsSpacePCS)", 328, "if", "main",
            security_relevant=True,
            note="Determines input profile detection — affects CMM construction"),
    ASTGate("pProfCfg->m_useBPC", 354, "if", "main",
            security_relevant=False, note="BPC hint gate"),
    ASTGate("pProfCfg->m_adjustPcsLuminance", 357, "if", "main",
            security_relevant=False, note="Luminance matching gate"),
    ASTGate("pProfCfg->m_pccFile.size()", 361, "if", "main",
            security_relevant=False, note="PCC profile loading gate"),
    ASTGate("pProfCfg->m_iccEnvVars.size() > 0", 372, "if", "main",
            security_relevant=False, note="Environment variable hint gate"),
    ASTGate("stat = namedCmm.Begin()", 397, "if", "main",
            security_relevant=True,
            note="CMM initialization failure — blocks Apply()"),
    ASTGate("SrcspaceSig == icSigNamedData", 469, "if", "main",
            security_relevant=True,
            note="Named vs pixel input determines Apply overload used"),
    ASTGate("namedCmm.GetInterface() switch", 479, "switch", "main",
            security_relevant=True,
            note="Interface type determines which Apply overload is called"),
    ASTGate("bInputProfile && IsSpacePCS(SrcspaceSig)", 418, "if", "main",
            security_relevant=True,
            note="PCS data encoding adjustment for input profiles"),
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
        "fidelity_note": "HIGH",
        "note": (
            "The applynamedcmm fuzzer has high fidelity with the tool. It exercises "
            "all 4 Apply() interface types (Named2Pixel, Pixel2Pixel, Named2Named, "
            "Pixel2Named), the full CIccNamedColorCmm pipeline (AddXform→Begin→Apply), "
            "encoding conversions (6 types × 2 directions), and hint mechanisms "
            "(BPC, luminance, env vars). The only gaps are: JSON/legacy config parsing, "
            "PCC profiles, and output writing."
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
            "1_config_parsing": {
                "description": "JSON/legacy configuration parsing",
                "calls": [asdict(c) for c in CONFIG_CALLS],
                "in_fuzzer": False,
                "reason": "Fuzzer uses hardcoded params, not config files",
            },
            "2_cmm_construction": {
                "description": "Named color CMM construction with hints",
                "calls": [asdict(c) for c in CMM_CALLS],
                "in_fuzzer": "partial",
                "reason": "PCC and PCC env vars not exercised by fuzzer",
            },
            "3_cmm_execution": {
                "description": "CMM Begin + space queries",
                "calls": [asdict(c) for c in EXEC_CALLS],
                "in_fuzzer": True,
            },
            "4_apply": {
                "description": "Apply transforms — 4 interface types",
                "calls": [asdict(c) for c in APPLY_CALLS],
                "in_fuzzer": True,
            },
            "5_encoding": {
                "description": "ToInternalEncoding / FromInternalEncoding",
                "calls": [asdict(c) for c in ENCODING_CALLS],
                "in_fuzzer": True,
            },
            "6_output": {
                "description": "Output writing (legacy, JSON, IT8)",
                "calls": [asdict(c) for c in OUTPUT_CALLS],
                "in_fuzzer": False,
                "reason": "Output-only operations, not part of attack surface",
            },
            "7_fuzzer_extras": {
                "description": "Additional CMM query APIs",
                "calls": [asdict(c) for c in FUZZER_EXTRA],
                "in_fuzzer": True,
            },
        },
        "gates": [asdict(g) for g in GATES],
        "fidelity": compute_fidelity(),
        "apply_interfaces": {
            "icApplyNamed2Pixel": "Named color input → pixel output (tint variations)",
            "icApplyPixel2Pixel": "Pixel input → pixel output (most common path)",
            "icApplyNamed2Named": "Named color → named color lookup",
            "icApplyPixel2Named": "Pixel input → closest named color",
        },
        "fuzzer_pixel_tests": [
            "Black (all zeros)",
            "White (all ones)",
            "Gray (all 0.5)",
            "Primary colors (one channel at 1.0)",
            "Negative values (-0.1)",
            "Over-range values (1.5)",
            "NaN values (0.0/0.0)",
            "+Inf values (1.0/0.0)",
            "Fuzz-data derived values",
            "Batch (3 pixels at once)",
        ],
        "fuzzer_input_format": {
            "description": "4-byte control header + ICC profile data",
            "control_bytes": {
                "byte[0] (flags)": "useBPC(0x01), useD2Bx(0x02), adjustPcsLuminance(0x04), useV5SubProfile(0x08), interp(0x10), envVars(0x80)",
                "byte[1]": "icRenderingIntent (& 0x03)",
                "byte[2-3]": "Reserved",
            },
            "min_size": 132,
            "max_size": "2MB",
        },
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[OK] JSON call graph: {output_file}")


def generate_dot(output_file):
    lines = [
        'digraph iccApplyNamedCmm {',
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
        '  tool [label="main()\\niccApplyNamedCmm.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '  fuzzer [label="LLVMFuzzerTestOneInput()\\nicc_applynamedcmm_fuzzer.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '',
        '  // Config parsing',
        '  subgraph cluster_config {',
        '    label="Phase 1: Config Parsing"; style=rounded;',
        '    json_cfg [label="fromJson\\n(config)", fillcolor="#D3D3D3"];',
        '    legacy_cfg [label="fromArgs\\n(legacy)", fillcolor="#D3D3D3"];',
        '  }',
        '',
        '  // CMM construction',
        '  subgraph cluster_cmm {',
        '    label="Phase 2: CMM Construction"; style=rounded; color=red;',
        '    open_prof [label="OpenIccProfile", fillcolor="#90EE90"];',
        '    named_cmm [label="CIccNamedColorCmm()", fillcolor="#90EE90", penwidth=3];',
        '    hint_mgr [label="HintManager\\n(BPC/Lum/Env)", fillcolor="#90EE90"];',
        '    add_xform [label="AddXform", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // CMM execution',
        '  subgraph cluster_exec {',
        '    label="Phase 3: CMM Execution"; style=rounded; color=red;',
        '    cmm_begin [label="Begin()", fillcolor="#90EE90"];',
        '    get_iface [label="GetInterface()", fillcolor="#90EE90"];',
        '    get_spaces [label="Get Src/Dst Space", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Apply interfaces',
        '  subgraph cluster_apply {',
        '    label="Phase 4: Apply (4 Interfaces)"; style=rounded; color=red;',
        '    named2pixel [label="Apply\\nNamed2Pixel", fillcolor="#90EE90"];',
        '    pixel2pixel [label="Apply\\nPixel2Pixel", fillcolor="#90EE90", penwidth=3];',
        '    named2named [label="Apply\\nNamed2Named", fillcolor="#90EE90"];',
        '    pixel2named [label="Apply\\nPixel2Named", fillcolor="#90EE90"];',
        '    batch_apply [label="Apply\\n(batch 3px)", fillcolor="#FFD700"];',
        '  }',
        '',
        '  // Encoding',
        '  subgraph cluster_encoding {',
        '    label="Phase 5: Encoding Conversion"; style=rounded;',
        '    to_internal [label="ToInternalEncoding\\n(6 types)", fillcolor="#90EE90"];',
        '    from_internal [label="FromInternalEncoding\\n(6 types)", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Output',
        '  subgraph cluster_output {',
        '    label="Phase 6: Output Writing"; style=rounded;',
        '    to_legacy [label="toLegacy", fillcolor="#ADD8E6"];',
        '    to_json [label="toJson", fillcolor="#ADD8E6"];',
        '    to_it8 [label="toIt8", fillcolor="#ADD8E6"];',
        '  }',
        '',
        '  // Tool edges',
        '  tool -> json_cfg [style=dashed];',
        '  tool -> legacy_cfg [style=dashed];',
        '  tool -> open_prof;',
        '  tool -> named_cmm [style=bold, penwidth=2];',
        '  tool -> hint_mgr;',
        '  tool -> add_xform [style=bold, penwidth=2];',
        '  tool -> cmm_begin [style=bold];',
        '  tool -> get_iface;',
        '  tool -> get_spaces;',
        '  tool -> named2pixel;',
        '  tool -> pixel2pixel [style=bold, penwidth=2];',
        '  tool -> named2named;',
        '  tool -> pixel2named;',
        '  tool -> to_internal;',
        '  tool -> from_internal;',
        '  tool -> to_legacy [style=dashed];',
        '  tool -> to_json [style=dashed];',
        '  tool -> to_it8 [style=dashed];',
        '',
        '  // Fuzzer edges',
        '  fuzzer -> open_prof [style=dotted, color=green];',
        '  fuzzer -> named_cmm [style=bold, color=green, penwidth=2];',
        '  fuzzer -> hint_mgr [style=dotted, color=green];',
        '  fuzzer -> add_xform [style=bold, color=green, penwidth=2];',
        '  fuzzer -> cmm_begin [style=bold, color=green];',
        '  fuzzer -> get_iface [style=dotted, color=green];',
        '  fuzzer -> get_spaces [style=dotted, color=green];',
        '  fuzzer -> named2pixel [style=dotted, color=green];',
        '  fuzzer -> pixel2pixel [style=bold, color=green, penwidth=2];',
        '  fuzzer -> named2named [style=dotted, color=green];',
        '  fuzzer -> pixel2named [style=dotted, color=green];',
        '  fuzzer -> batch_apply [style=bold, color=orange];',
        '  fuzzer -> to_internal [style=dotted, color=green];',
        '  fuzzer -> from_internal [style=dotted, color=green];',
        '',
        '  // Interface flow',
        '  get_iface -> named2pixel [style=dotted, label="Named src"];',
        '  get_iface -> pixel2pixel [style=dotted, label="Pixel src"];',
        '  get_iface -> named2named [style=dotted, label="Named both"];',
        '  get_iface -> pixel2named [style=dotted, label="Pixel→Named"];',
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
    parser = argparse.ArgumentParser(description="iccApplyNamedCmm call graph analysis")
    parser.add_argument("--dot", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--render", choices=["png", "svg", "pdf"], default=None)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    if args.summary or not any([args.dot, args.json]):
        fid = compute_fidelity()
        print(f"\n{'='*60}")
        print(f"iccApplyNamedCmm Call Graph & Fuzzer Fidelity")
        print(f"{'='*60}")
        print(f"Total call sites:       {fid['total_call_sites']}")
        print(f"CLI-only excluded:      {fid['cli_only_excluded']}")
        print(f"Fuzzable call sites:    {fid['fuzzable_call_sites']}")
        print(f"Matched by fuzzer:      {fid['matched_by_fuzzer']}")
        print(f"Output-only (not fuz):  {fid['output_only_not_in_fuzzer']}")
        print(f"Coverage:               {fid['coverage_percent']}%")
        print(f"Fidelity:               {fid['fidelity_note']}")
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
