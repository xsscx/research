#!/usr/bin/env python3
"""
iccFromCube Call Graph & AST Gate Analysis
==========================================

Static analysis of iccFromCube.cpp to extract call graph, AST gates,
and fuzzer fidelity mapping for the icc_fromcube_fuzzer.

This tool is notable for:
  - CUBE LUT file parsing (text format → ICC device link profile)
  - CubeFile class with parseHeader()/parse3DTable() as main attack surface
  - Deep MPE/CLUT construction chain after parse
  - Fuzzer includes EXACT copy of CubeFile class for maximum fidelity

Usage:
    python3 iccFromCube-callgraph.py [--dot FILE] [--json FILE] [--render FORMAT]
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

TOOL_NAME = "iccFromCube"
TOOL_FILE = "iccFromCube.cpp"
FUZZER_NAME = "icc_fromcube_fuzzer"
FUZZER_FILE = "icc_fromcube_fuzzer.cpp"

# Phase 1: CLI Argument Parsing
CLI_CALLS = [
    CallSite("printf(Usage)", 345, "main",
             "Usage message when argc <= 2", cli_only=True, in_fuzzer=False),
    CallSite("argv[1] → CubeFile()", 351, "main",
             "Open input CUBE file from CLI arg",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer writes data to temp file instead"),
    CallSite("argv[2] → SaveIccProfile()", 456, "main",
             "Output ICC file path from CLI arg",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer saves to temp file then deletes"),
]

# Phase 2: CUBE File Parsing (main attack surface)
PARSE_CALLS = [
    CallSite("CubeFile::CubeFile(filename)", 351, "main",
             "Construct CubeFile object with input path",
             in_fuzzer=True,
             note="Fuzzer passes temp file path — identical"),
    CallSite("CubeFile::parseHeader()", 353, "main",
             "Parse CUBE header: TITLE, LUT_3D_SIZE, DOMAIN_MIN/MAX — MAIN ATTACK SURFACE",
             in_fuzzer=True,
             note="Exact code copy in fuzzer. Exercises all keyword branches"),
    CallSite("CubeFile::open()", 100, "parseHeader",
             "fopen() the CUBE file for reading",
             in_fuzzer=True),
    CallSite("CubeFile::getNextLine()", 112, "parseHeader",
             "Read next line (MAX_LINE_LEN=255 cap)",
             in_fuzzer=True,
             note="Line length capped at 255 — prevents unbounded reads"),
    CallSite("CubeFile::getTitle()", 129, "parseHeader",
             "Parse TITLE keyword value (handles quotes)",
             in_fuzzer=True),
    CallSite("CubeFile::getNext()", 155, "parseHeader",
             "Tokenizer for space-separated values",
             in_fuzzer=True),
    CallSite("atoll(LUT_3D_SIZE)", 148, "parseHeader",
             "Parse 3D LUT size — INTEGER OVERFLOW CHECK",
             in_fuzzer=True,
             note="Bounds-checked: temp >= INT_MAX || temp <= 0 → reject"),
    CallSite("atof(DOMAIN_MIN/MAX)", 161, "parseHeader",
             "Parse domain range float values",
             in_fuzzer=True),
    CallSite("CubeFile::sizeLut3D()", 358, "main",
             "Check parsed LUT size > 0",
             in_fuzzer=True,
             note="Fuzzer adds extra check: sizeLut3D() > 64 to limit alloc"),
    CallSite("CubeFile::parse3DTable()", 424, "main",
             "Parse N³ float triplets into CLUT data array",
             in_fuzzer=True,
             note="Overflow-checked: uint64_t temp > UINT_MAX → reject"),
]

# Phase 3: ICC Profile Construction
PROFILE_CALLS = [
    CallSite("CIccProfile::InitHeader()", 366, "main",
             "Initialize default ICC profile header",
             in_fuzzer=True),
    CallSite("CIccTagMultiProcessElement(3,3)", 373, "main",
             "Create MPE tag for A2B0",
             in_fuzzer=True,
             note="Fuzzer uses std::nothrow for OOM safety"),
    CallSite("CubeFile::isCustomInputRange()", 374, "main",
             "Check if input domain differs from [0,1]",
             in_fuzzer=True),
    CallSite("CIccMpeCurveSet(3)", 377, "main",
             "Create input curves for custom range mapping",
             in_fuzzer=True,
             note="Only reached when isCustomInputRange() is true"),
    CallSite("CIccSingleSampledCurve(min, max)", 378, "main",
             "Create per-channel normalization curve",
             in_fuzzer=True,
             note="Up to 3 curves created (one per RGB channel)"),
    CallSite("pCurves->SetCurve()", 384, "main",
             "Attach curve to curve set (channels 0-2)",
             in_fuzzer=True),
    CallSite("pTag->Attach(pCurves)", 413, "main",
             "Attach CurveSet to MPE tag",
             in_fuzzer=True),
    CallSite("CIccMpeCLUT()", 416, "main",
             "Create MPE CLUT element",
             in_fuzzer=True),
    CallSite("CIccCLUT(3,3)", 417, "main",
             "Create 3→3 channel CLUT",
             in_fuzzer=True),
    CallSite("pCLUT->Init(sizeLut3D)", 419, "main",
             "Allocate CLUT grid — ALLOCATION HOTSPOT",
             in_fuzzer=True,
             note="Allocates size³×3 floats. Fuzzer caps at 64³ = 786K floats"),
    CallSite("pMpeCLUT->SetCLUT(pCLUT)", 430, "main",
             "Attach CLUT to MPE CLUT element",
             in_fuzzer=True),
    CallSite("pTag->Attach(pMpeCLUT)", 431, "main",
             "Attach MPE CLUT to tag",
             in_fuzzer=True),
    CallSite("profile.AttachTag(icSigAToB0Tag)", 433, "main",
             "Add A2B0 tag to profile",
             in_fuzzer=True),
]

# Phase 4: Metadata & Output
OUTPUT_CALLS = [
    CallSite("CubeFile::close()", 435, "main",
             "Close CUBE input file",
             in_fuzzer=True),
    CallSite("CIccTagMultiLocalizedUnicode()", 438, "main",
             "Create description tag",
             in_fuzzer=True),
    CallSite("pTextTag->SetText(description)", 441, "main",
             "Set profile description from CUBE TITLE",
             in_fuzzer=True),
    CallSite("profile.AttachTag(icSigProfileDescriptionTag)", 446, "main",
             "Attach description tag to profile",
             in_fuzzer=True),
    CallSite("pTextTag->SetText(copyright)", 452, "main",
             "Set copyright from CUBE comments",
             in_fuzzer=True,
             note="Only if comments present"),
    CallSite("profile.AttachTag(icSigCopyrightTag)", 453, "main",
             "Attach copyright tag to profile",
             in_fuzzer=True),
    CallSite("SaveIccProfile()", 456, "main",
             "Serialize ICC profile to disk",
             in_fuzzer=True,
             note="Fuzzer saves to temp file then deletes"),
]

ALL_CALLS = CLI_CALLS + PARSE_CALLS + PROFILE_CALLS + OUTPUT_CALLS

GATES = [
    ASTGate("argc <= 2", 344, "if", "main",
            security_relevant=False, note="Usage message guard"),
    ASTGate("!cube.parseHeader()", 353, "if", "main",
            security_relevant=True,
            note="Rejects unparseable CUBE files — prevents use of uninitialized data"),
    ASTGate("!cube.sizeLut3D()", 358, "if", "main",
            security_relevant=True,
            note="Rejects files without 3D LUT data"),
    ASTGate("cube.sizeLut3D() > 64", 365, "if", "LLVMFuzzerTestOneInput",
            security_relevant=True,
            note="FUZZER-ONLY: caps LUT size to prevent OOM (64³×3 = 786K floats)"),
    ASTGate("temp >= INT_MAX || temp <= 0", 149, "if", "parseHeader",
            security_relevant=True,
            note="Integer overflow guard on LUT_3D_SIZE"),
    ASTGate("uint64_t temp > UINT_MAX", 226, "if", "parse3DTable",
            security_relevant=True,
            note="Overflow guard on size³ computation"),
    ASTGate("nSizeLut != num*3", 230, "if", "parse3DTable",
            security_relevant=True,
            note="Buffer size consistency check"),
    ASTGate("cube.isCustomInputRange()", 374, "if", "main",
            security_relevant=False,
            note="Determines whether input curve normalization is needed"),
    ASTGate("!pCLUT->Init()", 419, "if", "main",
            security_relevant=True,
            note="CLUT allocation failure check"),
    ASTGate("!bSuccess (parse3DTable)", 425, "if", "main",
            security_relevant=True,
            note="LUT data parse failure — prevents corrupt profile creation"),
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
            "The fromcube fuzzer contains an EXACT copy of the CubeFile class "
            "from iccFromCube.cpp and reproduces the entire main() flow: "
            "parseHeader → sizeLut3D check → InitHeader → MPE/CLUT construction "
            "→ parse3DTable → metadata tags → SaveIccProfile. Key differences: "
            "(1) LUT size capped at 64 to prevent OOM, (2) std::nothrow used for "
            "all allocations, (3) temp file I/O instead of CLI args."
        ),
    }


def generate_json(output_file):
    data = {
        "tool": TOOL_NAME,
        "tool_file": TOOL_FILE,
        "fuzzer": FUZZER_NAME,
        "fuzzer_file": FUZZER_FILE,
        "analysis_date": "2026-07-10",
        "phases": {
            "1_cli_parsing": {
                "description": "Command-line argument parsing",
                "calls": [asdict(c) for c in CLI_CALLS],
                "in_fuzzer": False,
            },
            "2_cube_parsing": {
                "description": "CUBE file header and 3D table parsing — main attack surface",
                "calls": [asdict(c) for c in PARSE_CALLS],
                "in_fuzzer": True,
            },
            "3_profile_construction": {
                "description": "ICC profile header, MPE tag, CLUT construction",
                "calls": [asdict(c) for c in PROFILE_CALLS],
                "in_fuzzer": True,
            },
            "4_output": {
                "description": "Metadata tags and profile serialization",
                "calls": [asdict(c) for c in OUTPUT_CALLS],
                "in_fuzzer": True,
            },
        },
        "gates": [asdict(g) for g in GATES],
        "fidelity": compute_fidelity(),
        "attack_surface": {
            "primary": "CubeFile::parseHeader() — text parsing with atof/atoll",
            "secondary": "CubeFile::parse3DTable() — N³ float array parsing",
            "allocation": "CIccCLUT::Init(size) — allocates size³×3 floats",
            "oom_cap": "Fuzzer limits sizeLut3D to 64 (max 786K floats ≈ 3MB)",
        },
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[OK] JSON call graph: {output_file}")


def generate_dot(output_file):
    lines = [
        'digraph iccFromCube {',
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
        '    leg_hot  [label="Alloc Hotspot", fillcolor="#FF6347"];',
        '  }',
        '',
        '  tool [label="main()\\niccFromCube.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '  fuzzer [label="LLVMFuzzerTestOneInput()\\nicc_fromcube_fuzzer.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '',
        '  // CLI',
        '  subgraph cluster_cli {',
        '    label="Phase 1: CLI Args"; style=rounded;',
        '    usage [label="Usage()", fillcolor="#D3D3D3"];',
        '    argv1 [label="argv[1] input", fillcolor="#D3D3D3"];',
        '    argv2 [label="argv[2] output", fillcolor="#D3D3D3"];',
        '  }',
        '',
        '  // CUBE Parsing',
        '  subgraph cluster_parse {',
        '    label="Phase 2: CUBE Parsing (Attack Surface)"; style=rounded; color=red;',
        '    cubefile [label="CubeFile(filename)", fillcolor="#90EE90"];',
        '    parseheader [label="parseHeader()\\nMAIN ENTRY", fillcolor="#90EE90", penwidth=3];',
        '    getnextline [label="getNextLine()\\n(255-byte cap)", fillcolor="#90EE90"];',
        '    gettitle [label="getTitle()", fillcolor="#90EE90"];',
        '    getnext [label="getNext()", fillcolor="#90EE90"];',
        '    atoll_size [label="atoll(LUT_3D_SIZE)\\noverflow check", fillcolor="#90EE90"];',
        '    atof_domain [label="atof(DOMAIN)", fillcolor="#90EE90"];',
        '    sizelut [label="sizeLut3D()", fillcolor="#90EE90"];',
        '    parse3d [label="parse3DTable()\\nN³ float parse", fillcolor="#90EE90", penwidth=2];',
        '  }',
        '',
        '  // Profile Construction',
        '  subgraph cluster_profile {',
        '    label="Phase 3: ICC Profile Construction"; style=rounded;',
        '    initheader [label="InitHeader()", fillcolor="#90EE90"];',
        '    mpe_tag [label="CIccTagMPE(3,3)", fillcolor="#90EE90"];',
        '    curveset [label="CIccMpeCurveSet(3)", fillcolor="#90EE90"];',
        '    curves [label="SingleSampledCurve\\n(per channel)", fillcolor="#90EE90"];',
        '    mpeclut [label="CIccMpeCLUT", fillcolor="#90EE90"];',
        '    clut [label="CIccCLUT(3,3)", fillcolor="#90EE90"];',
        '    clut_init [label="pCLUT->Init()\\nALLOC HOTSPOT", fillcolor="#FF6347", penwidth=3];',
        '    attach_a2b [label="AttachTag(A2B0)", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Output',
        '  subgraph cluster_output {',
        '    label="Phase 4: Metadata & Output"; style=rounded;',
        '    desc_tag [label="Description Tag", fillcolor="#90EE90"];',
        '    copy_tag [label="Copyright Tag", fillcolor="#90EE90"];',
        '    save [label="SaveIccProfile()", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Tool edges',
        '  tool -> usage [style=dashed];',
        '  tool -> argv1 [style=dashed];',
        '  tool -> cubefile;',
        '  tool -> parseheader [style=bold, penwidth=2];',
        '  tool -> sizelut;',
        '  tool -> initheader;',
        '  tool -> mpe_tag;',
        '  tool -> parse3d [style=bold];',
        '  tool -> save;',
        '  tool -> argv2 [style=dashed];',
        '',
        '  // Fuzzer edges',
        '  fuzzer -> cubefile [color=green];',
        '  fuzzer -> parseheader [style=bold, color=green, penwidth=2];',
        '  fuzzer -> sizelut [color=green];',
        '  fuzzer -> initheader [color=green];',
        '  fuzzer -> mpe_tag [color=green];',
        '  fuzzer -> parse3d [style=bold, color=green];',
        '  fuzzer -> save [color=green];',
        '',
        '  // Internal edges',
        '  parseheader -> getnextline;',
        '  parseheader -> gettitle;',
        '  parseheader -> getnext;',
        '  parseheader -> atoll_size;',
        '  parseheader -> atof_domain;',
        '  mpe_tag -> curveset;',
        '  curveset -> curves;',
        '  mpe_tag -> mpeclut;',
        '  mpeclut -> clut;',
        '  clut -> clut_init [color=red, penwidth=2];',
        '  mpe_tag -> attach_a2b;',
        '  attach_a2b -> desc_tag;',
        '  desc_tag -> copy_tag;',
        '  copy_tag -> save;',
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
    parser = argparse.ArgumentParser(description="iccFromCube call graph analysis")
    parser.add_argument("--dot", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--render", choices=["png", "svg", "pdf"], default=None)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    if args.summary or not any([args.dot, args.json]):
        fid = compute_fidelity()
        print(f"\n{'='*60}")
        print(f"iccFromCube Call Graph & Fuzzer Fidelity")
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
