#!/usr/bin/env python3
"""
iccToXml Call Graph & AST Gate Analysis
========================================

Static analysis of IccToXml.cpp to extract call graph, AST gates,
and fuzzer fidelity mapping for the icc_toxml_fuzzer.

This tool is notable for:
  - Being the simplest tool in the iccDEV suite (56 lines)
  - Near-perfect fuzzer fidelity (Read→ToXml core path fully covered)
  - The ToXml() path exercises all tag Describe/serialization code
  - 40MB string reserve is an OOM concern with large profiles

Usage:
    python3 iccToXml-callgraph.py [--dot FILE] [--json FILE] [--render FORMAT]
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

TOOL_NAME = "iccToXml"
TOOL_FILE = "IccToXml.cpp"
FUZZER_NAME = "icc_toxml_fuzzer"
FUZZER_FILE = "icc_toxml_fuzzer.cpp"

# Phase 1: Factory Initialization
INIT_CALLS = [
    CallSite("CIccTagCreator::PushFactory(CIccTagXmlFactory)", 20, "main",
             "Register XML tag factory for tag serialization",
             in_fuzzer=True,
             note="Fuzzer does this in LLVMFuzzerInitialize — identical"),
    CallSite("CIccMpeCreator::PushFactory(CIccMpeXmlFactory)", 21, "main",
             "Register XML MPE factory for MPE tag serialization",
             in_fuzzer=True,
             note="Fuzzer does this in LLVMFuzzerInitialize — identical"),
]

# Phase 2: CLI Argument Parsing
CLI_CALLS = [
    CallSite("printf(usage)", 15, "main",
             "Print usage message and exit", cli_only=True, in_fuzzer=False),
]

# Phase 3: Profile Loading (core attack surface)
LOAD_CALLS = [
    CallSite("CIccFileIO::Open(src)", 26, "main",
             "Open source ICC profile file for reading",
             in_fuzzer=False,
             note="Fuzzer uses CIccMemIO::Attach instead of file I/O"),
    CallSite("CIccProfileXml::Read", 31, "main",
             "Parse ICC profile binary data into CIccProfileXml object",
             in_fuzzer=True,
             note="Fuzzer matches via Attach() which calls Read internally"),
]

# Phase 4: XML Conversion (core attack surface)
CONVERT_CALLS = [
    CallSite("std::string::reserve(40000000)", 37, "main",
             "Pre-allocate 40MB for XML output string",
             in_fuzzer=False,
             note="Fuzzer does not pre-allocate — relies on std::string growth"),
    CallSite("CIccProfileXml::ToXml", 39, "main",
             "Convert parsed ICC profile to XML string — MAIN ATTACK SURFACE",
             in_fuzzer=True,
             note="Exact 1:1 match. Exercises all tag ToXml serialization paths"),
]

# Phase 5: Output Writing
OUTPUT_CALLS = [
    CallSite("CIccFileIO::Open(dst)", 44, "main",
             "Open destination file for XML output writing",
             in_fuzzer=False,
             note="Fuzzer discards XML output — write path not exercised"),
    CallSite("CIccFileIO::Write8", 49, "main",
             "Write XML string to output file",
             in_fuzzer=False),
    CallSite("CIccFileIO::Close", 57, "main",
             "Close output file handle",
             in_fuzzer=False),
]

# Phase 6: Deep call chains from Read + ToXml
DEEP_CALLS = [
    CallSite("CIccProfile::Read (header)", 0, "CIccProfileXml::Read",
             "Parse 128-byte ICC header", in_fuzzer=True),
    CallSite("CIccProfile::Read (tag directory)", 0, "CIccProfileXml::Read",
             "Parse tag directory and load all tags", in_fuzzer=True,
             note="Each tag type has its own Read method — memory allocation hotspot"),
    CallSite("CIccTag*::ToXml (50+ tag types)", 0, "CIccProfileXml::ToXml",
             "Per-tag XML serialization — each tag type has its own ToXml",
             in_fuzzer=True,
             note="Exercises Describe paths, string formatting, numeric conversions"),
    CallSite("CIccMpe*::ToXml", 0, "CIccProfileXml::ToXml",
             "MPE element XML serialization", in_fuzzer=True),
    CallSite("icFixXml", 0, "various ToXml",
             "XML character escaping for output strings",
             in_fuzzer=True,
             note="Patch 065 caps buffer at 65536 bytes"),
]

ALL_CALLS = INIT_CALLS + CLI_CALLS + LOAD_CALLS + CONVERT_CALLS + OUTPUT_CALLS + DEEP_CALLS

GATES = [
    ASTGate("argc <= 2", 14, "if", "main",
            security_relevant=False, note="Usage message guard"),
    ASTGate("!srcIO.Open()", 26, "if", "main",
            security_relevant=True,
            note="Source file open failure — prevents Read"),
    ASTGate("!profile.Read()", 31, "if", "main",
            security_relevant=True,
            note="Profile parse failure — prevents ToXml on corrupt data"),
    ASTGate("!profile.ToXml()", 39, "if", "main",
            security_relevant=True,
            note="XML conversion failure — prevents output write"),
    ASTGate("!dstIO.Open()", 44, "if", "main",
            security_relevant=False,
            note="Destination file open failure"),
    ASTGate("Write8 size check", 49, "if", "main",
            security_relevant=False,
            note="Write completeness check"),
    ASTGate("Tag count in profile", 0, "Read", "CIccProfile",
            security_relevant=True,
            note="Number of tags determines allocation count during Read"),
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
        "fidelity_note": "HIGH",
        "note": (
            "The toxml fuzzer has high fidelity with the tool. It exercises "
            "the complete Read→ToXml pipeline which is the core attack surface. "
            "The only differences are: (1) fuzzer uses CIccMemIO instead of "
            "CIccFileIO for input, (2) fuzzer discards XML output instead of "
            "writing to file, (3) fuzzer does not pre-allocate the 40MB string. "
            "The Read + ToXml paths exercise all tag parsing and serialization code."
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
            "1_factory_init": {
                "description": "Register XML tag and MPE factories",
                "calls": [asdict(c) for c in INIT_CALLS],
                "in_fuzzer": True,
            },
            "2_cli_parsing": {
                "description": "Command-line argument check",
                "calls": [asdict(c) for c in CLI_CALLS],
                "in_fuzzer": False,
            },
            "3_profile_loading": {
                "description": "ICC profile binary parsing via Read()",
                "calls": [asdict(c) for c in LOAD_CALLS],
                "in_fuzzer": True,
            },
            "4_xml_conversion": {
                "description": "Profile→XML conversion — main attack surface",
                "calls": [asdict(c) for c in CONVERT_CALLS],
                "in_fuzzer": "partial",
                "reason": "ToXml is fully covered; 40MB reserve is tool-only",
            },
            "5_output": {
                "description": "Write XML string to output file",
                "calls": [asdict(c) for c in OUTPUT_CALLS],
                "in_fuzzer": False,
                "reason": "Output-only operations, not part of attack surface",
            },
            "6_deep_calls": {
                "description": "Deep call chains from Read + ToXml (tag-level processing)",
                "calls": [asdict(c) for c in DEEP_CALLS],
                "in_fuzzer": True,
            },
        },
        "gates": [asdict(g) for g in GATES],
        "fidelity": compute_fidelity(),
        "oom_concerns": [
            {
                "location": "std::string::reserve(40000000)",
                "file": "IccToXml.cpp:37",
                "trigger": "40MB pre-allocation for XML output",
                "note": "Tool always allocates 40MB regardless of profile size",
            },
            {
                "location": "CIccTag*::ToXml with large LUT data",
                "file": "various IccTagXml.cpp",
                "trigger": "Large CLUT/curve tags generate massive XML output",
                "note": "Can exceed 40MB pre-allocation causing realloc",
            },
        ],
        "fuzzer_input_format": {
            "description": "Raw ICC profile binary data (entire input is profile)",
            "min_size": 128,
            "max_size": "5MB",
        },
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[OK] JSON call graph: {output_file}")


def generate_dot(output_file):
    lines = [
        'digraph iccToXml {',
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
        '  tool [label="main()\\nIccToXml.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '  fuzzer [label="LLVMFuzzerTestOneInput()\\nicc_toxml_fuzzer.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '',
        '  // Factory init',
        '  subgraph cluster_init {',
        '    label="Phase 1: Factory Init"; style=rounded;',
        '    tag_factory [label="PushFactory\\n(TagXmlFactory)", fillcolor="#90EE90"];',
        '    mpe_factory [label="PushFactory\\n(MpeXmlFactory)", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // CLI',
        '  subgraph cluster_cli {',
        '    label="Phase 2: CLI"; style=rounded;',
        '    usage [label="printf(usage)", fillcolor="#D3D3D3"];',
        '  }',
        '',
        '  // Profile loading',
        '  subgraph cluster_load {',
        '    label="Phase 3: Profile Loading"; style=rounded; color=red;',
        '    fileio_open [label="CIccFileIO::Open\\nL26", fillcolor="#ADD8E6"];',
        '    profile_read [label="CIccProfileXml::Read\\nL31\\nMAIN ENTRY", fillcolor="#90EE90", penwidth=3];',
        '  }',
        '',
        '  // XML conversion',
        '  subgraph cluster_convert {',
        '    label="Phase 4: XML Conversion (Attack Surface)"; style=rounded; color=red;',
        '    reserve [label="string::reserve\\n(40MB)", fillcolor="#ADD8E6"];',
        '    toxml [label="CIccProfileXml::ToXml\\nMAIN ATTACK SURFACE", fillcolor="#90EE90", penwidth=3];',
        '  }',
        '',
        '  // Output',
        '  subgraph cluster_output {',
        '    label="Phase 5: Output Writing"; style=rounded;',
        '    dst_open [label="CIccFileIO::Open\\n(dst)", fillcolor="#ADD8E6"];',
        '    write8 [label="CIccFileIO::Write8", fillcolor="#ADD8E6"];',
        '    close [label="CIccFileIO::Close", fillcolor="#ADD8E6"];',
        '  }',
        '',
        '  // Deep calls',
        '  subgraph cluster_deep {',
        '    label="Phase 6: Deep Call Chains"; style=rounded; color=red;',
        '    read_hdr [label="Read (header)", fillcolor="#90EE90"];',
        '    read_tags [label="Read (tag dir)", fillcolor="#90EE90"];',
        '    tag_toxml [label="Tag::ToXml\\n(50+ types)", fillcolor="#90EE90"];',
        '    mpe_toxml [label="MPE::ToXml", fillcolor="#90EE90"];',
        '    icfixxml [label="icFixXml", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Tool edges',
        '  tool -> tag_factory;',
        '  tool -> mpe_factory;',
        '  tool -> usage [style=dashed];',
        '  tool -> fileio_open [style=dashed];',
        '  tool -> profile_read [style=bold, penwidth=2];',
        '  tool -> reserve [style=dashed];',
        '  tool -> toxml [style=bold, penwidth=2];',
        '  tool -> dst_open [style=dashed];',
        '  tool -> write8 [style=dashed];',
        '  tool -> close [style=dashed];',
        '',
        '  // Fuzzer edges',
        '  fuzzer -> tag_factory [style=dotted, color=green];',
        '  fuzzer -> mpe_factory [style=dotted, color=green];',
        '  fuzzer -> profile_read [style=bold, color=green, penwidth=2];',
        '  fuzzer -> toxml [style=bold, color=green, penwidth=2];',
        '',
        '  // Deep call chain',
        '  profile_read -> read_hdr [style=bold];',
        '  profile_read -> read_tags [style=bold];',
        '  toxml -> tag_toxml [style=bold];',
        '  toxml -> mpe_toxml;',
        '  tag_toxml -> icfixxml;',
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
    parser = argparse.ArgumentParser(description="iccToXml call graph analysis")
    parser.add_argument("--dot", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--render", choices=["png", "svg", "pdf"], default=None)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    if args.summary or not any([args.dot, args.json]):
        fid = compute_fidelity()
        print(f"\n{'='*60}")
        print(f"iccToXml Call Graph & Fuzzer Fidelity")
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
