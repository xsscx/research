#!/usr/bin/env python3
"""
iccFromXml Call Graph & AST Gate Analysis
==========================================

Static analysis of IccFromXml.cpp to extract call graph, AST gates,
and fuzzer fidelity mapping for the icc_fromxml_fuzzer.

This tool is notable for:
  - Being the primary OOM attack surface (XML→ICC parsing)
  - Having near-perfect fuzzer fidelity (direct code copy)
  - Deep call chains through CIccProfileXml::LoadXml → CIccTagXml::ParseXml

Usage:
    python3 iccFromXml-callgraph.py [--dot FILE] [--json FILE] [--render FORMAT]
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

TOOL_NAME = "iccFromXml"
TOOL_FILE = "IccFromXml.cpp"
FUZZER_NAME = "icc_fromxml_fuzzer"
FUZZER_FILE = "icc_fromxml_fuzzer.cpp"

# Phase 1: Factory Initialization
INIT_CALLS = [
    CallSite("CIccTagCreator::PushFactory(CIccTagXmlFactory)", 24, "main",
             "Register XML tag factory for tag deserialization",
             in_fuzzer=True,
             note="Fuzzer does this in LLVMFuzzerInitialize — identical"),
    CallSite("CIccMpeCreator::PushFactory(CIccMpeXmlFactory)", 25, "main",
             "Register XML MPE factory for calculator/MPE tags",
             in_fuzzer=True,
             note="Fuzzer does this in LLVMFuzzerInitialize — identical"),
]

# Phase 2: CLI Argument Parsing
CLI_CALLS = [
    CallSite("stricmp(-noid)", 39, "main",
             "Check for -noid flag", cli_only=True, in_fuzzer=False),
    CallSite("strncmp(-v)", 42, "main",
             "Check for RelaxNG schema validation flag",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer skips schema validation — matches tool default behavior"),
    CallSite("fopen(schema)", 60, "main",
             "Open RelaxNG schema file for validation",
             cli_only=True, in_fuzzer=False),
]

# Phase 3: XML Parsing (core attack surface — where OOMs occur)
PARSE_CALLS = [
    CallSite("CIccProfileXml::LoadXml", 72, "main",
             "Parse XML file into ICC profile — MAIN ATTACK SURFACE",
             in_fuzzer=True,
             note="Exact 1:1 match. This is where all OOM/crash paths originate"),
    CallSite("CIccProfileXml::Validate", 80, "main",
             "Validate parsed profile structure",
             in_fuzzer=True,
             note="Fuzzer runs Validate on both valid and invalid profiles"),
]

# Phase 4: Profile Output
OUTPUT_CALLS = [
    CallSite("SaveIccProfile(valid)", 92, "main",
             "Save parsed profile when validation <= warning",
             in_fuzzer=True,
             note="Fuzzer saves to temp file then deletes — exercises write path"),
    CallSite("SaveIccProfile(invalid)", 102, "main",
             "Save parsed profile even when validation fails",
             in_fuzzer=True,
             note="Fuzzer exercises both paths — valid and invalid save"),
]

# Phase 5: Fuzzer-only calls
FUZZER_EXTRA = [
    CallSite("xmlSetGenericErrorFunc", 0, "LLVMFuzzerInitialize",
             "Suppress libxml2 error output during fuzzing",
             in_fuzzer=True, note="Required to prevent stderr flooding"),
    CallSite("xmlSubstituteEntitiesDefault(0)", 0, "LLVMFuzzerInitialize",
             "Disable XXE entity substitution",
             in_fuzzer=True, note="Security hardening — prevents XXE attacks"),
    CallSite("xmlLoadExtDtdDefaultValue=0", 0, "LLVMFuzzerTestOneInput",
             "Disable external DTD loading",
             in_fuzzer=True, note="Security hardening — prevents DTD-based XXE"),
]

# Deep call chains from LoadXml (the real attack surface)
DEEP_CALLS = [
    CallSite("xmlParseFile", 0, "CIccProfileXml::LoadXml",
             "libxml2 parses XML file into DOM tree", in_fuzzer=True,
             note="This is where entity expansion OOMs can occur"),
    CallSite("icXmlParseProfHdr", 0, "CIccProfileXml::LoadXml",
             "Parse ICC header from XML", in_fuzzer=True),
    CallSite("CIccTag*::ParseXml (50+ tag types)", 0, "CIccProfileXml::LoadXml",
             "Per-tag XML parsing — each tag type has its own ParseXml",
             in_fuzzer=True,
             note="OOM hotspot: CIccLocalizedUnicode copy ctor (mluc tags)"),
    CallSite("CIccTagXmlMultiLocalizedUnicode::ParseXml", 0, "LoadXml→tag",
             "Parse mluc (multi-localized Unicode) — OOM HOTSPOT",
             in_fuzzer=True,
             note="IccTagBasic.cpp:7123 — CIccLocalizedUnicode copy ctor allocates"),
    CallSite("CIccMpeXml*::ParseXml", 0, "LoadXml→tag",
             "Parse MPE calculator elements",
             in_fuzzer=True),
    CallSite("CIccTagXmlProfileSeqDesc::ParseXml", 0, "LoadXml→tag",
             "Parse profile sequence description — allocation loop",
             in_fuzzer=True,
             note="Can allocate unbounded ProfileDescStructs"),
    CallSite("icFixXml", 0, "various ParseXml",
             "XML string unescaping — BUFFER OVERFLOW HOTSPOT",
             in_fuzzer=True,
             note="Patch 065 caps this at 65536 bytes"),
]

ALL_CALLS = INIT_CALLS + CLI_CALLS + PARSE_CALLS + OUTPUT_CALLS + FUZZER_EXTRA + DEEP_CALLS

GATES = [
    ASTGate("argc <= 2", 17, "if", "main",
            security_relevant=False, note="Usage message guard"),
    ASTGate("!profile.LoadXml()", 72, "if", "main",
            security_relevant=True,
            note="XML parse failure — prevents SaveIccProfile on corrupt data"),
    ASTGate("Validate() <= icValidateWarning", 80, "if", "main",
            security_relevant=True,
            note="Controls whether profile is saved as 'valid' or 'invalid'"),
    ASTGate("profileID check (i<16)", 84, "if", "main",
            security_relevant=False,
            note="Determines icAlwaysWriteID vs icVersionBasedID"),
    ASTGate("XML entity expansion size", 0, "xmlParseFile", "libxml2",
            security_relevant=True,
            note="libxml2 internal — can trigger unbounded memory allocation"),
    ASTGate("Tag count in XML", 0, "LoadXml", "CIccProfileXml",
            security_relevant=True,
            note="Number of <Tag> elements determines allocation count"),
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
            "The fromxml fuzzer is an almost exact copy of the tool code "
            "(IccFromXml.cpp lines 24-109). It exercises LoadXml, Validate, "
            "and SaveIccProfile on both valid and invalid paths. The only "
            "differences are: (1) schema validation is skipped (matches tool "
            "default), (2) XXE protection is added for security, (3) -noid "
            "flag is hardcoded to false."
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
            "1_factory_init": {
                "description": "Register XML tag and MPE factories",
                "calls": [asdict(c) for c in INIT_CALLS],
                "in_fuzzer": True,
            },
            "2_cli_parsing": {
                "description": "Command-line argument parsing",
                "calls": [asdict(c) for c in CLI_CALLS],
                "in_fuzzer": False,
            },
            "3_xml_parsing": {
                "description": "XML→ICC profile parsing — main attack surface",
                "calls": [asdict(c) for c in PARSE_CALLS],
                "in_fuzzer": True,
            },
            "4_output": {
                "description": "Save parsed profile to ICC file",
                "calls": [asdict(c) for c in OUTPUT_CALLS],
                "in_fuzzer": True,
            },
            "5_fuzzer_extras": {
                "description": "Security hardening and error suppression",
                "calls": [asdict(c) for c in FUZZER_EXTRA],
                "in_fuzzer": True,
            },
            "6_deep_calls": {
                "description": "Deep call chains from LoadXml (OOM/crash surface)",
                "calls": [asdict(c) for c in DEEP_CALLS],
                "in_fuzzer": True,
            },
        },
        "gates": [asdict(g) for g in GATES],
        "fidelity": compute_fidelity(),
        "oom_hotspots": [
            {
                "location": "CIccLocalizedUnicode::CIccLocalizedUnicode(copy)",
                "file": "IccTagBasic.cpp:7123",
                "trigger": "mluc tag with many LocalizedUnicode entries",
                "patch": "067 (allocation count cap)",
            },
            {
                "location": "CIccTagXmlProfileSeqDesc::ParseXml",
                "file": "IccTagXml.cpp",
                "trigger": "ProfileSeqDesc with many ProfileDescription entries",
                "patch": "067 (allocation loop cap)",
            },
            {
                "location": "icFixXml (char* overload)",
                "file": "IccUtilXml.cpp:307",
                "trigger": "Large XML text content → unchecked strcpy",
                "patch": "065 (65536-byte buffer cap)",
            },
            {
                "location": "XML entity expansion",
                "file": "libxml2",
                "trigger": "Billion laughs / entity expansion attack",
                "mitigation": "xmlSubstituteEntitiesDefault(0)",
            },
        ],
        "fuzzer_input_format": {
            "description": "Raw XML content (the entire input is treated as XML)",
            "min_size": 10,
            "max_size": "10MB",
        },
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[OK] JSON call graph: {output_file}")


def generate_dot(output_file):
    lines = [
        'digraph iccFromXml {',
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
        '    leg_oom  [label="OOM Hotspot", fillcolor="#FF6347"];',
        '  }',
        '',
        '  tool [label="main()\\nIccFromXml.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '  fuzzer [label="LLVMFuzzerTestOneInput()\\nicc_fromxml_fuzzer.cpp", fillcolor="#FF6B6B", shape=ellipse];',
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
        '    label="Phase 2: CLI Args"; style=rounded;',
        '    noid [label="-noid flag", fillcolor="#D3D3D3"];',
        '    schema [label="RelaxNG schema", fillcolor="#D3D3D3"];',
        '  }',
        '',
        '  // Core parsing',
        '  subgraph cluster_parse {',
        '    label="Phase 3: XML Parsing (Attack Surface)"; style=rounded; color=red;',
        '    loadxml [label="LoadXml()\\nMAIN ENTRY", fillcolor="#90EE90", penwidth=3];',
        '    validate [label="Validate()", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Output',
        '  subgraph cluster_output {',
        '    label="Phase 4: Output"; style=rounded;',
        '    save_valid [label="SaveIccProfile\\n(valid)", fillcolor="#90EE90"];',
        '    save_invalid [label="SaveIccProfile\\n(invalid)", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Deep calls',
        '  subgraph cluster_deep {',
        '    label="Phase 6: Deep Call Chains (OOM Surface)"; style=rounded; color=red;',
        '    xmlparse [label="xmlParseFile\\n(libxml2)", fillcolor="#90EE90"];',
        '    parsehdr [label="icXmlParseProfHdr", fillcolor="#90EE90"];',
        '    parsetags [label="Tag::ParseXml\\n(50+ types)", fillcolor="#90EE90"];',
        '    mluc [label="mluc ParseXml\\nOOM HOTSPOT", fillcolor="#FF6347", penwidth=3];',
        '    profseq [label="ProfileSeqDesc\\nOOM HOTSPOT", fillcolor="#FF6347", penwidth=3];',
        '    icfixxml [label="icFixXml\\nBUFFER OVERFLOW", fillcolor="#FF6347", penwidth=3];',
        '    mpe_parse [label="MPE ParseXml", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Tool edges',
        '  tool -> tag_factory;',
        '  tool -> mpe_factory;',
        '  tool -> noid [style=dashed];',
        '  tool -> schema [style=dashed];',
        '  tool -> loadxml [style=bold, penwidth=2];',
        '  tool -> validate;',
        '  tool -> save_valid;',
        '  tool -> save_invalid;',
        '',
        '  // Fuzzer edges (mirrors tool)',
        '  fuzzer -> tag_factory [style=dotted, color=green];',
        '  fuzzer -> mpe_factory [style=dotted, color=green];',
        '  fuzzer -> loadxml [style=bold, color=green, penwidth=2];',
        '  fuzzer -> validate [style=dotted, color=green];',
        '  fuzzer -> save_valid [style=dotted, color=green];',
        '  fuzzer -> save_invalid [style=dotted, color=green];',
        '',
        '  // Deep call chain',
        '  loadxml -> xmlparse [style=bold];',
        '  loadxml -> parsehdr;',
        '  loadxml -> parsetags [style=bold];',
        '  parsetags -> mluc [color=red, penwidth=2];',
        '  parsetags -> profseq [color=red, penwidth=2];',
        '  parsetags -> icfixxml [color=red, penwidth=2];',
        '  parsetags -> mpe_parse;',
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
    parser = argparse.ArgumentParser(description="iccFromXml call graph analysis")
    parser.add_argument("--dot", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--render", choices=["png", "svg", "pdf"], default=None)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    if args.summary or not any([args.dot, args.json]):
        fid = compute_fidelity()
        print(f"\n{'='*60}")
        print(f"iccFromXml Call Graph & Fuzzer Fidelity")
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
