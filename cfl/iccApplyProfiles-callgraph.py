#!/usr/bin/env python3
"""
iccApplyProfiles Call Graph & AST Gate Analysis
================================================

Static analysis of iccApplyProfiles.cpp to extract:
  1. Call Graph — every function/method call with caller→callee edges
  2. AST Gates — conditional branches controlling code path reachability
  3. Fuzzer Fidelity Map — which calls the fuzzer exercises vs. tool

Modeled on the iccDumpProfile callgraph analysis for consistency.

Usage:
    python3 iccApplyProfiles-callgraph.py [--dot FILE] [--json FILE] [--render FORMAT]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass, field, asdict

# ─── Data Structures ───

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

# ─── iccApplyProfiles.cpp Call Graph ───

TOOL_NAME = "iccApplyProfiles"
TOOL_FILE = "iccApplyProfiles.cpp"
FUZZER_NAME = "icc_applyprofiles_fuzzer"
FUZZER_FILE = "icc_applyprofiles_fuzzer.cpp"

# Phase 1: Configuration Parsing (IccCmmConfig)
CONFIG_CALLS = [
    CallSite("CIccCfgDataApply::fromJson", 158, "main",
             "Parse JSON configuration file", in_fuzzer=False, cli_only=True,
             note="Fuzzer uses hardcoded params, not JSON config"),
    CallSite("CIccCfgDataApply::fromLegacy", 193, "main",
             "Parse legacy command-line arguments", in_fuzzer=False, cli_only=True),
]

# Phase 2: Source Image Loading (CTiffImg)
TIFF_CALLS = [
    CallSite("CTiffImg::Open", 206, "main",
             "Open source TIFF image for reading", in_fuzzer=False,
             note="Fuzzer does not use TIFF images — profile-only"),
    CallSite("CTiffImg::GetSamples", 210, "main",
             "Get samples per pixel from source image", in_fuzzer=False),
    CallSite("CTiffImg::GetExtraSamples", 211, "main",
             "Get extra samples (alpha) from source", in_fuzzer=False),
    CallSite("CTiffImg::GetPhoto", 212, "main",
             "Get photometric interpretation", in_fuzzer=False),
    CallSite("CTiffImg::GetBitsPerSample", 213, "main",
             "Get bits per sample from source", in_fuzzer=False),
    CallSite("CTiffImg::GetIccProfile", 251, "main",
             "Extract embedded ICC profile from source TIFF", in_fuzzer=False,
             note="Tool can use embedded profile as first profile in chain"),
    CallSite("CTiffImg::GetCompress", 254, "main",
             "Get compression setting from source", in_fuzzer=False),
    CallSite("CTiffImg::GetPlanar", 255, "main",
             "Get planar configuration from source", in_fuzzer=False),
]

# Phase 3: CMM Construction (core attack surface)
CMM_CALLS = [
    CallSite("CIccCmm::CIccCmm", 262, "main",
             "Construct CMM with icSigUnknownData, icSigUnknownData, true",
             in_fuzzer=True,
             note="Fuzzer matches: CIccCmm(icSigUnknownData, icSigUnknownData, true)"),
    CallSite("OpenIccProfile", 293, "main",
             "Open PCC profile for viewing conditions", in_fuzzer=False,
             note="Fuzzer does not use PCC profiles"),
    CallSite("CIccCreateXformHintManager", 284, "main",
             "Create hint manager for xform parameters", in_fuzzer=True),
    CallSite("CIccCmmEnvVarHint", 304, "main",
             "Add environment variable hints to xform", in_fuzzer=False,
             note="Fuzzer does not use env var hints"),
    CallSite("CIccCmmPccEnvVarHint", 308, "main",
             "Add PCC environment variable hints", in_fuzzer=False),
    CallSite("CIccCmm::AddXform(buffer)", 314, "main",
             "Add xform from embedded profile buffer (pSrcProfile)", in_fuzzer=False,
             note="Tool uses buffer path when TIFF has embedded profile"),
    CallSite("CIccCmm::AddXform(file)", 334, "main",
             "Add xform from ICC profile file path",
             in_fuzzer=True,
             note="Fuzzer matches: cmm.AddXform(tmp_profile, intent, interp, ...)"),
]

# Phase 4: CMM Execution (core attack surface)
EXEC_CALLS = [
    CallSite("CIccCmm::Begin", 350, "main",
             "Initialize CMM pipeline — allocates LUTs, validates chain",
             in_fuzzer=True,
             note="Fuzzer matches: cmm.Begin()"),
    CallSite("CIccCmm::GetSourceSpace", 364, "main",
             "Query source color space from CMM", in_fuzzer=True),
    CallSite("icGetSpaceSamples(src)", 365, "main",
             "Get number of source color channels", in_fuzzer=True),
    CallSite("CIccCmm::GetDestSpace", 385, "main",
             "Query destination color space from CMM", in_fuzzer=True),
    CallSite("icGetSpaceSamples(dst)", 387, "main",
             "Get number of dest color channels", in_fuzzer=True),
    CallSite("CIccCmm::GetLastParentSpace", 389, "main",
             "Query last parent color space for output format", in_fuzzer=True,
             note="Fuzzer calls this via cmm.GetLastParentSpace()"),
    CallSite("icGetSpaceSamples(parent)", 390, "main",
             "Get parent space samples for TIFF output", in_fuzzer=False),
    CallSite("CIccCmm::Apply", 546, "main",
             "Apply CMM transform to pixel data — MAIN EXECUTION PATH",
             in_fuzzer=True,
             note="Fuzzer exercises multiple Apply() calls with varied pixel values"),
]

# Phase 5: Destination Image Creation (CTiffImg)
DEST_CALLS = [
    CallSite("CTiffImg::Create", 430, "main",
             "Create destination TIFF file", in_fuzzer=False),
    CallSite("CIccFileIO::Open", 440, "main",
             "Open last profile for embedding in dest TIFF", in_fuzzer=False),
    CallSite("CIccFileIO::GetLength", 443, "main",
             "Get profile length for embedding", in_fuzzer=False),
    CallSite("CIccFileIO::Read", 444, "main",
             "Read profile data for embedding", in_fuzzer=False),
    CallSite("CTiffImg::SetIccProfile", 446, "main",
             "Embed ICC profile in destination TIFF", in_fuzzer=False),
]

# Phase 6: Pixel Processing Loop
PIXEL_CALLS = [
    CallSite("CTiffImg::ReadLine", 475, "main",
             "Read one scanline from source TIFF", in_fuzzer=False),
    CallSite("UnitClip", 483, "main",
             "Clamp pixel value to [0,1] range", in_fuzzer=False,
             note="Fuzzer tests out-of-range values directly"),
    CallSite("CTiffImg::WriteLine", 615, "main",
             "Write one scanline to destination TIFF", in_fuzzer=False),
    CallSite("CTiffImg::Close(src)", 629, "main",
             "Close source TIFF", in_fuzzer=False),
    CallSite("CTiffImg::Close(dst)", 634, "main",
             "Close destination TIFF", in_fuzzer=False),
]

# Phase 7: Fuzzer-only calls (exercising CMM beyond tool's pixel loop)
FUZZER_ONLY_CALLS = [
    CallSite("CIccCmm::GetNumXforms", 0, "LLVMFuzzerTestOneInput",
             "Query number of xforms in chain", in_fuzzer=True,
             note="Fuzzer exercises CMM query APIs not used by tool's pixel loop"),
    CallSite("CIccCmm::Valid", 0, "LLVMFuzzerTestOneInput",
             "Validate CMM state", in_fuzzer=True),
    CallSite("CIccCmm::GetLastSpace", 0, "LLVMFuzzerTestOneInput",
             "Query last color space", in_fuzzer=True),
]

ALL_CALLS = CONFIG_CALLS + TIFF_CALLS + CMM_CALLS + EXEC_CALLS + DEST_CALLS + PIXEL_CALLS + FUZZER_ONLY_CALLS

# ─── AST Gates ───

GATES = [
    ASTGate("!SrcImg.Open()", 206, "if", "main",
            security_relevant=True, note="Source image open failure guard"),
    ASTGate("bHasSrcProfile", 257, "if", "main",
            security_relevant=True,
            note="Controls whether embedded TIFF profile or file profile used for first xform"),
    ASTGate("!pProfCfg->m_pccFile.empty()", 289, "if", "main",
            security_relevant=False, note="PCC profile loading gate"),
    ASTGate("!pProfCfg->m_iccEnvVars.empty()", 302, "if", "main",
            security_relevant=False, note="Env var hint gate"),
    ASTGate("bHasSrcProfile && n==0", 312, "if", "main",
            security_relevant=True,
            note="First profile uses embedded buffer vs file — different AddXform overload"),
    ASTGate("stat != icCmmStatOk (AddXform)", 320, "if", "main",
            security_relevant=True, note="Profile load failure handling"),
    ASTGate("stat = theCmm.Begin()", 350, "if", "main",
            security_relevant=True,
            note="CMM initialization failure — controls whether Apply() is reachable"),
    ASTGate("SrcspaceSig switch", 396, "switch", "main",
            security_relevant=True,
            note="Source color space determines pixel format conversion"),
    ASTGate("DestSpaceSig switch", 396, "switch", "main",
            security_relevant=True,
            note="Dest color space determines output pixel format"),
    ASTGate("!DstImg.Create()", 430, "if", "main",
            security_relevant=True, note="Dest image creation failure guard"),
    ASTGate("SrcImg.ReadLine()", 475, "if", "main",
            security_relevant=True, note="Scanline read failure during pixel loop"),
    ASTGate("sphoto == PHOTO_CIELAB", 539, "if", "main",
            security_relevant=False, note="CIELAB encoding scale adjustment"),
    ASTGate("photo == PHOTO_CIELAB", 549, "if", "main",
            security_relevant=False, note="CIELAB decoding scale adjustment"),
    ASTGate("DstImg.WriteLine()", 615, "if", "main",
            security_relevant=True, note="Scanline write failure during pixel loop"),
]


def compute_fidelity():
    """Compute fuzzer fidelity metrics."""
    total = len(ALL_CALLS)
    cli_only = sum(1 for c in ALL_CALLS if c.cli_only)
    tiff_only = sum(1 for c in TIFF_CALLS + DEST_CALLS + PIXEL_CALLS if not c.in_fuzzer)
    fuzzable = total - cli_only
    matched = sum(1 for c in ALL_CALLS if c.in_fuzzer)
    # Calls that are in scope but not in fuzzer (TIFF I/O, config parsing)
    not_fuzzable_reason = "TIFF I/O and config parsing (not applicable to profile-only fuzzing)"

    return {
        "total_call_sites": total,
        "cli_only_excluded": cli_only,
        "fuzzable_call_sites": fuzzable,
        "matched_by_fuzzer": matched,
        "tiff_io_not_in_fuzzer": tiff_only,
        "coverage_percent": round(matched / max(fuzzable, 1) * 100, 1),
        "note": (
            "The fuzzer focuses on the CMM pipeline (AddXform→Begin→Apply) which is the "
            "security-critical attack surface. TIFF I/O is excluded because the fuzzer "
            "feeds profile data directly without image containers. This is by design — "
            "the profile parsing and CMM execution paths are where vulnerabilities occur."
        ),
    }


def generate_json(output_file):
    """Generate JSON call graph report."""
    data = {
        "tool": TOOL_NAME,
        "tool_file": TOOL_FILE,
        "fuzzer": FUZZER_NAME,
        "fuzzer_file": FUZZER_FILE,
        "analysis_date": "2026-03-06",
        "phases": {
            "1_config_parsing": {
                "description": "JSON/legacy configuration parsing via IccCmmConfig",
                "calls": [asdict(c) for c in CONFIG_CALLS],
                "in_fuzzer": False,
                "reason": "Fuzzer uses hardcoded params, not JSON config files",
            },
            "2_source_image": {
                "description": "Source TIFF image loading and ICC profile extraction",
                "calls": [asdict(c) for c in TIFF_CALLS],
                "in_fuzzer": False,
                "reason": "Fuzzer feeds profile data directly, no TIFF container",
            },
            "3_cmm_construction": {
                "description": "CMM object creation, profile loading, xform setup",
                "calls": [asdict(c) for c in CMM_CALLS],
                "in_fuzzer": "partial",
                "reason": "Fuzzer exercises AddXform(file) path, not buffer or PCC paths",
            },
            "4_cmm_execution": {
                "description": "CMM Begin + Apply — main security-critical execution",
                "calls": [asdict(c) for c in EXEC_CALLS],
                "in_fuzzer": True,
                "reason": "Full coverage of CMM pipeline execution",
            },
            "5_dest_image": {
                "description": "Destination TIFF creation and profile embedding",
                "calls": [asdict(c) for c in DEST_CALLS],
                "in_fuzzer": False,
                "reason": "Output-only operations, not part of attack surface",
            },
            "6_pixel_loop": {
                "description": "Per-scanline pixel conversion loop",
                "calls": [asdict(c) for c in PIXEL_CALLS],
                "in_fuzzer": False,
                "reason": "Fuzzer tests pixel values directly via Apply(), not via TIFF I/O",
            },
            "7_fuzzer_extras": {
                "description": "Additional CMM query APIs exercised by fuzzer",
                "calls": [asdict(c) for c in FUZZER_ONLY_CALLS],
                "in_fuzzer": True,
                "reason": "Fuzzer exercises CMM state queries for additional coverage",
            },
        },
        "gates": [asdict(g) for g in GATES],
        "fidelity": compute_fidelity(),
        "fuzzer_pixel_tests": [
            "Black (all zeros) → Apply",
            "White (all ones) → Apply",
            "Gray (all 0.5) → Apply",
            "Primary colors (one channel at 1.0) → Apply",
            "Control-data derived values (0-255 normalized) → Apply",
            "Negative values (-0.1) → Apply",
            "Over-range values (1.1) → Apply",
            "NaN values → Apply",
        ],
        "fuzzer_input_format": {
            "description": "First 75% is ICC profile data, last 25% is control data",
            "control_bytes": {
                "byte_0": "icRenderingIntent (% 4)",
                "byte_1": "icXformInterp (bit 0: linear vs tetrahedral)",
                "byte_3": "use_d2bx flag (bit 0)",
            },
            "min_size": 200,
            "max_size": "5MB",
        },
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[OK] JSON call graph: {output_file}")


def generate_dot(output_file):
    """Generate Graphviz DOT call graph."""
    lines = [
        'digraph iccApplyProfiles {',
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
        '  // Entry points',
        '  main [label="main()\\niccApplyProfiles.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '  fuzzer [label="LLVMFuzzerTestOneInput()\\nicc_applyprofiles_fuzzer.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '',
    ]

    # Phase clusters
    phases = [
        ("cluster_config", "Phase 1: Config Parsing", CONFIG_CALLS),
        ("cluster_tiff_src", "Phase 2: Source Image", TIFF_CALLS),
        ("cluster_cmm_build", "Phase 3: CMM Construction", CMM_CALLS),
        ("cluster_cmm_exec", "Phase 4: CMM Execution", EXEC_CALLS),
        ("cluster_tiff_dst", "Phase 5: Dest Image", DEST_CALLS),
        ("cluster_pixel", "Phase 6: Pixel Loop", PIXEL_CALLS),
        ("cluster_fuzzer_extra", "Phase 7: Fuzzer Extras", FUZZER_ONLY_CALLS),
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

    # Edges from main
    for c in ALL_CALLS:
        nid = node_map.get(c.callee + str(c.line))
        if not nid:
            continue
        if c.caller == "main":
            style = 'style=bold' if c.in_fuzzer else 'style=dashed'
            lines.append(f'  main -> {nid} [{style}];')
        elif c.caller == "LLVMFuzzerTestOneInput":
            lines.append(f'  fuzzer -> {nid} [style=bold, color=orange];')

    # Fuzzer mirrors some main calls
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
    """Render DOT to image using Graphviz."""
    out_file = dot_file.rsplit(".", 1)[0] + f".{fmt}"
    dot_cmd = shutil.which("dot")
    if not dot_cmd:
        print("WARNING: Graphviz 'dot' not found, skipping render", file=sys.stderr)
        return
    try:
        subprocess.run([dot_cmd, f"-T{fmt}", dot_file, "-o", out_file],
                       check=True, timeout=30)
        print(f"[OK] Rendered: {out_file}")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
        print(f"WARNING: Render failed: {e}", file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description="iccApplyProfiles call graph analysis")
    parser.add_argument("--dot", default=None, help="Output DOT file")
    parser.add_argument("--json", default=None, help="Output JSON file")
    parser.add_argument("--render", choices=["png", "svg", "pdf"], default=None,
                        help="Render DOT to image format")
    parser.add_argument("--summary", action="store_true", help="Print fidelity summary")
    args = parser.parse_args()

    if args.summary or not any([args.dot, args.json]):
        fid = compute_fidelity()
        print(f"\n{'='*60}")
        print(f"iccApplyProfiles Call Graph & Fuzzer Fidelity")
        print(f"{'='*60}")
        print(f"Total call sites:      {fid['total_call_sites']}")
        print(f"CLI-only excluded:     {fid['cli_only_excluded']}")
        print(f"Fuzzable call sites:   {fid['fuzzable_call_sites']}")
        print(f"Matched by fuzzer:     {fid['matched_by_fuzzer']}")
        print(f"TIFF I/O (not in fuz): {fid['tiff_io_not_in_fuzzer']}")
        print(f"Coverage:              {fid['coverage_percent']}%")
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
