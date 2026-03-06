#!/usr/bin/env python3
"""
iccTiffDump Call Graph & AST Gate Analysis
==========================================

Static analysis of iccTiffDump.cpp to extract call graph, AST gates,
and fuzzer fidelity mapping for the icc_tiffdump_fuzzer.

This tool is notable for:
  - TIFF header/metadata dumping via CTiffImg
  - ICC profile extraction from TIFF (OpenIccProfile from memory)
  - Recursive DumpProfileInfo for embedded V5 profiles
  - Fuzzer uses in-memory TIFF I/O (TIFFClientOpen) — zero disk I/O

Usage:
    python3 iccTiffDump-callgraph.py [--dot FILE] [--json FILE] [--render FORMAT]
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

TOOL_NAME = "iccTiffDump"
TOOL_FILE = "iccTiffDump.cpp"
FUZZER_NAME = "icc_tiffdump_fuzzer"
FUZZER_FILE = "icc_tiffdump_fuzzer.cpp"

# Phase 1: CLI Argument Parsing
CLI_CALLS = [
    CallSite("Usage()", 188, "main",
             "Display usage message when argc <= 1",
             cli_only=True, in_fuzzer=False),
    CallSite("CTiffImg::Open(argv[1])", 193, "main",
             "Open TIFF file from CLI argument",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer uses TIFFClientOpen with in-memory I/O instead"),
    CallSite("fopen(argv[2], wb)", 221, "main",
             "Export ICC profile to file (optional argv[2])",
             cli_only=True, in_fuzzer=False),
    CallSite("fwrite(pProfMem)", 223, "main",
             "Write raw ICC profile bytes to export file",
             cli_only=True, in_fuzzer=False),
    CallSite("SaveIccProfile(argv[2])", 237, "main",
             "Save parsed ICC profile via IccProfLib",
             cli_only=True, in_fuzzer=False),
]

# Phase 2: TIFF Header Dumping
TIFF_CALLS = [
    CallSite("TIFFClientOpen(memory)", 105, "LLVMFuzzerTestOneInput",
             "Open TIFF from in-memory buffer — FUZZER ENTRY",
             in_fuzzer=True,
             note="Replaces CTiffImg::Open. Uses custom read/seek/close callbacks"),
    CallSite("TIFFGetField(IMAGEWIDTH)", 122, "LLVMFuzzerTestOneInput",
             "Read TIFF image width",
             in_fuzzer=True),
    CallSite("TIFFGetField(IMAGELENGTH)", 123, "LLVMFuzzerTestOneInput",
             "Read TIFF image height",
             in_fuzzer=True),
    CallSite("TIFFGetField(SAMPLESPERPIXEL)", 124, "LLVMFuzzerTestOneInput",
             "Read samples per pixel",
             in_fuzzer=True),
    CallSite("TIFFGetField(BITSPERSAMPLE)", 125, "LLVMFuzzerTestOneInput",
             "Read bits per sample",
             in_fuzzer=True),
    CallSite("TIFFGetField(PHOTOMETRIC)", 126, "LLVMFuzzerTestOneInput",
             "Read photometric interpretation",
             in_fuzzer=True),
    CallSite("TIFFGetField(ROWSPERSTRIP)", 127, "LLVMFuzzerTestOneInput",
             "Read rows per strip",
             in_fuzzer=True),
    CallSite("TIFFGetField(SAMPLEFORMAT)", 128, "LLVMFuzzerTestOneInput",
             "Read sample format (uint/float)",
             in_fuzzer=True),
    CallSite("TIFFGetField(ORIENTATION)", 129, "LLVMFuzzerTestOneInput",
             "Read image orientation",
             in_fuzzer=True),
    CallSite("TIFFReadDirectory(tif)", 219, "LLVMFuzzerTestOneInput",
             "Advance to next TIFF directory (multi-page TIFFs)",
             in_fuzzer=True,
             note="Tool processes single page; fuzzer iterates all directories"),
    CallSite("TIFFClose(tif)", 221, "LLVMFuzzerTestOneInput",
             "Close TIFF handle",
             in_fuzzer=True),
]

# Phase 3: TIFF Metadata Display (tool uses printf; fuzzer uses API)
METADATA_CALLS = [
    CallSite("GetId(SrcImg.GetPlanar())", 203, "main",
             "Map planar config to string",
             in_fuzzer=False,
             note="Fuzzer reads fields directly via TIFFGetField"),
    CallSite("GetId(SrcImg.GetPhoto())", 209, "main",
             "Map photometric to string",
             in_fuzzer=False,
             note="Fuzzer reads fields directly"),
    CallSite("GetId(SrcImg.GetCompress())", 212, "main",
             "Map compression to string",
             in_fuzzer=False,
             note="Fuzzer does not exercise compression ID lookup"),
    CallSite("SrcImg.GetExtraSamples()", 206, "main",
             "Get extra sample count",
             in_fuzzer=False,
             note="Fuzzer reads samples via TIFFGetField"),
]

# Phase 4: ICC Profile Extraction (core security surface)
ICC_CALLS = [
    CallSite("SrcImg.GetIccProfile(pProfMem, nLen)", 216, "main",
             "Extract embedded ICC profile bytes from TIFF",
             in_fuzzer=True,
             note="Fuzzer uses TIFFGetField(TIFFTAG_ICCPROFILE) directly"),
    CallSite("OpenIccProfile(pProfMem, nLen)", 232, "main",
             "Parse ICC profile from memory — MAIN ATTACK SURFACE",
             in_fuzzer=True,
             note="Exact match: both parse profile from memory buffer"),
    CallSite("CIccInfo::GetVersionName()", 128, "DumpProfileInfo",
             "Format profile version string",
             in_fuzzer=True),
    CallSite("CIccInfo::GetColorSpaceSigName(colorSpace)", 131, "DumpProfileInfo",
             "Format color space signature",
             in_fuzzer=True),
    CallSite("CIccInfo::GetColorSpaceSigName(pcs)", 133, "DumpProfileInfo",
             "Format PCS signature",
             in_fuzzer=True),
    CallSite("CIccInfo::GetSpectralColorSigName()", 135, "DumpProfileInfo",
             "Format spectral PCS signature",
             in_fuzzer=True),
    CallSite("icF16toF(spectralRange.start/end)", 138, "DumpProfileInfo",
             "Convert half-float spectral range values",
             in_fuzzer=True),
    CallSite("icF16toF(biSpectralRange.start/end)", 143, "DumpProfileInfo",
             "Convert half-float bi-spectral range values",
             in_fuzzer=True),
    CallSite("pProfile->FindTag(icSigProfileDescriptionTag)", 150, "DumpProfileInfo",
             "Look up profile description tag",
             in_fuzzer=True),
    CallSite("CIccTagTextDescription::GetText()", 154, "DumpProfileInfo",
             "Get text from desc tag (v2 type)",
             in_fuzzer=True),
    CallSite("CIccTagMultiLocalizedUnicode::GetText()", 161, "DumpProfileInfo",
             "Get text from desc tag (v4 mluc type)",
             in_fuzzer=True),
]

# Phase 5: Embedded Profile (recursive)
EMBEDDED_CALLS = [
    CallSite("pProfile->FindTag(icSigEmbeddedV5ProfileTag)", 169, "DumpProfileInfo",
             "Check for embedded V5 profile tag",
             in_fuzzer=True),
    CallSite("CIccTagEmbeddedProfile::GetProfile()", 174, "DumpProfileInfo",
             "Get embedded sub-profile pointer",
             in_fuzzer=True),
    CallSite("DumpProfileInfo(recursive)", 176, "DumpProfileInfo",
             "Recursively dump embedded profile — RECURSIVE ATTACK SURFACE",
             in_fuzzer=True,
             note="Fuzzer exercises this via pSubProfile->ReadTags()"),
    CallSite("pProfile->ReadTags(pProfile)", 236, "main",
             "Read all tags from profile for export",
             in_fuzzer=True,
             note="Fuzzer calls ReadTags on both main and embedded profiles"),
]

# Phase 6: Fuzzer-only
FUZZER_EXTRA = [
    CallSite("TIFFSetErrorHandler(silent)", 86, "LLVMFuzzerInitialize",
             "Suppress libtiff error output",
             in_fuzzer=True),
    CallSite("TIFFSetWarningHandler(silent)", 87, "LLVMFuzzerInitialize",
             "Suppress libtiff warning output",
             in_fuzzer=True),
    CallSite("mem_read/mem_seek/mem_close", 33, "LLVMFuzzerTestOneInput",
             "Custom in-memory TIFF I/O callbacks",
             in_fuzzer=True,
             note="Zero disk I/O — all processing in memory"),
]

ALL_CALLS = CLI_CALLS + TIFF_CALLS + METADATA_CALLS + ICC_CALLS + EMBEDDED_CALLS + FUZZER_EXTRA

GATES = [
    ASTGate("argc <= 1", 187, "if", "main",
            security_relevant=False, note="Usage guard"),
    ASTGate("!SrcImg.Open(argv[1])", 193, "if", "main",
            security_relevant=True,
            note="TIFF open failure"),
    ASTGate("TIFF magic (II or MM)", 96, "if", "LLVMFuzzerTestOneInput",
            security_relevant=True,
            note="FUZZER: rejects non-TIFF data early"),
    ASTGate("rowsPerStrip == 0 || samples == 0 || bps == 0", 133, "if",
            "LLVMFuzzerTestOneInput",
            security_relevant=True,
            note="FUZZER: rejects corrupt TIFF parameters"),
    ASTGate("SrcImg.GetIccProfile()", 216, "if", "main",
            security_relevant=True,
            note="Controls whether ICC profile extraction occurs"),
    ASTGate("TIFFGetField(TIFFTAG_ICCPROFILE)", 149, "if", "LLVMFuzzerTestOneInput",
            security_relevant=True,
            note="Controls ICC profile extraction in fuzzer"),
    ASTGate("icc_len > 128 && icc_len < 10MB", 150, "if", "LLVMFuzzerTestOneInput",
            security_relevant=True,
            note="FUZZER: bounds ICC profile size for OOM safety"),
    ASTGate("pProfile != nullptr", 233, "if", "main",
            security_relevant=True,
            note="OpenIccProfile failure check"),
    ASTGate("pDesc->GetType() == icSigTextDescriptionType", 152, "if", "DumpProfileInfo",
            security_relevant=True,
            note="Type discrimination for description tag"),
    ASTGate("pEmbedded->GetType() == icSigEmbeddedProfileType", 172, "if", "DumpProfileInfo",
            security_relevant=True,
            note="Type safety for embedded profile tag — prevents bad cast"),
    ASTGate("argc > 2", 220, "if", "main",
            security_relevant=False,
            note="Optional ICC profile export"),
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
            "The tiffdump fuzzer exercises the core attack surface: TIFF header "
            "field reading, ICC profile extraction via TIFFGetField, profile parsing "
            "via OpenIccProfile, CIccInfo formatting, tag lookup (description, "
            "spectral, embedded), and recursive embedded profile processing. "
            "Key differences: (1) uses TIFFClientOpen with in-memory I/O instead "
            "of CTiffImg::Open (bypasses file I/O), (2) iterates multi-page TIFFs "
            "via TIFFReadDirectory, (3) GetId() lookup tables not exercised, "
            "(4) profile export to file not exercised."
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
                "description": "Command-line argument parsing and file open",
                "calls": [asdict(c) for c in CLI_CALLS],
                "in_fuzzer": False,
            },
            "2_tiff_header": {
                "description": "TIFF header field reading (direct libtiff API)",
                "calls": [asdict(c) for c in TIFF_CALLS],
                "in_fuzzer": True,
            },
            "3_metadata_display": {
                "description": "TIFF metadata formatting (GetId lookups)",
                "calls": [asdict(c) for c in METADATA_CALLS],
                "in_fuzzer": False,
            },
            "4_icc_extraction": {
                "description": "ICC profile extraction and parsing — main attack surface",
                "calls": [asdict(c) for c in ICC_CALLS],
                "in_fuzzer": True,
            },
            "5_embedded_profile": {
                "description": "Recursive embedded V5 profile processing",
                "calls": [asdict(c) for c in EMBEDDED_CALLS],
                "in_fuzzer": True,
            },
            "6_fuzzer_extras": {
                "description": "TIFF error suppression and in-memory I/O",
                "calls": [asdict(c) for c in FUZZER_EXTRA],
                "in_fuzzer": True,
            },
        },
        "gates": [asdict(g) for g in GATES],
        "fidelity": compute_fidelity(),
        "attack_surface": {
            "primary": "OpenIccProfile(pProfMem, nLen) — ICC profile from TIFF",
            "secondary": "DumpProfileInfo recursion — embedded V5 profiles",
            "tiff_surface": "TIFFGetField × 8 tags — exercises libtiff parsing",
            "fuzzer_advantage": "In-memory I/O eliminates file system overhead",
        },
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[OK] JSON call graph: {output_file}")


def generate_dot(output_file):
    lines = [
        'digraph iccTiffDump {',
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
        '    leg_hot  [label="Attack Surface", fillcolor="#FF6347"];',
        '  }',
        '',
        '  tool [label="main()\\niccTiffDump.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '  fuzzer [label="LLVMFuzzerTestOneInput()\\nicc_tiffdump_fuzzer.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '',
        '  // CLI',
        '  subgraph cluster_cli {',
        '    label="Phase 1: CLI"; style=rounded;',
        '    usage [label="Usage()", fillcolor="#D3D3D3"];',
        '    open_file [label="CTiffImg::Open(argv[1])", fillcolor="#D3D3D3"];',
        '    export_icc [label="fopen/fwrite\\nICC export", fillcolor="#D3D3D3"];',
        '  }',
        '',
        '  // TIFF Header',
        '  subgraph cluster_tiff {',
        '    label="Phase 2: TIFF Header Fields"; style=rounded;',
        '    clientopen [label="TIFFClientOpen()\\nin-memory I/O", fillcolor="#90EE90", penwidth=2];',
        '    getfield [label="TIFFGetField × 8\\nwidth,height,spp,bps\\nphoto,rows,fmt,orient", fillcolor="#90EE90"];',
        '    readdir [label="TIFFReadDirectory()\\nmulti-page", fillcolor="#90EE90"];',
        '    tiffclose [label="TIFFClose()", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Metadata (tool only)',
        '  subgraph cluster_meta {',
        '    label="Phase 3: Metadata (Tool Only)"; style=rounded;',
        '    getid [label="GetId() lookups\\nplanar/photo/compress", fillcolor="#ADD8E6"];',
        '  }',
        '',
        '  // ICC Extraction',
        '  subgraph cluster_icc {',
        '    label="Phase 4: ICC Profile Extraction"; style=rounded; color=red;',
        '    get_icc [label="GetIccProfile()\\n/ TIFFGetField", fillcolor="#90EE90"];',
        '    open_icc [label="OpenIccProfile()\\nMAIN ATTACK SURFACE", fillcolor="#FF6347", penwidth=3];',
        '    get_version [label="GetVersionName()", fillcolor="#90EE90"];',
        '    get_colorspace [label="GetColorSpaceSigName()", fillcolor="#90EE90"];',
        '    get_spectral [label="GetSpectralColorSigName()", fillcolor="#90EE90"];',
        '    f16tof [label="icF16toF()\\nspectral ranges", fillcolor="#90EE90"];',
        '    find_desc [label="FindTag(desc)", fillcolor="#90EE90"];',
        '    get_text [label="GetText()\\nv2/v4 types", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Embedded Profile',
        '  subgraph cluster_embedded {',
        '    label="Phase 5: Embedded V5 Profile"; style=rounded; color=red;',
        '    find_embedded [label="FindTag(embeddedV5)", fillcolor="#90EE90"];',
        '    get_subprofile [label="GetProfile()\\nrecursive", fillcolor="#FF6347", penwidth=2];',
        '    readtags [label="ReadTags()", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Tool edges',
        '  tool -> usage [style=dashed];',
        '  tool -> open_file [style=dashed];',
        '  tool -> getid;',
        '  tool -> get_icc [style=bold, penwidth=2];',
        '  tool -> export_icc [style=dashed];',
        '',
        '  // Fuzzer edges',
        '  fuzzer -> clientopen [style=bold, color=green, penwidth=2];',
        '  fuzzer -> getfield [color=green];',
        '  fuzzer -> readdir [color=green];',
        '  fuzzer -> get_icc [style=bold, color=green];',
        '  fuzzer -> tiffclose [color=green];',
        '',
        '  // Internal edges',
        '  get_icc -> open_icc [style=bold, color=red, penwidth=2];',
        '  open_icc -> get_version;',
        '  open_icc -> get_colorspace;',
        '  open_icc -> get_spectral;',
        '  get_spectral -> f16tof;',
        '  open_icc -> find_desc;',
        '  find_desc -> get_text;',
        '  open_icc -> find_embedded;',
        '  find_embedded -> get_subprofile [color=red];',
        '  get_subprofile -> readtags;',
        '  clientopen -> getfield;',
        '  getfield -> readdir;',
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
    parser = argparse.ArgumentParser(description="iccTiffDump call graph analysis")
    parser.add_argument("--dot", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--render", choices=["png", "svg", "pdf"], default=None)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    if args.summary or not any([args.dot, args.json]):
        fid = compute_fidelity()
        print(f"\n{'='*60}")
        print(f"iccTiffDump Call Graph & Fuzzer Fidelity")
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
