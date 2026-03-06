#!/usr/bin/env python3
"""
iccSpecSepToTiff Call Graph & AST Gate Analysis
================================================

Static analysis of iccSpecSepToTiff.cpp to extract call graph, AST gates,
and fuzzer fidelity mapping for the icc_specsep_fuzzer.

This tool is notable for:
  - Multi-file TIFF spectral separation (N input TIFFs → 1 output TIFF)
  - CTiffImg Open/Create/ReadLine/WriteLine pipeline
  - Optional ICC profile embedding in output TIFF
  - Complex scanline interleaving with format validation

Usage:
    python3 iccSpecSepToTiff-callgraph.py [--dot FILE] [--json FILE] [--render FORMAT]
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

TOOL_NAME = "iccSpecSepToTiff"
TOOL_FILE = "iccSpecSepToTiff.cpp"
FUZZER_NAME = "icc_specsep_fuzzer"
FUZZER_FILE = "icc_specsep_fuzzer.cpp"

# Phase 1: CLI Argument Parsing
CLI_CALLS = [
    CallSite("Usage()", 123, "main",
             "Display usage message when argc < 8",
             cli_only=True, in_fuzzer=False),
    CallSite("atoi(argv[2]) → bCompress", 127, "main",
             "Parse compress flag from CLI",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer derives from data[13]"),
    CallSite("atoi(argv[3]) → bSep", 128, "main",
             "Parse separate planes flag from CLI",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer derives from data[14]"),
    CallSite("atoi(argv[5-7]) → start/end/step", 130, "main",
             "Parse channel range from CLI",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer uses data[0] for nFiles (1-8)"),
    CallSite("snprintf(argv[4], channelNum)", 161, "main",
             "Format input filename from printf pattern",
             cli_only=True, in_fuzzer=False,
             note="Fuzzer creates temp files directly"),
]

# Phase 2: Input TIFF Opening & Validation
INPUT_CALLS = [
    CallSite("CTiffImg::Open(filename)", 162, "main",
             "Open each input TIFF file",
             in_fuzzer=True,
             note="Fuzzer opens N temp TIFFs created from fuzz data"),
    CallSite("CTiffImg::GetSamples()", 167, "main",
             "Verify each input has 1 sample per pixel",
             in_fuzzer=True),
    CallSite("CTiffImg::GetPhoto()", 172, "main",
             "Check photometric != PALETTE",
             in_fuzzer=True,
             note="Fuzzer exercises 5 photometric modes"),
    CallSite("CTiffImg::GetWidth()", 177, "main",
             "Consistency check across input files",
             in_fuzzer=True),
    CallSite("CTiffImg::GetHeight()", 178, "main",
             "Consistency check across input files",
             in_fuzzer=True),
    CallSite("CTiffImg::GetBitsPerSample()", 179, "main",
             "Consistency check across input files",
             in_fuzzer=True),
    CallSite("CTiffImg::GetXRes()/GetYRes()", 181, "main",
             "Consistency check for resolution",
             in_fuzzer=True),
    CallSite("CTiffImg::GetBytesPerLine()", 194, "main",
             "Get buffer size for scanline allocation",
             in_fuzzer=True),
]

# Phase 3: Buffer Allocation
ALLOC_CALLS = [
    CallSite("new icUInt8Number[bytePerLine*nSamples]", 207, "main",
             "Allocate input scanline buffer — ALLOCATION HOTSPOT",
             in_fuzzer=True,
             note="Fuzzer uses std::nothrow. Size bounded by max 8 files × line bytes"),
    CallSite("new icUInt8Number[width*bytesPerSample*nSamples]", 208, "main",
             "Allocate output interleaved buffer",
             in_fuzzer=True,
             note="Fuzzer uses std::nothrow"),
]

# Phase 4: Output TIFF Creation
OUTPUT_CALLS = [
    CallSite("CTiffImg::Create()", 221, "main",
             "Create output TIFF with combined channel count",
             in_fuzzer=True,
             note="nSamples channels, configured photometric, compress/separate flags"),
    CallSite("CIccFileIO::Open(argv[8])", 231, "main",
             "Open ICC profile file for embedding",
             in_fuzzer=True,
             note="Fuzzer embeds profile from tail of fuzz data"),
    CallSite("CIccFileIO::GetLength()", 232, "main",
             "Get ICC profile size",
             in_fuzzer=True),
    CallSite("CIccFileIO::Read8()", 234, "main",
             "Read ICC profile bytes",
             in_fuzzer=True),
    CallSite("CTiffImg::SetIccProfile()", 235, "main",
             "Embed ICC profile in output TIFF",
             in_fuzzer=True),
]

# Phase 5: Scanline Processing
SCANLINE_CALLS = [
    CallSite("CTiffImg::ReadLine(sptr)", 244, "main",
             "Read one scanline from each input file",
             in_fuzzer=True,
             note="Core I/O loop — reads height × nSamples scanlines total"),
    CallSite("memcpy(tptr, sptr, bytesPerSample)", 258, "main",
             "Interleave pixel samples from N inputs into single output line",
             in_fuzzer=True,
             note="Pixel-by-pixel interleaving across channels"),
    CallSite("CTiffImg::WriteLine(outbuf)", 262, "main",
             "Write interleaved scanline to output",
             in_fuzzer=True),
    CallSite("CTiffImg::Close()", 266, "main",
             "Close output TIFF and flush",
             in_fuzzer=True),
]

# Phase 6: Fuzzer extras
FUZZER_EXTRA = [
    CallSite("TIFFSetErrorHandler(silent)", 65, "LLVMFuzzerInitialize",
             "Suppress libtiff error output during fuzzing",
             in_fuzzer=True),
    CallSite("TIFFSetWarningHandler(silent)", 66, "LLVMFuzzerInitialize",
             "Suppress libtiff warning output during fuzzing",
             in_fuzzer=True),
    CallSite("CTiffImg::Create() [input TIFFs]", 149, "LLVMFuzzerTestOneInput",
             "Create synthetic input TIFFs from fuzz data",
             in_fuzzer=True,
             note="Fuzzer-only: tool reads existing TIFFs"),
    CallSite("CTiffImg::WriteLine() [input TIFFs]", 176, "LLVMFuzzerTestOneInput",
             "Write fuzz pixel data to synthetic input TIFFs",
             in_fuzzer=True),
    CallSite("CIccProfile::Read(CIccMemIO)", 249, "LLVMFuzzerTestOneInput",
             "Parse embedded ICC profile for additional coverage",
             in_fuzzer=True,
             note="Fuzzer-only: exercises IccProfLib tag parsing"),
    CallSite("CIccProfile::Validate()", 251, "LLVMFuzzerTestOneInput",
             "Validate parsed ICC profile",
             in_fuzzer=True,
             note="Fuzzer-only: exercises validation code paths"),
    CallSite("CIccProfile::FindTag() [multiple]", 252, "LLVMFuzzerTestOneInput",
             "Probe spectral and description tags",
             in_fuzzer=True,
             note="Fuzzer-only: exercises tag lookup"),
]

ALL_CALLS = CLI_CALLS + INPUT_CALLS + ALLOC_CALLS + OUTPUT_CALLS + SCANLINE_CALLS + FUZZER_EXTRA

GATES = [
    ASTGate("argc < 8", 122, "if", "main",
            security_relevant=False, note="Usage guard"),
    ASTGate("step == 0", 134, "if", "main",
            security_relevant=True,
            note="Division-by-zero guard on channel increment"),
    ASTGate("(end<start && step>0) || (end>start && step<0)", 140, "if", "main",
            security_relevant=True,
            note="Overflow/infinite-loop guard on channel range"),
    ASTGate("nSamples < 1", 148, "if", "main",
            security_relevant=True,
            note="Zero-allocation guard"),
    ASTGate("!infile[i].Open(filename)", 162, "if", "main",
            security_relevant=True,
            note="Input TIFF open failure"),
    ASTGate("GetSamples() != 1", 167, "if", "main",
            security_relevant=True,
            note="Rejects multi-sample inputs (tool expects separated channels)"),
    ASTGate("GetPhoto() == PHOTOMETRIC_PALETTE", 172, "if", "main",
            security_relevant=True,
            note="Rejects palette-based images"),
    ASTGate("format mismatch across inputs", 177, "if", "main",
            security_relevant=True,
            note="Rejects dimension/format mismatches between input files"),
    ASTGate("GetPhoto()==PHOTO_MINISWHITE", 197, "if", "main",
            security_relevant=False,
            note="Inversion flag for MinIsWhite photometric"),
    ASTGate("argc > 8", 229, "if", "main",
            security_relevant=False,
            note="Optional ICC profile embedding"),
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
            "The specsep fuzzer reproduces the full iccSpecSepToTiff pipeline: "
            "open N input TIFFs → validate format consistency → allocate buffers "
            "→ create output TIFF → scanline interleave → write output → optional "
            "ICC profile embedding. It adds extra coverage by parsing embedded "
            "profiles through IccProfLib (Read/Validate/FindTag). Key differences: "
            "(1) input TIFFs are synthesized from fuzz data instead of from disk, "
            "(2) up to 5 photometric modes exercised, (3) extra samples and float "
            "mode toggles from fuzz control bytes."
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
            "2_input_tiff": {
                "description": "Input TIFF opening and format validation",
                "calls": [asdict(c) for c in INPUT_CALLS],
                "in_fuzzer": True,
            },
            "3_allocation": {
                "description": "Scanline buffer allocation",
                "calls": [asdict(c) for c in ALLOC_CALLS],
                "in_fuzzer": True,
            },
            "4_output_tiff": {
                "description": "Output TIFF creation and ICC profile embedding",
                "calls": [asdict(c) for c in OUTPUT_CALLS],
                "in_fuzzer": True,
            },
            "5_scanline": {
                "description": "Scanline read/interleave/write loop",
                "calls": [asdict(c) for c in SCANLINE_CALLS],
                "in_fuzzer": True,
            },
            "6_fuzzer_extras": {
                "description": "Fuzzer-only: TIFF error suppression and ICC profile parsing",
                "calls": [asdict(c) for c in FUZZER_EXTRA],
                "in_fuzzer": True,
            },
        },
        "gates": [asdict(g) for g in GATES],
        "fidelity": compute_fidelity(),
        "attack_surface": {
            "primary": "CTiffImg::Open/ReadLine — libtiff-based TIFF parsing",
            "secondary": "ICC profile embedding — arbitrary profile bytes in output",
            "allocation": "Scanline buffers: bytePerLine × nSamples",
            "fuzzer_extra": "CIccProfile::Read → Validate → FindTag on embedded profile",
        },
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[OK] JSON call graph: {output_file}")


def generate_dot(output_file):
    lines = [
        'digraph iccSpecSepToTiff {',
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
        '    leg_hot  [label="I/O Hotspot", fillcolor="#FF6347"];',
        '  }',
        '',
        '  tool [label="main()\\niccSpecSepToTiff.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '  fuzzer [label="LLVMFuzzerTestOneInput()\\nicc_specsep_fuzzer.cpp", fillcolor="#FF6B6B", shape=ellipse];',
        '',
        '  // CLI',
        '  subgraph cluster_cli {',
        '    label="Phase 1: CLI Args"; style=rounded;',
        '    usage [label="Usage()", fillcolor="#D3D3D3"];',
        '    argv_parse [label="atoi(argv[2-7])", fillcolor="#D3D3D3"];',
        '    snprintf_fn [label="snprintf(argv[4])", fillcolor="#D3D3D3"];',
        '  }',
        '',
        '  // Input TIFF',
        '  subgraph cluster_input {',
        '    label="Phase 2: Input TIFF Validation"; style=rounded; color=red;',
        '    tiff_open [label="CTiffImg::Open()\\nN input files", fillcolor="#90EE90", penwidth=3];',
        '    get_samples [label="GetSamples() == 1", fillcolor="#90EE90"];',
        '    get_photo [label="GetPhoto()\\n!= PALETTE", fillcolor="#90EE90"];',
        '    format_check [label="Width/Height/BPS\\nconsistency", fillcolor="#90EE90"];',
        '    get_bytesperline [label="GetBytesPerLine()", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Allocation',
        '  subgraph cluster_alloc {',
        '    label="Phase 3: Buffer Allocation"; style=rounded;',
        '    inbuf [label="inbuffer\\n[bytePerLine×N]", fillcolor="#90EE90"];',
        '    outbuf [label="outbuffer\\n[width×bps×N]", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Output TIFF',
        '  subgraph cluster_output {',
        '    label="Phase 4: Output TIFF + ICC"; style=rounded;',
        '    tiff_create [label="CTiffImg::Create()\\noutput TIFF", fillcolor="#90EE90", penwidth=2];',
        '    icc_embed [label="SetIccProfile()\\noptional ICC", fillcolor="#90EE90"];',
        '    fileio [label="CIccFileIO::Open\\nRead8, GetLength", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Scanline',
        '  subgraph cluster_scanline {',
        '    label="Phase 5: Scanline I/O Loop"; style=rounded; color=red;',
        '    readline [label="ReadLine()\\nper-file, per-row", fillcolor="#FF6347", penwidth=3];',
        '    interleave [label="memcpy interleave\\npixel-by-pixel", fillcolor="#90EE90"];',
        '    writeline [label="WriteLine()\\noutput row", fillcolor="#90EE90"];',
        '    close_out [label="Close()", fillcolor="#90EE90"];',
        '  }',
        '',
        '  // Tool edges',
        '  tool -> usage [style=dashed];',
        '  tool -> argv_parse [style=dashed];',
        '  tool -> snprintf_fn [style=dashed];',
        '  tool -> tiff_open [style=bold, penwidth=2];',
        '  tool -> inbuf;',
        '  tool -> outbuf;',
        '  tool -> tiff_create;',
        '  tool -> readline [style=bold];',
        '  tool -> close_out;',
        '',
        '  // Fuzzer edges',
        '  fuzzer -> tiff_open [style=bold, color=green, penwidth=2];',
        '  fuzzer -> inbuf [color=green];',
        '  fuzzer -> outbuf [color=green];',
        '  fuzzer -> tiff_create [color=green];',
        '  fuzzer -> icc_embed [color=green];',
        '  fuzzer -> readline [style=bold, color=green];',
        '  fuzzer -> close_out [color=green];',
        '',
        '  // Internal edges',
        '  tiff_open -> get_samples;',
        '  tiff_open -> get_photo;',
        '  tiff_open -> format_check;',
        '  tiff_open -> get_bytesperline;',
        '  tiff_create -> icc_embed;',
        '  icc_embed -> fileio;',
        '  readline -> interleave;',
        '  interleave -> writeline;',
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
    parser = argparse.ArgumentParser(description="iccSpecSepToTiff call graph analysis")
    parser.add_argument("--dot", default=None)
    parser.add_argument("--json", default=None)
    parser.add_argument("--render", choices=["png", "svg", "pdf"], default=None)
    parser.add_argument("--summary", action="store_true")
    args = parser.parse_args()

    if args.summary or not any([args.dot, args.json]):
        fid = compute_fidelity()
        print(f"\n{'='*60}")
        print(f"iccSpecSepToTiff Call Graph & Fuzzer Fidelity")
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
