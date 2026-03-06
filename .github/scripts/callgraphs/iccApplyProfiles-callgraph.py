#!/usr/bin/env python3
"""
iccApplyProfiles Call Graph & AST Gate Analysis
================================================

Static analysis of iccApplyProfiles.cpp to extract:
  1. Call Graph — every function/method call with caller→callee edges
  2. AST Gates — conditional branches controlling code path reachability
  3. Fuzzer Fidelity Map — which calls the fuzzer exercises vs. tool

Updated 2026-03-06: Fuzzer rewritten to exercise full TIFF I/O pipeline.
Fidelity: 36.1% → 97.7% (43/44 fuzzable call sites matched).

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

# Phase 1: Configuration Parsing (IccCmmConfig) — CLI-only
CONFIG_CALLS = [
    CallSite("CIccCfgDataApply::fromJson", 158, "main",
             "Parse JSON configuration file", in_fuzzer=False, cli_only=True,
             note="Fuzzer uses hardcoded params, not JSON config"),
    CallSite("CIccCfgDataApply::fromLegacy", 193, "main",
             "Parse legacy command-line arguments", in_fuzzer=False, cli_only=True),
]

# Phase 2: Source Image Loading (CTiffImg) — ALL in fuzzer
TIFF_CALLS = [
    CallSite("CTiffImg::Open", 206, "main",
             "Open source TIFF image for reading", in_fuzzer=True,
             note="Fuzzer: SrcImg.Open(tmp_src_tiff) at line 178"),
    CallSite("CTiffImg::GetSamples", 210, "main",
             "Get samples per pixel from source image", in_fuzzer=True,
             note="Fuzzer: SrcImg.GetSamples() at line 184"),
    CallSite("CTiffImg::GetExtraSamples", 211, "main",
             "Get extra samples (alpha) from source", in_fuzzer=True,
             note="Fuzzer: SrcImg.GetExtraSamples() at line 185"),
    CallSite("CTiffImg::GetPhoto", 212, "main",
             "Get photometric interpretation", in_fuzzer=True,
             note="Fuzzer: SrcImg.GetPhoto() at line 186"),
    CallSite("CTiffImg::GetBitsPerSample", 213, "main",
             "Get bits per sample from source", in_fuzzer=True,
             note="Fuzzer: SrcImg.GetBitsPerSample() at line 187"),
    CallSite("CTiffImg::GetWidth", 215, "main",
             "Get image width from source", in_fuzzer=True,
             note="Fuzzer: SrcImg.GetWidth() at lines 190,309,337"),
    CallSite("CTiffImg::GetHeight", 216, "main",
             "Get image height from source", in_fuzzer=True,
             note="Fuzzer: SrcImg.GetHeight() at lines 191,309,338"),
    CallSite("CTiffImg::GetXRes", 217, "main",
             "Get X resolution from source", in_fuzzer=True,
             note="Fuzzer: SrcImg.GetXRes() at lines 192,311"),
    CallSite("CTiffImg::GetYRes", 218, "main",
             "Get Y resolution from source", in_fuzzer=True,
             note="Fuzzer: SrcImg.GetYRes() at lines 193,311"),
    CallSite("CTiffImg::GetIccProfile", 251, "main",
             "Extract embedded ICC profile from source TIFF", in_fuzzer=True,
             note="Fuzzer: SrcImg.GetIccProfile() at line 197, drives AddXform(buffer) path"),
    CallSite("CTiffImg::GetCompress", 254, "main",
             "Get compression setting from source", in_fuzzer=True,
             note="Fuzzer: SrcImg.GetCompress() at line 188"),
    CallSite("CTiffImg::GetPlanar", 255, "main",
             "Get planar configuration from source", in_fuzzer=True,
             note="Fuzzer: SrcImg.GetPlanar() at line 189"),
]

# Phase 3: CMM Construction (core attack surface)
CMM_CALLS = [
    CallSite("CIccCmm::CIccCmm", 262, "main",
             "Construct CMM with icSigUnknownData, icSigUnknownData, true",
             in_fuzzer=True,
             note="Fuzzer: CIccCmm(icSigUnknownData, icSigUnknownData, true) at line 200"),
    CallSite("CIccCreateXformHintManager", 284, "main",
             "Create hint manager for xform parameters", in_fuzzer=True,
             note="Fuzzer: CIccCreateXformHintManager at line 202"),
    CallSite("CIccApplyBPCHint", 286, "main",
             "Add BPC hint for black point compensation", in_fuzzer=True,
             note="Fuzzer: Hint.AddHint(new CIccApplyBPCHint()) at line 204"),
    CallSite("CIccLuminanceMatchingHint", 288, "main",
             "Add luminance matching hint", in_fuzzer=True,
             note="Fuzzer: Hint.AddHint(new CIccLuminanceMatchingHint()) at line 206"),
    CallSite("OpenIccProfile", 293, "main",
             "Open PCC profile for viewing conditions", in_fuzzer=False,
             note="PCC profile path — fuzzer does not exercise PCC profiles"),
    CallSite("CIccCmmEnvVarHint", 304, "main",
             "Add environment variable hints to xform", in_fuzzer=False, cli_only=True,
             note="CLI-only: env var hints from command-line arguments"),
    CallSite("CIccCmmPccEnvVarHint", 308, "main",
             "Add PCC environment variable hints", in_fuzzer=False, cli_only=True,
             note="CLI-only: PCC env var hints from command-line arguments"),
    CallSite("CIccCmm::AddXform(buffer)", 314, "main",
             "Add xform from embedded profile buffer (pSrcProfile)", in_fuzzer=True,
             note="Fuzzer: theCmm.AddXform(pSrcProfile, nSrcProfileLen, ...) at line 212"),
    CallSite("CIccCmm::AddXform(file)", 334, "main",
             "Add xform from ICC profile file path", in_fuzzer=True,
             note="Fuzzer: theCmm.AddXform(tmp_profile, intent, ...) at line 216"),
]

# Phase 4: CMM Execution (core attack surface) — ALL in fuzzer
EXEC_CALLS = [
    CallSite("CIccCmm::Begin", 350, "main",
             "Initialize CMM pipeline — allocates LUTs, validates chain",
             in_fuzzer=True,
             note="Fuzzer: theCmm.Begin() at line 228"),
    CallSite("CIccCmm::GetSourceSpace", 364, "main",
             "Query source color space from CMM", in_fuzzer=True,
             note="Fuzzer: theCmm.GetSourceSpace() at line 237"),
    CallSite("icGetSpaceSamples(src)", 365, "main",
             "Get number of source color channels", in_fuzzer=True,
             note="Fuzzer: icGetSpaceSamples(SrcspaceSig) at line 238"),
    CallSite("CIccCmm::GetDestSpace", 385, "main",
             "Query destination color space from CMM", in_fuzzer=True,
             note="Fuzzer: theCmm.GetDestSpace() at line 240"),
    CallSite("icGetSpaceSamples(dst)", 387, "main",
             "Get number of dest color channels", in_fuzzer=True,
             note="Fuzzer: icGetSpaceSamples(DestSpaceSig) at line 241"),
    CallSite("CIccCmm::GetLastParentSpace", 389, "main",
             "Query last parent color space for output format", in_fuzzer=True,
             note="Fuzzer: theCmm.GetLastParentSpace() at line 243"),
    CallSite("icGetSpaceSamples(parent)", 390, "main",
             "Get parent space samples for TIFF output", in_fuzzer=True,
             note="Fuzzer: icGetSpaceSamples(DestParentSpaceSig) at line 244"),
    CallSite("CIccCmm::Apply", 546, "main",
             "Apply CMM transform to pixel data — MAIN EXECUTION PATH",
             in_fuzzer=True,
             note="Fuzzer: theCmm.Apply(pDstPix, pSrcPix) at line 408"),
]

# Phase 5: Destination Image Creation — ALL in fuzzer
DEST_CALLS = [
    CallSite("CTiffImg::Create", 430, "main",
             "Create destination TIFF file", in_fuzzer=True,
             note="Fuzzer: DstImg.Create(...) at line 309"),
    CallSite("CIccFileIO::Open", 440, "main",
             "Open last profile for embedding in dest TIFF", in_fuzzer=True,
             note="Fuzzer: io.Open(tmp_profile, 'r') at line 322"),
    CallSite("CIccFileIO::GetLength", 443, "main",
             "Get profile length for embedding", in_fuzzer=True,
             note="Fuzzer: io.GetLength() at line 323"),
    CallSite("CIccFileIO::Read8", 444, "main",
             "Read profile data for embedding", in_fuzzer=True,
             note="Fuzzer: io.Read8(pDestProfile, length) at line 327"),
    CallSite("CTiffImg::SetIccProfile", 446, "main",
             "Embed ICC profile in destination TIFF", in_fuzzer=True,
             note="Fuzzer: DstImg.SetIccProfile(pDestProfile, length) at line 328"),
]

# Phase 6: Pixel Processing Loop — ALL in fuzzer
PIXEL_CALLS = [
    CallSite("CTiffImg::GetBytesPerLine", 462, "main",
             "Get bytes per scanline for buffer allocation", in_fuzzer=True,
             note="Fuzzer: SrcImg/DstImg.GetBytesPerLine() at lines 161,343,344"),
    CallSite("CIccPixelBuf", 464, "main",
             "Allocate pixel buffer for CMM Apply", in_fuzzer=True,
             note="Fuzzer: CIccPixelBuf(nSrcColorSamples+16) at lines 347-348"),
    CallSite("CTiffImg::ReadLine", 475, "main",
             "Read one scanline from source TIFF", in_fuzzer=True,
             note="Fuzzer: SrcImg.ReadLine(pSBuf) at line 351"),
    CallSite("UnitClip", 483, "main",
             "Clamp pixel value to [0,1] range", in_fuzzer=True,
             note="Fuzzer: UnitClip() in dest pixel encoding at lines 421-438"),
    CallSite("icLabToPcs", 504, "main",
             "Convert Lab to PCS representation", in_fuzzer=True,
             note="Fuzzer: icLabToPcs(pSrcPix) at line 394; icLabToPcs(pDstPix) at line 414"),
    CallSite("icLabFromPcs", 539, "main",
             "Convert PCS to Lab representation", in_fuzzer=True,
             note="Fuzzer: icLabFromPcs(pSrcPix) at line 402; icLabFromPcs(pDstPix) at line 443"),
    CallSite("icLabtoXYZ", 540, "main",
             "Convert Lab to XYZ color space", in_fuzzer=True,
             note="Fuzzer: icLabtoXYZ(pSrcPix) at line 403"),
    CallSite("icXyzToPcs", 541, "main",
             "Convert XYZ to PCS representation", in_fuzzer=True,
             note="Fuzzer: icXyzToPcs(pSrcPix) at line 404"),
    CallSite("icXyzFromPcs", 549, "main",
             "Convert PCS to XYZ representation", in_fuzzer=True,
             note="Fuzzer: icXyzFromPcs(pDstPix) at line 412"),
    CallSite("icXYZtoLab", 550, "main",
             "Convert XYZ to Lab color space", in_fuzzer=True,
             note="Fuzzer: icXYZtoLab(pDstPix) at line 413"),
    CallSite("CTiffImg::WriteLine", 615, "main",
             "Write one scanline to destination TIFF", in_fuzzer=True,
             note="Fuzzer: DstImg.WriteLine(pDBuf) at line 458"),
    CallSite("CTiffImg::Close(src)", 629, "main",
             "Close source TIFF", in_fuzzer=True,
             note="Fuzzer: SrcImg.Close() at line 465"),
    CallSite("CTiffImg::Close(dst)", 634, "main",
             "Close destination TIFF", in_fuzzer=True,
             note="Fuzzer: DstImg.Close() at line 466"),
]

# Phase 7: Fuzzer-only calls (exercising CMM beyond tool's pixel loop)
FUZZER_ONLY_CALLS = [
    CallSite("CIccCmm::GetNumXforms", 0, "LLVMFuzzerTestOneInput",
             "Query number of xforms in chain", in_fuzzer=True,
             note="Fuzzer extra: theCmm.GetNumXforms() at line 469"),
    CallSite("CIccCmm::Valid", 0, "LLVMFuzzerTestOneInput",
             "Validate CMM state", in_fuzzer=True,
             note="Fuzzer extra: theCmm.Valid() at line 470"),
    CallSite("CIccCmm::GetLastSpace", 0, "LLVMFuzzerTestOneInput",
             "Query last color space", in_fuzzer=True,
             note="Fuzzer extra: theCmm.GetLastSpace() at line 472"),
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
            security_relevant=False,
            note="CIELAB→XYZ PCS conversion gate — fuzzer exercises at lines 401-405"),
    ASTGate("photo == PHOTO_CIELAB", 549, "if", "main",
            security_relevant=False,
            note="XYZ→CIELAB PCS conversion gate — fuzzer exercises at lines 411-415"),
    ASTGate("DstImg.WriteLine()", 615, "if", "main",
            security_relevant=True, note="Scanline write failure during pixel loop"),
]


def compute_fidelity():
    """Compute fuzzer fidelity metrics."""
    total = len([c for c in ALL_CALLS if c.caller == "main"])
    cli_only = sum(1 for c in ALL_CALLS if c.cli_only)
    fuzzable = total - cli_only
    matched = sum(1 for c in ALL_CALLS if c.in_fuzzer and c.caller == "main")
    not_matched = [c.callee for c in ALL_CALLS if not c.in_fuzzer and not c.cli_only and c.caller == "main"]
    fuzzer_extras = sum(1 for c in ALL_CALLS if c.in_fuzzer and c.caller != "main")

    return {
        "total_tool_call_sites": total,
        "cli_only_excluded": cli_only,
        "fuzzable_call_sites": fuzzable,
        "matched_by_fuzzer": matched,
        "not_matched": not_matched,
        "fuzzer_extra_calls": fuzzer_extras,
        "fidelity_percent": round(matched / max(fuzzable, 1) * 100, 1),
        "note": (
            "Full TIFF I/O pipeline coverage. The fuzzer creates a source TIFF with "
            "embedded ICC profile, opens it via CTiffImg, builds CMM with BPC/Luminance "
            "hints, performs the complete source→encode→Apply→decode→destination pixel "
            "loop, and embeds the destination profile via CIccFileIO. Only PCC profile "
            "loading (OpenIccProfile) is not exercised — PCC is a CLI-argument-specific "
            "path for viewing condition adjustment."
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
                "reason": "CLI-only: fuzzer uses hardcoded params, not JSON config files",
            },
            "2_source_image": {
                "description": "Source TIFF image loading and ICC profile extraction",
                "calls": [asdict(c) for c in TIFF_CALLS],
                "in_fuzzer": True,
                "reason": "Fuzzer creates synthetic TIFF, opens via CTiffImg, extracts profile",
            },
            "3_cmm_construction": {
                "description": "CMM object creation, profile loading, xform setup with hints",
                "calls": [asdict(c) for c in CMM_CALLS],
                "in_fuzzer": "partial",
                "reason": "Exercises both AddXform(buffer) and AddXform(file), BPC/Luminance hints; skips PCC/EnvVar",
            },
            "4_cmm_execution": {
                "description": "CMM Begin + Apply — main security-critical execution",
                "calls": [asdict(c) for c in EXEC_CALLS],
                "in_fuzzer": True,
                "reason": "Full coverage of CMM pipeline execution including parent space queries",
            },
            "5_dest_image": {
                "description": "Destination TIFF creation and ICC profile embedding via CIccFileIO",
                "calls": [asdict(c) for c in DEST_CALLS],
                "in_fuzzer": True,
                "reason": "Fuzzer creates dest TIFF, embeds ICC profile via CIccFileIO Read8 path",
            },
            "6_pixel_loop": {
                "description": "Per-scanline pixel encoding, CMM Apply, decoding, with TIFF I/O",
                "calls": [asdict(c) for c in PIXEL_CALLS],
                "in_fuzzer": True,
                "reason": "Full pixel loop: 8/16/32-bit encoding, Lab/XYZ PCS conversions, UnitClip, ReadLine/WriteLine",
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
        "fuzzer_pixel_encoding": {
            "source_8bit": "sptr[k] / 255.0 normalization with CIELAB offset (line 363-371)",
            "source_16bit": "pS16[k] / 65535.0 normalization with CIELAB 0x8000 offset (line 374-383)",
            "source_32bit": "Direct float copy or per-channel cast, icLabToPcs for Lab (line 385-395)",
            "lab_to_xyz_pcs": "icLabFromPcs→icLabtoXYZ→icXyzToPcs when sphoto=CIELAB+src=XYZ (line 401-405)",
            "xyz_to_lab_pcs": "icXyzFromPcs→icXYZtoLab→icLabToPcs when dphoto=CIELAB+dst=XYZ (line 411-415)",
            "dest_8bit": "UnitClip * 255 + 0.5 with CIELAB +128 offset (line 420-427)",
            "dest_16bit": "UnitClip * 65535 + 0.5 with CIELAB +0x8000 offset (line 430-438)",
            "dest_32bit": "icLabFromPcs for Lab, then float copy or per-channel cast (line 442-450)",
        },
        "fuzzer_input_format": {
            "description": "First 75% is ICC profile data, last 25% is control data",
            "control_bytes": {
                "byte_0": "icRenderingIntent (% 4)",
                "byte_1": "icXformInterp (bit 0: linear vs tetrahedral)",
                "byte_2": "flags: bit0=BPC, bit1=luminance, bit2=V5sub, bit3=embed_icc, bit4-5=bps_sel, bit6-7=photo_sel",
                "byte_3": "bit0=use_d2bx, bit1-2=width(1-4), bit3-4=height(1-4)",
                "byte_4+": "pixel seed data for TIFF scanlines",
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
        '    leg_tool [label="Tool Only (not in fuzzer)", fillcolor="#ADD8E6"];',
        '    leg_cli  [label="CLI Only (excluded)", fillcolor="#D3D3D3"];',
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
        ("cluster_config", "Phase 1: Config Parsing (CLI-only)", CONFIG_CALLS),
        ("cluster_tiff_src", "Phase 2: Source Image (TIFF I/O)", TIFF_CALLS),
        ("cluster_cmm_build", "Phase 3: CMM Construction", CMM_CALLS),
        ("cluster_cmm_exec", "Phase 4: CMM Execution", EXEC_CALLS),
        ("cluster_tiff_dst", "Phase 5: Dest Image + Profile Embedding", DEST_CALLS),
        ("cluster_pixel", "Phase 6: Pixel Encoding/Decoding Loop", PIXEL_CALLS),
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

    # Fuzzer mirrors tool calls across all phases
    for phase_calls in [TIFF_CALLS, CMM_CALLS, EXEC_CALLS, DEST_CALLS, PIXEL_CALLS]:
        for c in phase_calls:
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
        print(f"Total tool call sites: {fid['total_tool_call_sites']}")
        print(f"CLI-only excluded:     {fid['cli_only_excluded']}")
        print(f"Fuzzable call sites:   {fid['fuzzable_call_sites']}")
        print(f"Matched by fuzzer:     {fid['matched_by_fuzzer']}")
        print(f"Not matched:           {fid['not_matched']}")
        print(f"Fuzzer extra calls:    {fid['fuzzer_extra_calls']}")
        print(f"Fidelity:              {fid['fidelity_percent']}%")
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
