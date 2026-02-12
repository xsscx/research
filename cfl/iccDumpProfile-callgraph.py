#!/usr/bin/env python3
"""
iccDumpProfile Call Graph & AST Gate Analysis
=============================================

Static analysis of iccDumpProfile.cpp to extract:
  1. Call Graph — every function/method call with caller→callee edges
  2. AST Gates — conditional branches controlling code path reachability
  3. Fuzzer Fidelity Map — which gates/calls the fuzzer exercises

Modeled on iccanalyzer-lite's CIccAnalyzerCallGraph DOT generation
and exploitability tree format.

Usage:
    python3 iccDumpProfile-callgraph.py [--dot FILE] [--fuzzer FILE] [--format text|json]
    python3 iccDumpProfile-callgraph.py --dot graph.dot --render png
    python3 iccDumpProfile-callgraph.py --fuzzer fuzzer.cpp --format json
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Optional


# ─── Data Structures (mirrors iccanalyzer-lite CallGraphNode/ASANFrame) ───

@dataclass
class CallSite:
    """A single API/function call at a specific source location."""
    callee: str
    line: int
    caller: str
    context: str = ""      # surrounding code snippet
    gate: str = ""         # controlling condition, if any
    is_indirect: bool = False
    cli_only: bool = False # True if only relevant to CLI, not fuzzer

@dataclass
class ASTGate:
    """A conditional branch that controls reachability of code paths."""
    condition: str
    line: int
    gate_type: str         # "if", "else", "else-if", "switch-case", "ternary"
    parent_func: str
    true_calls: list = field(default_factory=list)   # calls reachable on true
    false_calls: list = field(default_factory=list)   # calls reachable on false/else
    depth: int = 0
    security_relevant: bool = False
    note: str = ""

@dataclass
class FunctionDef:
    """A function definition with its call sites and gates."""
    name: str
    line_start: int
    line_end: int
    params: str
    return_type: str
    calls: list = field(default_factory=list)
    gates: list = field(default_factory=list)


# ─── iccDumpProfile.cpp Static Model ───
# Hand-verified against source-of-truth/Tools/CmdLine/IccDumpProfile/iccDumpProfile.cpp
# This is a precise model, not a regex parse — every entry verified against the source.

FUNCTIONS = [
    FunctionDef("DumpTagCore", 93, 114, "CIccTag *pTag, icTagSignature sig, int nVerboseness", "void"),
    FunctionDef("DumpTagSig", 117, 121, "CIccProfile *pIcc, icTagSignature sig, int nVerboseness", "void"),
    FunctionDef("DumpTagEntry", 124, 128, "CIccProfile *pIcc, IccTagEntry &entry, int nVerboseness", "void"),
    FunctionDef("printUsage", 130, 136, "void", "void"),
    FunctionDef("main", 139, 496, "int argc, char* argv[]", "int"),
]

# Every call site in the tool, with the gate (condition) that controls it.
CALL_SITES = [
    # ── DumpTagCore (lines 93-114) ──
    CallSite("Fmt.GetTagSigName",           102, "DumpTagCore",  gate="pTag != NULL"),
    CallSite("icGetSig [tag sig]",          102, "DumpTagCore",  gate="pTag != NULL"),
    CallSite("pTag->IsArrayType",           104, "DumpTagCore",  gate="pTag != NULL"),
    CallSite("Fmt.GetTagTypeSigName",       107, "DumpTagCore",  gate="pTag != NULL"),
    CallSite("pTag->GetType",               107, "DumpTagCore",  gate="pTag != NULL"),
    CallSite("icGetSig [tag type]",         107, "DumpTagCore",  gate="pTag != NULL"),
    CallSite("pTag->Describe",              108, "DumpTagCore",  gate="pTag != NULL"),
    CallSite("icGetSig [not found]",        112, "DumpTagCore",  gate="pTag == NULL"),

    # ── DumpTagSig (lines 117-121) ──
    CallSite("pIcc->FindTag(sig)",          119, "DumpTagSig"),
    CallSite("DumpTagCore",                 120, "DumpTagSig"),

    # ── DumpTagEntry (lines 124-128) ──
    CallSite("pIcc->FindTag(entry)",        126, "DumpTagEntry"),
    CallSite("DumpTagCore",                 127, "DumpTagEntry"),

    # ── main: argument parsing (lines 159-219) ──
    CallSite("printUsage",                  163, "main",         gate="argc <= 1", cli_only=True),
    CallSite("strncmp [-V/-v]",             172, "main",         cli_only=True),
    CallSite("strtol [verbosity]",          181, "main",         gate="-v flag present", cli_only=True),
    CallSite("ValidateIccProfile",          198, "main",         gate="-v flag present"),
    CallSite("strtol [verbosity]",          204, "main",         gate="-v flag absent", cli_only=True),
    CallSite("OpenIccProfile",              218, "main",         gate="-v flag absent"),

    # ── main: header dump (lines 221-295) ──
    CallSite("Fmt.IsProfileIDCalculated",   236, "main",         gate="pIcc != NULL"),
    CallSite("Fmt.GetProfileID",            237, "main",         gate="pIcc && profileID calculated"),
    CallSite("Fmt.GetDeviceAttrName",       244, "main",         gate="pIcc != NULL"),
    CallSite("Fmt.GetCmmSigName",           245, "main",         gate="pIcc != NULL"),
    CallSite("icGetSig [creator]",          249, "main",         gate="pIcc != NULL"),
    CallSite("icGetSig [manufacturer]",     250, "main",         gate="pIcc != NULL"),
    CallSite("Fmt.GetColorSpaceSigName [data]", 251, "main",     gate="pIcc != NULL"),
    CallSite("Fmt.GetProfileFlagsName",     252, "main",         gate="pIcc != NULL"),
    CallSite("Fmt.GetColorSpaceSigName [PCS]",  253, "main",     gate="pIcc != NULL"),
    CallSite("Fmt.GetPlatformSigName",      254, "main",         gate="pIcc != NULL"),
    CallSite("Fmt.GetRenderingIntentName",  255, "main",         gate="pIcc != NULL"),
    CallSite("Fmt.GetProfileClassSigName",  256, "main",         gate="pIcc != NULL"),
    CallSite("icGetSig [deviceSubClass]",   258, "main",         gate="pHdr->deviceSubClass != 0"),
    CallSite("Fmt.GetVersionName",          261, "main",         gate="pIcc != NULL"),
    CallSite("Fmt.GetSubClassVersionName",  263, "main",         gate="version >= v5 && deviceSubClass"),
    CallSite("icFtoD [illuminant X/Y/Z]",   266, "main",         gate="pIcc != NULL"),
    CallSite("Fmt.GetSpectralColorSigName", 269, "main",         gate="pIcc != NULL"),
    CallSite("icF16toF [spectralRange]",    272, "main",         gate="spectralRange defined"),
    CallSite("icF16toF [biSpectralRange]",  281, "main",         gate="biSpectralRange defined"),
    CallSite("Fmt.GetColorSpaceSigName [MCS]", 291, "main",      gate="pHdr->mcs != 0"),

    # ── main: tag table display (lines 297-336) ──
    CallSite("std::sort [offsets]",         315, "main",         gate="pIcc != NULL"),
    CallSite("std::upper_bound [display]",  323, "main",         gate="tag iteration"),
    CallSite("Fmt.GetTagSigName [table]",   334, "main",         gate="tag iteration"),
    CallSite("icGetSig [tag table]",        335, "main",         gate="tag iteration"),

    # ── main: duplicate detection (lines 340-354) ──
    CallSite("unordered_map::find",         346, "main",         gate="tag iteration"),
    CallSite("icMaxStatus [dup warning]",   349, "main",         gate="duplicate sig found"),

    # ── main: validation pass (lines 369-438) ──
    CallSite("icMaxStatus [size align]",    380, "main",         gate="bDumpValidation && version>=4.2 && size%4!=0"),
    CallSite("std::upper_bound [validate]", 403, "main",         gate="bDumpValidation"),
    CallSite("Fmt.GetTagSigName [OOB]",     391, "main",         gate="bDumpValidation && offset+size > EOF"),
    CallSite("Fmt.GetTagSigName [overlap]", 414, "main",         gate="bDumpValidation && overlap detected"),
    CallSite("Fmt.GetTagSigName [gap]",     422, "main",         gate="bDumpValidation && gap detected"),
    CallSite("icMaxStatus [non-compliant]", 436, "main",         gate="bDumpValidation && first tag gap"),

    # ── main: tag content dump (lines 440-449) ──
    CallSite("DumpTagEntry [ALL]",          443, "main",         gate="argv has tag arg && arg=='ALL'"),
    CallSite("icGetSigVal",                 447, "main",         gate="argv has tag arg && arg!='ALL'", cli_only=True),
    CallSite("DumpTagSig",                  447, "main",         gate="argv has tag arg && arg!='ALL'", cli_only=True),

    # ── main: validation report (lines 454-484) ──
    CallSite("Fmt.GetVersionName [report]", 461, "main",         gate="bDumpValidation"),
]

# AST gates — every conditional branch with security/fuzzing relevance
AST_GATES = [
    # ── DumpTagCore ──
    ASTGate("pTag != NULL",                     101, "if",     "DumpTagCore",
            true_calls=["GetTagSigName", "icGetSig", "IsArrayType", "GetTagTypeSigName",
                         "GetType", "Describe"],
            false_calls=["icGetSig [not found]"],
            security_relevant=True,
            note="NULL deref guard — fuzzer must exercise both paths"),

    ASTGate("pTag->IsArrayType()",              104, "if",     "DumpTagCore",
            true_calls=["printf('Array of')"],
            note="TagArrayType formatting gate"),

    # ── main: mode selection ──
    ASTGate("argc <= 1",                        162, "if",     "main",
            true_calls=["printUsage"],
            note="Early exit — no profile to parse"),

    ASTGate("-V/-v flag in argv[1]",            172, "if",     "main",
            true_calls=["ValidateIccProfile"],
            false_calls=["OpenIccProfile"],
            security_relevant=True,
            note="CRITICAL: Controls validation vs non-validating read path. "
                 "Fuzzer must exercise BOTH to match tool fidelity."),

    ASTGate("strtol verbosity parse success",   182, "if",     "main",
            true_calls=["verbosity clamp"],
            false_calls=["verbosity = 100 default"],
            note="Integer parse of verbosity argument"),

    ASTGate("pIcc != NULL",                     226, "if",     "main",
            true_calls=["header dump", "tag table", "tag content"],
            false_calls=["printf('Unable to parse')"],
            security_relevant=True,
            note="Profile load failure — sets icValidateCriticalError"),

    ASTGate("Fmt.IsProfileIDCalculated()",      236, "if",     "main",
            true_calls=["GetProfileID"],
            false_calls=["printf('not calculated')"],
            note="Profile ID presence check"),

    ASTGate("pHdr->deviceSubClass != 0",        257, "if",     "main",
            true_calls=["icGetSig(deviceSubClass)"],
            false_calls=["printf('Not Defined')"],
            note="SubClass presence gate"),

    ASTGate("version >= v5 && deviceSubClass",  262, "if",     "main",
            true_calls=["GetSubClassVersionName"],
            note="V5 sub-class version gate"),

    ASTGate("spectralRange.start || .end || .steps",  270, "if", "main",
            true_calls=["icF16toF × 2"],
            false_calls=["printf('Not Defined')"],
            security_relevant=True,
            note="Spectral range parsing — icF16toF can produce anomalous floats"),

    ASTGate("biSpectralRange defined",          280, "if",     "main",
            true_calls=["icF16toF × 2"],
            false_calls=["printf('Not Defined')"],
            security_relevant=True,
            note="BiSpectral range parsing"),

    ASTGate("pHdr->mcs != 0",                  290, "if",     "main",
            true_calls=["GetColorSpaceSigName(mcs)"],
            false_calls=["printf('Not Defined')"],
            note="MCS color space gate"),

    ASTGate("upper_bound == cend()",            324, "if",     "main",
            true_calls=["closest = pHdr->size"],
            false_calls=["closest = *match"],
            security_relevant=True,
            note="Tag overlap boundary — last tag edge case"),

    ASTGate("duplicate sig found in unordered_map", 347, "if", "main",
            true_calls=["icMaxStatus(warning)"],
            false_calls=["tag_lookup[sig] = n"],
            note="Duplicate tag detection"),

    ASTGate("bDumpValidation",                  369, "if",     "main",
            security_relevant=True,
            note="CRITICAL: Entire validation block gated on -v flag. "
                 "Contains 5 sub-gates for structural integrity checks."),

    ASTGate("version >= v4.2 && size % 4 != 0", 377, "if",    "main",
            true_calls=["icMaxStatus(NonCompliant)"],
            security_relevant=True,
            note="File size alignment check — spec clause 7.2.1(c)",
            depth=1),

    ASTGate("offset + size > pHdr->size",       388, "if",     "main",
            true_calls=["icMaxStatus(NonCompliant)"],
            security_relevant=True,
            note="Tag data beyond EOF — buffer overread risk",
            depth=1),

    ASTGate("closest < offset+size && closest < EOF", 411, "if", "main",
            true_calls=["icMaxStatus(Warning)"],
            security_relevant=True,
            note="Tag data overlap — data confusion / type confusion risk",
            depth=1),

    ASTGate("closest > offset + rndup",         420, "if",     "main",
            true_calls=["icMaxStatus(Warning)"],
            note="Unnecessary gap between tags",
            depth=1),

    ASTGate("smallest_offset > expected_first", 431, "if",     "main",
            true_calls=["icMaxStatus(NonCompliant)"],
            security_relevant=True,
            note="First tag not immediately after tag table — spec clause 7.2.1(b)",
            depth=1),

    ASTGate("argv has tag argument",            440, "if",     "main",
            true_calls=["DumpTagEntry or DumpTagSig"],
            note="Tag content dump gate"),

    ASTGate("stricmp(arg, 'ALL') == 0",         441, "if",     "main",
            true_calls=["DumpTagEntry (loop over all)"],
            false_calls=["icGetSigVal + DumpTagSig (single tag)"],
            security_relevant=True,
            note="ALL path iterates every tag → wider attack surface"),

    ASTGate("bDumpValidation [report]",         454, "if",     "main",
            note="Validation status report output"),

    ASTGate("switch(nStatus)",                  457, "switch", "main",
            note="4 cases: OK, Warning, NonCompliant, CriticalError + default"),
]


# ─── Output Generators ───

def emit_text(functions, calls, gates, fuzzer_map=None):
    """Terminal-friendly output matching iccanalyzer-lite tree format."""

    print("=" * 72)
    print("iccDumpProfile.cpp — Call Graph & AST Gate Analysis")
    print("=" * 72)

    # ── Function Table ──
    print("\n┌─────────────────────────────────────────────────────────────────────┐")
    print("│ Functions                                                           │")
    print("├─────────────────────────────────────────────────────────────────────┤")
    for f in functions:
        call_count = sum(1 for c in calls if c.caller == f.name)
        gate_count = sum(1 for g in gates if g.parent_func == f.name)
        print(f"│  {f.return_type:5s} {f.name}({f.params})")
        print(f"│       lines {f.line_start}–{f.line_end}   "
              f"calls: {call_count}  gates: {gate_count}")
    print("└─────────────────────────────────────────────────────────────────────┘")

    # ── Call Graph ──
    print("\n" + "=" * 72)
    print("CALL GRAPH — caller → callee (line)")
    print("=" * 72)

    by_caller = {}
    for c in calls:
        by_caller.setdefault(c.caller, []).append(c)

    for caller in ["main", "DumpTagCore", "DumpTagSig", "DumpTagEntry", "printUsage"]:
        sites = by_caller.get(caller, [])
        if not sites:
            continue
        print(f"\n  {caller}()")
        prev_gate = None
        for s in sites:
            gate_mark = ""
            if s.gate and s.gate != prev_gate:
                gate_mark = f"  ⊳ gate: {s.gate}"
                prev_gate = s.gate

            fidelity = ""
            if fuzzer_map is not None:
                if s.cli_only:
                    fidelity = " ⊘ N/A(CLI)"
                elif _check_fidelity(s, fuzzer_map):
                    fidelity = " ✅"
                else:
                    fidelity = " ❌"

            if gate_mark:
                print(f"  │{gate_mark}")
            print(f"  ├── L{s.line:3d}  {s.callee}{fidelity}")

    # ── AST Gates ──
    print("\n" + "=" * 72)
    print("AST GATES — conditional branches controlling reachability")
    print("=" * 72)

    sec_count = sum(1 for g in gates if g.security_relevant)
    print(f"\nTotal gates: {len(gates)}   Security-relevant: {sec_count}")

    for g in gates:
        indent = "  " * (g.depth + 1)
        sec_tag = " 🔴 SEC" if g.security_relevant else ""
        print(f"\n{indent}[{g.gate_type.upper():10s}] L{g.line:3d} in {g.parent_func}(){sec_tag}")
        print(f"{indent}  condition: {g.condition}")
        if g.true_calls:
            print(f"{indent}  ├─ true  → {', '.join(g.true_calls)}")
        if g.false_calls:
            print(f"{indent}  └─ false → {', '.join(g.false_calls)}")
        if g.note:
            print(f"{indent}  ℹ  {g.note}")

    # ── Summary ──
    unique_callees = set(c.callee for c in calls)
    cli_count = sum(1 for c in calls if c.cli_only)
    fuzzable = len(calls) - cli_count
    print("\n" + "=" * 72)
    print("SUMMARY")
    print("=" * 72)
    print(f"  Functions:          {len(functions)}")
    print(f"  Total call sites:   {len(calls)}")
    print(f"  Unique callees:     {len(unique_callees)}")
    print(f"  CLI-only calls:     {cli_count}")
    print(f"  Fuzzable calls:     {fuzzable}")
    print(f"  AST gates:          {len(gates)}")
    print(f"  Security gates:     {sec_count}")
    val_count = sum(1 for g in gates
                    if 'Validation' in g.note or 'bDumpValidation' in g.condition)
    print(f"  Validation-only:    {val_count}")

    if fuzzer_map is not None:
        matched = sum(1 for c in calls if not c.cli_only and _check_fidelity(c, fuzzer_map))
        pct = (matched / fuzzable * 100) if fuzzable else 0
        print(f"\n  Fuzzer fidelity:    {matched}/{fuzzable} "
              f"({pct:.0f}%) fuzzable call sites covered")
        print(f"  CLI-only excluded:  {cli_count} (not applicable to fuzzer)")
    print()


def _check_fidelity(site, fuzzer_map):
    """Return True if a call site is matched in the fuzzer map."""
    base = re.sub(r'\s*\[.*\]', '', site.callee)
    base = re.sub(r'^(Fmt|pTag|pIcc|pLut)\.', '', base)
    base = re.sub(r'^(Fmt|pTag|pIcc|pLut)->', '', base)
    candidates = [base, site.callee, base.lower()]
    if '(' in base:
        candidates.append(base.split('(')[0])
    # Handle C++ qualified calls: unordered_map::find → also check unordered_map
    if '::' in base:
        candidates.append(base.split('::')[0])
    return any(cand in pat for cand in candidates for pat in fuzzer_map)


def emit_dot(functions, calls, gates, outfile):
    """Generate Graphviz DOT file (modeled on iccanalyzer-lite GenerateDOTGraph)."""
    safe_out = os.path.normpath(os.path.realpath(outfile))
    if not os.path.isabs(safe_out):
        raise ValueError(f"Output path must be absolute: {outfile}")
    with open(safe_out, "w") as f:
        f.write("digraph iccDumpProfile {\n")
        f.write("  rankdir=TB;\n")
        f.write('  node [shape=box, style=filled, fontname="Helvetica"];\n')
        f.write('  edge [fontname="Helvetica", fontsize=9];\n\n')

        # Subgraph: functions
        f.write("  // Function definitions\n")
        colors = {
            "main": "lightgreen",
            "DumpTagCore": "lightyellow",
            "DumpTagSig": "lightyellow",
            "DumpTagEntry": "lightyellow",
            "printUsage": "lightgray",
        }
        for func in functions:
            color = colors.get(func.name, "lightblue")
            call_count = sum(1 for c in calls if c.caller == func.name)
            f.write(f'  {func.name} [label="{func.name}()\\n'
                    f'L{func.line_start}-{func.line_end} '
                    f'({call_count} calls)", '
                    f'fillcolor={color}];\n')

        # Deduplicated library API nodes — group by base name
        f.write("\n  // Library API nodes (deduplicated)\n")
        func_names = {fn.name for fn in functions}
        api_groups = {}  # base_id -> {lines, is_sec, cli_only}
        for c in calls:
            if c.callee in func_names:
                continue
            # Use base callee (strip annotation) as group key
            base_callee = re.sub(r'\s*\[.*\]', '', c.callee)
            node_id = re.sub(r'[^a-zA-Z0-9_]', '_', base_callee)
            if node_id not in api_groups:
                api_groups[node_id] = {
                    "label": base_callee,
                    "lines": [],
                    "is_sec": False,
                    "cli_only": True,
                }
            api_groups[node_id]["lines"].append(c.line)
            if not c.cli_only:
                api_groups[node_id]["cli_only"] = False
            if any(g.security_relevant for g in gates
                   if c.callee in (g.true_calls + g.false_calls)):
                api_groups[node_id]["is_sec"] = True

        for node_id, info in api_groups.items():
            if info["cli_only"]:
                color = "lightgray"
            elif info["is_sec"]:
                color = "salmon"
            else:
                color = "lightblue"
            lines_str = ",".join(str(l) for l in sorted(set(info["lines"])))
            f.write(f'  {node_id} [label="{info["label"]}\\n'
                    f'L{lines_str}", '
                    f'fillcolor={color}, shape=ellipse];\n')

        # Call edges — deduplicate by base callee
        f.write("\n  // Call edges\n")
        seen_edges = set()
        for c in calls:
            if c.callee in func_names:
                target = c.callee
            else:
                base_callee = re.sub(r'\s*\[.*\]', '', c.callee)
                target = re.sub(r'[^a-zA-Z0-9_]', '_', base_callee)
            edge_key = f"{c.caller}->{target}"
            if edge_key in seen_edges:
                continue
            seen_edges.add(edge_key)

            attrs = []
            if c.gate:
                attrs.append(f'label="{c.gate[:35]}"')
            is_sec = any(g.security_relevant for g in gates if c.gate == g.condition)
            if is_sec:
                attrs.append("color=red")
                attrs.append("penwidth=2.0")
            if c.cli_only:
                attrs.append("style=dashed")
                attrs.append("color=gray")
            attr_str = f" [{', '.join(attrs)}]" if attrs else ""
            f.write(f"  {c.caller} -> {target}{attr_str};\n")

        # Gate nodes (diamond) connected to their gated callees
        f.write("\n  // Security-relevant AST gates\n")
        for i, g in enumerate(gates):
            if not g.security_relevant:
                continue
            gid = f"gate_{i}"
            cond_short = g.condition[:40]
            depth_label = f"  (depth {g.depth})" if g.depth else ""
            f.write(f'  {gid} [label="GATE L{g.line}\\n{cond_short}{depth_label}", '
                    f'shape=diamond, fillcolor=orange, fontsize=8];\n')
            f.write(f"  {g.parent_func} -> {gid} [style=dashed, color=gray];\n")

            # Connect gate to gated callee nodes
            for callee_name in g.true_calls:
                target_id = re.sub(r'[^a-zA-Z0-9_]', '_', callee_name)
                if target_id in api_groups or callee_name in func_names:
                    actual_target = callee_name if callee_name in func_names else target_id
                    f.write(f"  {gid} -> {actual_target} "
                            f'[style=dashed, color=darkgreen, label="true"];\n')

        f.write("}\n")

    print(f"[OK] DOT graph written: {safe_out}")
    print(f"     Render: dot -Tpng {safe_out} -o {safe_out.replace('.dot', '.png')}")
    return safe_out


def emit_json(functions, calls, gates, fuzzer_map=None):
    """Machine-readable JSON output for downstream tooling."""
    cli_count = sum(1 for c in calls if c.cli_only)
    fuzzable = len(calls) - cli_count

    data = {
        "source": "iccDumpProfile.cpp",
        "functions": [
            {
                "name": f.name,
                "lines": [f.line_start, f.line_end],
                "params": f.params,
                "return_type": f.return_type,
                "call_count": sum(1 for c in calls if c.caller == f.name),
                "gate_count": sum(1 for g in gates if g.parent_func == f.name),
            }
            for f in functions
        ],
        "call_sites": [
            {
                "caller": c.caller,
                "callee": c.callee,
                "line": c.line,
                "gate": c.gate or None,
                "cli_only": c.cli_only,
            }
            for c in calls
        ],
        "ast_gates": [
            {
                "condition": g.condition,
                "line": g.line,
                "type": g.gate_type,
                "parent_func": g.parent_func,
                "true_calls": g.true_calls,
                "false_calls": g.false_calls,
                "depth": g.depth,
                "security_relevant": g.security_relevant,
                "note": g.note or None,
            }
            for g in gates
        ],
        "summary": {
            "functions": len(functions),
            "call_sites": len(calls),
            "unique_callees": len(set(c.callee for c in calls)),
            "cli_only_calls": cli_count,
            "fuzzable_calls": fuzzable,
            "ast_gates": len(gates),
            "security_gates": sum(1 for g in gates if g.security_relevant),
        },
    }

    if fuzzer_map is not None:
        matched = [c.callee for c in calls
                   if not c.cli_only and _check_fidelity(c, fuzzer_map)]
        missed = [c.callee for c in calls
                  if not c.cli_only and not _check_fidelity(c, fuzzer_map)]
        data["fidelity"] = {
            "matched": len(matched),
            "fuzzable": fuzzable,
            "percentage": round(len(matched) / fuzzable * 100, 1) if fuzzable else 0,
            "matched_calls": sorted(set(matched)),
            "missed_calls": sorted(set(missed)),
            "cli_excluded": [c.callee for c in calls if c.cli_only],
        }

    print(json.dumps(data, indent=2))


def load_fuzzer_map(fuzzer_path):
    """Parse a fuzzer .cpp for exercised API calls to produce a fidelity map."""
    if not fuzzer_path:
        return None
    safe_path = os.path.normpath(os.path.realpath(fuzzer_path))
    if not os.path.isfile(safe_path):
        return None

    fmap = set()
    with open(safe_path) as f:
        for lineno, line in enumerate(f, 1):
            line_stripped = line.strip()
            # Match common ICC API patterns (case-insensitive collection)
            for m in re.finditer(
                r'(?:(?:fmt|Fmt)\.\w+|icGetSig|icF16toF|icFtoD|icGetSigVal|icMaxStatus'
                r'|(?:pTag|pIcc|pLut|pMpe|pProfile)->\w+'
                r'|ValidateIccProfile|OpenIccProfile|FindTag'
                r'|std::sort|std::upper_bound|upper_bound'
                r'|unordered_map|GetRenderingIntentName'
                r'|IsArrayType|Describe|Validate|GetType|IsSupported'
                r'|DumpTagCore|DumpTagSig|DumpTagEntry'
                r'|GetColorSpaceSigName|GetTagSigName|GetTagTypeSigName'
                r'|GetProfileClassSigName|GetVersionName|GetSubClassVersionName'
                r'|GetPlatformSigName|GetDeviceAttrName|GetCmmSigName'
                r'|GetProfileFlagsName|GetSpectralColorSigName'
                r'|IsProfileIDCalculated|GetProfileID'
                r'|AreTagsUnique|GetSpaceSamples)',
                line_stripped,
            ):
                token = m.group(0)
                fmap.add(f"{token}@{lineno}")
                fmap.add(token)
                # Also add without object prefix for loose matching
                cleaned = re.sub(r'^(?:fmt|Fmt|pTag|pIcc|pLut|pMpe|pProfile)[\.\->]+', '', token)
                fmap.add(cleaned)
    return fmap


def main():
    parser = argparse.ArgumentParser(
        description="iccDumpProfile Call Graph & AST Gate Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                                    # text report to stdout
  %(prog)s --dot callgraph.dot                # Graphviz DOT output
  %(prog)s --dot callgraph.dot --render png   # DOT + auto-render to PNG
  %(prog)s --dot callgraph.dot --render svg   # DOT + auto-render to SVG
  %(prog)s --format json                      # JSON for tooling
  %(prog)s --format json --fuzzer f.cpp       # JSON with fidelity data
  %(prog)s --fuzzer ../cfl/icc_deep_dump_fuzzer.cpp  # fidelity check
        """,
    )
    parser.add_argument("--dot", metavar="FILE", help="Write Graphviz DOT file")
    parser.add_argument("--render", metavar="FMT", choices=["png", "svg", "pdf"],
                        help="Auto-render DOT to this format (requires graphviz)")
    parser.add_argument("--fuzzer", metavar="FILE",
                        help="Fuzzer source to check fidelity against")
    parser.add_argument("--format", choices=["text", "json"], default="text",
                        help="Output format (default: text)")
    args = parser.parse_args()

    fuzzer_map = None
    if args.fuzzer:
        fuzzer_map = load_fuzzer_map(args.fuzzer)
        if fuzzer_map:
            print(f"[OK] Loaded {len(fuzzer_map)} call patterns from {args.fuzzer}\n",
                  file=sys.stderr)

    if args.dot:
        dot_path = emit_dot(FUNCTIONS, CALL_SITES, AST_GATES, args.dot)
        if args.render:
            dot_bin = shutil.which("dot")
            if dot_bin:
                out_path = dot_path.replace(".dot", f".{args.render}")
                try:
                    subprocess.run(
                        [dot_bin, f"-T{args.render}", dot_path, "-o", out_path],
                        check=True, capture_output=True)
                    print(f"[OK] Rendered: {out_path}")
                except subprocess.CalledProcessError as e:
                    print(f"[ERR] dot render failed: {e.stderr.decode()}", file=sys.stderr)
            else:
                print("[WARN] graphviz 'dot' not found — install with: "
                      "apt install graphviz", file=sys.stderr)

    if args.format == "json":
        emit_json(FUNCTIONS, CALL_SITES, AST_GATES, fuzzer_map)
    else:
        emit_text(FUNCTIONS, CALL_SITES, AST_GATES, fuzzer_map)


if __name__ == "__main__":
    main()
