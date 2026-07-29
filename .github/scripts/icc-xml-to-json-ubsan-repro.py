#!/usr/bin/env python3
"""Convert an ICC XML profile toward JSON and replay sanitizer checks.

The primary path is the iccDEV round trip:

    ICC XML -> iccFromXml -> ICC profile -> iccToJson -> ICC JSON

If iccFromXml trips UBSAN before producing a usable ICC profile, the script still
writes a lossy XML-tree JSON approximation with numeric range findings. That
artifact is useful for mapping XML-only crashes to likely JSON fields and values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_TOOLS_DIR = REPO_ROOT / "iccDEV" / "Build" / "Tools"
DEFAULT_TIMEOUT = 60
UINT16_MAX = 0xFFFF
INT16_MIN = -0x8000
INT16_MAX = 0x7FFF
NUMBER_RE = re.compile(r"[-+]?(?:0[xX][0-9a-fA-F]+|\d+(?:\.\d+)?)")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Convert an ICC XML profile to canonical JSON when possible, "
            "write a lossy XML JSON approximation, and replay iccDEV "
            "sanitizer checks."
        )
    )
    parser.add_argument("xml", help="ICC XML input profile")
    parser.add_argument(
        "-o",
        "--out-dir",
        default=None,
        help="Output directory for artifacts (default: temporary directory)",
    )
    parser.add_argument(
        "--tools-dir",
        default=os.environ.get("ICCDEV_TOOLS_DIR", str(DEFAULT_TOOLS_DIR)),
        help="iccDEV Build/Tools directory",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Per-tool timeout in seconds (default: {DEFAULT_TIMEOUT})",
    )
    parser.add_argument(
        "--test-approx-json",
        action="store_true",
        help="Also pass the lossy XML-shaped JSON approximation to iccFromJson",
    )
    parser.add_argument(
        "--fail-on-sanitizer",
        action="store_true",
        help="Exit non-zero if ASAN/UBSAN output is detected",
    )
    return parser.parse_args()


def tool_path(tools_dir: Path, subdir: str, binary: str) -> Path:
    path = tools_dir / subdir / binary
    if not path.is_file() or not os.access(path, os.X_OK):
        raise FileNotFoundError(f"missing executable: {path}")
    return path


def sanitizer_env() -> dict[str, str]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = env.get(
        "ASAN_OPTIONS", "detect_leaks=0,halt_on_error=0,abort_on_error=0"
    )
    env["UBSAN_OPTIONS"] = env.get(
        "UBSAN_OPTIONS", "halt_on_error=0,print_stacktrace=1"
    )
    env["LLVM_PROFILE_FILE"] = env.get("LLVM_PROFILE_FILE", "/dev/null")

    lib_dirs = [
        REPO_ROOT / "iccDEV" / "Build" / "IccProfLib",
        REPO_ROOT / "iccDEV" / "Build" / "IccXML",
        REPO_ROOT / "iccDEV" / "Build" / "IccJSON",
        REPO_ROOT / "iccDEV" / "Build" / "IccMath",
    ]
    existing = [str(path) for path in lib_dirs if path.is_dir()]
    current = env.get("LD_LIBRARY_PATH")
    if current:
        existing.append(current)
    if existing:
        env["LD_LIBRARY_PATH"] = ":".join(existing)
    return env


def run_tool(
    name: str,
    argv: list[str],
    log_path: Path,
    timeout: int,
    env: dict[str, str],
) -> dict[str, Any]:
    def as_text(value: str | bytes | None) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return value

    try:
        completed = subprocess.run(
            argv,
            cwd=REPO_ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
        )
        output = completed.stdout + completed.stderr
        log_path.write_text(output, encoding="utf-8")
        return {
            "name": name,
            "command": argv,
            "exitCode": completed.returncode,
            "timedOut": False,
            "log": str(log_path),
            "sanitizers": detect_sanitizers(output),
        }
    except subprocess.TimeoutExpired as exc:
        output = as_text(exc.stdout) + as_text(exc.stderr)
        log_path.write_text(output, encoding="utf-8")
        return {
            "name": name,
            "command": argv,
            "exitCode": None,
            "timedOut": True,
            "log": str(log_path),
            "sanitizers": detect_sanitizers(output),
        }


def detect_sanitizers(output: str) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    lines = output.splitlines()
    for index, line in enumerate(lines):
        if "runtime error:" in line or "UndefinedBehaviorSanitizer" in line:
            findings.append(
                {
                    "kind": "UBSAN",
                    "line": line,
                    "summary": next_summary(lines, index),
                }
            )
        elif "ERROR: AddressSanitizer" in line:
            findings.append(
                {
                    "kind": "ASAN",
                    "line": line,
                    "summary": next_summary(lines, index),
                }
            )
    return findings


def next_summary(lines: list[str], start: int) -> str:
    for line in lines[start : start + 8]:
        if line.startswith("SUMMARY:"):
            return line
    return ""


def strip_namespace(tag: str) -> str:
    if "}" in tag:
        return tag.rsplit("}", 1)[1]
    return tag


def parse_number(value: str) -> int | float | None:
    value = value.strip()
    if not value:
        return None
    try:
        if value.lower().startswith(("0x", "+0x", "-0x")):
            sign = -1 if value.startswith("-") else 1
            return sign * int(value.lstrip("+-"), 16)
        if "." in value:
            return float(value)
        return int(value, 10)
    except ValueError:
        return None


def numeric_tokens(text: str) -> list[int | float]:
    values: list[int | float] = []
    for match in NUMBER_RE.finditer(text):
        parsed = parse_number(match.group(0))
        if parsed is not None:
            values.append(parsed)
    return values


def record_numeric_findings(
    findings: list[dict[str, Any]],
    path: str,
    source: str,
    value: int | float,
) -> None:
    if isinstance(value, int):
        if value < 0 or value > UINT16_MAX:
            findings.append(
                {
                    "path": path,
                    "source": source,
                    "value": value,
                    "issue": "outside unsigned 16-bit range",
                    "uint16Wrapped": value & UINT16_MAX,
                }
            )
        if value < INT16_MIN or value > INT16_MAX:
            findings.append(
                {
                    "path": path,
                    "source": source,
                    "value": value,
                    "issue": "outside signed 16-bit range",
                }
            )


def element_to_json(
    elem: ElementTree.Element,
    path: str,
    findings: list[dict[str, Any]],
) -> dict[str, Any]:
    name = strip_namespace(elem.tag)
    current_path = f"{path}/{name}" if path else name
    obj: dict[str, Any] = {"name": name}

    if elem.attrib:
        obj["attributes"] = dict(elem.attrib)
        for attr_name, attr_value in elem.attrib.items():
            for value in numeric_tokens(attr_value):
                record_numeric_findings(
                    findings, current_path, f"@{attr_name}", value
                )

    text = (elem.text or "").strip()
    if text:
        values = numeric_tokens(text)
        obj["text"] = text
        if values:
            obj["numericText"] = values
            for value in values:
                record_numeric_findings(findings, current_path, "text", value)

    children = [element_to_json(child, current_path, findings) for child in list(elem)]
    if children:
        obj["children"] = children
    return obj


def write_approx_json(xml_path: Path, output_path: Path) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    document: dict[str, Any] = {
        "format": "lossy-icc-xml-tree",
        "sourceXml": str(xml_path),
        "note": (
            "This is not canonical iccDEV JSON. It preserves XML element names, "
            "attributes, text, and suspicious numeric values for UBSAN mapping."
        ),
    }
    try:
        root = ElementTree.parse(xml_path).getroot()
        document["root"] = element_to_json(root, "", findings)
    except ElementTree.ParseError as exc:
        raw = xml_path.read_text(encoding="utf-8", errors="replace")
        document["parseError"] = str(exc)
        document["rawPreview"] = raw[:4096]
        for value in numeric_tokens(raw):
            record_numeric_findings(findings, "$raw", "raw", value)

    document["numericFindings"] = findings
    output_path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    return document


def print_step(result: dict[str, Any]) -> None:
    exit_code = "timeout" if result["timedOut"] else str(result["exitCode"])
    sanitizer_count = len(result["sanitizers"])
    print(f"{result['name']}: exit={exit_code} sanitizers={sanitizer_count}")
    for finding in result["sanitizers"]:
        print(f"  {finding['kind']}: {finding['line']}")
        if finding["summary"]:
            print(f"  {finding['summary']}")


def main() -> int:
    args = parse_args()
    xml_path = Path(args.xml).resolve()
    if not xml_path.is_file():
        print(f"input XML not found: {xml_path}", file=sys.stderr)
        return 64

    tools_dir = Path(args.tools_dir).resolve()
    try:
        from_xml = tool_path(tools_dir, "IccFromXml", "iccFromXml")
        to_json = tool_path(tools_dir, "IccToJson", "iccToJson")
        from_json = tool_path(tools_dir, "IccFromJson", "iccFromJson")
    except FileNotFoundError as exc:
        print(str(exc), file=sys.stderr)
        return 69

    if args.out_dir:
        out_dir = Path(args.out_dir).resolve()
        out_dir.mkdir(parents=True, exist_ok=True)
    else:
        out_dir = Path(tempfile.mkdtemp(prefix="icc-xml-json-ubsan-"))

    stem = xml_path.name.replace("/", "_")
    generated_icc = out_dir / f"{stem}.from-xml.icc"
    canonical_json = out_dir / f"{stem}.canonical.json"
    approx_json = out_dir / f"{stem}.approx.json"
    from_json_icc = out_dir / f"{stem}.from-json.icc"
    approx_from_json_icc = out_dir / f"{stem}.approx-from-json.icc"
    summary_path = out_dir / f"{stem}.summary.json"
    env = sanitizer_env()

    summary: dict[str, Any] = {
        "inputXml": str(xml_path),
        "outDir": str(out_dir),
        "artifacts": {},
        "steps": [],
    }

    approx = write_approx_json(xml_path, approx_json)
    summary["artifacts"]["approxJson"] = str(approx_json)
    summary["approxNumericFindings"] = approx.get("numericFindings", [])

    steps = [
        (
            "iccFromXml",
            [str(from_xml), str(xml_path), str(generated_icc)],
            out_dir / "iccFromXml.log",
        )
    ]
    for name, command, log_path in steps:
        result = run_tool(name, command, log_path, args.timeout, env)
        summary["steps"].append(result)
        print_step(result)

    if generated_icc.is_file() and generated_icc.stat().st_size > 0:
        summary["artifacts"]["generatedIcc"] = str(generated_icc)
        result = run_tool(
            "iccToJson",
            [str(to_json), str(generated_icc), str(canonical_json), "-indent=2"],
            out_dir / "iccToJson.log",
            args.timeout,
            env,
        )
        summary["steps"].append(result)
        print_step(result)
        if canonical_json.is_file() and canonical_json.stat().st_size > 0:
            summary["artifacts"]["canonicalJson"] = str(canonical_json)
            result = run_tool(
                "iccFromJson",
                [str(from_json), str(canonical_json), str(from_json_icc)],
                out_dir / "iccFromJson.log",
                args.timeout,
                env,
            )
            summary["steps"].append(result)
            print_step(result)
            if from_json_icc.is_file() and from_json_icc.stat().st_size > 0:
                summary["artifacts"]["fromJsonIcc"] = str(from_json_icc)
    else:
        summary["note"] = "iccFromXml did not produce a usable ICC profile"

    if args.test_approx_json:
        result = run_tool(
            "iccFromJsonApprox",
            [str(from_json), str(approx_json), str(approx_from_json_icc)],
            out_dir / "iccFromJsonApprox.log",
            args.timeout,
            env,
        )
        summary["steps"].append(result)
        print_step(result)
        if approx_from_json_icc.is_file() and approx_from_json_icc.stat().st_size > 0:
            summary["artifacts"]["approxFromJsonIcc"] = str(approx_from_json_icc)

    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    print(f"approxJson: {approx_json}")
    if canonical_json.is_file():
        print(f"canonicalJson: {canonical_json}")
    print(f"summary: {summary_path}")

    found_sanitizer = any(step["sanitizers"] for step in summary["steps"])
    if found_sanitizer and args.fail_on_sanitizer:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
