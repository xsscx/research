#!/usr/bin/env python3
"""Normalize V1 iccAnalyzer-lite `-a` text output into conformance records.

This adapter exists because the V1 `--json` path omits a material subset of
raw ICC conformance checks that are still present in the legacy text audit.
The parser accepts both the historical `[H####] CF-...` header form and the
current bare `[CF-###] ...` raw-conformance header form.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

from runtimeEnv import v1_runtime_env


LEGACY_HEADER_RE = re.compile(
    r"^\[H(?P<hid>\d+)\]\s+CF-(?P<start>\d{3})(?:\.\.CF-(?P<end>\d{3}))?:\s*(?P<title>.+?)\s*$"
)
RAW_HEADER_RE = re.compile(
    r"^\[CF-(?P<start>\d{3})(?:\.\.CF-(?P<end>\d{3}))?\]\s*(?P<title>.+?)\s*$"
)
STATUS_RE = re.compile(
    r"^\[(?P<status>OK|WARN|FAIL|INFO|SKIP|ERROR|N/A|GAP|NOT RUN)\]\s*(?P<message>.*)$"
)
CF_STATUS_RE = re.compile(
    r"^\[(?P<status>OK|WARN|FAIL|INFO|SKIP|ERROR|N/A|GAP|NOT RUN)\]\s*"
    r"CF-(?P<cfid>\d{3}):\s*(?P<message>.*)$"
)
CF_INLINE_RE = re.compile(r"\bCF-(?P<cfid>\d{3})\b")
ANSI_RE = re.compile(r"\x1B[@-_][0-?]*[ -/]*[@-~]")
NONCONFORMANCE_RE = re.compile(r"(?P<count>\d+)\s+non-conformance\(s\)")


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_v1_binary() -> Path:
    return repo_root() / "iccanalyzer-lite"


def conformance_registry_path() -> Path:
    return repo_root() / "IccConformanceRegistry.h"


def load_cf_registry(path: Path) -> dict[str, dict[str, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    pattern = re.compile(
        r'\{"CF-(\d{3})",\s*"([^"]+)",\s*"([^"]*)",\s*"([^"]*)",\s*'
        r'CFSeverity::([A-Z]+),\s*CFCategory::([A-Z0-9_]+)\}',
        re.MULTILINE,
    )
    out: dict[str, dict[str, str]] = {}
    for match in pattern.finditer(text):
        number, title, spec_ref, spec_doc, severity, category = match.groups()
        cf_id = f"CF-{number}"
        out[cf_id] = {
            "title": title,
            "specRef": spec_ref,
            "specDoc": spec_doc,
            "canonicalSeverity": severity,
            "category": category,
        }
    return out


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def run_v1_text(
    binary: Path,
    input_file: Path,
    *,
    disable_library_ub_defense: bool = False,
) -> dict:
    cmd = [str(binary), "-a", str(input_file)]

    proc = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        env=v1_runtime_env(binary, disable_library_ub_defense=disable_library_ub_defense),
        check=False,
        errors="replace",
    )

    if not proc.stdout.strip():
        raise RuntimeError(
            f"V1 text command produced no stdout (rc={proc.returncode})."
            f" stderr={proc.stderr.strip()[:400]}"
        )

    return {
        "stdout": proc.stdout,
        "stdoutStripped": strip_ansi(proc.stdout),
        "stderr": proc.stderr,
        "cmd": cmd,
        "returncode": proc.returncode,
    }


def normalize_gap_status(message: str) -> str:
    text = " ".join(message.strip().lower().split())
    skip_fragments = (
        "not run",
        "not evaluated",
        "skipped",
        "skip ",
        "due to non-finite",
        "due to invalid",
        "requires parseable",
    )
    if any(fragment in text for fragment in skip_fragments):
        return "skip"
    return "ok"


def normalize_status(status: str, message: str = "") -> str:
    if status in {"SKIP", "NOT RUN"}:
        return "skip"
    if status == "GAP":
        return normalize_gap_status(message)
    if status in {"WARN", "FAIL", "ERROR"}:
        return "finding"
    if status in {"OK", "INFO", "N/A"}:
        return "ok"
    return "unknown"


def canonical_cf_id(number: int | str) -> str:
    return f"CF-{int(number):03d}"


def is_block_terminator(line: str) -> bool:
    if not line:
        return False
    if line.startswith("--- ") and line.endswith(" ---"):
        return True
    if line.startswith("Deep Conformance Summary:"):
        return True
    if line.startswith("PHASE "):
        return True
    if set(line) == {"="}:
        return True
    return False


def is_summary_status_message(message: str) -> bool:
    text = message.strip()
    if not text:
        return False
    if NONCONFORMANCE_RE.fullmatch(text):
        return True
    if text in {"Conformant", "Not applicable"}:
        return True
    return False


def header_range(header: dict) -> list[str]:
    start = int(header["start"])
    end = int(header["end"] or header["start"])
    return [canonical_cf_id(number) for number in range(start, end + 1)]


def build_record(
    *,
    cf_id: str,
    header: dict,
    lines: list[str],
    explicit_statuses: list[tuple[str, str]],
    registry: dict[str, dict[str, str]],
) -> dict:
    meta = registry.get(cf_id, {})
    stripped_lines = [line.strip() for line in lines if line.strip()]
    finding_count = sum(
        1
        for status, message in explicit_statuses
        if status in {"WARN", "FAIL", "ERROR"} and not is_summary_status_message(message)
    )
    summary_count = 0
    for line in stripped_lines:
        match = NONCONFORMANCE_RE.search(line)
        if match:
            summary_count = max(summary_count, int(match.group("count")))
    finding_count = max(finding_count, summary_count)

    normalized = "ok"
    if any(normalize_status(status, message) == "skip" for status, message in explicit_statuses):
        normalized = "skip"
    if finding_count > 0:
        normalized = "finding"

    block_title = header["title"].strip()
    canonical_name = meta.get("title", block_title)

    return {
        "tool": "v1-text-normalized",
        "lane": "conformance",
        "rawId": int(header["hid"]),
        "canonicalId": cf_id,
        "rawName": f"{cf_id}: {block_title}",
        "canonicalName": canonical_name,
        "reportedStatus": normalized,
        "normalizedStatus": normalized,
        "reportedSeverity": meta.get("canonicalSeverity", ""),
        "canonicalSeverity": meta.get("canonicalSeverity", ""),
        "findingCount": finding_count,
        "detail": "\n".join(stripped_lines),
        "specRef": meta.get("specRef", ""),
        "specDoc": meta.get("specDoc", ""),
        "category": meta.get("category", ""),
    }


def parse_block(header: dict, lines: list[str], registry: dict[str, dict[str, str]]) -> list[dict]:
    grouped: dict[str, dict[str, list]] = defaultdict(lambda: {"lines": [], "statuses": []})

    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue

        cf_status_match = CF_STATUS_RE.match(line)
        if cf_status_match:
            cf_id = canonical_cf_id(cf_status_match.group("cfid"))
            grouped[cf_id]["lines"].append(line)
            grouped[cf_id]["statuses"].append(
                (cf_status_match.group("status"), cf_status_match.group("message"))
            )
            continue

        if grouped:
            inline_ids = {canonical_cf_id(match.group("cfid")) for match in CF_INLINE_RE.finditer(line)}
            if len(inline_ids) == 1:
                cf_id = next(iter(inline_ids))
                grouped[cf_id]["lines"].append(line)
                status_match = STATUS_RE.match(line)
                if status_match:
                    grouped[cf_id]["statuses"].append(
                        (status_match.group("status"), status_match.group("message"))
                    )
                continue

    if grouped:
        records: list[dict] = []
        for cf_id in sorted(grouped, key=lambda item: int(item[3:])):
            records.append(
                build_record(
                    cf_id=cf_id,
                    header=header,
                    lines=grouped[cf_id]["lines"],
                    explicit_statuses=grouped[cf_id]["statuses"],
                    registry=registry,
                )
            )
        return records

    statuses: list[tuple[str, str]] = []
    stripped_lines = [line.strip() for line in lines if line.strip()]
    for line in stripped_lines:
        status_match = STATUS_RE.match(line)
        if status_match:
            statuses.append((status_match.group("status"), status_match.group("message")))

    records: list[dict] = []
    for cf_id in header_range(header):
        records.append(
            build_record(
                cf_id=cf_id,
                header=header,
                lines=stripped_lines,
                explicit_statuses=statuses,
                registry=registry,
            )
        )
    return records


def parse_conformance_records(text: str, registry: dict[str, dict[str, str]]) -> list[dict]:
    records: list[dict] = []
    current_header: dict | None = None
    current_lines: list[str] = []

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        header_match = LEGACY_HEADER_RE.match(stripped)
        if header_match:
            if current_header is not None:
                records.extend(parse_block(current_header, current_lines, registry))
            current_header = header_match.groupdict()
            current_lines = []
            continue

        raw_header_match = RAW_HEADER_RE.match(stripped)
        if raw_header_match:
            if current_header is not None:
                records.extend(parse_block(current_header, current_lines, registry))
            current_header = raw_header_match.groupdict()
            current_header["hid"] = current_header["start"]
            current_lines = []
            continue

        if current_header is not None and is_block_terminator(stripped):
            records.extend(parse_block(current_header, current_lines, registry))
            current_header = None
            current_lines = []
            continue

        if current_header is not None:
            current_lines.append(raw_line)

    if current_header is not None:
        records.extend(parse_block(current_header, current_lines, registry))

    deduped: dict[str, dict] = {}
    for record in records:
        deduped[record["canonicalId"]] = record

    return [deduped[cf_id] for cf_id in sorted(deduped, key=lambda item: int(item[3:]))]


def build_output(
    *,
    input_file: Path,
    subprocess_result: dict,
    records: list[dict],
) -> dict:
    return {
        "tool": "v1-text-normalized",
        "sourceTool": "iccAnalyzer-lite",
        "inputFile": str(input_file),
        "lane": "conformance",
        "legacyMode": False,
        "exitCode": subprocess_result["returncode"],
        "subprocessReturnCode": subprocess_result["returncode"],
        "records": records,
        "_subprocess": {
            "cmd": subprocess_result["cmd"],
            "returncode": subprocess_result["returncode"],
            "stderr": subprocess_result["stderr"],
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_file", type=Path)
    parser.add_argument(
        "--binary",
        type=Path,
        default=default_v1_binary(),
        help="Path to the V1 iccAnalyzer-lite binary",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    parser.add_argument(
        "--disable-library-ub-defense",
        action="store_true",
        help="Disable the V1 library UB defense for parity measurement only",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.binary.is_file():
        print(
            json.dumps(
                {
                    "tool": "v1-text-normalized",
                    "error": f"V1 binary not found: {args.binary}",
                },
                indent=2,
            )
        )
        return 2

    registry = load_cf_registry(conformance_registry_path())
    subprocess_result = run_v1_text(
        args.binary,
        args.input_file,
        disable_library_ub_defense=args.disable_library_ub_defense,
    )
    records = parse_conformance_records(subprocess_result["stdoutStripped"], registry)
    out = build_output(
        input_file=args.input_file,
        subprocess_result=subprocess_result,
        records=records,
    )
    json.dump(out, sys.stdout, indent=2 if args.pretty else None)
    if args.pretty:
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
