#!/usr/bin/env python3
"""Normalize V1 `-img` text output into image-lane parity records."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from runtimeEnv import v1_runtime_env


ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
FORMAT_RE = re.compile(r"IMAGE FILE ANALYSIS\s+[—-]\s+([A-Z0-9_]+)")
HEURISTIC_RE = re.compile(r"^\[H(\d+)\]\s+(.*)$")
STATUS_RE = re.compile(r"^\[(OK|SKIP|WARN|CRIT|FAIL|INJECT|INFO|N/A|GAP|NOT RUN)\]\s*(.*)$")
IMAGE_CHECK_IDS = {139, 140, 141, 149, 150}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_v1_binary() -> Path:
    return repo_root() / "iccanalyzer-lite"


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def normalize_name(name: str) -> str:
    return re.sub(r"\s+\(CWE-[^)]+\)$", "", name).strip()


def gap_is_skip(message: str) -> bool:
    text = " ".join(message.strip().lower().split())
    skip_fragments = (
        "not run",
        "not evaluated",
        "skipped",
        "skip ",
        "requires parseable",
    )
    return any(fragment in text for fragment in skip_fragments)


def finalize_record(record: dict | None) -> dict | None:
    if not record:
        return None

    finding_count = 0
    saw_ok = False
    saw_skip = False
    saw_na = False
    summary = ""

    for line in record.pop("_block", []):
        match = STATUS_RE.match(line)
        if not match:
            continue
        status, message = match.groups()
        message = message.strip() or line
        summary = message
        if status in {"WARN", "CRIT", "FAIL", "INJECT"}:
            finding_count += 1
        elif status in {"SKIP", "NOT RUN"}:
            saw_skip = True
        elif status == "GAP":
            if gap_is_skip(message):
                saw_skip = True
            else:
                saw_na = True
        elif status == "N/A":
            saw_na = True
        elif status == "OK":
            saw_ok = True

    if finding_count > 0:
        normalized_status = "finding"
        if not summary:
            summary = f"{finding_count} issue(s)"
    elif saw_skip:
        normalized_status = "skip"
    elif saw_ok or saw_na:
        normalized_status = "ok"
    else:
        normalized_status = "ok"

    record["normalizedStatus"] = normalized_status
    record["findingCount"] = finding_count
    record["detail"] = summary
    return record


def parse_output(text: str, input_path: Path) -> dict:
    clean = strip_ansi(text)
    fmt = ""
    container_open_failure = False
    container_open_message = ""
    embedded_profile_present = False
    records: list[dict] = []
    current: dict | None = None

    for raw_line in clean.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        format_match = FORMAT_RE.search(stripped)
        if format_match and not fmt:
            fmt = format_match.group(1)

        if "HEURISTIC: Cannot open TIFF file" in stripped:
            container_open_failure = True
            container_open_message = stripped

        if (
            "[FOUND] ICC profile embedded" in stripped
            or "[FOUND] ICC profile in iCCP chunk" in stripped
            or "[FOUND] ICC profile in APP2 marker(s)" in stripped
        ):
            embedded_profile_present = True

        header_match = HEURISTIC_RE.match(stripped)
        if header_match:
            finalized = finalize_record(current)
            if finalized:
                records.append(finalized)

            number = int(header_match.group(1))
            if number not in IMAGE_CHECK_IDS:
                current = None
                continue
            name = normalize_name(header_match.group(2))
            current = {
                "lane": "image",
                "canonicalId": f"H{number}",
                "canonicalName": name,
                "_block": [],
            }
            continue

        if current is not None:
            if not stripped:
                finalized = finalize_record(current)
                if finalized:
                    records.append(finalized)
                current = None
                continue
            current["_block"].append(stripped)

    finalized = finalize_record(current)
    if finalized:
        records.append(finalized)

    return {
        "tool": "normalize-v1-image-text",
        "inputFile": str(input_path),
        "format": fmt,
        "containerOpenFailure": container_open_failure,
        "containerOpenMessage": container_open_message,
        "containerParseable": not container_open_failure,
        "embeddedProfilePresent": embedded_profile_present,
        "recordCount": len(records),
        "records": records,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--binary", type=Path, default=default_v1_binary())
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    cmd = [str(args.binary), "-img", str(args.input)]
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=v1_runtime_env(args.binary),
        check=False,
    )

    payload = parse_output(proc.stdout, args.input.resolve())
    payload["_command"] = cmd
    payload["_subprocessReturnCode"] = proc.returncode

    json.dump(payload, sys.stdout, indent=2 if args.pretty else None)
    if args.pretty:
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
