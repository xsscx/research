#!/usr/bin/env python3
"""Normalize V1 iccAnalyzer-lite JSON into parity-friendly records.

This is intentionally limited to raw ICC input paths. V1 image/container
analysis still needs a dedicated text adapter because `--json` does not
route through the TIFF/PNG/JPEG extraction path.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from runtimeEnv import v1_runtime_env


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


def run_v1_json(
    binary: Path,
    input_file: Path,
    legacy: bool,
    *,
    disable_library_ub_defense: bool = False,
) -> dict:
    cmd = [str(binary), "--json"]
    if legacy:
        cmd.append("--legacy")
    cmd.append(str(input_file))

    proc = subprocess.run(
        cmd,
        capture_output=True,
        env=v1_runtime_env(binary, disable_library_ub_defense=disable_library_ub_defense),
        check=False,
    )

    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")

    if not stdout.strip():
        raise RuntimeError(
            f"V1 JSON command produced no stdout (rc={proc.returncode})."
            f" stderr={stderr.strip()[:400]}"
        )

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Failed to parse V1 JSON: {exc}"
        ) from exc

    payload["_subprocess"] = {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stderr": stderr,
    }
    return payload


def normalized_status(status: str) -> str:
    if status == "ok":
        return "ok"
    if status == "skip":
        return "skip"
    if status in {"warn", "critical"}:
        return "finding"
    return "unknown"


def infer_heuristic_primary_findings(detail: str) -> int:
    auxiliary_prefixes = (
        "risk:",
        "cwe-",
        "ref:",
        "expected:",
        "note:",
        "call chain:",
        "impact:",
        "upstream:",
        "truncation:",
        "[ok]",
        "info:",
    )

    count = 0
    for raw_line in detail.splitlines():
        if not raw_line.strip():
            continue

        if raw_line[:1].isspace():
            continue

        line = raw_line.strip()
        lowered = line.lower()
        if any(lowered.startswith(prefix) for prefix in auxiliary_prefixes):
            continue

        count += 1

    return count


def infer_finding_count(item: dict, lane: str, normalized: str) -> int:
    detail = item.get("detail", "") or ""
    if lane == "conformance":
        match = re.search(r"(\d+)\s+non-conformance", detail)
        if match:
            return int(match.group(1))

    if normalized in {"ok", "skip"}:
        return 0

    if lane == "heuristic":
        primary = infer_heuristic_primary_findings(detail)
        if primary > 0:
            return primary

    if item.get("status") in {"warn", "critical"}:
        return 1
    return 0


def normalize_result(item: dict, cf_registry: dict[str, dict[str, str]]) -> dict:
    raw_id = int(item["id"])
    if raw_id >= 1000:
        canonical_id = f"CF-{raw_id - 1000:03d}"
        lane = "conformance"
    else:
        canonical_id = f"H{raw_id}"
        lane = "heuristic"

    raw_name = item.get("name", "")
    normalized_name = raw_name
    if lane == "conformance":
        prefix = f"{canonical_id}: "
        if raw_name.startswith(prefix):
            normalized_name = raw_name[len(prefix):]

    normalized = normalized_status(item.get("status", ""))
    record = {
        "tool": "v1",
        "lane": lane,
        "rawId": raw_id,
        "canonicalId": canonical_id,
        "rawName": raw_name,
        "canonicalName": normalized_name,
        "reportedStatus": item.get("status", ""),
        "normalizedStatus": normalized,
        "reportedSeverity": item.get("severity", ""),
        "findingCount": infer_finding_count(item, lane, normalized),
        "detail": item.get("detail", "") or "",
    }

    if lane == "conformance":
        meta = cf_registry.get(canonical_id, {})
        record["canonicalName"] = meta.get("title", normalized_name)
        record.update(
            {
                "canonicalSeverity": meta.get("canonicalSeverity", ""),
                "specRef": meta.get("specRef", ""),
                "specDoc": meta.get("specDoc", ""),
                "category": meta.get("category", ""),
            }
        )
    else:
        record.update(
            {
                "canonicalSeverity": item.get("severity", ""),
                "specRef": item.get("specRef", ""),
                "specDoc": "ICC.1-2022-05" if item.get("specRef") else "",
                "category": "",
            }
        )

    return record


def maybe_synthesize_h151(records: list[dict]) -> None:
    if any(record.get("canonicalId") == "H151" for record in records):
        return

    h37 = next(
        (
            record for record in records
            if record.get("lane") == "heuristic" and record.get("canonicalId") == "H37"
        ),
        None,
    )
    if not h37:
        return

    detail = h37.get("detail", "") or ""
    primary_lines: list[str] = []
    for raw_line in detail.splitlines():
        line = raw_line.strip()
        lowered = line.lower()
        if not line or raw_line[:1].isspace():
            continue
        if (
            "calculator channel function signature" in lowered
            or "calculator operator signatures" in lowered
            or ("calculator has" in lowered and "float-to-int cast operators" in lowered)
        ):
            primary_lines.append(line)

    if h37.get("normalizedStatus") == "skip":
        status = "skip"
        raw_status = "skip"
    elif primary_lines:
        status = "finding"
        raw_status = "warn"
    else:
        status = "ok"
        raw_status = "ok"

    records.append(
        {
            "tool": "v1-synth",
            "lane": "heuristic",
            "rawId": 151,
            "canonicalId": "H151",
            "rawName": "Calculator Operator Enum Validation",
            "canonicalName": "Calculator Operator Enum Validation",
            "reportedStatus": raw_status,
            "normalizedStatus": status,
            "reportedSeverity": "CRITICAL",
            "findingCount": len(primary_lines),
            "detail": "\n".join(primary_lines),
            "canonicalSeverity": "CRITICAL",
            "specRef": "§10.26",
            "specDoc": "ICC.1-2022-05",
            "category": "",
        }
    )


def build_output(payload: dict, cf_registry: dict[str, dict[str, str]], lane: str) -> dict:
    records = [normalize_result(item, cf_registry) for item in payload.get("results", [])]
    maybe_synthesize_h151(records)
    if lane != "all":
        records = [record for record in records if record["lane"] == lane]

    return {
        "tool": "v1-normalized",
        "sourceTool": "iccAnalyzer-lite",
        "sourceVersionField": payload.get("summary", {}).get("registry", {}).get("totalHeuristics"),
        "inputFile": payload.get("file", ""),
        "legacyMode": any(arg == "--legacy" for arg in payload["_subprocess"]["cmd"]),
        "lane": lane,
        "exitCode": payload.get("exitCode"),
        "subprocessReturnCode": payload["_subprocess"]["returncode"],
        "summary": payload.get("summary", {}),
        "records": records,
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
        "--lane",
        choices=["all", "heuristic", "conformance"],
        default="all",
        help="Filter normalized records by lane",
    )
    parser.add_argument(
        "--legacy",
        action="store_true",
        help="Run V1 with --legacy to include heuristic findings",
    )
    parser.add_argument(
        "--disable-library-ub-defense",
        action="store_true",
        help="Disable the V1 library UB defense for parity measurement only",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.binary.is_file():
        print(
            json.dumps(
                {
                    "tool": "v1-normalized",
                    "error": f"V1 binary not found: {args.binary}",
                },
                indent=2,
            )
        )
        return 2

    cf_registry = load_cf_registry(conformance_registry_path())
    payload = run_v1_json(
        args.binary,
        args.input_file,
        args.legacy,
        disable_library_ub_defense=args.disable_library_ub_defense,
    )
    out = build_output(payload, cf_registry, args.lane)
    json.dump(out, sys.stdout, indent=2 if args.pretty else None)
    if args.pretty:
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
