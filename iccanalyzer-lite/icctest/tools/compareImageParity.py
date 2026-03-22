#!/usr/bin/env python3
"""Compare V1/V2 image-container parity, including extracted embedded ICC."""

from __future__ import annotations

import argparse
import base64
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

import compareRawParity as raw


IMAGE_EXTS = {".tif", ".tiff", ".png", ".jpg", ".jpeg"}


def is_tiff_family(fmt: str) -> bool:
    upper = (fmt or "").upper()
    return upper in {"TIFF", "TIFF_LE", "TIFF_BE", "BIGTIFF_LE", "BIGTIFF_BE"}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_v1_binary() -> Path:
    return repo_root() / "iccanalyzer-lite"


def default_v1_image_normalizer() -> Path:
    return Path(__file__).resolve().with_name("normalizeV1ImageText.py")


def default_v2_binary() -> Path:
    return repo_root() / "icctest" / "build" / "tools" / "icctest-parity"


def default_remap_tsv() -> Path:
    return Path(__file__).resolve().with_name("heuristic-remap.tsv")


def collect_inputs(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for path in paths:
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.is_file() and candidate.suffix.lower() in IMAGE_EXTS:
                    resolved = candidate.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        out.append(resolved)
            continue

        if path.is_file() and path.suffix.lower() in IMAGE_EXTS:
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                out.append(resolved)

    return out


def run_v1_image_normalized(
    input_path: Path,
    *,
    v1_binary: Path,
    v1_image_normalizer: Path,
) -> dict:
    cmd = [
        "python3",
        str(v1_image_normalizer),
        "--binary",
        str(v1_binary),
        str(input_path),
    ]
    payload, returncode = raw.run_json_command(cmd)
    payload["_command"] = cmd
    payload["_subprocessReturnCode"] = returncode
    return payload


def run_v2_image_parity(input_path: Path, *, v2_binary: Path) -> dict:
    cmd = [str(v2_binary), "--lane", "image", "--emit-embedded-profile-base64", str(input_path)]
    payload, returncode = raw.run_json_command(cmd)
    payload["_command"] = cmd
    payload["_subprocessReturnCode"] = returncode
    return payload


def compare_outer_image(
    *,
    v1_payload: dict,
    v2_payload: dict,
    include_matches: bool,
) -> dict:
    fmt = v1_payload.get("format") or v2_payload.get("profile", {}).get("imageFormat", "")
    v1_map = {record["canonicalId"]: record for record in v1_payload.get("records", [])}
    v2_map = {
        record["canonicalId"]: record
        for record in (raw.normalize_v2_percheck(entry) for entry in v2_payload.get("perCheck", []))
        if record["canonicalId"].startswith("H")
    }

    if is_tiff_family(fmt):
        ids = sorted(set(v1_map) | set(v2_map), key=raw.sort_key)
    else:
        ids = []
    counts = Counter()
    issue_counts = Counter()
    deltas: list[dict] = []
    matches: list[dict] = []

    for check_id in ids:
        v1_record = v1_map.get(check_id)
        v2_record = v2_map.get(check_id)
        entry_issues: list[str] = []

        if not v1_record:
            entry_issues.append("missing_in_v1")
        if not v2_record:
            entry_issues.append("missing_in_v2")

        if v1_record and v2_record:
            if v1_record.get("canonicalName", "") != v2_record.get("canonicalName", ""):
                entry_issues.append("name_mismatch")
            if v1_record.get("normalizedStatus", "") != v2_record.get("normalizedStatus", ""):
                entry_issues.append("status_mismatch")
            if int(v1_record.get("findingCount", 0)) != int(v2_record.get("findingCount", 0)):
                entry_issues.append("finding_count_mismatch")

        if entry_issues:
            counts["delta"] += 1
            for issue in entry_issues:
                issue_counts[issue] += 1
            deltas.append(
                {
                    "id": check_id,
                    "comparison": "delta",
                    "issues": entry_issues,
                    "v1": raw.compact_v1(v1_record),
                    "v2": raw.compact_v2(v2_record),
                }
            )
        else:
            counts["match"] += 1
            if include_matches:
                matches.append(
                    {
                        "id": check_id,
                        "comparison": "match",
                        "v1": raw.compact_v1(v1_record),
                        "v2": raw.compact_v2(v2_record),
                    }
                )

    v1_container_open = bool(v1_payload.get("containerOpenFailure"))
    v2_profile = v2_payload.get("profile", {})
    v2_container_open = bool(
        v2_profile.get("isImage")
        and v2_profile.get("imageParseable") is False
        and v2_profile.get("imageParseError")
    )
    container_alignment = {
        "comparison": "match" if v1_container_open == v2_container_open else "delta",
        "v1": {
            "containerOpenFailure": v1_container_open,
            "message": v1_payload.get("containerOpenMessage", ""),
        },
        "v2": {
            "containerOpenFailure": v2_container_open,
            "message": v2_profile.get("imageParseError", ""),
        },
    }
    counts["containerOpenMatch" if container_alignment["comparison"] == "match" else "containerOpenDelta"] += 1

    v1_embedded = bool(v1_payload.get("embeddedProfilePresent"))
    v2_embedded = bool(v2_profile.get("embeddedProfilePresent"))
    embedded_alignment = {
        "comparison": "match" if v1_embedded == v2_embedded else "delta",
        "v1": {"embeddedProfilePresent": v1_embedded},
        "v2": {
            "embeddedProfilePresent": v2_embedded,
            "embeddedProfileSource": v2_profile.get("embeddedProfileSource", ""),
            "embeddedProfileSize": v2_profile.get("embeddedProfileSize", 0),
        },
    }
    counts["embeddedPresenceMatch" if embedded_alignment["comparison"] == "match" else "embeddedPresenceDelta"] += 1

    return {
        "format": fmt,
        "summary": {
            "counts": dict(sorted(counts.items())),
            "issueCounts": dict(sorted(issue_counts.items())),
        },
        "containerOpen": container_alignment,
        "embeddedProfile": embedded_alignment,
        "deltas": deltas,
        "matches": matches,
    }


def compare_embedded_raw(
    *,
    image_input: Path,
    v2_image_payload: dict,
    heuristic_remap: dict[str, dict[str, str]],
    args: argparse.Namespace,
) -> dict | None:
    profile = v2_image_payload.get("profile", {})
    if not profile.get("embeddedProfilePresent"):
        return None

    encoded = profile.get("embeddedProfileBase64", "")
    if not encoded:
        raise RuntimeError(
            f"Embedded profile bytes missing for {image_input}; "
            "v2 image parity output did not include base64 payload."
        )

    decoded = base64.b64decode(encoded)
    with tempfile.TemporaryDirectory(prefix="icctest-image-parity-") as tmpdir:
        extracted = Path(tmpdir) / (image_input.stem + ".icc")
        extracted.write_bytes(decoded)

        lane_results: dict[str, dict] = {}
        overall_counts = Counter()
        overall_issue_counts = Counter()

        for lane in ("heuristic", "conformance"):
            v1_payload = raw.run_v1_normalized(
                extracted,
                lane,
                v1_binary=args.v1_binary,
                v1_normalizer=args.v1_normalizer,
                v1_conformance_normalizer=args.v1_conformance_normalizer,
            )
            v2_payload = raw.run_v2_parity(
                extracted,
                lane,
                v2_binary=args.v2_binary,
                check_ids=None,
            )
            lane_result = raw.compare_lane(
                input_path=extracted,
                lane=lane,
                v1_payload=v1_payload,
                v2_payload=v2_payload,
                heuristic_remap=heuristic_remap,
                include_matches=args.include_matches,
                include_quarantined=args.include_quarantined,
                selected_ids=None,
            )
            lane_results[lane] = lane_result
            for key, value in lane_result["summary"]["counts"].items():
                overall_counts[key] += value
            for key, value in lane_result["summary"]["issueCounts"].items():
                overall_issue_counts[key] += value

    return {
        "embeddedProfileSize": len(decoded),
        "summary": {
            "counts": dict(sorted(overall_counts.items())),
            "issueCounts": dict(sorted(overall_issue_counts.items())),
        },
        "lanes": lane_results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--v1-binary", type=Path, default=default_v1_binary())
    parser.add_argument("--v1-image-normalizer", type=Path, default=default_v1_image_normalizer())
    parser.add_argument("--v1-normalizer", type=Path, default=raw.default_v1_normalizer())
    parser.add_argument(
        "--v1-conformance-normalizer",
        type=Path,
        default=raw.default_v1_conformance_normalizer(),
    )
    parser.add_argument("--v2-binary", type=Path, default=default_v2_binary())
    parser.add_argument(
        "--heuristic-remap",
        "--remap-tsv",
        dest="heuristic_remap",
        type=Path,
        default=default_remap_tsv(),
    )
    parser.add_argument("--include-matches", action="store_true")
    parser.add_argument("--include-quarantined", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    heuristic_remap = raw.load_heuristic_remap(args.heuristic_remap)
    input_files = collect_inputs(args.paths)
    if not input_files:
        raise SystemExit("No image inputs found")

    overall_outer_counts = Counter()
    overall_outer_issues = Counter()
    overall_embedded_counts = Counter()
    overall_embedded_issues = Counter()
    results: list[dict] = []

    for input_file in input_files:
        v1_image = run_v1_image_normalized(
            input_file,
            v1_binary=args.v1_binary,
            v1_image_normalizer=args.v1_image_normalizer,
        )
        v2_image = run_v2_image_parity(input_file, v2_binary=args.v2_binary)

        outer = compare_outer_image(
            v1_payload=v1_image,
            v2_payload=v2_image,
            include_matches=args.include_matches,
        )
        for key, value in outer["summary"]["counts"].items():
            overall_outer_counts[key] += value
        for key, value in outer["summary"]["issueCounts"].items():
            overall_outer_issues[key] += value

        embedded = compare_embedded_raw(
            image_input=input_file,
            v2_image_payload=v2_image,
            heuristic_remap=heuristic_remap,
            args=args,
        )
        if embedded:
            for key, value in embedded["summary"]["counts"].items():
                overall_embedded_counts[key] += value
            for key, value in embedded["summary"]["issueCounts"].items():
                overall_embedded_issues[key] += value

        results.append(
            {
                "inputFile": str(input_file),
                "outerImage": outer,
                "embeddedRaw": embedded,
            }
        )

    payload = {
        "tool": "compare-image-parity",
        "inputs": [str(path) for path in input_files],
        "notes": [
            "Outer image parity compares the V1 `-img` text adapter against V2 `--lane image` per-check results for H139/H140/H141/H149/H150.",
            "Embedded ICC parity reuses the existing raw ICC comparator by decoding the V2-extracted embedded profile bytes to a temporary `.icc` file.",
            "Container-open mismatch is tracked separately from check deltas because V1 reports the unparseable-TIFF condition as a top-level image finding rather than as H139/H140/H141/H150 findings.",
        ],
        "summary": {
            "inputCount": len(input_files),
            "outerImage": {
                "counts": dict(sorted(overall_outer_counts.items())),
                "issueCounts": dict(sorted(overall_outer_issues.items())),
            },
            "embeddedRaw": {
                "counts": dict(sorted(overall_embedded_counts.items())),
                "issueCounts": dict(sorted(overall_embedded_issues.items())),
            },
        },
        "results": results,
    }

    json.dump(payload, fp=sys.stdout, indent=2 if args.pretty else None)
    if args.pretty:
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
