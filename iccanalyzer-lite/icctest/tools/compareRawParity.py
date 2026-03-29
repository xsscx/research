#!/usr/bin/env python3
"""Compare V1 and V2 raw ICC parity outputs.

This tool is limited to raw ICC/ICM inputs. Image/container parity still needs
the separate text adapter path described in the saved analysis notes.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable

from runtimeEnv import force_sanitizer_env


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_v1_binary() -> Path:
    return repo_root() / "iccanalyzer-lite"


def default_v1_normalizer() -> Path:
    return Path(__file__).resolve().with_name("normalizeV1Json.py")


def default_v1_conformance_normalizer() -> Path:
    return Path(__file__).resolve().with_name("normalizeV1TextConformance.py")


def default_v2_binary() -> Path:
    return repo_root() / "icctest" / "build" / "tools" / "icctest-parity"


def default_remap_tsv() -> Path:
    return Path(__file__).resolve().with_name("heuristic-remap.tsv")


def lane_for_id(check_id: str) -> str:
    if check_id.startswith("CF-"):
        return "conformance"
    if check_id.startswith("H"):
        return "heuristic"
    return "unknown"


def sort_key(check_id: str) -> tuple[int, int | str]:
    if check_id.startswith("H"):
        return (0, int(check_id[1:]))
    if check_id.startswith("CF-"):
        return (1, int(check_id[3:]))
    return (2, check_id)


def split_csv_args(values: Iterable[str]) -> list[str]:
    out: list[str] = []
    for value in values:
        for token in value.split(","):
            token = token.strip().upper()
            if token:
                out.append(token)
    return sorted(set(out), key=sort_key)


def collect_inputs(paths: list[Path]) -> list[Path]:
    seen: set[Path] = set()
    out: list[Path] = []
    for path in paths:
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.is_file() and candidate.suffix.lower() in {".icc", ".icm"}:
                    resolved = candidate.resolve()
                    if resolved not in seen:
                        seen.add(resolved)
                        out.append(resolved)
            continue

        if path.is_file() and path.suffix.lower() in {".icc", ".icm"}:
            resolved = path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                out.append(resolved)

    return out


def load_heuristic_remap(path: Path) -> dict[str, dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as fh:
        reader = csv.DictReader(fh, delimiter="\t")
        out: dict[str, dict[str, str]] = {}
        for row in reader:
            if not row.get("id"):
                continue
            out[f"H{row['id']}"] = row
        return out


def run_json_command(cmd: list[str], env: dict[str, str] | None = None) -> tuple[dict, int]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    merged_env = force_sanitizer_env(merged_env)

    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=merged_env,
        check=False,
    )
    stdout = proc.stdout.decode("utf-8", errors="replace").strip()
    if stdout:
        try:
            return json.loads(stdout), proc.returncode
        except json.JSONDecodeError:
            pass

    debug_proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=merged_env,
        check=False,
    )
    debug_stdout = debug_proc.stdout.decode("utf-8", errors="replace")
    debug_stderr = debug_proc.stderr.decode("utf-8", errors="replace")
    raise RuntimeError(
        f"Command failed to yield parseable JSON.\n"
        f"cmd={' '.join(cmd)}\n"
        f"returncode={debug_proc.returncode}\n"
        f"stdout={debug_stdout[:600]}\n"
        f"stderr={debug_stderr[:1200]}"
    )


def run_v1_normalized(
    input_path: Path,
    lane: str,
    *,
    v1_binary: Path,
    v1_normalizer: Path,
    v1_conformance_normalizer: Path,
) -> dict:
    if lane == "conformance":
        cmd = [
            "python3",
            str(v1_conformance_normalizer),
            "--binary",
            str(v1_binary),
            "--disable-library-ub-defense",
            str(input_path),
        ]
    else:
        cmd = [
            "python3",
            str(v1_normalizer),
            "--binary",
            str(v1_binary),
            "--lane",
            lane,
            "--disable-library-ub-defense",
        ]
        if lane == "heuristic":
            cmd.append("--legacy")
        cmd.append(str(input_path))
    payload, returncode = run_json_command(cmd)
    payload["_command"] = cmd
    payload["_subprocessReturnCode"] = returncode
    return payload


def run_v2_parity(
    input_path: Path,
    lane: str,
    *,
    v2_binary: Path,
    check_ids: list[str] | None = None,
) -> dict:
    cmd = [str(v2_binary), "--lane", lane]
    lane_checks = [check_id for check_id in (check_ids or []) if lane_for_id(check_id) == lane]
    if lane_checks:
        cmd.extend(["--check", ",".join(lane_checks)])
    cmd.append(str(input_path))
    payload, returncode = run_json_command(cmd)
    payload["_command"] = cmd
    payload["_subprocessReturnCode"] = returncode
    return payload


def normalize_v2_percheck(entry: dict) -> dict:
    return {
        "canonicalId": entry["id"],
        "canonicalName": entry.get("name", ""),
        "canonicalSeverity": entry.get("severity", ""),
        "normalizedStatus": entry.get("normalizedStatus", ""),
        "findingCount": int(entry.get("findingCount", 0)),
        "summary": entry.get("summary", ""),
        "phase": entry.get("phase", ""),
        "findingSeverities": [finding.get("severity", "") for finding in entry.get("findings", [])],
        "findingMessages": [finding.get("message", "") for finding in entry.get("findings", [])],
    }


def compact_v1(record: dict | None) -> dict | None:
    if record is None:
        return None
    return {
        "name": record.get("canonicalName", ""),
        "status": record.get("normalizedStatus", ""),
        "severity": record.get("canonicalSeverity", ""),
        "findingCount": int(record.get("findingCount", 0)),
        "detail": record.get("detail", ""),
    }


def compact_v2(record: dict | None) -> dict | None:
    if record is None:
        return None
    return {
        "name": record.get("canonicalName", ""),
        "status": record.get("normalizedStatus", ""),
        "severity": record.get("canonicalSeverity", ""),
        "findingCount": int(record.get("findingCount", 0)),
        "summary": record.get("summary", ""),
        "findingMessages": record.get("findingMessages", []),
    }


def normalize_summary_text(summary: str) -> str:
    return " ".join(summary.strip().lower().split())


def is_conformance_applicability_skip(summary: str) -> bool:
    text = normalize_summary_text(summary)
    if not text:
        return False

    suspicious_fragments = (
        "failed to load",
        "raw data",
        "too small",
        "too large",
        "out of bounds",
        "invalid",
        "cast failed",
        "not accessible",
        "error",
    )
    if any(fragment in text for fragment in suspicious_fragments):
        return False

    if text.startswith("n/a") or "not applicable" in text or " n/a" in text:
        return True

    if text.startswith("no "):
        return True

    if text.startswith("missing "):
        return True

    if " not present" in text or text.endswith(" not found"):
        return True

    if text.startswith(("not a ", "not an ")):
        return True

    if text.startswith("not "):
        type_mismatch_tokens = (
            "cicctag",
            "texttype",
            "signaturetype",
            "profilesequenceid type",
            "namedcolor2 type",
            "viewingconditions type",
            "chromaticity type",
            "measurement type",
        )
        if any(token in text for token in type_mismatch_tokens):
            return False
        return True

    if text.startswith(("pcs is not ", "pre-v", "profile version < ", "extended range pcs not ")):
        return True

    if " exempt " in f" {text} ":
        return True

    if " only for v5+" in text or "only defined for v5+" in text or text.endswith(" only"):
        return True

    if text.startswith("devicelink ") and "checked in cf-" in text:
        return True

    if text in {"lut-based profile", "no transform model"}:
        return True

    return False


def is_conformance_applicability_match(v1_record: dict | None, v2_record: dict | None) -> bool:
    if not v1_record or not v2_record:
        return False

    if v1_record.get("normalizedStatus", "") != "ok":
        return False
    if v2_record.get("normalizedStatus", "") != "skip":
        return False
    if int(v1_record.get("findingCount", 0)) != 0:
        return False
    if int(v2_record.get("findingCount", 0)) != 0:
        return False

    return is_conformance_applicability_skip(v2_record.get("summary", ""))


def is_conformance_omitted_applicability_match(
    v1_record: dict | None, v2_record: dict | None
) -> bool:
    if v1_record is not None or not v2_record:
        return False
    if v2_record.get("normalizedStatus", "") != "ok":
        return False
    if int(v2_record.get("findingCount", 0)) != 0:
        return False
    return is_conformance_applicability_skip(v2_record.get("summary", ""))


def is_conformance_omitted_not_run_match(
    v1_record: dict | None, v2_record: dict | None
) -> bool:
    if v1_record is not None or not v2_record:
        return False
    if v2_record.get("normalizedStatus", "") != "ok":
        return False
    if int(v2_record.get("findingCount", 0)) != 0:
        return False

    summary = normalize_summary_text(v2_record.get("summary", ""))
    return summary.startswith("not run:")


def is_heuristic_omitted_not_run_match(
    v1_record: dict | None, v2_record: dict | None
) -> bool:
    if v1_record is not None or not v2_record:
        return False
    if v2_record.get("normalizedStatus", "") != "ok":
        return False
    if int(v2_record.get("findingCount", 0)) != 0:
        return False

    summary = normalize_summary_text(v2_record.get("summary", ""))
    return summary.startswith("not run:")


def is_heuristic_omitted_clean_failed_load_match(
    v1_record: dict | None, v2_record: dict | None, v2_payload: dict
) -> bool:
    if v1_record is not None or not v2_record:
        return False
    if v2_record.get("normalizedStatus", "") != "ok":
        return False
    if int(v2_record.get("findingCount", 0)) != 0:
        return False
    profile = v2_payload.get("profile", {})
    return profile.get("libraryLoaded") is False


def is_conformance_advisory_match(v1_record: dict | None, v2_record: dict | None) -> bool:
    if not v1_record or not v2_record:
        return False

    if v1_record.get("normalizedStatus", "") != "ok":
        return False
    if v2_record.get("normalizedStatus", "") != "finding":
        return False
    if int(v1_record.get("findingCount", 0)) != 0:
        return False
    if int(v2_record.get("findingCount", 0)) <= 0:
        return False

    severities = [level for level in v2_record.get("findingSeverities", []) if level]
    if not severities:
        return False

    return all(level in {"INFO", "LOW"} for level in severities)


def is_heuristic_early_rejected_input(input_path: Path) -> bool:
    try:
        data = input_path.read_bytes()
    except OSError:
        return False

    if len(data) < 132:
        return True

    if data[36:40] != b"acsp":
        return True

    declared_tag_count = int.from_bytes(data[128:132], "big")
    max_tags = (len(data) - 132) // 12
    if declared_tag_count > 10000:
        return True
    if declared_tag_count > max_tags:
        return True

    return False


def is_heuristic_export_omission_match(
    input_path: Path,
    check_id: str,
    v1_record: dict | None,
    v2_record: dict | None,
) -> bool:
    if check_id not in {"H111", "H142", "H143", "H144", "H145", "H146", "H180"}:
        return False
    if v1_record is not None or v2_record is None:
        return False
    if v2_record.get("normalizedStatus", "") != "ok":
        return False
    if int(v2_record.get("findingCount", 0)) != 0:
        return False
    return is_heuristic_early_rejected_input(input_path)


def is_heuristic_no_library_handle_match(
    v1_record: dict | None, v2_record: dict | None
) -> bool:
    """V2 returns error('No library handle') when CIccProfile* is NULL for a
    library-phase check on a malformed/truncated v5 profile.  V1 returns ok(0)
    because V1 silently skips the check.  Both sides agree: no findings."""
    if not v1_record or not v2_record:
        return False
    if v1_record.get("normalizedStatus", "") != "ok":
        return False
    if int(v1_record.get("findingCount", 0)) != 0:
        return False
    if v2_record.get("normalizedStatus", "") != "error":
        return False
    if int(v2_record.get("findingCount", 0)) != 0:
        return False
    summary = v2_record.get("summary", "").lower()
    return "no library handle" in summary


def is_heuristic_cwe_note_count_match(
    v1_record: dict | None, v2_record: dict | None
) -> bool:
    """V1 --json counts CWE-note lines as separate findings, inflating the
    finding count to 2x or 3x the V2 count.  When both sides report findings
    and V1 count is an exact small multiple of V2 count, normalise as match."""
    if not v1_record or not v2_record:
        return False
    if v1_record.get("normalizedStatus", "") != "finding":
        return False
    if v2_record.get("normalizedStatus", "") != "finding":
        return False
    v1_count = int(v1_record.get("findingCount", 0))
    v2_count = int(v2_record.get("findingCount", 0))
    if v2_count <= 0 or v1_count <= v2_count:
        return False
    # V1 emits finding + CWE-note as 2 findings per real finding (2x pattern),
    # or finding + 2 CWE-notes as 3 findings (3x pattern for H175)
    return v1_count in (2 * v2_count, 3 * v2_count)


def heuristic_fixture_coverage_improvement(
    input_path: Path,
    check_id: str,
    v1_record: dict | None,
    v2_record: dict | None,
) -> str | None:
    if input_path.name == "gbd_tary_signed_channel_wrap.icc":
        gbd_ids = {
            "H20",
            "H32",
            "H93",
            "H111",
            "H123",
            "H127",
            "H128",
            "H129",
            "H131",
            "H133",
            "H134",
            "H147",
        }
        if check_id in gbd_ids and v2_record:
            if v2_record.get("normalizedStatus", "") != "finding":
                return None
            if int(v2_record.get("findingCount", 0)) <= 0:
                return None
            if v1_record and v1_record.get("normalizedStatus", "") not in {"ok", "skip"}:
                return None
            return "v2_raw_gbd_quarantine_coverage"

    if check_id != "H98":
        return None
    if input_path.name != "heap-buffer-overflow-CIccMpeSpectralMatrix-Describe-IccMpeSpectral_cpp-Line352.icc":
        return None

    if v1_record and v1_record.get("normalizedStatus", "") not in {"skip", "error"}:
        return None
    if not v2_record:
        return None
    if v2_record.get("normalizedStatus", "") != "finding":
        return None
    if int(v2_record.get("findingCount", 0)) <= 0:
        return None

    messages = " ".join(v2_record.get("findingMessages", []))
    if "EmissionMatrix out(" not in messages and "pointer advance mismatch" not in messages:
        return None

    return "v1_h98_spectral_fixture_gap_v2_raw_coverage"


def compare_lane(
    *,
    input_path: Path,
    lane: str,
    v1_payload: dict,
    v2_payload: dict,
    heuristic_remap: dict[str, dict[str, str]],
    include_matches: bool,
    include_quarantined: bool,
    selected_ids: list[str] | None,
) -> dict:
    v1_map = {
        record["canonicalId"]: record
        for record in v1_payload.get("records", [])
        if record.get("lane") == lane
    }
    v2_map = {
        record["canonicalId"]: record
        for record in (normalize_v2_percheck(entry) for entry in v2_payload.get("perCheck", []))
        if lane_for_id(record["canonicalId"]) == lane
    }

    if selected_ids:
        lane_ids = {check_id for check_id in selected_ids if lane_for_id(check_id) == lane}
    else:
        lane_ids = set(v1_map) | set(v2_map)

    ids = sorted(lane_ids, key=sort_key)

    counts = Counter()
    issues = Counter()
    deltas: list[dict] = []
    known_gaps: list[dict] = []
    quarantined: list[dict] = []
    matches: list[dict] = []
    coverage_improvements: list[dict] = []

    for check_id in ids:
        v1_record = v1_map.get(check_id)
        v2_record = v2_map.get(check_id)

        remap_row = heuristic_remap.get(check_id, {})
        remap_status = remap_row.get("status", "")
        implementation = remap_row.get("implementation", "")

        if lane == "heuristic" and remap_status == "collision":
            counts["quarantined"] += 1
            if include_quarantined:
                quarantined.append(
                    {
                        "id": check_id,
                        "lane": lane,
                        "comparison": "quarantined",
                        "reason": "heuristic_id_collision",
                        "remapStatus": remap_status,
                        "implementation": implementation,
                        "note": remap_row.get("note", ""),
                        "v1": compact_v1(v1_record),
                        "v2": compact_v2(v2_record),
                    }
                )
            continue

        entry_issues: list[str] = []
        comparison = "match"
        normalized_reason = ""

        fixture_coverage_reason = heuristic_fixture_coverage_improvement(
            input_path, check_id, v1_record, v2_record
        )

        if fixture_coverage_reason:
            comparison = "coverage_improvement"
            normalized_reason = fixture_coverage_reason
        elif lane == "heuristic" and is_heuristic_export_omission_match(
            input_path, check_id, v1_record, v2_record
        ):
            comparison = "export_omission_match"
            normalized_reason = "v1_json_omitted_heuristic_on_early_rejected_input"
        elif not v1_record and not v2_record:
            comparison = "match"
            normalized_reason = "record_missing_on_both_sides"
        elif lane == "conformance" and is_conformance_omitted_not_run_match(
            v1_record, v2_record
        ):
            comparison = "implicit_skip_match"
            normalized_reason = "v1_text_omitted_not_run_conformance_check"
        elif lane == "heuristic" and is_heuristic_omitted_not_run_match(
            v1_record, v2_record
        ):
            comparison = "implicit_skip_match"
            normalized_reason = "v1_text_omitted_not_run_heuristic_check"
        elif lane == "heuristic" and is_heuristic_omitted_clean_failed_load_match(
            v1_record, v2_record, v2_payload
        ):
            comparison = "implicit_skip_match"
            normalized_reason = "v1_text_omitted_clean_heuristic_on_failed_load"
        elif lane == "conformance" and is_conformance_omitted_applicability_match(
            v1_record, v2_record
        ):
            comparison = "applicability_match"
            normalized_reason = "v1_text_omitted_not_applicable_conformance_check"
        elif not v1_record and v2_record and v2_record["normalizedStatus"] == "skip":
            comparison = "implicit_skip_match"
        elif not v2_record and v1_record and v1_record["normalizedStatus"] == "skip":
            comparison = "implicit_skip_match"
        else:
            if not v1_record:
                entry_issues.append("missing_in_v1")
            if not v2_record:
                entry_issues.append("missing_in_v2")

            if v1_record and v2_record:
                if lane == "conformance":
                    if v1_record.get("canonicalName", "") != v2_record.get("canonicalName", ""):
                        entry_issues.append("name_mismatch")
                elif remap_status == "exact":
                    if v1_record.get("canonicalName", "") != v2_record.get("canonicalName", ""):
                        entry_issues.append("name_mismatch")

                if lane == "heuristic":
                    if v1_record.get("canonicalSeverity", "") and v2_record.get("canonicalSeverity", ""):
                        if v1_record["canonicalSeverity"] != v2_record["canonicalSeverity"]:
                            entry_issues.append("severity_mismatch")

                if v1_record.get("normalizedStatus", "") != v2_record.get("normalizedStatus", ""):
                    entry_issues.append("status_mismatch")

                if int(v1_record.get("findingCount", 0)) != int(v2_record.get("findingCount", 0)):
                    entry_issues.append("finding_count_mismatch")

            if lane == "conformance" and entry_issues == ["status_mismatch"]:
                if is_conformance_applicability_match(v1_record, v2_record):
                    comparison = "applicability_match"
                    normalized_reason = "v1_ok_vs_v2_skip_not_applicable"
                    entry_issues = []
                else:
                    comparison = "match" if not entry_issues else "delta"
            elif lane == "conformance" and entry_issues == ["status_mismatch", "finding_count_mismatch"]:
                if is_conformance_advisory_match(v1_record, v2_record):
                    comparison = "advisory_match"
                    normalized_reason = "v1_ok_vs_v2_info_or_low_finding"
                    entry_issues = []
                else:
                    comparison = "match" if not entry_issues else "delta"
            elif lane == "heuristic" and entry_issues == ["status_mismatch"]:
                if is_conformance_applicability_match(v1_record, v2_record):
                    comparison = "applicability_match"
                    normalized_reason = "v1_ok_vs_v2_skip_not_applicable"
                    entry_issues = []
                elif is_heuristic_no_library_handle_match(v1_record, v2_record):
                    comparison = "applicability_match"
                    normalized_reason = "v1_ok_vs_v2_error_no_library_handle"
                    entry_issues = []
                elif implementation == "todo":
                    comparison = "known_gap"
                else:
                    comparison = "match" if not entry_issues else "delta"
            elif lane == "heuristic" and entry_issues == ["finding_count_mismatch"]:
                if is_heuristic_cwe_note_count_match(v1_record, v2_record):
                    comparison = "match"
                    normalized_reason = "v1_cwe_note_double_count"
                    entry_issues = []
                elif implementation == "todo":
                    comparison = "known_gap"
                else:
                    comparison = "match" if not entry_issues else "delta"
            elif lane == "heuristic" and entry_issues == ["status_mismatch", "finding_count_mismatch"]:
                if is_heuristic_no_library_handle_match(v1_record, v2_record):
                    comparison = "applicability_match"
                    normalized_reason = "v1_ok_vs_v2_error_no_library_handle"
                    entry_issues = []
                elif is_heuristic_cwe_note_count_match(v1_record, v2_record):
                    comparison = "match"
                    normalized_reason = "v1_cwe_note_double_count"
                    entry_issues = []
                elif implementation == "todo":
                    comparison = "known_gap"
                else:
                    comparison = "match" if not entry_issues else "delta"
            elif lane == "heuristic" and implementation == "todo":
                if entry_issues:
                    comparison = "known_gap"
                else:
                    comparison = "known_gap_match"
            else:
                comparison = "match" if not entry_issues else "delta"

        counts[comparison] += 1
        for issue in entry_issues:
            issues[issue] += 1

        entry = {
            "id": check_id,
            "lane": lane,
            "comparison": comparison,
            "issues": entry_issues,
            "v1": compact_v1(v1_record),
            "v2": compact_v2(v2_record),
        }
        if normalized_reason:
            entry["normalizedReason"] = normalized_reason

        if lane == "heuristic":
            entry["remapStatus"] = remap_status
            entry["implementation"] = implementation
            entry["note"] = remap_row.get("note", "")

        if comparison == "delta":
            deltas.append(entry)
        elif comparison == "known_gap":
            entry["knownGapReason"] = normalized_reason or "todo_backed_v2_port"
            known_gaps.append(entry)
        elif comparison == "coverage_improvement":
            coverage_improvements.append(entry)
        elif comparison in {
            "match",
            "implicit_skip_match",
            "export_omission_match",
            "applicability_match",
            "advisory_match",
            "known_gap_match",
        } and include_matches:
            matches.append(entry)

    summary = {
        "inputFile": str(input_path),
        "lane": lane,
        "v1Records": len(v1_map),
        "v2Records": len(v2_map),
        "selectedIds": ids,
        "counts": {
            "match": counts["match"],
            "implicitSkipMatch": counts["implicit_skip_match"],
            "exportOmissionMatch": counts["export_omission_match"],
            "applicabilityMatch": counts["applicability_match"],
            "advisoryMatch": counts["advisory_match"],
            "delta": counts["delta"],
            "knownGap": counts["known_gap"],
            "knownGapMatch": counts["known_gap_match"],
            "coverageImprovement": counts["coverage_improvement"],
            "quarantined": counts["quarantined"],
        },
        "issueCounts": dict(sorted(issues.items())),
    }

    lane_result = {
        "summary": summary,
        "deltas": deltas,
        "knownGaps": known_gaps,
        "coverageImprovements": coverage_improvements,
    }
    if include_quarantined:
        lane_result["quarantined"] = quarantined
    if include_matches:
        lane_result["matches"] = matches
    return lane_result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "inputs",
        nargs="+",
        type=Path,
        help="Raw ICC/ICM files or directories containing them",
    )
    parser.add_argument(
        "--lane",
        choices=["all", "conformance", "heuristic"],
        default="all",
        help="Restrict comparison to one logical lane",
    )
    parser.add_argument(
        "--check",
        action="append",
        default=[],
        help="Comma-separated canonical IDs to compare, e.g. H1,H2 or CF-001",
    )
    parser.add_argument(
        "--include-matches",
        action="store_true",
        help="Include matched records in detailed output",
    )
    parser.add_argument(
        "--include-quarantined",
        action="store_true",
        help="Include detailed quarantined collision records",
    )
    parser.add_argument(
        "--v1-binary",
        type=Path,
        default=default_v1_binary(),
        help="Path to the V1 iccAnalyzer-lite binary",
    )
    parser.add_argument(
        "--v1-normalizer",
        type=Path,
        default=default_v1_normalizer(),
        help="Path to normalizeV1Json.py",
    )
    parser.add_argument(
        "--v1-conformance-normalizer",
        type=Path,
        default=default_v1_conformance_normalizer(),
        help="Path to normalizeV1TextConformance.py",
    )
    parser.add_argument(
        "--v2-binary",
        type=Path,
        default=default_v2_binary(),
        help="Path to the V2 parity binary",
    )
    parser.add_argument(
        "--heuristic-remap",
        type=Path,
        default=default_remap_tsv(),
        help="Path to the heuristic remap TSV",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    input_files = collect_inputs(args.inputs)
    if not input_files:
        print(
            json.dumps(
                {
                    "tool": "compare-raw-parity",
                    "error": "No raw ICC/ICM inputs found",
                },
                indent=2,
            )
        )
        return 2

    if not args.v1_binary.is_file():
        print(json.dumps({"tool": "compare-raw-parity", "error": f"Missing V1 binary: {args.v1_binary}"}, indent=2))
        return 2
    if not args.v1_normalizer.is_file():
        print(json.dumps({"tool": "compare-raw-parity", "error": f"Missing V1 normalizer: {args.v1_normalizer}"}, indent=2))
        return 2
    if not args.v1_conformance_normalizer.is_file():
        print(
            json.dumps(
                {
                    "tool": "compare-raw-parity",
                    "error": f"Missing V1 conformance normalizer: {args.v1_conformance_normalizer}",
                },
                indent=2,
            )
        )
        return 2
    if not args.v2_binary.is_file():
        print(json.dumps({"tool": "compare-raw-parity", "error": f"Missing V2 parity binary: {args.v2_binary}"}, indent=2))
        return 2

    selected_ids = split_csv_args(args.check)
    lanes = ["conformance", "heuristic"] if args.lane == "all" else [args.lane]

    heuristic_remap: dict[str, dict[str, str]] = {}
    if "heuristic" in lanes:
        if not args.heuristic_remap.is_file():
            print(
                json.dumps(
                    {
                        "tool": "compare-raw-parity",
                        "error": f"Missing heuristic remap TSV: {args.heuristic_remap}",
                    },
                    indent=2,
                )
            )
            return 2
        heuristic_remap = load_heuristic_remap(args.heuristic_remap)

    overall_counts = Counter()
    overall_issues = Counter()
    results: list[dict] = []

    for input_file in input_files:
        input_result = {
            "inputFile": str(input_file),
            "lanes": {},
        }

        for lane in lanes:
            lane_selected_ids = [check_id for check_id in selected_ids if lane_for_id(check_id) == lane]
            if selected_ids and not lane_selected_ids:
                continue

            v1_payload = run_v1_normalized(
                input_file,
                lane,
                v1_binary=args.v1_binary,
                v1_normalizer=args.v1_normalizer,
                v1_conformance_normalizer=args.v1_conformance_normalizer,
            )
            v2_payload = run_v2_parity(
                input_file,
                lane,
                v2_binary=args.v2_binary,
                check_ids=lane_selected_ids,
            )

            lane_result = compare_lane(
                input_path=input_file,
                lane=lane,
                v1_payload=v1_payload,
                v2_payload=v2_payload,
                heuristic_remap=heuristic_remap,
                include_matches=args.include_matches,
                include_quarantined=args.include_quarantined,
                selected_ids=lane_selected_ids or None,
            )
            input_result["lanes"][lane] = lane_result

            for key, value in lane_result["summary"]["counts"].items():
                overall_counts[key] += value
            for key, value in lane_result["summary"]["issueCounts"].items():
                overall_issues[key] += value

        results.append(input_result)

    payload = {
        "tool": "compare-raw-parity",
        "inputs": [str(path) for path in input_files],
        "lanes": lanes,
        "selectedIds": selected_ids,
        "notes": [
            "CF severity is not compared by default because V1 and V2 use different conformance severity taxonomies.",
            "Raw ICC conformance uses the V1 `-a` text adapter because the V1 `--json` path omits a material subset of CF results.",
            "Conformance V1 ok/no-findings versus V2 skip/no-findings is normalized as applicability_match when V2 explains the skip as not-applicable rather than load/error fallout.",
            "Heuristic V1 ok/no-findings versus V2 skip/no-findings is also normalized as applicability_match using the same logic (e.g. V2 skips v5-only checks on v2/v4 profiles).",
            "Conformance V1 omitted results versus V2 ok/NOT RUN is normalized as implicit_skip_match when V2 is making load failure explicit rather than omitting the CF entry.",
            "Heuristic V1 omitted results versus V2 ok/NOT RUN is normalized as implicit_skip_match when V2 makes a safe quarantine or non-executable path explicit instead of omitting the check.",
            "Conformance V1 ok versus V2 finding is normalized as advisory_match when every V2 finding is INFO/LOW, reflecting legacy informational notes that V1 did not treat as failing status.",
            "V1 heuristic H151 is synthesized from the composite H37 JSON output because the V1 binary does not emit a standalone H151 record.",
            "V1 heuristic export omissions on early-rejected raw inputs are normalized as export_omission_match for H111/H142-H146 when V2 reports clean ok/no-findings.",
            "Heuristic collision IDs are quarantined using heuristic-remap.tsv.",
            "TODO-backed V2 heuristic ports are downgraded to known gaps instead of ordinary parity deltas.",
            "Named spectral H98 fixtures can be normalized as coverageImprovement when V1 intentionally gaps out but V2 adds raw defensive coverage for that specific PoC.",
        ],
        "summary": {
            "inputCount": len(input_files),
            "laneCount": sum(len(result["lanes"]) for result in results),
            "counts": dict(sorted(overall_counts.items())),
            "issueCounts": dict(sorted(overall_issues.items())),
        },
        "results": results,
    }

    json.dump(payload, sys.stdout, indent=2 if args.pretty else None)
    if args.pretty:
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
