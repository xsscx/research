#!/usr/bin/env python3
"""Verify V1 and V2 PAWG report structure and checklist wording."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


ITEM_LINE_RE = re.compile(r"^\s+\[(OK|WARN|FAIL|N/A|GAP| -- )\]\s+([SCQ]\d+)\s+(.*)$", re.MULTILINE)
COUNT_LINE_RE = re.compile(r"^\s+(PASS|WARN|FAIL|N/A|GAP|NOT RUN):\s+(\d+)$", re.MULTILINE)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_v1_binary() -> Path:
    return repo_root() / "iccanalyzer-lite"


def default_v2_binary() -> Path:
    return repo_root() / "icctest" / "build" / "cli" / "icctest"


def default_good_profile() -> Path:
    return repo_root() / "tests" / "corpus" / "valid_srgb.icc"


def default_bad_profile() -> Path:
    return repo_root() / "tests" / "corpus" / "wrong_d50_illuminant.icc"


def expected_spec_reference_paths() -> list[str]:
    spec_dir = repo_root().parent / "docs" / "iccDEV" / "specifications"
    return [
        f"docs/iccDEV/specifications/{entry.name}"
        for entry in sorted(spec_dir.iterdir(), key=lambda path: path.name)
        if entry.is_file() and entry.name != "ICC.1_Adaptive_Gain_Curve.pdf"
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v1-binary", type=Path, default=default_v1_binary())
    parser.add_argument("--v2-binary", type=Path, default=default_v2_binary())
    parser.add_argument("--good-profile", type=Path, default=default_good_profile())
    parser.add_argument("--bad-profile", type=Path, default=default_bad_profile())
    return parser.parse_args()


def ensure_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Missing {label}: {path}")


def run(cmd: list[str], *, label: str) -> str:
    env = os.environ.copy()
    env.setdefault("ASAN_OPTIONS", "detect_leaks=0")
    env.setdefault("LLVM_PROFILE_FILE", "/dev/null")
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        check=False,
    )
    if proc.returncode not in (0, 1):
        raise RuntimeError(
            f"{label} failed\n"
            f"returncode={proc.returncode}\n"
            f"cmd={' '.join(cmd)}\n"
            f"stdout={proc.stdout[:4000]}\n"
            f"stderr={proc.stderr[:4000]}"
        )
    text = proc.stdout + ("\n" + proc.stderr if proc.stderr.strip() else "")
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    return text


def require(text: str, needle: str, failures: list[str], label: str) -> None:
    if needle not in text:
        failures.append(f"{label}: missing {needle!r}")


def require_regex(text: str, pattern: str, failures: list[str], label: str) -> None:
    if re.search(pattern, text) is None:
        failures.append(f"{label}: missing /{pattern}/")


def parse_item_lines(text: str, failures: list[str], label: str) -> dict[str, tuple[str, str]]:
    items: dict[str, tuple[str, str]] = {}
    for verdict, item_id, title in ITEM_LINE_RE.findall(text):
        items[item_id] = (verdict.strip(), title.strip())
    if len(items) != 31:
        failures.append(f"{label}: expected 31 PAWG item lines, found {len(items)}")
    return items


def parse_summary_counts(text: str) -> dict[str, int]:
    return {name: int(value) for name, value in COUNT_LINE_RE.findall(text)}


def compare_items(label_a: str,
                  items_a: dict[str, tuple[str, str]],
                  label_b: str,
                  items_b: dict[str, tuple[str, str]],
                  failures: list[str]) -> None:
    if set(items_a) != set(items_b):
        failures.append(
            f"{label_a}/{label_b}: PAWG item ID drift: "
            f"{sorted(set(items_a).symmetric_difference(items_b))}"
        )
        return
    for item_id in sorted(items_a):
        verdict_a, title_a = items_a[item_id]
        verdict_b, title_b = items_b[item_id]
        if title_a != title_b:
            failures.append(
                f"{label_a}/{label_b}: title mismatch for {item_id}: {title_a!r} != {title_b!r}"
            )
        if verdict_a != verdict_b:
            failures.append(
                f"{label_a}/{label_b}: verdict mismatch for {item_id}: {verdict_a!r} != {verdict_b!r}"
            )


def check_report(label: str, text: str, failures: list[str]) -> None:
    require(text, "ICC PROFILE ASSESSMENT REPORT (PAWG)", failures, label)
    require(
        text,
        "ICC Profile Assessment Working Group Checklist Reference: https://www.color.org/profiles/assessment/index.xalter",
        failures,
        label,
    )
    require(text, "ICC Specification References:", failures, label)
    require(text, "[ SECURITY ]", failures, label)
    require(text, "[ CONFORMANCE ]", failures, label)
    require(text, "[ QUALITY ]", failures, label)
    require(text, "[ ASSESSMENT SUMMARY ]", failures, label)
    require(text, "[ CONFORMANCE CHECK COVERAGE ]", failures, label)
    require(text, "[ SPECIFICATION REFERENCES ]", failures, label)
    require(text, "Total checklist items:  31", failures, label)
    require(text, "Excessive calculator elements not present (ideally provide an estimate of computation cost)", failures, label)
    require(text, "Private tags do not contain exploitable non-operation (NOP) instructions", failures, label)
    for path in expected_spec_reference_paths():
        require(text, path, failures, label)
    if "docs/iccDEV/specifications/ICC.1_Adaptive_Gain_Curve.pdf" in text:
        failures.append(f"{label}: unexpected adaptive gain curve reference")

    for i in range(1, 14):
        require_regex(text, rf"\bS{i}\b", failures, label)
    for i in range(1, 15):
        require_regex(text, rf"\bC{i}\b", failures, label)
    for i in range(1, 5):
        require_regex(text, rf"\bQ{i}\b", failures, label)

    counts = parse_summary_counts(text)
    total = sum(counts.values())
    if total != 31:
        failures.append(f"{label}: PAWG summary count total {total}, expected 31")


def main() -> int:
    args = parse_args()
    ensure_file(args.v1_binary, "V1 binary")
    ensure_file(args.v2_binary, "V2 binary")
    ensure_file(args.good_profile, "good profile")
    ensure_file(args.bad_profile, "bad profile")

    failures: list[str] = []

    v1_good = run([str(args.v1_binary), "-pawg", str(args.good_profile)], label="v1 good PAWG")
    v2_good = run([str(args.v2_binary), "--no-sandbox", "--no-color", "--pawg", str(args.good_profile)], label="v2 good PAWG")
    v1_bad = run([str(args.v1_binary), "-pawg", str(args.bad_profile)], label="v1 bad PAWG")
    v2_bad = run([str(args.v2_binary), "--no-sandbox", "--no-color", "--pawg", str(args.bad_profile)], label="v2 bad PAWG")

    check_report("v1 good", v1_good, failures)
    check_report("v2 good", v2_good, failures)
    check_report("v1 bad", v1_bad, failures)
    check_report("v2 bad", v2_bad, failures)

    v1_good_items = parse_item_lines(v1_good, failures, "v1 good")
    v2_good_items = parse_item_lines(v2_good, failures, "v2 good")
    v1_bad_items = parse_item_lines(v1_bad, failures, "v1 bad")
    v2_bad_items = parse_item_lines(v2_bad, failures, "v2 bad")

    compare_items("v1 good", v1_good_items, "v2 good", v2_good_items, failures)
    compare_items("v1 bad", v1_bad_items, "v2 bad", v2_bad_items, failures)

    if v1_good_items.get("S1", ("", ""))[0] != "OK":
        failures.append("v1 good: expected S1 to render as OK")
    if v2_good_items.get("S1", ("", ""))[0] != "OK":
        failures.append("v2 good: expected S1 to render as OK")
    if v1_good_items.get("Q4", ("", ""))[0] != "N/A":
        failures.append("v1 good: expected Q4 to render as N/A")
    if v2_good_items.get("Q4", ("", ""))[0] != "N/A":
        failures.append("v2 good: expected Q4 to render as N/A")

    require_regex(v1_bad, r"WARN:\s+[1-9]\d*", failures, "v1 bad")
    require_regex(v2_bad, r"WARN:\s+[1-9]\d*", failures, "v2 bad")
    require(v2_bad, "CF-008:", failures, "v2 bad")

    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1

    print("PAWG verification passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
