#!/usr/bin/env python3
"""Verify V1 and V2 PAWG report structure and checklist wording."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


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
