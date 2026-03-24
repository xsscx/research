#!/usr/bin/env python3
"""Regression checks for parity tooling on malformed raw ICC inputs."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from runtimeEnv import force_sanitizer_env


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_v1_binary() -> Path:
    return repo_root() / "iccanalyzer-lite"


def default_v2_binary() -> Path:
    return repo_root() / "icctest" / "build" / "tools" / "icctest-parity"


def default_fixture() -> Path:
    return (
        repo_root().parent
        / "test-profiles"
        / "ub-npd-spectral-fuzzer-CIccApplyCmm-IccCmm_cpp-Line8845.icc"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v1-binary", type=Path, default=default_v1_binary())
    parser.add_argument("--v2-binary", type=Path, default=default_v2_binary())
    parser.add_argument("--fixture", type=Path, default=default_fixture())
    return parser.parse_args()


def ensure_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Missing {label}: {path}")


def run_json(cmd: list[str]) -> dict:
    env = force_sanitizer_env(os.environ.copy())
    proc = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        check=False,
        timeout=30,
    )
    stdout = proc.stdout.decode("utf-8", errors="replace")
    stderr = proc.stderr.decode("utf-8", errors="replace")
    if proc.returncode != 0:
        raise RuntimeError(
            f"Command failed\ncmd={' '.join(cmd)}\nrc={proc.returncode}\n"
            f"stdout={stdout[:4000]}\nstderr={stderr[:4000]}"
        )
    if any(token in stderr for token in ("AddressSanitizer", "UndefinedBehaviorSanitizer", "runtime error:")):
        raise RuntimeError(
            f"Sanitizer diagnostics detected\ncmd={' '.join(cmd)}\nstderr={stderr[:4000]}"
        )
    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"JSON parse failed\ncmd={' '.join(cmd)}\nstdout={stdout[:4000]}\nstderr={stderr[:4000]}"
        ) from exc


def main() -> int:
    args = parse_args()
    ensure_file(args.v1_binary, "V1 binary")
    ensure_file(args.v2_binary, "V2 parity binary")
    ensure_file(args.fixture, "malformed spectral fixture")

    tool_dir = Path(__file__).resolve().parent
    normalize = tool_dir / "normalizeV1Json.py"
    compare = tool_dir / "compareRawParity.py"

    v1_payload = run_json(
        [
            sys.executable,
            str(normalize),
            "--binary",
            str(args.v1_binary),
            "--lane",
            "heuristic",
            "--disable-library-ub-defense",
            "--legacy",
            str(args.fixture),
        ]
    )
    if v1_payload.get("lane") != "heuristic":
        raise RuntimeError("normalizeV1Json returned unexpected lane")

    compare_payload = run_json(
        [
            sys.executable,
            str(compare),
            "--lane",
            "heuristic",
            "--check",
            "H98",
            "--v1-binary",
            str(args.v1_binary),
            "--v2-binary",
            str(args.v2_binary),
            str(args.fixture),
        ]
    )

    counts = compare_payload.get("summary", {}).get("counts", {})
    if int(counts.get("delta", 0)) != 0:
        raise RuntimeError(
            f"Expected H98 comparator delta=0 for malformed spectral fixture, got {counts}"
        )
    if int(counts.get("implicitSkipMatch", 0)) != 1:
        raise RuntimeError(
            f"Expected H98 comparator implicitSkipMatch=1 for malformed spectral fixture, got {counts}"
        )

    print("verifyParityTooling: pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
