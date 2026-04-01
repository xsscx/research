#!/usr/bin/env python3
"""Regression check for the sandboxed CLI on malformed high-finding profiles."""

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


def default_cli_binary() -> Path:
    return repo_root() / "icctest" / "build" / "cli" / "icctest"


def default_fixture() -> Path:
    return (
        repo_root().parent
        / "test-profiles"
        / "ub-npd-spectral-fuzzer-CIccApplyCmm-IccCmm_cpp-Line8845.icc"
    )


def default_coverage_fixture() -> Path:
    return repo_root() / "tests" / "corpus" / "v5_spac_basic.icc"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli-binary", type=Path, default=default_cli_binary())
    parser.add_argument("--fixture", type=Path, default=default_fixture())
    parser.add_argument("--coverage-fixture", type=Path, default=default_coverage_fixture())
    parser.add_argument("--timeout-seconds", type=int, default=20)
    return parser.parse_args()


def ensure_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Missing {label}: {path}")


def main() -> int:
    args = parse_args()
    ensure_file(args.cli_binary, "icctest CLI binary")
    ensure_file(args.fixture, "sandbox regression fixture")
    ensure_file(args.coverage_fixture, "coverage regression fixture")

    env = force_sanitizer_env(os.environ.copy())
    proc = subprocess.run(
        [str(args.cli_binary), "-a", str(args.fixture)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=args.timeout_seconds,
        check=False,
    )

    if proc.returncode != 1:
        raise RuntimeError(
            f"sandboxed CLI expected exit code 1, got {proc.returncode}\n"
            f"stdout={proc.stdout[:4000]}\n"
            f"stderr={proc.stderr[:4000]}"
        )

    stderr = proc.stderr
    if any(token in stderr for token in ("AddressSanitizer", "UndefinedBehaviorSanitizer", "runtime error:")):
        raise RuntimeError(
            "sandboxed CLI emitted sanitizer diagnostics\n"
            f"stderr={stderr[:4000]}"
        )

    stdout = proc.stdout
    required = [
        "ICC Profile Security & Conformance Analyzer",
        "Library-phase checks skipped due to UB pre-scan findings",
        "Tag 'mBA ' offset=32 size=262144 exceeds available raw bytes",
        "[H10] CRITICAL",
    ]
    missing = [needle for needle in required if needle not in stdout]
    if missing:
        raise RuntimeError(
            "sandboxed CLI output missing expected markers: "
            + ", ".join(missing)
            + f"\nstdout={stdout[:4000]}"
        )

    if "Analysis terminated by sandbox" in stdout:
        raise RuntimeError(
            "sandboxed CLI still reports sandbox termination\n"
            f"stdout={stdout[:4000]}"
        )

    sandbox_json = subprocess.run(
        [str(args.cli_binary), "--json", str(args.coverage_fixture)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=args.timeout_seconds,
        check=False,
    )
    if sandbox_json.returncode != 1:
        raise RuntimeError(
            f"sandboxed JSON CLI expected exit code 1, got {sandbox_json.returncode}\n"
            f"stdout={sandbox_json.stdout[:4000]}\n"
            f"stderr={sandbox_json.stderr[:4000]}"
        )

    nosandbox_json = subprocess.run(
        [str(args.cli_binary), "--no-sandbox", "--json", str(args.coverage_fixture)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
        timeout=args.timeout_seconds,
        check=False,
    )
    if nosandbox_json.returncode != 1:
        raise RuntimeError(
            f"in-process JSON CLI expected exit code 1, got {nosandbox_json.returncode}\n"
            f"stdout={nosandbox_json.stdout[:4000]}\n"
            f"stderr={nosandbox_json.stderr[:4000]}"
        )

    for label, json_proc in (("sandboxed JSON", sandbox_json), ("in-process JSON", nosandbox_json)):
        if any(token in json_proc.stderr for token in ("AddressSanitizer", "UndefinedBehaviorSanitizer", "runtime error:")):
            raise RuntimeError(
                f"{label} emitted sanitizer diagnostics\n"
                f"stderr={json_proc.stderr[:4000]}"
            )

    sandbox_payload = json.loads(sandbox_json.stdout)
    nosandbox_payload = json.loads(nosandbox_json.stdout)

    sandbox_coverage = int(sandbox_payload["stats"]["coverageOnlyChecks"])
    nosandbox_coverage = int(nosandbox_payload["stats"]["coverageOnlyChecks"])
    if sandbox_coverage <= 0:
        raise RuntimeError(
            f"sandboxed JSON coverageOnlyChecks must be > 0, got {sandbox_coverage}\n"
            f"stdout={sandbox_json.stdout[:4000]}"
        )
    if sandbox_coverage != nosandbox_coverage:
        raise RuntimeError(
            "sandboxed and in-process JSON coverageOnlyChecks diverged\n"
            f"sandboxed={sandbox_coverage} in_process={nosandbox_coverage}\n"
            f"sandboxed_stdout={sandbox_json.stdout[:4000]}\n"
            f"in_process_stdout={nosandbox_json.stdout[:4000]}"
        )

    for label, payload in (("sandboxed JSON", sandbox_payload), ("in-process JSON", nosandbox_payload)):
        finding_ids = {finding.get("id", "") for finding in payload.get("findings", [])}
        if "CF-190" not in finding_ids:
            raise RuntimeError(
                f"{label} missing CF-190 load-failure finding\n"
                f"payload={json.dumps(payload)[:4000]}"
            )

    print("verifyCliSandbox: pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
