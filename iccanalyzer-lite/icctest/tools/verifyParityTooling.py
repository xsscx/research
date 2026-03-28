#!/usr/bin/env python3
"""Regression checks for parity tooling on malformed raw ICC inputs."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
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


def make_h172_lut_matrix_profile_bytes(malformed: bool) -> bytes:
    data = bytearray(228)

    def put_u32(offset: int, value: int) -> None:
        data[offset:offset + 4] = int(value & 0xFFFFFFFF).to_bytes(4, "big", signed=False)

    def put_s32(offset: int, value: int) -> None:
        data[offset:offset + 4] = int(value).to_bytes(4, "big", signed=True)

    put_u32(0, len(data))
    put_u32(8, 0x04400000)
    put_u32(12, 0x70727472)
    put_u32(16, 0x52474220)
    put_u32(20, 0x4C616220)
    put_u32(36, 0x61637370)

    put_u32(128, 1)
    put_u32(132, 0x41324230)
    put_u32(136, 144)
    put_u32(140, 116)

    put_u32(144, 0x6D414220)
    data[152] = 3
    data[153] = 3
    put_u32(156, 32)
    put_u32(160, 68)
    put_u32(164, 0)
    put_u32(168, 0)
    put_u32(172, 0)

    for curve in range(3):
        off = 176 + curve * 12
        put_u32(off, 0x63757276)
        put_u32(off + 4, 0)
        put_u32(off + 8, 0)

    identity = 1 << 16
    matrix_off = 212
    if malformed:
        put_s32(matrix_off + 0, 0)
        put_s32(matrix_off + 4, 0)
        put_s32(matrix_off + 8, 0)
        put_s32(matrix_off + 12, 0)
        put_s32(matrix_off + 16, identity)
        put_s32(matrix_off + 20, 0)
        put_s32(matrix_off + 24, 0)
        put_s32(matrix_off + 28, 0)
        put_s32(matrix_off + 32, 200 << 16)
        put_s32(matrix_off + 36, 20 << 16)
        put_s32(matrix_off + 40, 0)
        put_s32(matrix_off + 44, 0)
    else:
        put_s32(matrix_off + 0, identity)
        put_s32(matrix_off + 4, 0)
        put_s32(matrix_off + 8, 0)
        put_s32(matrix_off + 12, 0)
        put_s32(matrix_off + 16, identity)
        put_s32(matrix_off + 20, 0)
        put_s32(matrix_off + 24, 0)
        put_s32(matrix_off + 28, 0)
        put_s32(matrix_off + 32, identity)
        put_s32(matrix_off + 36, 0)
        put_s32(matrix_off + 40, 0)
        put_s32(matrix_off + 44, 0)

    return bytes(data)


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

    with tempfile.TemporaryDirectory(prefix="icctest-parity-tooling-") as tmpdir:
        malformed_h172 = Path(tmpdir) / "h172-lut-matrix.icc"
        clean_h172 = Path(tmpdir) / "h172-lut-matrix-clean.icc"
        malformed_h172.write_bytes(make_h172_lut_matrix_profile_bytes(True))
        clean_h172.write_bytes(make_h172_lut_matrix_profile_bytes(False))

        h172_payload = run_json(
            [
                sys.executable,
                str(normalize),
                "--binary",
                str(args.v1_binary),
                "--lane",
                "heuristic",
                "--disable-library-ub-defense",
                "--legacy",
                str(malformed_h172),
            ]
        )
        h172_record = next(
            (record for record in h172_payload.get("records", []) if record.get("canonicalId") == "H172"),
            None,
        )
        if not h172_record:
            raise RuntimeError("Expected normalizeV1Json to synthesize H172 from legacy text")
        if h172_record.get("normalizedStatus") != "finding":
            raise RuntimeError(f"Expected synthesized H172 finding status, got {h172_record}")
        if int(h172_record.get("findingCount", 0)) != 4:
            raise RuntimeError(f"Expected synthesized H172 findingCount=4, got {h172_record}")

        for fixture in (malformed_h172, clean_h172):
            compare_h172 = run_json(
                [
                    sys.executable,
                    str(compare),
                    "--lane",
                    "heuristic",
                    "--check",
                    "H172",
                    "--v1-binary",
                    str(args.v1_binary),
                    "--v2-binary",
                    str(args.v2_binary),
                    str(fixture),
                ]
            )
            h172_counts = compare_h172.get("summary", {}).get("counts", {})
            if int(h172_counts.get("delta", 0)) != 0:
                raise RuntimeError(
                    f"Expected H172 comparator delta=0 for {fixture.name}, got {h172_counts}"
                )

    print("verifyParityTooling: pass")
    return 0


if __name__ == "__main__":
    sys.exit(main())
