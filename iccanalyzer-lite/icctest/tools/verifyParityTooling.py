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


def default_h30_fixture() -> Path:
    return repo_root() / "tests" / "corpus" / "gbd_tary_signed_channel_wrap.icc"


def default_h21_fixture() -> Path:
    return (
        repo_root().parent
        / "test-profiles"
        / "sbo-CIccTagStruct-GetElemNumberValue-IccTagComposite_cpp-Line737.icc"
    )


def default_cf190_fixture() -> Path:
    return repo_root() / "tests" / "corpus" / "v5_spac_basic.icc"


def make_h21_tag_struct_profile_bytes() -> bytes:
    return bytes.fromhex(
        "000002d0000000000500000063656e63524742200000000000000000000000000000000061637370000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000372666e6d000000a80000001463736e6d000000bc0000001063657074000000cc00000204757466380000000049534f2032323032382d3100757466380000000062672d73524742007473747200000000636570740000000f7258595a000000c4000000146758595a000000d8000000146258595a000000ec0000001466756e630000010000000070776c756d000001700000000c7758595a0000017c0000001065526e670000018c00000010626974730000019c0000000b696d7374000001a80000000c69626b67000001b40000000c73726e64000001c00000000c61696c6d000001cc0000000c6d77706c000001d80000000c6d777063000001e4000000106d627063000001f400000010666c3332000000003f23d70a3ea8f5c33cf5c28f666c3332000000003e99999a3f19999a3dcccccd666c3332000000003e19999a3d75c28f3f4a3d71637572660000000000030000bb4d2e1c3b4d2e1c70617266000000000003000043d55555bf870a3dbf80000000000000000000007061726600000000000000003f800000414eb85200000000000000007061726600000000000300003ed555553f870a3d3f8000000000000000000000666c33320000000042a00000666c3332000000003e870a3d3f8000000000000000000000666c33320000000042a00000666c3332000000003ea01a373ea872b0666c333200000000bf07ae143fd70a3d75693038000000000a0c10007369672000000000646f7263666c33320000000042a00000666c3332000000003ea01a373ea872b0666c3332000000003ea01a373ea872b0"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v1-binary", type=Path, default=default_v1_binary())
    parser.add_argument("--v2-binary", type=Path, default=default_v2_binary())
    parser.add_argument("--fixture", type=Path, default=default_fixture())
    parser.add_argument("--h30-fixture", type=Path, default=default_h30_fixture())
    parser.add_argument("--h21-fixture", type=Path, default=default_h21_fixture())
    parser.add_argument("--cf190-fixture", type=Path, default=default_cf190_fixture())
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
    ensure_file(args.h30_fixture, "H30 GBD fixture")
    ensure_file(args.cf190_fixture, "CF-190 failed-load fixture")

    tool_dir = Path(__file__).resolve().parent
    normalize = tool_dir / "normalizeV1Json.py"
    normalize_conformance = tool_dir / "normalizeV1TextConformance.py"
    compare = tool_dir / "compareRawParity.py"

    with tempfile.TemporaryDirectory(prefix="icctest-parity-tooling-") as tmpdir:
        tmpdir_path = Path(tmpdir)
        h21_fixture = args.h21_fixture
        if not h21_fixture.is_file():
            h21_fixture = tmpdir_path / "h21-tagstruct.icc"
            h21_fixture.write_bytes(make_h21_tag_struct_profile_bytes())

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

        h30_payload = run_json(
            [
                sys.executable,
                str(compare),
                "--lane",
                "heuristic",
                "--check",
                "H30",
                "--v1-binary",
                str(args.v1_binary),
                "--v2-binary",
                str(args.v2_binary),
                str(args.h30_fixture),
            ]
        )
        h30_counts = h30_payload.get("summary", {}).get("counts", {})
        if int(h30_counts.get("delta", 0)) != 0:
            raise RuntimeError(
                f"Expected H30 comparator delta=0 for nested GBD fixture, got {h30_counts}"
            )

        gbd_extra_payload = run_json(
            [
                sys.executable,
                str(compare),
                "--lane",
                "heuristic",
                "--check",
                "H74,H107,H110,H116,H117",
                "--v1-binary",
                str(args.v1_binary),
                "--v2-binary",
                str(args.v2_binary),
                str(args.h30_fixture),
            ]
        )
        gbd_extra_counts = gbd_extra_payload.get("summary", {}).get("counts", {})
        if int(gbd_extra_counts.get("delta", 0)) != 0:
            raise RuntimeError(
                "Expected GBD raw-only comparator delta=0 for H74/H107/H110/H116/H117, "
                f"got {gbd_extra_counts}"
            )
        if int(gbd_extra_counts.get("coverageImprovement", 0)) == 5:
            pass
        elif int(gbd_extra_counts.get("match", 0)) == 5:
            pass
        else:
            raise RuntimeError(
                "Expected GBD raw-only comparator to report either "
                "coverageImprovement=5 or match=5 for H74/H107/H110/H116/H117, "
                f"got {gbd_extra_counts}"
            )

        h21_payload = run_json(
            [
                sys.executable,
                str(compare),
                "--lane",
                "heuristic",
                "--check",
                "H21,H22,H23,H24",
                "--v1-binary",
                str(args.v1_binary),
                "--v2-binary",
                str(args.v2_binary),
                str(h21_fixture),
            ]
        )
        h21_counts = h21_payload.get("summary", {}).get("counts", {})
        if int(h21_counts.get("delta", 0)) != 0:
            raise RuntimeError(
                f"Expected H21-H24 comparator delta=0 for tagStruct fixture, got {h21_counts}"
            )

        cf190_normalized = run_json(
            [
                sys.executable,
                str(normalize_conformance),
                "--binary",
                str(args.v1_binary),
                str(args.cf190_fixture),
            ]
        )
        cf190_record = next(
            (
                record
                for record in cf190_normalized.get("records", [])
                if record.get("canonicalId") == "CF-190"
            ),
            None,
        )
        if not cf190_record:
            raise RuntimeError("Expected normalizeV1TextConformance to synthesize CF-190")
        if cf190_record.get("normalizedStatus") != "finding":
            raise RuntimeError(f"Expected synthesized CF-190 finding status, got {cf190_record}")
        if int(cf190_record.get("findingCount", 0)) != 1:
            raise RuntimeError(f"Expected synthesized CF-190 findingCount=1, got {cf190_record}")
        if "profileDescriptionTag - Tag has invalid structure!" not in cf190_record.get("detail", ""):
            raise RuntimeError(
                "Expected synthesized CF-190 detail to preserve ReadValidate failure detail"
            )

        cf190_compare = run_json(
            [
                sys.executable,
                str(compare),
                "--lane",
                "conformance",
                "--check",
                "CF-190",
                "--v1-binary",
                str(args.v1_binary),
                "--v2-binary",
                str(args.v2_binary),
                str(args.cf190_fixture),
            ]
        )
        cf190_lane = cf190_compare["results"][0]["lanes"]["conformance"]
        cf190_counts = cf190_lane["summary"]["counts"]
        if int(cf190_counts.get("delta", 0)) != 0:
            raise RuntimeError(
                f"Expected CF-190 comparator delta=0 for failed-load fixture, got {cf190_counts}"
            )
        if int(cf190_counts.get("implicitSkipMatch", 0)) != 0:
            raise RuntimeError(
                "Expected CF-190 comparator to stop treating the failed-load case as implicit skip, "
                f"got {cf190_counts}"
            )
        if int(cf190_counts.get("match", 0)) != 1:
            raise RuntimeError(
                f"Expected CF-190 comparator match=1 for failed-load fixture, got {cf190_counts}"
            )

        malformed_h172 = tmpdir_path / "h172-lut-matrix.icc"
        clean_h172 = tmpdir_path / "h172-lut-matrix-clean.icc"
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
            (
                record
                for record in h172_payload.get("records", [])
                if record.get("canonicalId") == "H172"
            ),
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
