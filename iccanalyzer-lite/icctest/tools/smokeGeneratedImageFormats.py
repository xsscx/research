#!/usr/bin/env python3
"""Generate PNG/JPEG fixtures with embedded ICC and run image parity smoke."""

from __future__ import annotations

import argparse
import base64
import json
import subprocess
import struct
import sys
import tempfile
import zlib
from pathlib import Path


JPEG_1X1_TEMPLATE_B64 = (
    "/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAIBAQEBAQIBAQECAgICAgQDAgICAgUEBAMEBgUG"
    "BgYFBgYGBwkIBgcJBwYGCAsICQoKCgoKBggLDAsKDAkKCgr/2wBDAQICAgICAgUDAwUKBwYH"
    "CgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgr/wAAR"
    "CAABAAEDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAA"
    "AgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkK"
    "FhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWG"
    "h4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl"
    "5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREA"
    "AgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYk"
    "NOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOE"
    "hYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk"
    "5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD2iiiiv1Q/Mz//2Q=="
)


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_icc() -> Path:
    return repo_root() / "tests" / "corpus" / "valid_srgb.icc"


def default_compare_script() -> Path:
    return Path(__file__).resolve().with_name("compareImageParity.py")


def default_v1_binary() -> Path:
    return repo_root() / "iccanalyzer-lite"


def default_v2_binary() -> Path:
    return repo_root() / "icctest" / "build" / "tools" / "icctest-parity"


def default_remap_tsv() -> Path:
    return Path(__file__).resolve().with_name("heuristic-remap.tsv")


def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
    header = struct.pack(">I", len(data)) + chunk_type + data
    crc = struct.pack(">I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)
    return header + crc


def build_png_with_icc(icc_bytes: bytes) -> bytes:
    png_sig = b"\x89PNG\r\n\x1a\n"
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    iccp = b"ICC Profile\x00\x00" + zlib.compress(icc_bytes)
    idat = zlib.compress(b"\x00" + bytes((128, 160, 192)))
    return b"".join(
        [
            png_sig,
            png_chunk(b"IHDR", ihdr),
            png_chunk(b"iCCP", iccp),
            png_chunk(b"IDAT", idat),
            png_chunk(b"IEND", b""),
        ]
    )


def jpeg_segment(marker: int, payload: bytes) -> bytes:
    return b"\xFF" + bytes([marker]) + struct.pack(">H", len(payload) + 2) + payload


def build_jpeg_with_icc(icc_bytes: bytes) -> bytes:
    jpeg_bytes = base64.b64decode(JPEG_1X1_TEMPLATE_B64)
    if not jpeg_bytes.startswith(b"\xFF\xD8"):
        raise ValueError("Invalid JPEG template")

    app2_payload = b"ICC_PROFILE\x00" + bytes((1, 1)) + icc_bytes
    app2 = jpeg_segment(0xE2, app2_payload)

    offset = 2
    limit = len(jpeg_bytes)
    while offset + 4 <= limit and jpeg_bytes[offset] == 0xFF:
        marker = jpeg_bytes[offset + 1]
        if 0xE0 <= marker <= 0xEF or marker == 0xFE:
            seg_len = int.from_bytes(jpeg_bytes[offset + 2: offset + 4], "big")
            if seg_len < 2:
                raise ValueError("Invalid JPEG segment length")
            offset += 2 + seg_len
            continue
        break

    return jpeg_bytes[:offset] + app2 + jpeg_bytes[offset:]


def generate_images(out_dir: Path, icc_path: Path) -> list[Path]:
    icc_bytes = icc_path.read_bytes()

    png_path = out_dir / "generated_with_icc.png"
    jpg_path = out_dir / "generated_with_icc.jpg"

    png_path.write_bytes(build_png_with_icc(icc_bytes))
    jpg_path.write_bytes(build_jpeg_with_icc(icc_bytes))
    return [jpg_path, png_path]


def run_compare(
    compare_script: Path,
    image_dir: Path,
    *,
    v1_binary: Path,
    v2_binary: Path,
    heuristic_remap: Path,
) -> dict:
    proc = subprocess.run(
        [
            sys.executable,
            str(compare_script),
            "--pretty",
            "--v1-binary",
            str(v1_binary),
            "--v2-binary",
            str(v2_binary),
            "--heuristic-remap",
            str(heuristic_remap),
            str(image_dir),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"compareImageParity.py failed\n"
            f"returncode={proc.returncode}\n"
            f"stdout={proc.stdout[:2000]}\n"
            f"stderr={proc.stderr[:2000]}"
        )
    return json.loads(proc.stdout)


def validate(payload: dict, expected_inputs: int) -> list[str]:
    summary = payload.get("summary", {})
    outer = summary.get("outerImage", {}).get("counts", {})
    embedded = summary.get("embeddedRaw", {}).get("counts", {})

    failures: list[str] = []
    if int(summary.get("inputCount", 0)) != expected_inputs:
        failures.append(
            f"inputCount={summary.get('inputCount')} expected {expected_inputs}"
        )
    if int(outer.get("containerOpenMatch", 0)) != expected_inputs:
        failures.append(
            f"containerOpenMatch={outer.get('containerOpenMatch', 0)} expected {expected_inputs}"
        )
    if int(outer.get("embeddedPresenceMatch", 0)) != expected_inputs:
        failures.append(
            f"embeddedPresenceMatch={outer.get('embeddedPresenceMatch', 0)} expected {expected_inputs}"
        )
    if int(outer.get("delta", 0)) != 0:
        failures.append(f"outer delta={outer.get('delta', 0)} expected 0")
    if int(embedded.get("delta", 0)) != 0:
        failures.append(f"embedded delta={embedded.get('delta', 0)} expected 0")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--icc", type=Path, default=default_icc())
    parser.add_argument("--compare-script", type=Path, default=default_compare_script())
    parser.add_argument("--v1-binary", type=Path, default=default_v1_binary())
    parser.add_argument("--v2-binary", type=Path, default=default_v2_binary())
    parser.add_argument("--heuristic-remap", type=Path, default=default_remap_tsv())
    parser.add_argument("--keep-dir", type=Path, help="Persist generated fixtures here")
    parser.add_argument("--pretty", action="store_true")
    args = parser.parse_args()

    if not args.icc.is_file():
        raise SystemExit(f"Missing ICC fixture: {args.icc}")
    if not args.compare_script.is_file():
        raise SystemExit(f"Missing compareImageParity.py: {args.compare_script}")
    if not args.v1_binary.is_file():
        raise SystemExit(f"Missing V1 binary: {args.v1_binary}")
    if not args.v2_binary.is_file():
        raise SystemExit(f"Missing V2 parity binary: {args.v2_binary}")
    if not args.heuristic_remap.is_file():
        raise SystemExit(f"Missing heuristic remap TSV: {args.heuristic_remap}")

    if args.keep_dir:
        image_dir = args.keep_dir.resolve()
        image_dir.mkdir(parents=True, exist_ok=True)
        generate_images(image_dir, args.icc)
        payload = run_compare(
            args.compare_script,
            image_dir,
            v1_binary=args.v1_binary,
            v2_binary=args.v2_binary,
            heuristic_remap=args.heuristic_remap,
        )
        failures = validate(payload, expected_inputs=2)
        if args.pretty:
            json.dump(payload, sys.stdout, indent=2)
            sys.stdout.write("\n")
        else:
            print(json.dumps({"generatedDir": str(image_dir), "summary": payload["summary"]}))
        if failures:
            print(json.dumps({"smokeFailures": failures}, indent=2), file=sys.stderr)
            return 1
        return 0

    with tempfile.TemporaryDirectory(prefix="icctest-image-smoke-") as tmpdir:
        image_dir = Path(tmpdir)
        generate_images(image_dir, args.icc)
        payload = run_compare(
            args.compare_script,
            image_dir,
            v1_binary=args.v1_binary,
            v2_binary=args.v2_binary,
            heuristic_remap=args.heuristic_remap,
        )
        failures = validate(payload, expected_inputs=2)
        out = {
            "generatedDir": str(image_dir),
            "summary": payload["summary"],
        }
        json.dump(out if not args.pretty else payload, sys.stdout, indent=2 if args.pretty else None)
        sys.stdout.write("\n")
        if failures:
            print(json.dumps({"smokeFailures": failures}, indent=2), file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
