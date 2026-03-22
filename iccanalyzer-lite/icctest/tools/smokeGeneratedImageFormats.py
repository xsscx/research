#!/usr/bin/env python3
"""Generate PNG/JPEG fixtures with embedded ICC and run image parity smoke."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from PIL import Image


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


def generate_images(out_dir: Path, icc_path: Path) -> list[Path]:
    icc_bytes = icc_path.read_bytes()
    image = Image.new("RGB", (1, 1), (128, 160, 192))

    png_path = out_dir / "generated_with_icc.png"
    jpg_path = out_dir / "generated_with_icc.jpg"

    image.save(png_path, format="PNG", icc_profile=icc_bytes)
    image.save(jpg_path, format="JPEG", quality=95, icc_profile=icc_bytes)
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
