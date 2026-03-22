#!/usr/bin/env python3
"""Run unit tests plus raw and image parity verification in one shot."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def default_v1_binary() -> Path:
    return repo_root() / "iccanalyzer-lite"


def default_v2_binary() -> Path:
    return repo_root() / "icctest" / "build" / "tools" / "icctest-parity"


def default_unit_binary() -> Path:
    return repo_root() / "icctest" / "build" / "lib" / "tests" / "icctest_unit_tests"


def default_corpus_dir() -> Path:
    return repo_root() / "tests" / "corpus"


def default_icc_fixture() -> Path:
    return default_corpus_dir() / "valid_srgb.icc"


def default_compare_raw_script() -> Path:
    return Path(__file__).resolve().with_name("compareRawParity.py")


def default_compare_image_script() -> Path:
    return Path(__file__).resolve().with_name("compareImageParity.py")


def default_generated_smoke_script() -> Path:
    return Path(__file__).resolve().with_name("smokeGeneratedImageFormats.py")


def default_heuristic_remap() -> Path:
    return Path(__file__).resolve().with_name("heuristic-remap.tsv")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v1-binary", type=Path, default=default_v1_binary())
    parser.add_argument("--v2-binary", type=Path, default=default_v2_binary())
    parser.add_argument("--unit-binary", type=Path, default=default_unit_binary())
    parser.add_argument("--heuristic-remap", type=Path, default=default_heuristic_remap())
    parser.add_argument("--compare-raw-script", type=Path, default=default_compare_raw_script())
    parser.add_argument("--compare-image-script", type=Path, default=default_compare_image_script())
    parser.add_argument(
        "--generated-smoke-script",
        type=Path,
        default=default_generated_smoke_script(),
    )
    parser.add_argument("--raw-input", action="append", type=Path, default=[])
    parser.add_argument("--image-input", action="append", type=Path, default=[])
    parser.add_argument("--icc-fixture", type=Path, default=default_icc_fixture())
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--skip-unit", action="store_true")
    parser.add_argument("--skip-generated-smoke", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    return parser.parse_args()


def ensure_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise FileNotFoundError(f"Missing {label}: {path}")


def ensure_paths(args: argparse.Namespace) -> None:
    ensure_file(args.v1_binary, "V1 binary")
    ensure_file(args.v2_binary, "V2 parity binary")
    ensure_file(args.heuristic_remap, "heuristic remap TSV")
    ensure_file(args.compare_raw_script, "raw parity compare script")
    ensure_file(args.compare_image_script, "image parity compare script")
    ensure_file(args.generated_smoke_script, "generated image smoke script")
    ensure_file(args.icc_fixture, "ICC fixture")
    if not args.skip_unit:
        ensure_file(args.unit_binary, "unit test binary")


def selected_inputs(values: list[Path]) -> list[Path]:
    return values or [default_corpus_dir()]


def run_process(cmd: list[str], *, label: str) -> subprocess.CompletedProcess[str]:
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
    if proc.returncode != 0:
        raise RuntimeError(
            f"{label} failed\n"
            f"returncode={proc.returncode}\n"
            f"cmd={' '.join(cmd)}\n"
            f"stdout={proc.stdout[:4000]}\n"
            f"stderr={proc.stderr[:4000]}"
        )
    return proc


def run_json_process(cmd: list[str], *, label: str) -> dict:
    proc = run_process(cmd, label=label)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"{label} returned non-JSON stdout\n"
            f"cmd={' '.join(cmd)}\n"
            f"stdout={proc.stdout[:4000]}\n"
            f"stderr={proc.stderr[:4000]}"
        ) from exc


def summarize_unit_output(stdout: str) -> str:
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]
    return lines[-1] if lines else ""


def validate_raw(payload: dict) -> list[str]:
    counts = payload.get("summary", {}).get("counts", {})
    failures: list[str] = []
    if int(counts.get("delta", 0)) != 0:
        failures.append(f"raw delta={counts.get('delta', 0)} expected 0")
    return failures


def validate_image(payload: dict) -> list[str]:
    summary = payload.get("summary", {})
    outer = summary.get("outerImage", {}).get("counts", {})
    embedded = summary.get("embeddedRaw", {}).get("counts", {})
    failures: list[str] = []
    if int(outer.get("delta", 0)) != 0:
        failures.append(f"image outer delta={outer.get('delta', 0)} expected 0")
    if int(outer.get("containerOpenDelta", 0)) != 0:
        failures.append(
            f"image containerOpenDelta={outer.get('containerOpenDelta', 0)} expected 0"
        )
    if int(outer.get("embeddedPresenceDelta", 0)) != 0:
        failures.append(
            f"image embeddedPresenceDelta={outer.get('embeddedPresenceDelta', 0)} expected 0"
        )
    if int(embedded.get("delta", 0)) != 0:
        failures.append(f"image embedded delta={embedded.get('delta', 0)} expected 0")
    return failures


def write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    args = parse_args()
    ensure_paths(args)

    raw_inputs = [path.resolve() for path in selected_inputs(args.raw_input)]
    image_inputs = [path.resolve() for path in selected_inputs(args.image_input)]

    output_dir = args.output_dir.resolve() if args.output_dir else None
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    failures: list[str] = []
    unit_summary: dict | None = None

    if not args.skip_unit:
        unit_proc = run_process([str(args.unit_binary)], label="icctest_unit_tests")
        unit_summary = {
            "binary": str(args.unit_binary),
            "status": "pass",
            "summaryLine": summarize_unit_output(unit_proc.stdout),
        }
        if output_dir:
            (output_dir / "unit-tests.log").write_text(
                unit_proc.stdout + unit_proc.stderr,
                encoding="utf-8",
            )
    else:
        unit_summary = {
            "binary": str(args.unit_binary),
            "status": "skipped",
        }

    raw_cmd = [
        sys.executable,
        str(args.compare_raw_script),
        "--v1-binary",
        str(args.v1_binary),
        "--v2-binary",
        str(args.v2_binary),
        "--heuristic-remap",
        str(args.heuristic_remap),
    ]
    raw_cmd.extend(str(path) for path in raw_inputs)
    raw_payload = run_json_process(raw_cmd, label="compareRawParity.py")
    failures.extend(validate_raw(raw_payload))
    if output_dir:
        write_json(output_dir / "raw-parity.json", raw_payload)

    image_cmd = [
        sys.executable,
        str(args.compare_image_script),
        "--v1-binary",
        str(args.v1_binary),
        "--v2-binary",
        str(args.v2_binary),
        "--heuristic-remap",
        str(args.heuristic_remap),
    ]
    image_cmd.extend(str(path) for path in image_inputs)
    image_payload = run_json_process(image_cmd, label="compareImageParity.py")
    failures.extend(validate_image(image_payload))
    if output_dir:
        write_json(output_dir / "image-parity.json", image_payload)

    smoke_summary: dict | None = None
    if args.skip_generated_smoke:
        smoke_summary = {
            "status": "skipped",
        }
    else:
        smoke_cmd = [
            sys.executable,
            str(args.generated_smoke_script),
            "--icc",
            str(args.icc_fixture),
            "--compare-script",
            str(args.compare_image_script),
            "--v1-binary",
            str(args.v1_binary),
            "--v2-binary",
            str(args.v2_binary),
            "--heuristic-remap",
            str(args.heuristic_remap),
        ]
        smoke_payload = run_json_process(smoke_cmd, label="smokeGeneratedImageFormats.py")
        smoke_summary = {
            "status": "pass",
            "summary": smoke_payload.get("summary", {}),
        }
        if output_dir:
            write_json(output_dir / "generated-image-smoke.json", smoke_payload)

    payload = {
        "tool": "verify-parity",
        "paths": {
            "v1Binary": str(args.v1_binary),
            "v2Binary": str(args.v2_binary),
            "unitBinary": str(args.unit_binary),
            "heuristicRemap": str(args.heuristic_remap),
            "rawInputs": [str(path) for path in raw_inputs],
            "imageInputs": [str(path) for path in image_inputs],
            "iccFixture": str(args.icc_fixture),
            "outputDir": str(output_dir) if output_dir else "",
        },
        "summary": {
            "status": "pass" if not failures else "fail",
            "failureCount": len(failures),
            "failures": failures,
            "unitTests": unit_summary,
            "rawParity": raw_payload.get("summary", {}),
            "imageParity": image_payload.get("summary", {}),
            "generatedImageSmoke": smoke_summary,
        },
    }

    if output_dir:
        write_json(output_dir / "verify-parity-summary.json", payload)

    json.dump(payload, sys.stdout, indent=2 if args.pretty else None)
    sys.stdout.write("\n")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
