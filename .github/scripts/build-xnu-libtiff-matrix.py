#!/usr/bin/env python3
"""Build a libtiff-targeted TIFF matrix from committed XNU image outputs.

This script uses TIFF files already produced by xnuimagetools/xnuimagefuzzer as
pixel-source material, then derives storage/layout variants that exercise the
libtiff-facing paths used by iccDEV tooling:

- classic TIFF and BigTIFF
- little-endian and big-endian output
- strips, tiles, and multi-IFD pages
- none, LZW, PackBits, Deflate, and JPEG compression
- RGB/RGBA, grayscale, CMYK, 16-bit, and float32 samples

The generated matrix is deterministic and is intended for local iccTiffDump
tests and for seed-corpus curation.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import numpy as np
import tifffile


REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SOURCES = [
    REPO_ROOT / "xnuimagefuzzer" / "fuzzed-images",
    REPO_ROOT / "xnuimagetools" / "fuzzed-images",
]
DEFAULT_OUTDIR = REPO_ROOT / "temp" / "xnu-libtiff-matrix"
PROFILE_DIR = REPO_ROOT / "test-profiles"

PROFILE_MAP = {
    "srgb": "sRGB_v4_ICC_preference.icc",
    "gray": "GrayGSDF.icc",
    "cmyk": "CMYK-3DLUTs2.icc",
    "rec2020": "Rec2020rgbColorimetric.icc",
    "rec2100": "Rec2100HlgFull.icc",
}

TIFF_MAGIC = {
    b"II\x2a\x00",
    b"MM\x00\x2a",
    b"II\x2b\x00",
    b"MM\x00\x2b",
}


@dataclass(frozen=True)
class SourceSpec:
    label: str
    patterns: tuple[str, ...]
    profile_key: str
    description: str


SOURCE_SPECS = (
    SourceSpec(
        label="rgba_u8",
        patterns=("fuzzed_image_standard_rgb.tiff",),
        profile_key="srgb",
        description="XNU standard RGB with associated alpha",
    ),
    SourceSpec(
        label="gray_u8",
        patterns=("fuzzed_image_grayscale.tiff",),
        profile_key="gray",
        description="XNU grayscale with alpha sidecar",
    ),
    SourceSpec(
        label="cmyk_u8",
        patterns=("fuzzed_image_cmyk.tiff",),
        profile_key="cmyk",
        description="XNU CMYK separated image",
    ),
    SourceSpec(
        label="rgba_u16",
        patterns=("fuzzed_image_16bit_depth.tiff",),
        profile_key="rec2020",
        description="XNU 16-bit RGBA image",
    ),
    SourceSpec(
        label="rgba_f32",
        patterns=("fuzzed_image_32bit_float4.tiff", "fuzzed_image_hdr_float.tiff"),
        profile_key="rec2100",
        description="XNU float32 RGBA image",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a libtiff-targeted TIFF matrix from XNU fuzzed images"
    )
    parser.add_argument(
        "--source",
        action="append",
        default=[],
        help="Additional or replacement source root (repeatable)",
    )
    parser.add_argument(
        "--outdir",
        default=str(DEFAULT_OUTDIR),
        help="Output directory for base files, matrix files, and manifest",
    )
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Generate a smaller matrix for smoke tests",
    )
    return parser.parse_args()


def ensure_deps() -> None:
    for tool in ("tiffcp", "exiftool"):
        if shutil.which(tool) is None:
            raise SystemExit(f"error: required tool not found: {tool}")


def valid_tiff_magic(path: Path) -> bool:
    try:
        return path.read_bytes()[:4] in TIFF_MAGIC
    except OSError:
        return False


def all_tiff_files(source_roots: list[Path]) -> list[Path]:
    files: list[Path] = []
    for root in source_roots:
        if not root.is_dir():
            continue
        for path in root.rglob("*"):
            if path.suffix.lower() not in (".tif", ".tiff"):
                continue
            if valid_tiff_magic(path):
                files.append(path)
    return sorted(files, reverse=True)


def run(cmd: list[str]) -> None:
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise RuntimeError(f"{' '.join(cmd)} failed: {message}")


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def embed_icc(path: Path, profile_name: str) -> None:
    profile_path = PROFILE_DIR / profile_name
    if not profile_path.is_file():
        raise FileNotFoundError(f"ICC profile missing: {profile_path}")
    run(
        [
            "exiftool",
            "-overwrite_original",
            f"-ICC_Profile<={profile_path}",
            str(path),
        ]
    )


def load_array(path: Path) -> np.ndarray:
    with tifffile.TiffFile(path) as tif:
        return np.asarray(tif.asarray())


def write_base_tiff(path: Path, data: np.ndarray, photometric: str, profile_name: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tifffile.imwrite(
        path,
        data,
        photometric=photometric,
        byteorder="<",
        metadata=None,
        resolution=(72, 72),
    )
    embed_icc(path, profile_name)


def tiffcp_variant(src: Path, dst: Path, options: list[str]) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    run(["tiffcp", *options, str(src), str(dst)])


def inspect_tiff(path: Path) -> dict[str, object]:
    with tifffile.TiffFile(path) as tif:
        page = tif.pages[0]
        photometric = int(page.photometric)
        compression = int(page.compression)
        planar = getattr(page, "planarconfig", None)
        sampleformat = getattr(page, "sampleformat", None)
        return {
            "is_bigtiff": bool(tif.is_bigtiff),
            "compression": compression,
            "photometric": photometric,
            "shape": list(page.shape),
            "dtype": str(page.dtype),
            "pages": len(tif.pages),
            "is_tiled": bool(page.is_tiled),
            "planarconfig": None if planar is None else int(planar),
            "sampleformat": None if sampleformat is None else int(sampleformat),
            "has_icc": 34675 in page.tags,
        }


def find_sources(files: list[Path]) -> dict[str, Path]:
    found: dict[str, Path] = {}
    lowered = [(path, path.name.lower()) for path in files]
    for spec in SOURCE_SPECS:
        for path, name in lowered:
            if any(pattern in name for pattern in spec.patterns):
                found[spec.label] = path
                break
        if spec.label not in found:
            patterns = ", ".join(spec.patterns)
            raise FileNotFoundError(f"no TIFF source found for {spec.label}: {patterns}")
    return found


def build_base_files(base_dir: Path, source_paths: dict[str, Path]) -> tuple[dict[str, Path], dict[str, dict[str, object]]]:
    bases: dict[str, Path] = {}
    source_meta: dict[str, dict[str, object]] = {}

    rgba_u8 = load_array(source_paths["rgba_u8"])
    gray_u8 = load_array(source_paths["gray_u8"])
    cmyk_u8 = load_array(source_paths["cmyk_u8"])
    rgba_u16 = load_array(source_paths["rgba_u16"])
    rgba_f32 = load_array(source_paths["rgba_f32"])

    source_meta["rgba_u8"] = {
        "path": str(source_paths["rgba_u8"].relative_to(REPO_ROOT)),
        "shape": list(rgba_u8.shape),
        "dtype": str(rgba_u8.dtype),
    }
    source_meta["gray_u8"] = {
        "path": str(source_paths["gray_u8"].relative_to(REPO_ROOT)),
        "shape": list(gray_u8.shape),
        "dtype": str(gray_u8.dtype),
    }
    source_meta["cmyk_u8"] = {
        "path": str(source_paths["cmyk_u8"].relative_to(REPO_ROOT)),
        "shape": list(cmyk_u8.shape),
        "dtype": str(cmyk_u8.dtype),
    }
    source_meta["rgba_u16"] = {
        "path": str(source_paths["rgba_u16"].relative_to(REPO_ROOT)),
        "shape": list(rgba_u16.shape),
        "dtype": str(rgba_u16.dtype),
    }
    source_meta["rgba_f32"] = {
        "path": str(source_paths["rgba_f32"].relative_to(REPO_ROOT)),
        "shape": list(rgba_f32.shape),
        "dtype": str(rgba_f32.dtype),
    }

    rgb_u8 = rgba_u8[..., :3]
    gray_plane = gray_u8[..., 0] if gray_u8.ndim == 3 else gray_u8

    base_specs = [
        (
            "rgb_u8",
            rgb_u8,
            "rgb",
            PROFILE_MAP["srgb"],
            "base-rgb-u8-srgb.tiff",
        ),
        (
            "rgba_u8",
            rgba_u8,
            "rgb",
            PROFILE_MAP["srgb"],
            "base-rgba-u8-srgb.tiff",
        ),
        (
            "gray_u8",
            gray_plane,
            "minisblack",
            PROFILE_MAP["gray"],
            "base-gray-u8-graygsdf.tiff",
        ),
        (
            "cmyk_u8",
            cmyk_u8,
            "separated",
            PROFILE_MAP["cmyk"],
            "base-cmyk-u8-cmyk3dluts2.tiff",
        ),
        (
            "rgba_u16",
            rgba_u16,
            "rgb",
            PROFILE_MAP["rec2020"],
            "base-rgba-u16-rec2020.tiff",
        ),
        (
            "rgba_f32",
            rgba_f32,
            "rgb",
            PROFILE_MAP["rec2100"],
            "base-rgba-f32-rec2100.tiff",
        ),
    ]

    for label, data, photometric, profile_name, filename in base_specs:
        path = base_dir / filename
        write_base_tiff(path, data, photometric, profile_name)
        bases[label] = path

    multipage = base_dir / "base-rgb-u8-multipage-srgb.tiff"
    with tifffile.TiffWriter(multipage, byteorder="<") as writer:
        writer.write(rgb_u8, photometric="rgb", metadata=None, resolution=(72, 72))
        writer.write(np.flipud(rgb_u8), photometric="rgb", metadata=None, resolution=(72, 72))
    embed_icc(multipage, PROFILE_MAP["srgb"])
    bases["rgb_u8_multipage"] = multipage

    return bases, source_meta


def full_matrix() -> list[tuple[str, str, list[str], str]]:
    return [
        ("classic-rgb-none-le-srgb.tiff", "rgb_u8", [], "baseline classic TIFF"),
        ("classic-rgb-lzw-le-srgb.tiff", "rgb_u8", ["-c", "lzw:2"], "LZW compression"),
        ("classic-rgb-packbits-le-srgb.tiff", "rgb_u8", ["-c", "packbits"], "PackBits compression"),
        ("classic-rgb-deflate-le-srgb.tiff", "rgb_u8", ["-c", "zip:2"], "Deflate compression"),
        ("classic-rgb-jpeg-le-srgb.tiff", "rgb_u8", ["-c", "jpeg"], "JPEG-in-TIFF compression"),
        ("classic-rgb-strips2-le-srgb.tiff", "rgb_u8", ["-s", "-r", "2"], "multi-strip layout"),
        ("classic-rgb-tiled16-le-srgb.tiff", "rgb_u8", ["-t", "-w", "16", "-l", "16"], "tiled layout"),
        ("classic-rgb-none-be-srgb.tiff", "rgb_u8", ["-B"], "big-endian classic TIFF"),
        ("bigtiff-rgb-none-le-srgb.tiff", "rgb_u8", ["-8"], "BigTIFF baseline"),
        (
            "bigtiff-rgb-deflate-tiled-le-srgb.tiff",
            "rgb_u8",
            ["-8", "-c", "zip:2", "-t", "-w", "16", "-l", "16"],
            "BigTIFF with tiled Deflate storage",
        ),
        ("classic-rgba-none-le-srgb.tiff", "rgba_u8", [], "RGBA extra-sample baseline"),
        ("classic-rgba-deflate-le-srgb.tiff", "rgba_u8", ["-c", "zip:2"], "RGBA Deflate"),
        ("classic-gray-none-le-graygsdf.tiff", "gray_u8", [], "grayscale baseline"),
        ("classic-gray-deflate-le-graygsdf.tiff", "gray_u8", ["-c", "zip:2"], "grayscale Deflate"),
        ("bigtiff-gray-none-le-graygsdf.tiff", "gray_u8", ["-8"], "grayscale BigTIFF"),
        ("classic-cmyk-none-le-cmyk3dluts2.tiff", "cmyk_u8", [], "CMYK baseline"),
        ("classic-cmyk-planar-le-cmyk3dluts2.tiff", "cmyk_u8", ["-p", "separate"], "CMYK planar separate"),
        ("bigtiff-cmyk-none-le-cmyk3dluts2.tiff", "cmyk_u8", ["-8"], "CMYK BigTIFF"),
        ("classic-rgba-u16-none-le-rec2020.tiff", "rgba_u16", [], "16-bit RGBA baseline"),
        ("bigtiff-rgba-u16-none-le-rec2020.tiff", "rgba_u16", ["-8"], "16-bit RGBA BigTIFF"),
        (
            "classic-rgba-f32-deflate-le-rec2100.tiff",
            "rgba_f32",
            ["-c", "zip:3"],
            "float32 RGBA with floating-point predictor",
        ),
        (
            "bigtiff-rgba-f32-deflate-le-rec2100.tiff",
            "rgba_f32",
            ["-8", "-c", "zip:3"],
            "float32 RGBA BigTIFF with floating-point predictor",
        ),
        (
            "classic-rgb-multipage-le-srgb.tiff",
            "rgb_u8_multipage",
            [],
            "multi-IFD classic TIFF",
        ),
    ]


def quick_matrix() -> list[tuple[str, str, list[str], str]]:
    names = {
        "classic-rgb-none-le-srgb.tiff",
        "classic-rgb-lzw-le-srgb.tiff",
        "classic-rgb-packbits-le-srgb.tiff",
        "classic-rgb-tiled16-le-srgb.tiff",
        "bigtiff-rgb-none-le-srgb.tiff",
        "classic-gray-none-le-graygsdf.tiff",
        "bigtiff-gray-none-le-graygsdf.tiff",
        "classic-cmyk-planar-le-cmyk3dluts2.tiff",
        "bigtiff-rgba-u16-none-le-rec2020.tiff",
        "classic-rgba-f32-deflate-le-rec2100.tiff",
    }
    return [entry for entry in full_matrix() if entry[0] in names]


def main() -> int:
    args = parse_args()
    ensure_deps()

    source_roots = [Path(p).resolve() for p in (args.source or [str(p) for p in DEFAULT_SOURCES])]
    outdir = Path(args.outdir).resolve()
    base_dir = outdir / "base"
    matrix_dir = outdir / "matrix"

    if outdir.exists():
        shutil.rmtree(outdir)
    base_dir.mkdir(parents=True, exist_ok=True)
    matrix_dir.mkdir(parents=True, exist_ok=True)

    files = all_tiff_files(source_roots)
    if not files:
        raise SystemExit("error: no valid TIFF inputs found under the supplied source roots")

    source_paths = find_sources(files)
    bases, source_meta = build_base_files(base_dir, source_paths)

    manifest: dict[str, object] = {
        "sources": source_meta,
        "matrix": [],
    }

    cases = quick_matrix() if args.quick else full_matrix()
    for filename, base_label, options, description in cases:
        dst = matrix_dir / filename
        src = bases[base_label]
        if options:
            tiffcp_variant(src, dst, options)
        else:
            shutil.copy2(src, dst)

        info = inspect_tiff(dst)
        manifest["matrix"].append(
            {
                "name": filename,
                "base": base_label,
                "source": display_path(src),
                "description": description,
                "tiffcp_options": options,
                "info": info,
            }
        )

    manifest_path = outdir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    print(f"built {len(cases)} TIFF cases in {outdir}")
    print(f"manifest: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
