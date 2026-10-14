#!/usr/bin/env python3
# Copyright (c) International Color Consortium.
# SPDX-License-Identifier: BSD-3-Clause

"""Install deterministic raw-TIFF and SSP3 seeds for the SpecSep fuzzer."""

import argparse
import struct
from pathlib import Path


MAX_SEPARATIONS = 16


def tiff_entry(tag: int, field_type: int, count: int, value: int) -> bytes:
    return struct.pack("<HHII", tag, field_type, count, value)


def grayscale_tiff(
    bits: int,
    photometric: int,
    sample_format: int,
    resolution_unit: int = 2,
    resolution_numerator: int = 72,
) -> bytes:
    width = 4
    height = 4
    if bits == 8:
        pixels = bytes(range(width * height))
    elif bits == 16:
        pixels = struct.pack("<16H", *range(width * height))
    elif bits == 32 and sample_format == 3:
        pixels = struct.pack("<16f", *(index / 16 for index in range(16)))
    else:
        raise ValueError("unsupported synthetic grayscale TIFF format")

    entry_count = 14
    ifd_offset = 8
    ifd_size = 2 + entry_count * 12 + 4
    x_resolution_offset = ifd_offset + ifd_size
    y_resolution_offset = x_resolution_offset + 8
    pixels_offset = y_resolution_offset + 8
    entries = [
        tiff_entry(256, 4, 1, width),
        tiff_entry(257, 4, 1, height),
        tiff_entry(258, 3, 1, bits),
        tiff_entry(259, 3, 1, 1),
        tiff_entry(262, 3, 1, photometric),
        tiff_entry(273, 4, 1, pixels_offset),
        tiff_entry(277, 3, 1, 1),
        tiff_entry(278, 4, 1, height),
        tiff_entry(279, 4, 1, len(pixels)),
        tiff_entry(282, 5, 1, x_resolution_offset),
        tiff_entry(283, 5, 1, y_resolution_offset),
        tiff_entry(284, 3, 1, 1),
        tiff_entry(296, 3, 1, resolution_unit),
        tiff_entry(339, 3, 1, sample_format),
    ]
    resolution = struct.pack("<II", resolution_numerator, 1)
    return (
        struct.pack("<2sHIH", b"II", 42, ifd_offset, entry_count)
        + b"".join(entries)
        + struct.pack("<I", 0)
        + resolution
        + resolution
        + pixels
    )


def bundle(flags: int, tiffs: list[bytes], profile: bytes = b"") -> bytes:
    if not 1 <= len(tiffs) <= MAX_SEPARATIONS:
        raise ValueError("SSP3 needs 1 to 16 TIFF inputs")
    if any(len(tiff) < 8 for tiff in tiffs):
        raise ValueError("SSP3 TIFF inputs must be at least 8 bytes")

    tile_width_selector = flags & 3
    tile_height_selector = (flags >> 2) & 3
    header = struct.pack(
        "<4sBBBBI",
        b"SSP3",
        flags,
        len(tiffs),
        tile_width_selector,
        tile_height_selector,
        len(profile),
    )
    lengths = b"".join(struct.pack("<I", len(tiff)) for tiff in tiffs)
    return header + lengths + b"".join(tiffs) + profile


def read_required(path: Path) -> bytes:
    if not path.is_file():
        raise FileNotFoundError(f"required SpecSep seed is missing: {path}")
    return path.read_bytes()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parents[2]
    spectral_dir = repo_root / "test-profiles" / "spectral"
    codec_dir = repo_root / "test-profiles" / "tiff-codecs"
    profile_path = repo_root / "test-profiles" / "sRGB_v4_ICC_preference.icc"

    separations = [
        read_required(spectral_dir / f"spec_{index:03d}.tif")
        for index in range(1, 9)
    ]
    rgb_profile = read_required(profile_path)
    tiled_gray = read_required(
        repo_root / "fuzz" / "graphics" / "spectral" / "valid"
        / "gray8_tiled_icc_le.tiff"
    )
    miniswhite_u8 = grayscale_tiff(8, 0, 1)
    miniswhite_u16 = grayscale_tiff(16, 0, 1)
    float_black = grayscale_tiff(32, 1, 3)
    float_white = grayscale_tiff(32, 0, 3)
    zero_res_cm = grayscale_tiff(8, 1, 1, 3, 0)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    seeds: dict[str, bytes] = {}

    raw_paths = [
        spectral_dir / "spec_001.tif",
        codec_dir / "seed-tiff-none-gray-8x8.tif",
        codec_dir / "seed-tiff-none-gray-16bps-16x16.tif",
        codec_dir / "seed-tiff-none-gray-32bps-16x16.tif",
        codec_dir / "seed-tiff-lzw-gray-32x32.tif",
        codec_dir / "seed-tiff-deflate-gray-32x32.tif",
        codec_dir / "seed-tiff-packbits-gray-32x32.tif",
        codec_dir / "seed-tiff-jpeg-gray-32x32.tif",
        codec_dir / "seed-bigtiff-rgb-32x32.tif",
    ]
    for path in raw_paths:
        seeds[f"raw-{path.name}"] = read_required(path)
    seeds["raw-synthetic-miniswhite-u8.tif"] = miniswhite_u8
    seeds["raw-synthetic-miniswhite-u16.tif"] = miniswhite_u16
    seeds["raw-synthetic-float-black.tif"] = float_black
    seeds["raw-synthetic-float-white-reject.tif"] = float_white
    seeds["raw-synthetic-zero-resolution-centimeter.tif"] = zero_res_cm
    seeds["raw-gray8-tiled.tif"] = tiled_gray

    for flags in range(16):
        seeds[f"ssp3-one-mode-{flags:02x}"] = bundle(flags, separations[:1])
        seeds[f"ssp3-rgb-mode-{flags:02x}"] = bundle(
            flags, separations[:3], rgb_profile
        )
        seeds[f"ssp3-eight-mode-{flags:02x}"] = bundle(flags, separations)
        seeds[f"ssp3-miniswhite-mode-{flags:02x}"] = bundle(
            flags, [miniswhite_u8]
        )
        seeds[f"ssp3-float-mode-{flags:02x}"] = bundle(flags, [float_black])
        seeds[f"ssp3-tiled-input-mode-{flags:02x}"] = bundle(flags, [tiled_gray])

    mismatch = [
        separations[0],
        read_required(codec_dir / "seed-tiff-none-gray-8x8.tif"),
    ]
    seeds["ssp3-format-mismatch"] = bundle(0, mismatch)

    legacy_payload = separations[0] + separations[0]
    seeds["legacy-two-channel"] = bytes([1, 0]) + legacy_payload

    for name, payload in seeds.items():
        (args.output_dir / name).write_bytes(payload)

    print(f"Installed {len(seeds)} SpecSep seeds in {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
