#!/usr/bin/env python3
# Copyright (c) International Color Consortium.
# SPDX-License-Identifier: BSD-3-Clause

"""Generate deterministic HEIF parser-limit seeds below the 5 MiB lane cap."""

import argparse
import struct
from pathlib import Path


def box(kind: bytes, payload: bytes) -> bytes:
    return struct.pack(">I4s", len(payload) + 8, kind) + payload


def heif_carrier(iprp_payload: bytes) -> bytes:
    ftyp = box(b"ftyp", b"heic" + bytes(4) + b"mif1heic")
    meta = box(b"meta", bytes(4) + box(b"iprp", iprp_payload))
    return ftyp + meta


def property_limit_seed() -> bytes:
    properties = box(b"free", b"") * 32768
    return heif_carrier(box(b"ipco", properties))


def association_limit_seed() -> bytes:
    ipco = box(b"ipco", box(b"colr", b"prof"))
    entries = []
    associations = bytes([1]) * 255
    for item_id in range(1, 18):
        entries.append(struct.pack(">HB", item_id, 255) + associations)
    ipma = box(b"ipma", bytes(4) + struct.pack(">I", 17) + b"".join(entries))
    return heif_carrier(ipco + ipma)


def extracted_bytes_limit_seed() -> bytes:
    profile = bytes(4 * 1024 * 1024)
    ipco = box(b"ipco", box(b"colr", b"prof" + profile))
    associations = bytes([1]) * 65
    ipma = box(
        b"ipma",
        bytes(4) + struct.pack(">IHB", 1, 1, len(associations)) + associations,
    )
    return heif_carrier(ipco + ipma)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_dir", type=Path)
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)

    seeds = {
        "heif-property-count-limit.heic": property_limit_seed(),
        "heif-association-count-limit.heic": association_limit_seed(),
        "heif-extracted-bytes-limit.heic": extracted_bytes_limit_seed(),
    }
    for name, payload in seeds.items():
        (args.output_dir / name).write_bytes(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
