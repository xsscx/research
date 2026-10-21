#!/usr/bin/env python3
"""Generate deterministic JPEG APP2 ICC extraction fixtures."""

import argparse
from pathlib import Path


MAX_CHUNK_BYTES = 0xFFEF
ICC_SIGNATURE = b"ICC_PROFILE\x00"


def app2_marker(payload: bytes, sequence: int, total: int) -> bytes:
    data = ICC_SIGNATURE + bytes((sequence, total)) + payload
    segment_length = len(data) + 2
    return b"\xff\xe2" + segment_length.to_bytes(2, "big") + data


def make_container(profile: bytes, corrupt_second_sequence: bool) -> bytes:
    payloads = [
        profile[offset : offset + MAX_CHUNK_BYTES]
        for offset in range(0, len(profile), MAX_CHUNK_BYTES)
    ]
    if len(payloads) < 2 or len(payloads) > 255:
        raise ValueError("test profile must require between 2 and 255 APP2 chunks")

    markers = []
    total = len(payloads)
    for index, payload in enumerate(payloads, start=1):
        sequence = 0 if corrupt_second_sequence and index == 2 else index
        markers.append(app2_marker(payload, sequence, total))
    return b"\xff\xd8" + b"".join(markers) + b"\xff\xd9"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-icc", required=True, type=Path)
    parser.add_argument("--out-dir", required=True, type=Path)
    args = parser.parse_args()

    profile = args.source_icc.read_bytes()
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "valid-chunks.jpg").write_bytes(make_container(profile, False))
    (args.out_dir / "malformed-sequence.jpg").write_bytes(make_container(profile, True))
    (args.out_dir / "no-profile.jpg").write_bytes(b"\xff\xd8\xff\xd9")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
