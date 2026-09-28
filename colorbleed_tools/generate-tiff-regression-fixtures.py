#!/usr/bin/env python3
"""Generate temporary TIFF/ICC fixtures for iccTiffDump_unsafe regression tests."""

import argparse
import pathlib
import struct


def icc_header(size):
    header = bytearray(128)
    struct.pack_into(">I", header, 0, size)
    header[8:12] = b"\x05\0\0\0"
    header[12:16] = b"mntr"
    header[16:20] = b"RGB "
    header[20:24] = b"XYZ "
    header[36:40] = b"acsp"
    return header


def nested_icc(depth):
    profile = icc_header(132) + struct.pack(">I", 0)
    for _ in range(depth):
        tag = b"ICCp" + b"\0\0\0\0" + profile
        size = 144 + len(tag)
        profile = (
            icc_header(size)
            + struct.pack(">I", 1)
            + b"ICC5"
            + struct.pack(">II", 144, len(tag))
            + tag
        )
    return profile


def align(data):
    if len(data) % 2:
        data += b"\0"
    return data


def build_tiff(profiles, descriptions=None):
    descriptions = descriptions or [None] * len(profiles)
    directory_counts = [12 + (1 if desc is not None else 0) for desc in descriptions]
    directory_sizes = [2 + count * 12 + 4 for count in directory_counts]
    directory_offsets = []
    offset = 8
    for size in directory_sizes:
        directory_offsets.append(offset)
        offset += size

    payload = bytearray()
    payload_base = offset
    directories = []
    for index, profile in enumerate(profiles):
        bits_offset = payload_base + len(payload)
        payload += struct.pack("<HHH", 8, 8, 8)
        payload = bytearray(align(bytes(payload)))

        pixel_offset = payload_base + len(payload)
        payload += b"\0\0\0"
        payload = bytearray(align(bytes(payload)))

        profile_offset = payload_base + len(payload)
        payload += profile
        payload = bytearray(align(bytes(payload)))

        entries = [
            (256, 4, 1, 1),
            (257, 4, 1, 1),
            (258, 3, 3, bits_offset),
            (259, 3, 1, 1),
            (262, 3, 1, 2),
            (273, 4, 1, pixel_offset),
            (277, 3, 1, 3),
            (278, 4, 1, 1),
            (279, 4, 1, 3),
            (284, 3, 1, 1),
            (296, 3, 1, 2),
            (34675, 7, len(profile), profile_offset),
        ]
        description = descriptions[index]
        if description is not None:
            description_offset = payload_base + len(payload)
            payload += description
            payload = bytearray(align(bytes(payload)))
            entries.append((270, 2, len(description), description_offset))
        directories.append(sorted(entries))

    output = bytearray(b"II" + struct.pack("<H", 42) + struct.pack("<I", 8))
    for index, entries in enumerate(directories):
        output += struct.pack("<H", len(entries))
        for tag, value_type, count, value in entries:
            output += struct.pack("<HHI", tag, value_type, count)
            if value_type == 3 and count == 1:
                output += struct.pack("<H", value) + b"\0\0"
            else:
                output += struct.pack("<I", value)
        next_offset = directory_offsets[index + 1] if index + 1 < len(directories) else 0
        output += struct.pack("<I", next_offset)
    output += payload
    return bytes(output)


def write(path, data):
    path.write_bytes(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-icc", required=True, type=pathlib.Path)
    parser.add_argument("--out-dir", required=True, type=pathlib.Path)
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)
    source = args.source_icc.read_bytes()
    malformed = b"not an ICC profile"
    noncompliant = bytearray(source)
    noncompliant[16:20] = b"\0\0\0\0"
    nested = nested_icc(512)
    truncated_chain = bytearray(build_tiff([source]))
    entry_count = struct.unpack_from("<H", truncated_chain, 8)[0]
    struct.pack_into("<I", truncated_chain, 8 + 2 + entry_count * 12, 0xFFFFFF00)

    fixtures = {
        "valid.icc": source,
        "malformed.icc": malformed,
        "noncompliant.icc": bytes(noncompliant),
        "nested-depth-512.icc": nested,
        "valid.tif": build_tiff([source]),
        "malformed.tif": build_tiff([malformed]),
        "noncompliant.tif": build_tiff([bytes(noncompliant)]),
        "nested-depth-512.tif": build_tiff([nested]),
        "multiple-icc.tif": build_tiff([source, source]),
        "truncated-chain.tif": bytes(truncated_chain),
        "escaped-description.tif": build_tiff(
            [source], [b"bad\n\x1b[31mX!!\0"]
        ),
    }
    for name, data in fixtures.items():
        write(args.out_dir / name, data)


if __name__ == "__main__":
    main()
