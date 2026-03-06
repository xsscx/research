#!/usr/bin/env python3
"""Synthesize minimal ICC profiles for unit testing iccanalyzer-lite.

Each profile is designed to trigger (or not trigger) specific heuristics
and validate specific exit-code paths. Profiles are written to tests/corpus/.

ICC profile structure (minimum):
  Header:      128 bytes
  Tag table:   4 + N*12 bytes (count + entries)
  Tag data:    variable

Reference: ICC.1:2022, clause 7
"""

import struct
import os
import sys

CORPUS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "corpus")


def write_icc_header(
    size,
    preferred_cmm=0,
    version=0x04400000,  # 4.4.0.0
    device_class=b"mntr",
    color_space=b"RGB ",
    pcs=b"XYZ ",
    rendering_intent=0,
    creator=b"test",
    profile_id=b"\x00" * 16,
):
    """Build a 128-byte ICC header."""
    hdr = bytearray(128)
    struct.pack_into(">I", hdr, 0, size)
    hdr[4:8] = preferred_cmm.to_bytes(4, "big") if isinstance(preferred_cmm, int) else preferred_cmm
    struct.pack_into(">I", hdr, 8, version)
    hdr[12:16] = device_class
    hdr[16:20] = color_space
    hdr[20:24] = pcs
    # Date/time: 2024-01-01 00:00:00
    struct.pack_into(">HHH HHH", hdr, 24, 2024, 1, 1, 0, 0, 0)
    hdr[36:40] = b"acsp"  # magic
    hdr[40:44] = b"APPL"  # platform
    struct.pack_into(">I", hdr, 44, 0)  # flags
    hdr[48:52] = b"\x00" * 4  # device manufacturer
    hdr[52:56] = b"\x00" * 4  # device model
    hdr[56:64] = b"\x00" * 8  # device attributes
    struct.pack_into(">I", hdr, 64, rendering_intent)
    # PCS illuminant (D50): X=0.9642, Y=1.0000, Z=0.8249
    struct.pack_into(">i", hdr, 68, int(0.9642 * 65536))
    struct.pack_into(">i", hdr, 72, int(1.0000 * 65536))
    struct.pack_into(">i", hdr, 76, int(0.8249 * 65536))
    hdr[80:84] = creator
    hdr[84:100] = profile_id
    return bytes(hdr)


def make_tag_entry(sig, offset, size):
    return struct.pack(">4sII", sig, offset, size)


def make_text_tag(text):
    """Create a textType tag (ICC v2)."""
    data = b"text" + b"\x00" * 4 + text.encode("ascii") + b"\x00"
    # Pad to 4-byte boundary
    while len(data) % 4:
        data += b"\x00"
    return data


def make_mluc_tag(text):
    """Create a multiLocalizedUnicodeType tag (ICC v4)."""
    utf16 = text.encode("utf-16-be")
    record_size = 12
    string_offset = 16 + record_size
    data = b"mluc" + b"\x00" * 4
    data += struct.pack(">II", 1, record_size)  # 1 record, 12 bytes each
    data += b"enUS"  # language + country
    data += struct.pack(">II", len(utf16), string_offset)
    data += utf16
    while len(data) % 4:
        data += b"\x00"
    return data


def make_xyz_tag(x, y, z):
    """Create an XYZType tag."""
    data = b"XYZ " + b"\x00" * 4
    data += struct.pack(">iii", int(x * 65536), int(y * 65536), int(z * 65536))
    return data


def make_curve_tag(values=None, gamma=None):
    """Create a curveType tag."""
    data = b"curv" + b"\x00" * 4
    if gamma is not None:
        data += struct.pack(">I", 1)
        data += struct.pack(">H", int(gamma * 256))
        data += b"\x00\x00"  # pad
    elif values:
        data += struct.pack(">I", len(values))
        for v in values:
            data += struct.pack(">H", min(65535, max(0, int(v * 65535))))
        if len(values) % 2:
            data += b"\x00\x00"
    else:
        data += struct.pack(">I", 0)  # identity
    return data


def build_profile(tags_data, **header_kwargs):
    """Assemble a complete ICC profile from tag data list.
    
    tags_data: list of (signature_bytes, tag_data_bytes)
    """
    tag_count = len(tags_data)
    tag_table_size = 4 + tag_count * 12
    header_size = 128

    # Calculate offsets
    data_offset = header_size + tag_table_size
    # Align to 4 bytes
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    offsets = []
    current = data_offset
    for sig, data in tags_data:
        offsets.append(current)
        current += len(data)
        if current % 4:
            current += 4 - (current % 4)

    total_size = current
    header = write_icc_header(total_size, **header_kwargs)

    # Tag table
    table = struct.pack(">I", tag_count)
    for i, (sig, data) in enumerate(tags_data):
        table += make_tag_entry(sig, offsets[i], len(data))

    # Assemble
    profile = bytearray(header)
    profile += table
    # Pad to data_offset
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, (sig, data) in enumerate(tags_data):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += data
        while len(profile) % 4:
            profile += b"\x00"

    # Fix size
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_valid_srgb():
    """Minimal valid v4 mntr/RGB profile with required tags."""
    tags = [
        (b"desc", make_mluc_tag("sRGB Test Profile")),
        (b"cprt", make_mluc_tag("Copyright 2024 Test")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0000, 1.0890)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags, version=0x04400000, device_class=b"mntr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_truncated():
    """Profile truncated mid-tag-table (triggers preflight/exit 2)."""
    valid = synth_valid_srgb()
    return valid[:80]  # Truncate before magic


def synth_bad_magic():
    """Profile with invalid 'acsp' magic (triggers H1)."""
    data = bytearray(synth_valid_srgb())
    data[36:40] = b"XXXX"
    return bytes(data)


def synth_zero_tags():
    """Profile with 0 tags (triggers preflight rejection)."""
    hdr = write_icc_header(132)
    return hdr + struct.pack(">I", 0)


def synth_oversized_tag():
    """Profile where tag size exceeds file size (triggers H3/H5)."""
    tags = [
        (b"desc", make_mluc_tag("Test")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
    ]
    data = bytearray(build_profile(tags))
    # Corrupt: set first tag size to 999999
    struct.pack_into(">I", data, 128 + 4 + 8, 999999)
    return bytes(data)


def synth_wrong_version_encoding():
    """v2 profile using mluc for cprt (triggers H116)."""
    tags = [
        (b"desc", make_mluc_tag("Test")),
        (b"cprt", make_mluc_tag("Copyright")),  # Wrong: v2 should use textType
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
    ]
    return build_profile(tags, version=0x02100000, device_class=b"mntr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_wrong_tag_type():
    """Profile with desc as XYZ type (triggers H117)."""
    tags = [
        (b"desc", make_xyz_tag(1.0, 1.0, 1.0)),  # Wrong type for desc
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
    ]
    return build_profile(tags, version=0x04400000)


def synth_private_tags():
    """Profile with unknown private tags (triggers H108, H127)."""
    private_data = b"priv" + b"\x00" * 4 + b"PRIVATE DATA PAYLOAD" + b"\x00\x00"
    tags = [
        (b"desc", make_mluc_tag("Private Tag Test")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"zzzz", private_data),  # Private/unknown tag
        (b"xxxx", private_data),  # Another private tag
    ]
    return build_profile(tags)


def synth_malware_private_tag():
    """Profile with private tag containing PE header signature (triggers H126)."""
    # MZ header signature
    pe_payload = b"priv" + b"\x00" * 4 + b"MZ" + b"\x90" * 58 + b"PE\x00\x00" + b"\x00" * 60
    tags = [
        (b"desc", make_mluc_tag("Malware Test")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"zzzz", pe_payload),
    ]
    return build_profile(tags)


def synth_v5_tags_on_v4():
    """v4 profile with v5-only tags (triggers H124)."""
    d2b_data = b"mpet" + b"\x00" * 4 + struct.pack(">HH I", 3, 3, 0)
    tags = [
        (b"desc", make_mluc_tag("Version Mismatch")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"D2B0", d2b_data),  # v5-only tag on v4 profile
    ]
    return build_profile(tags, version=0x04400000)


def synth_non_monotonic_curve():
    """Profile with non-monotonic TRC (triggers H114)."""
    # Non-monotonic: goes up, down, up
    values = [0.0, 0.2, 0.4, 0.6, 0.3, 0.5, 0.7, 0.8, 0.9, 1.0]
    tags = [
        (b"desc", make_mluc_tag("Non-Monotonic TRC")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(values=values)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ", pcs=b"XYZ ")


def synth_bad_wtpt():
    """Profile with wtpt far from D50 (triggers H112)."""
    tags = [
        (b"desc", make_mluc_tag("Bad White Point")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.5, 0.5, 0.5)),  # Not D50
    ]
    return build_profile(tags)


def synth_reserved_bytes_nonzero():
    """Profile with non-zero reserved header bytes (triggers H111)."""
    data = bytearray(synth_valid_srgb())
    # Reserved bytes at offset 44 (flags has reserved bits) and 100-127
    data[100:128] = b"\xFF" * 28
    return bytes(data)


def synth_empty_file():
    """Zero-byte file (triggers exit 2)."""
    return b""


def synth_just_header():
    """128-byte header only, no tag table (triggers preflight)."""
    return write_icc_header(128)


def synth_huge_tag_count():
    """Profile claiming 999999 tags (triggers preflight H4 tag count)."""
    hdr = write_icc_header(256)
    return hdr + struct.pack(">I", 999999) + b"\x00" * 124


def synth_xyz_out_of_range():
    """Profile with XYZ values outside [-5, 10] (triggers H122)."""
    tags = [
        (b"desc", make_mluc_tag("XYZ Out of Range")),
        (b"cprt", make_mluc_tag("Copyright")),
        (b"wtpt", make_xyz_tag(0.9505, 1.0, 1.089)),
        (b"rXYZ", make_xyz_tag(15.0, -8.0, 20.0)),  # Out of range
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
    ]
    return build_profile(tags, device_class=b"mntr", color_space=b"RGB ", pcs=b"XYZ ")


def main():
    os.makedirs(CORPUS_DIR, exist_ok=True)

    profiles = {
        "valid_srgb.icc": synth_valid_srgb(),
        "truncated.icc": synth_truncated(),
        "bad_magic.icc": synth_bad_magic(),
        "zero_tags.icc": synth_zero_tags(),
        "oversized_tag.icc": synth_oversized_tag(),
        "wrong_version_encoding.icc": synth_wrong_version_encoding(),
        "wrong_tag_type.icc": synth_wrong_tag_type(),
        "private_tags.icc": synth_private_tags(),
        "malware_private_tag.icc": synth_malware_private_tag(),
        "v5_tags_on_v4.icc": synth_v5_tags_on_v4(),
        "non_monotonic_curve.icc": synth_non_monotonic_curve(),
        "bad_wtpt.icc": synth_bad_wtpt(),
        "reserved_bytes_nonzero.icc": synth_reserved_bytes_nonzero(),
        "empty_file.icc": synth_empty_file(),
        "just_header.icc": synth_just_header(),
        "huge_tag_count.icc": synth_huge_tag_count(),
        "xyz_out_of_range.icc": synth_xyz_out_of_range(),
    }

    for name, data in profiles.items():
        path = os.path.join(CORPUS_DIR, name)
        with open(path, "wb") as f:
            f.write(data)
        print(f"  {name:40s} {len(data):6d} bytes")

    print(f"\n{len(profiles)} profiles written to {CORPUS_DIR}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
