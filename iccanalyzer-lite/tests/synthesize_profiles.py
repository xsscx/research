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


# --- New heuristic-targeted profiles ---


def synth_null_colorspace():
    """Profile with null colorSpace (triggers H3)."""
    data = bytearray(synth_valid_srgb())
    data[16:20] = b"\x00\x00\x00\x00"
    return bytes(data)


def synth_invalid_pcs():
    """Profile with invalid PCS signature (triggers H4)."""
    data = bytearray(synth_valid_srgb())
    data[20:24] = b"XXXX"
    return bytes(data)


def synth_unknown_platform():
    """Profile with unknown platform signature (triggers H5)."""
    data = bytearray(synth_valid_srgb())
    data[40:44] = b"ZZZZ"
    return bytes(data)


def synth_invalid_rendering_intent():
    """Profile with invalid rendering intent value (triggers H6)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">I", data, 64, 99)
    return bytes(data)


def synth_unknown_device_class():
    """Profile with unknown profile class (triggers H7)."""
    data = bytearray(synth_valid_srgb())
    data[12:16] = b"ZZZZ"
    return bytes(data)


def synth_negative_illuminant():
    """Profile with negative illuminant values (triggers H8)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">i", data, 68, int(-1.0 * 65536))
    return bytes(data)


def synth_invalid_date():
    """Profile with invalid date fields month=13, day=32 (triggers H15)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">HHH", data, 24, 2024, 13, 32)
    return bytes(data)


def synth_version_bcd_invalid():
    """Profile with non-BCD nibble in version byte (triggers H128)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">I", data, 8, 0x044A0000)  # nibble A is non-BCD
    return bytes(data)


def synth_wrong_d50_illuminant():
    """Profile with PCS illuminant not matching D50 (triggers H129)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">i", data, 68, int(0.5 * 65536))
    struct.pack_into(">i", data, 72, int(0.5 * 65536))
    struct.pack_into(">i", data, 76, int(0.5 * 65536))
    return bytes(data)


def synth_flags_reserved_bits():
    """Profile with reserved flag bits set (triggers H133)."""
    data = bytearray(synth_valid_srgb())
    struct.pack_into(">I", data, 44, 0xFFFFFFFC)
    return bytes(data)


def synth_duplicate_tags():
    """Profile with duplicate tag signatures (triggers H135)."""
    desc = make_mluc_tag("Duplicate Tags Test")
    cprt = make_mluc_tag("Copyright")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    # Build manually to allow duplicate sigs
    tag_count = 4
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    tag_data = [
        (b"desc", desc),
        (b"desc", desc),  # duplicate!
        (b"cprt", cprt),
        (b"wtpt", wtpt),
    ]
    offsets = []
    current = data_offset
    for sig, d in tag_data:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current)
    table = struct.pack(">I", tag_count)
    for i, (sig, d) in enumerate(tag_data):
        table += make_tag_entry(sig, offsets[i], len(d))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, (sig, d) in enumerate(tag_data):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_tag_misaligned():
    """Profile with tag offsets not 4-byte aligned (triggers H130/H40)."""
    desc = make_mluc_tag("Misaligned Tags")
    cprt = make_mluc_tag("Copyright")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    tag_count = 3
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    # Force misaligned offsets by adding 1 byte
    offset1 = data_offset + 1  # NOT 4-byte aligned
    offset2 = offset1 + len(desc) + 1
    offset3 = offset2 + len(cprt) + 1

    total_size = offset3 + len(wtpt) + 4

    hdr = write_icc_header(total_size)
    table = struct.pack(">I", tag_count)
    table += make_tag_entry(b"desc", offset1, len(desc))
    table += make_tag_entry(b"cprt", offset2, len(cprt))
    table += make_tag_entry(b"wtpt", offset3, len(wtpt))

    profile = bytearray(hdr) + table
    while len(profile) < total_size:
        profile += b"\x00"
    profile[offset1:offset1 + len(desc)] = desc
    profile[offset2:offset2 + len(cprt)] = cprt
    profile[offset3:offset3 + len(wtpt)] = wtpt
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_extra_trailing_bytes():
    """Profile with extra bytes appended past declared size (triggers H1)."""
    data = bytearray(synth_valid_srgb())
    data += b"\xDE\xAD" * 50  # 100 extra bytes
    return bytes(data)


def synth_null_tag_type():
    """Profile with tag having null type signature (triggers H20)."""
    desc = make_mluc_tag("Null Type Test")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)
    # Tag with null type sig (first 4 bytes = 0x00000000)
    null_cprt = b"\x00\x00\x00\x00" + b"\x00" * 4 + b"fake data here!!"
    while len(null_cprt) % 4:
        null_cprt += b"\x00"

    tags = [
        (b"desc", desc),
        (b"cprt", null_cprt),
        (b"wtpt", wtpt),
    ]
    return build_profile(tags)


def synth_nan_float_tag():
    """Profile with fl32 tag containing NaN/Inf values (triggers H49)."""
    desc = make_mluc_tag("NaN Float Test")
    cprt = make_mluc_tag("Copyright")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)
    # fl32 tag with NaN and Inf values
    fl32_data = b"fl32" + b"\x00" * 4
    fl32_data += struct.pack(">I", 0x7FC00000)  # quiet NaN
    fl32_data += struct.pack(">I", 0x7F800000)  # +Inf
    fl32_data += struct.pack(">f", 1.0)          # normal
    while len(fl32_data) % 4:
        fl32_data += b"\x00"

    tags = [
        (b"desc", desc),
        (b"cprt", cprt),
        (b"wtpt", wtpt),
        (b"fl32", fl32_data),
    ]
    return build_profile(tags)


def synth_odd_utf16_mluc():
    """Profile with mluc tag having odd-length UTF-16 string (triggers H55)."""
    data = bytearray(synth_valid_srgb())
    # Find cprt tag in the tag table and get its offset
    tag_count = struct.unpack_from(">I", data, 128)[0]
    for i in range(tag_count):
        entry_off = 132 + i * 12
        sig = data[entry_off:entry_off + 4]
        if sig == b"cprt":
            tag_offset = struct.unpack_from(">I", data, entry_off + 4)[0]
            # Verify it's mluc type
            if data[tag_offset:tag_offset + 4] == b"mluc":
                # strLen is at tag_offset + 20 (after type+reserved+numRec+recSz+lang)
                current_len = struct.unpack_from(">I", data, tag_offset + 20)[0]
                # Set to odd value
                struct.pack_into(">I", data, tag_offset + 20, current_len - 1)
            break
    return bytes(data)


def synth_suspicious_profile_id():
    """Profile with suspicious profile ID pattern (triggers H69)."""
    data = bytearray(synth_valid_srgb())
    data[84:100] = b"\xFF" * 16  # all 0xFF is suspicious
    return bytes(data)


def synth_tag_aliasing():
    """Profile where multiple tags share the same offset (tag aliasing)."""
    desc = make_mluc_tag("Tag Aliasing Test")
    cprt = make_mluc_tag("Copyright")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    tag_count = 3
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    offsets = []
    current = data_offset
    tag_data_list = [desc, cprt, wtpt]
    for d in tag_data_list:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current)
    table = struct.pack(">I", tag_count)
    # desc and cprt both point to same offset (aliasing)
    table += make_tag_entry(b"desc", offsets[0], len(desc))
    table += make_tag_entry(b"cprt", offsets[0], len(desc))  # same offset!
    table += make_tag_entry(b"wtpt", offsets[2], len(wtpt))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, d in enumerate(tag_data_list):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_named_color2_excessive_coords():
    """NamedColor2 tag with nDeviceCoords=20 (>16 ICC spec max).
    Triggers H64 (CWE-787 device coord count exceeds ICC spec max).
    Based on CFL-076 finding: timeout-0bec9575 had nCoords=20734320."""
    desc = make_mluc_tag("NamedColor2 Excessive Coords")
    cprt = make_mluc_tag("Test")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    # Build ncl2 tag with nDeviceCoords=20
    ncl2_sig = b"ncl2"
    n_device_coords = 20  # > 16
    n_colors = 2
    # ncl2 tag structure: type(4) + reserved(4) + vendorFlag(4) + nColors(4) +
    #   nDeviceCoords(4) + prefix(32) + suffix(32) +
    #   entries[nColors]: name(32) + PCS(6) + device(nDeviceCoords*2)
    entry_size = 32 + 6 + n_device_coords * 2
    ncl2_data = struct.pack(">4sI", b"ncl2", 0)  # type + reserved
    ncl2_data += struct.pack(">I", 0)  # vendor flag
    ncl2_data += struct.pack(">I", n_colors)
    ncl2_data += struct.pack(">I", n_device_coords)
    ncl2_data += b"\x00" * 32  # prefix
    ncl2_data += b"\x00" * 32  # suffix
    for i in range(n_colors):
        name = f"Color{i}".encode("ascii").ljust(32, b"\x00")
        ncl2_data += name
        ncl2_data += b"\x00" * 6  # PCS coords
        ncl2_data += b"\x00" * (n_device_coords * 2)  # device coords

    tag_count = 4
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    tag_data_list = [desc, cprt, wtpt, ncl2_data]
    offsets = []
    current = data_offset
    for d in tag_data_list:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current, color_space=b"RGB ", device_class=b"nmcl")
    table = struct.pack(">I", tag_count)
    table += make_tag_entry(b"desc", offsets[0], len(desc))
    table += make_tag_entry(b"cprt", offsets[1], len(cprt))
    table += make_tag_entry(b"wtpt", offsets[2], len(wtpt))
    table += make_tag_entry(b"ncl2", offsets[3], len(ncl2_data))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, d in enumerate(tag_data_list):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_high_dimensional_colorspace():
    """Profile with 8-channel color space (icSig8colorData).
    Triggers H137 (CWE-400 high-dimensional grid complexity).
    33^8 = 1.41T iterations in EvaluateProfile."""
    desc = make_mluc_tag("8-Channel High Dimensional")
    cprt = make_mluc_tag("Test")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    # icSig8colorData = '8CLR' = 0x38434C52
    tag_count = 3
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    tag_data_list = [desc, cprt, wtpt]
    offsets = []
    current = data_offset
    for d in tag_data_list:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current, color_space=b"8CLR", device_class=b"prtr")
    table = struct.pack(">I", tag_count)
    table += make_tag_entry(b"desc", offsets[0], len(desc))
    table += make_tag_entry(b"cprt", offsets[1], len(cprt))
    table += make_tag_entry(b"wtpt", offsets[2], len(wtpt))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, d in enumerate(tag_data_list):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def synth_response_curve_excessive_measurements():
    """ResponseCurveSet16 tag with nMeasurements=500000 per channel.
    Triggers H136 (CWE-400 unbounded measurement count)."""
    desc = make_mluc_tag("ResponseCurve Excessive Measurements")
    cprt = make_mluc_tag("Test")
    wtpt = make_xyz_tag(0.9505, 1.0, 1.089)

    # Build a minimal rcs2 (responseCurveSet16Type) tag
    # Structure: type(4) + reserved(4) + nChannels(2) + nMeasTypes(2) +
    #   offsets[nMeasTypes](4 each) + ResponseCurveStruct(s)
    n_channels = 3
    n_meas_types = 1
    rcs2_type = b"rcs2"
    rcs2_hdr = struct.pack(">4sI", rcs2_type, 0)  # type + reserved
    rcs2_hdr += struct.pack(">HH", n_channels, n_meas_types)
    # Offset to first curve struct (relative to start of tag)
    curve_struct_offset = 12 + n_meas_types * 4
    rcs2_hdr += struct.pack(">I", curve_struct_offset)
    # ResponseCurveStruct: measurementUnit(4) + nMeasurements[nChannels](4 each)
    meas_unit = 0x53746149  # 'StaI'
    excessive_count = 500000
    rcs2_curve = struct.pack(">I", meas_unit)
    for _ in range(n_channels):
        rcs2_curve += struct.pack(">I", excessive_count)
    # We don't need actual measurement data — the heuristic checks the count
    rcs2_data = rcs2_hdr + rcs2_curve

    tag_count = 4
    tag_table_size = 4 + tag_count * 12
    data_offset = 128 + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    # Use signature 'rcs2' in tag table — actual tag sig doesn't matter,
    # H136 scans by type signature inside the tag data
    tag_data_list = [desc, cprt, wtpt, rcs2_data]
    offsets = []
    current = data_offset
    for d in tag_data_list:
        offsets.append(current)
        current += len(d)
        if current % 4:
            current += 4 - (current % 4)

    hdr = write_icc_header(current)
    table = struct.pack(">I", tag_count)
    table += make_tag_entry(b"desc", offsets[0], len(desc))
    table += make_tag_entry(b"cprt", offsets[1], len(cprt))
    table += make_tag_entry(b"wtpt", offsets[2], len(wtpt))
    # Use 'rTRC' as the tag sig (arbitrary — H136 scans by type sig in data)
    table += make_tag_entry(b"rTRC", offsets[3], len(rcs2_data))

    profile = bytearray(hdr) + table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, d in enumerate(tag_data_list):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += d
        while len(profile) % 4:
            profile += b"\x00"
    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


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
        # New heuristic-targeted profiles
        "null_colorspace.icc": synth_null_colorspace(),
        "invalid_pcs.icc": synth_invalid_pcs(),
        "unknown_platform.icc": synth_unknown_platform(),
        "invalid_rendering_intent.icc": synth_invalid_rendering_intent(),
        "unknown_device_class.icc": synth_unknown_device_class(),
        "negative_illuminant.icc": synth_negative_illuminant(),
        "invalid_date.icc": synth_invalid_date(),
        "version_bcd_invalid.icc": synth_version_bcd_invalid(),
        "wrong_d50_illuminant.icc": synth_wrong_d50_illuminant(),
        "flags_reserved_bits.icc": synth_flags_reserved_bits(),
        "duplicate_tags.icc": synth_duplicate_tags(),
        "tag_misaligned.icc": synth_tag_misaligned(),
        "extra_trailing_bytes.icc": synth_extra_trailing_bytes(),
        "null_tag_type.icc": synth_null_tag_type(),
        "nan_float_tag.icc": synth_nan_float_tag(),
        "odd_utf16_mluc.icc": synth_odd_utf16_mluc(),
        "suspicious_profile_id.icc": synth_suspicious_profile_id(),
        "tag_aliasing.icc": synth_tag_aliasing(),
        # CWE-400 systemic patterns (CFL-074/075/076 findings)
        "named_color2_excessive_coords.icc": synth_named_color2_excessive_coords(),
        "high_dimensional_colorspace.icc": synth_high_dimensional_colorspace(),
        "response_curve_excessive_measurements.icc": synth_response_curve_excessive_measurements(),
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
