#!/usr/bin/env python3
"""Synthesize ICC profiles for conformance baseline testing.

Generates well-structured ICC profiles targeting specific CF-* conformance checks.
Both conforming (should PASS) and deliberately non-conforming (should trigger
specific CF findings) variants are created.

These are NOT fuzzing profiles (those go in test-profiles/ or cfl/corpus-*).
These are structured baseline profiles for validating the 329 conformance checks
in iccanalyzer-lite.

Categories:
  1. Tag Type Validation (CF-020..CF-039, CF-213, CF-247, CF-251, CF-253)
  2. Required Tags Per Class (CF-040..CF-053)
  3. LUT/Matrix Conformance (CF-060..CF-079, CF-163..CF-168)
  4. Header/Metadata (CF-001..CF-019, CF-107, CF-184..CF-246)
  5. Cross-Tag Consistency (CF-209, CF-256, CF-259, CF-260)
  6. Text/Unicode (CF-220..CF-234, CF-249-250, CF-275-276)
  7. Chad / Chromatic Adaptation (CF-068..CF-070)

Reference: ICC.1-2022-05, ICC.2-2023
"""

import struct
import os
import sys
import math

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# ═══════════════════════════════════════════════════════════════════════════════
# ICC Profile Infrastructure (shared with synthesize_dtob_btod.py)
# ═══════════════════════════════════════════════════════════════════════════════

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
    flags=0,
    device_manufacturer=b"\x00\x00\x00\x00",
    device_model=b"\x00\x00\x00\x00",
    device_attributes=b"\x00" * 8,
    platform=b"APPL",
):
    """Build a 128-byte ICC v4 header."""
    hdr = bytearray(128)
    struct.pack_into(">I", hdr, 0, size)
    if isinstance(preferred_cmm, bytes):
        hdr[4:8] = preferred_cmm
    else:
        struct.pack_into(">I", hdr, 4, preferred_cmm)
    struct.pack_into(">I", hdr, 8, version)
    hdr[12:16] = device_class
    hdr[16:20] = color_space
    hdr[20:24] = pcs
    # Date/time: 2024-01-01 00:00:00
    struct.pack_into(">HHH HHH", hdr, 24, 2024, 1, 1, 0, 0, 0)
    hdr[36:40] = b"acsp"
    hdr[40:44] = platform
    struct.pack_into(">I", hdr, 44, flags)
    hdr[48:52] = device_manufacturer
    hdr[52:56] = device_model
    hdr[56:64] = device_attributes
    struct.pack_into(">I", hdr, 64, rendering_intent)
    # PCS illuminant D50
    struct.pack_into(">i", hdr, 68, int(0.9642 * 65536))
    struct.pack_into(">i", hdr, 72, int(1.0000 * 65536))
    struct.pack_into(">i", hdr, 76, int(0.8249 * 65536))
    hdr[80:84] = creator
    hdr[84:100] = profile_id
    return bytes(hdr)


def make_tag_entry(sig, offset, size):
    return struct.pack(">4sII", sig, offset, size)


def pad4(data):
    """Pad data to 4-byte boundary."""
    while len(data) % 4:
        data += b"\x00"
    return data


def build_profile(tags_data, **header_kwargs):
    """Assemble a complete ICC profile from tag data list."""
    tag_count = len(tags_data)
    tag_table_size = 4 + tag_count * 12
    header_size = 128
    data_offset = header_size + tag_table_size
    if data_offset % 4:
        data_offset += 4 - (data_offset % 4)

    offsets = []
    current = data_offset
    for _sig, data in tags_data:
        offsets.append(current)
        current += len(data)
        if current % 4:
            current += 4 - (current % 4)

    total_size = current
    header = write_icc_header(total_size, **header_kwargs)

    table = struct.pack(">I", tag_count)
    for i, (sig, data) in enumerate(tags_data):
        table += make_tag_entry(sig, offsets[i], len(data))

    profile = bytearray(header)
    profile += table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, (_sig, data) in enumerate(tags_data):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += data
        while len(profile) % 4:
            profile += b"\x00"

    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def write_profile(filename, data):
    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  wrote {filename} ({len(data)} bytes)")


# ═══════════════════════════════════════════════════════════════════════════════
# Tag Type Builders
# ═══════════════════════════════════════════════════════════════════════════════

def make_text_tag(text):
    """Create a textType tag (ICC v2/v4)."""
    data = b"text" + b"\x00" * 4 + text.encode("ascii") + b"\x00"
    return pad4(data)


def make_mluc_tag(text):
    """Create a multiLocalizedUnicodeType tag."""
    utf16 = text.encode("utf-16-be")
    record_size = 12
    string_offset = 16 + record_size
    data = b"mluc" + b"\x00" * 4
    data += struct.pack(">II", 1, record_size)
    data += b"enUS"
    data += struct.pack(">II", len(utf16), string_offset)
    data += utf16
    return pad4(data)


def make_xyz_tag(x, y, z):
    """Create an XYZType tag with one triplet."""
    data = b"XYZ " + b"\x00" * 4
    data += struct.pack(">iii", int(x * 65536), int(y * 65536), int(z * 65536))
    return data


def make_xyz_array_tag(triplets):
    """Create an XYZType tag with multiple triplets."""
    data = b"XYZ " + b"\x00" * 4
    for x, y, z in triplets:
        data += struct.pack(">iii", int(x * 65536), int(y * 65536), int(z * 65536))
    return data


def make_curve_tag(values=None, gamma=None):
    """Create a curveType tag."""
    data = b"curv" + b"\x00" * 4
    if gamma is not None:
        data += struct.pack(">I", 1)
        data += struct.pack(">H", int(gamma * 256))
        data += b"\x00\x00"
    elif values:
        data += struct.pack(">I", len(values))
        for v in values:
            data += struct.pack(">H", min(65535, max(0, int(v * 65535))))
        if len(values) % 2:
            data += b"\x00\x00"
    else:
        data += struct.pack(">I", 0)
    return data


def make_para_tag(func_type=0, params=None):
    """Create a parametricCurveType tag.

    ICC.1-2022-05 §10.18:
      Type 0: Y = X^g                  (1 param: g)
      Type 1: Y = (aX+b)^g  if X>=-b/a (3 params: g, a, b)
      Type 2: Y = (aX+b)^g+c           (4 params: g, a, b, c)
      Type 3: Y = (aX+b)^g+c if X>=d   (5 params: g, a, b, c, d)
      Type 4: Y = (aX+b)^g+c+eX+f      (7 params: g, a, b, c, d, e, f)
    """
    data = b"para" + b"\x00" * 4
    data += struct.pack(">HH", func_type, 0)  # funcType + reserved
    if params is None:
        param_counts = {0: 1, 1: 3, 2: 4, 3: 5, 4: 7}
        n = param_counts.get(func_type, 1)
        params = [2.2] + [1.0] * (n - 1)
    for p in params:
        data += struct.pack(">i", int(p * 65536))  # s15Fixed16
    return pad4(data)


def make_sf32_tag(values):
    """Create an s15Fixed16ArrayType tag."""
    data = b"sf32" + b"\x00" * 4
    for v in values:
        data += struct.pack(">i", int(v * 65536))
    return data


def make_sig_tag(signature):
    """Create a signatureType tag."""
    data = b"sig " + b"\x00" * 4
    if isinstance(signature, bytes):
        data += signature
    else:
        data += struct.pack(">I", signature)
    return data


def make_viewing_conditions_tag(illum_x, illum_y, illum_z,
                                 surr_x, surr_y, surr_z,
                                 illum_type):
    """Create a viewingConditionsType tag.

    ICC.1-2022-05 §10.32:
      sig(4) + reserved(4) + illuminantXYZ(12) + surroundXYZ(12) + illuminantType(4) = 36 bytes
    """
    data = b"view" + b"\x00" * 4
    data += struct.pack(">iii",
                        int(illum_x * 65536),
                        int(illum_y * 65536),
                        int(illum_z * 65536))
    data += struct.pack(">iii",
                        int(surr_x * 65536),
                        int(surr_y * 65536),
                        int(surr_z * 65536))
    data += struct.pack(">I", illum_type)
    return data


def make_measurement_tag(observer=1, backing_x=0, backing_y=0, backing_z=0,
                          geometry=1, flare=0.0, illuminant_type=1):
    """Create a measurementType tag.

    ICC.1-2022-05 §10.14:
      sig(4) + reserved(4) + observer(4) + backing(12) + geometry(4) + flare(4) + illuminant(4) = 36 bytes
    """
    data = b"meas" + b"\x00" * 4
    data += struct.pack(">I", observer)
    data += struct.pack(">iii",
                        int(backing_x * 65536),
                        int(backing_y * 65536),
                        int(backing_z * 65536))
    data += struct.pack(">I", geometry)
    data += struct.pack(">I", int(flare * 65536))
    data += struct.pack(">I", illuminant_type)
    return data


def make_chromaticity_tag(n_channels, phosphor_type, xy_pairs):
    """Create a chromaticityType tag.

    ICC.1-2022-05 §10.2:
      sig(4) + reserved(4) + nChannels(2) + phosphorType(2) + xy_pairs(8*n)
    """
    data = b"chrm" + b"\x00" * 4
    data += struct.pack(">HH", n_channels, phosphor_type)
    for x, y in xy_pairs:
        data += struct.pack(">II",
                            int(x * 65536) & 0xFFFFFFFF,
                            int(y * 65536) & 0xFFFFFFFF)
    return data


def make_colorant_table_tag(colorants):
    """Create a colorantTableType tag.

    ICC.1-2022-05 §10.4:
      sig(4) + reserved(4) + count(4) + entries(38*n)
      Each entry: name(32) + PCS_XYZ(6)
    """
    data = b"clrt" + b"\x00" * 4
    data += struct.pack(">I", len(colorants))
    for name, pcs_vals in colorants:
        name_bytes = name.encode("ascii")[:31] + b"\x00" * (32 - min(len(name), 31))
        data += name_bytes
        for v in pcs_vals:
            data += struct.pack(">H", min(65535, max(0, int(v))))
        # Pad to 3 PCS values (6 bytes total)
        for _ in range(3 - len(pcs_vals)):
            data += struct.pack(">H", 0)
    return pad4(data)


def make_colorant_order_tag(order):
    """Create a colorantOrderType tag.

    ICC.1-2022-05 §10.3:
      sig(4) + reserved(4) + count(4) + order_bytes(n)
    """
    data = b"clro" + b"\x00" * 4
    data += struct.pack(">I", len(order))
    for idx in order:
        data += struct.pack("B", idx)
    return pad4(data)


def make_named_color2_tag(vendor_flag=0, n_device_coords=3,
                           prefix="", suffix="",
                           colors=None):
    """Create a namedColor2Type tag.

    ICC.1-2022-05 §10.17:
      sig(4) + reserved(4) + vendorFlag(4) + count(4) + nDeviceCoords(4) +
      prefix(32) + suffix(32) + entries(var)
    """
    if colors is None:
        colors = [("Red", [32768, 0, 0], [65535, 0, 0])]

    data = b"ncl2" + b"\x00" * 4
    data += struct.pack(">III", vendor_flag, len(colors), n_device_coords)
    # prefix (32 bytes)
    prefix_bytes = prefix.encode("ascii")[:31] + b"\x00"
    prefix_bytes += b"\x00" * (32 - len(prefix_bytes))
    data += prefix_bytes
    # suffix (32 bytes)
    suffix_bytes = suffix.encode("ascii")[:31] + b"\x00"
    suffix_bytes += b"\x00" * (32 - len(suffix_bytes))
    data += suffix_bytes
    # entries
    for name, pcs_coords, device_coords in colors:
        name_bytes = name.encode("ascii")[:31] + b"\x00"
        name_bytes += b"\x00" * (32 - len(name_bytes))
        data += name_bytes
        # PCS coordinates (3 x uint16)
        for v in pcs_coords[:3]:
            data += struct.pack(">H", min(65535, max(0, int(v))))
        for _ in range(3 - len(pcs_coords)):
            data += struct.pack(">H", 0)
        # Device coordinates (n_device_coords x uint16)
        for v in device_coords[:n_device_coords]:
            data += struct.pack(">H", min(65535, max(0, int(v))))
        for _ in range(n_device_coords - len(device_coords)):
            data += struct.pack(">H", 0)
    return pad4(data)


def make_datetime_tag(year=2024, month=1, day=1, hour=0, minute=0, second=0):
    """Create a dateTimeType tag.

    ICC.1-2022-05 §10.7:
      sig(4) + reserved(4) + dateTimeNumber(12)
    """
    data = b"dtim" + b"\x00" * 4
    data += struct.pack(">HHHHHH", year, month, day, hour, minute, second)
    return data


def make_profile_seq_desc_tag(profiles):
    """Create a profileSequenceDescType tag.

    ICC.1-2022-05 §10.21:
      sig(4) + reserved(4) + count(4) + entries(var)
    Each entry:
      manufacturer(4) + model(4) + attributes(8) + technology(4) +
      manufacturerDesc(mluc) + modelDesc(mluc)
    """
    data = b"pseq" + b"\x00" * 4
    data += struct.pack(">I", len(profiles))
    for mfr, model, attrs, tech, mfr_desc, model_desc in profiles:
        if isinstance(mfr, bytes):
            data += mfr
        else:
            data += struct.pack(">I", mfr)
        if isinstance(model, bytes):
            data += model
        else:
            data += struct.pack(">I", model)
        data += attrs if len(attrs) == 8 else attrs + b"\x00" * (8 - len(attrs))
        if isinstance(tech, bytes):
            data += tech
        else:
            data += struct.pack(">I", tech)
        # mluc for manufacturer desc
        mluc1 = make_mluc_tag(mfr_desc)
        data += mluc1
        # mluc for model desc
        mluc2 = make_mluc_tag(model_desc)
        data += mluc2
    return pad4(data)


def make_response_curve_set_tag(n_channels=3, n_types=1):
    """Create a minimal responseCurveSet16Type tag.

    ICC.1-2022-05 §10.22:
      sig(4) + reserved(4) + nChannels(2) + nMeasTypes(2) + offsets(4*n)
      Per measurement type: signature(4) + nMeasurements[n_ch](4*n) + XYZ[n_ch](12*n) + response_arrays
    """
    # Minimal: 1 measurement type, 2 measurements per channel
    n_meas = 2
    data = b"rcs2" + b"\x00" * 4
    data += struct.pack(">HH", n_channels, n_types)

    # Calculate offset to first measurement structure
    header_size = 12 + 4 * n_types
    data += struct.pack(">I", header_size)

    # Measurement structure
    data += b"StaA"  # statusA measurement type
    for _ in range(n_channels):
        data += struct.pack(">I", n_meas)
    # XYZ values for each channel (12 bytes each)
    for ch in range(n_channels):
        x = 0.4 + ch * 0.2
        data += struct.pack(">iii",
                            int(x * 65536),
                            int(0.3 * 65536),
                            int(0.2 * 65536))
    # Response values: icResponse16Number = deviceCode(2) + reserved(2) + measurementValue(s15Fixed16)(4) = 8 bytes
    for ch in range(n_channels):
        for m in range(n_meas):
            device_code = int(65535 * m / max(1, n_meas - 1))
            meas_val = m / max(1, n_meas - 1)
            data += struct.pack(">HHi", device_code, 0, int(meas_val * 65536))
    return pad4(data)


def make_lut8_tag(n_in, n_out, grid=2, clut_values=None, matrix_values=None):
    """Create a lut8Type tag."""
    if matrix_values is None:
        matrix_values = ((1.0, 0.0, 0.0), (0.0, 1.0, 0.0), (0.0, 0.0, 1.0))

    matrix = b""
    for r in range(3):
        for c in range(3):
            matrix += struct.pack(">i", int(matrix_values[r][c] * 65536))

    input_table = bytes(range(256)) * n_in
    clut_size = (grid ** n_in) * n_out
    if clut_values is None:
        clut = bytes([int(255 * i / max(1, clut_size - 1)) for i in range(clut_size)])
    else:
        clut = bytes(max(0, min(255, int(round(v)))) for v in clut_values)
    output_table = bytes(range(256)) * n_out

    lut8 = b"mft1" + b"\x00" * 4
    lut8 += struct.pack("BBBB", n_in, n_out, grid, 0)
    lut8 += matrix + input_table + clut + output_table
    return lut8


def make_lut16_tag(n_in, n_out, grid=2, input_entries=256, output_entries=256):
    """Create a lut16Type tag.

    ICC.1-2022-05 §10.10:
      sig(4) + reserved(4) + inputCh(1) + outputCh(1) + gridPoints(1) + reserved(1)
      + matrix(36) + inputTableEntries(2) + outputTableEntries(2)
      + inputTables(2*inputEntries*inputCh) + CLUT(2*grid^in*out) + outputTables(2*outputEntries*outCh)
    """
    matrix = b""
    for r in range(3):
        for c in range(3):
            val = 1.0 if r == c else 0.0
            matrix += struct.pack(">i", int(val * 65536))

    data = b"mft2" + b"\x00" * 4
    data += struct.pack("BBBB", n_in, n_out, grid, 0)
    data += matrix
    data += struct.pack(">HH", input_entries, output_entries)

    # Input tables
    for _ in range(n_in):
        for i in range(input_entries):
            data += struct.pack(">H", int(65535 * i / max(1, input_entries - 1)))

    # CLUT
    clut_size = (grid ** n_in) * n_out
    for i in range(clut_size):
        data += struct.pack(">H", int(65535 * i / max(1, clut_size - 1)))

    # Output tables
    for _ in range(n_out):
        for i in range(output_entries):
            data += struct.pack(">H", int(65535 * i / max(1, output_entries - 1)))

    return data


def make_mab_tag(n_in, n_out, has_b=True, has_m=False, has_matrix=False,
                  has_a=False, has_clut=False, grid=2):
    """Create a lutAToBType ('mAB ') tag.

    ICC.1-2022-05 §10.11:
      sig(4) + reserved(4) + inputCh(1) + outputCh(1) + reserved(2)
      + offsetB(4) + offsetMatrix(4) + offsetM(4) + offsetCLUT(4) + offsetA(4)
      + element data
    """
    header_size = 32  # sig+reserved+channels+offsets

    # Build elements
    elements = {}
    current_offset = header_size

    if has_b:
        b_curves = b""
        for _ in range(n_out):
            b_curves += make_curve_tag(gamma=2.2)
        elements["B"] = (current_offset, b_curves)
        current_offset += len(b_curves)
        current_offset = (current_offset + 3) & ~3

    if has_matrix:
        # 3x3 matrix + 3 offsets = 12 s15Fixed16 values (48 bytes)
        mat = b""
        for r in range(3):
            for c in range(3):
                val = 1.0 if r == c else 0.0
                mat += struct.pack(">i", int(val * 65536))
        for _ in range(3):
            mat += struct.pack(">i", 0)
        elements["matrix"] = (current_offset, mat)
        current_offset += len(mat)
        current_offset = (current_offset + 3) & ~3

    if has_m:
        m_curves = b""
        for _ in range(n_out):
            m_curves += make_curve_tag(gamma=1.0)
        elements["M"] = (current_offset, m_curves)
        current_offset += len(m_curves)
        current_offset = (current_offset + 3) & ~3

    if has_clut:
        clut = b""
        clut += struct.pack("BBBBBBBBBBBBBBBB",
                            grid, grid, grid, 0, 0, 0, 0, 0,
                            0, 0, 0, 0, 0, 0, 0, 0)
        clut += struct.pack(">B", 2)  # precision = 2 bytes
        clut += b"\x00" * 3
        clut_size = (grid ** n_in) * n_out
        for i in range(clut_size):
            clut += struct.pack(">H", int(65535 * i / max(1, clut_size - 1)))
        clut = pad4(clut)
        elements["CLUT"] = (current_offset, clut)
        current_offset += len(clut)
        current_offset = (current_offset + 3) & ~3

    if has_a:
        a_curves = b""
        for _ in range(n_in):
            a_curves += make_curve_tag(gamma=1.0)
        elements["A"] = (current_offset, a_curves)
        current_offset += len(a_curves)

    data = b"mAB " + b"\x00" * 4
    data += struct.pack("BB", n_in, n_out)
    data += b"\x00\x00"
    data += struct.pack(">I", elements.get("B", (0, b""))[0] if "B" in elements else 0)
    data += struct.pack(">I", elements.get("matrix", (0, b""))[0] if "matrix" in elements else 0)
    data += struct.pack(">I", elements.get("M", (0, b""))[0] if "M" in elements else 0)
    data += struct.pack(">I", elements.get("CLUT", (0, b""))[0] if "CLUT" in elements else 0)
    data += struct.pack(">I", elements.get("A", (0, b""))[0] if "A" in elements else 0)

    # Append element data in offset order
    for key in ["B", "matrix", "M", "CLUT", "A"]:
        if key in elements:
            data = pad4(data)
            while len(data) < elements[key][0]:
                data += b"\x00"
            data += elements[key][1]

    return pad4(data)


def make_mba_tag(n_in, n_out, has_b=True, has_m=False, has_matrix=False,
                  has_a=False, has_clut=False, grid=2):
    """Create a lutBToAType ('mBA ') tag — same structure as mAB but different sig."""
    mab = make_mab_tag(n_in, n_out, has_b=has_b, has_m=has_m,
                        has_matrix=has_matrix, has_a=has_a, has_clut=has_clut, grid=grid)
    return b"mBA " + mab[4:]


# ═══════════════════════════════════════════════════════════════════════════════
# Common Tag Sets
# ═══════════════════════════════════════════════════════════════════════════════

def base_tags(desc="Conformance Test"):
    """Minimal required tags for any v4 profile."""
    return [
        (b"desc", make_mluc_tag(desc)),
        (b"cprt", make_mluc_tag("Copyright 2026 ICC Conformance Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0000, 0.8249)),
    ]


def mntr_tags(desc="Display Conformance"):
    """Required tags for a valid display (mntr) profile: matrix/TRC."""
    tags = base_tags(desc)
    tags.extend([
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ])
    return tags


def scnr_tags(desc="Input Scanner Conformance"):
    """Required tags for a valid input (scnr) profile."""
    tags = base_tags(desc)
    tags.extend([
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ])
    return tags


def prtr_tags(desc="Output Printer Conformance"):
    """Required tags for a valid output (prtr) profile: needs AToB0."""
    tags = base_tags(desc)
    tags.append((b"A2B0", make_lut8_tag(3, 3, grid=2)))
    return tags


def link_tags(desc="DeviceLink Conformance"):
    """Required tags for a DeviceLink profile."""
    tags = [
        (b"desc", make_mluc_tag(desc)),
        (b"cprt", make_mluc_tag("Copyright 2026 ICC DeviceLink Test")),
        (b"A2B0", make_lut8_tag(3, 3, grid=2)),
        (b"psid", make_mluc_tag("Sequence ID")),
    ]
    return tags


def spac_tags(desc="ColorSpace Conformance"):
    """Required tags for a ColorSpace (spac) profile."""
    tags = base_tags(desc)
    tags.extend([
        (b"A2B0", make_lut8_tag(3, 3, grid=2)),
        (b"B2A0", make_lut8_tag(3, 3, grid=2)),
    ])
    return tags


def abst_tags(desc="Abstract Conformance"):
    """Required tags for an Abstract profile."""
    tags = base_tags(desc)
    tags.append((b"A2B0", make_lut8_tag(3, 3, grid=2)))
    return tags


def nmcl_tags(desc="NamedColor Conformance"):
    """Required tags for a NamedColor profile."""
    tags = base_tags(desc)
    tags.append((b"ncl2", make_named_color2_tag(
        n_device_coords=3,
        colors=[
            ("Red", [32768, 0, 0], [65535, 0, 0]),
            ("Green", [0, 32768, 0], [0, 65535, 0]),
            ("Blue", [0, 0, 32768], [0, 0, 65535]),
        ]
    )))
    return tags


# ═══════════════════════════════════════════════════════════════════════════════
# Category 1: Tag Type Validation
# ═══════════════════════════════════════════════════════════════════════════════

def synth_para_valid_type0():
    """parametricCurveType type 0: Y=X^g — valid (CF-023, CF-024)."""
    tags = mntr_tags("para type0 valid")
    tags[6] = (b"rTRC", make_para_tag(func_type=0, params=[2.2]))
    tags[7] = (b"gTRC", make_para_tag(func_type=0, params=[2.2]))
    tags[8] = (b"bTRC", make_para_tag(func_type=0, params=[2.2]))
    return build_profile(tags)


def synth_para_valid_type3():
    """parametricCurveType type 3: 5 params — valid (CF-023, CF-024)."""
    # sRGB-like: g=2.4, a=1/1.055, b=0.055/1.055, c=1/12.92, d=0.04045
    tags = mntr_tags("para type3 valid")
    params = [2.4, 1.0/1.055, 0.055/1.055, 1.0/12.92, 0.04045]
    tags[6] = (b"rTRC", make_para_tag(func_type=3, params=params))
    tags[7] = (b"gTRC", make_para_tag(func_type=3, params=params))
    tags[8] = (b"bTRC", make_para_tag(func_type=3, params=params))
    return build_profile(tags)


def synth_para_valid_type4():
    """parametricCurveType type 4: 7 params — valid."""
    tags = mntr_tags("para type4 valid")
    params = [2.4, 1.0/1.055, 0.055/1.055, 1.0/12.92, 0.04045, 0.0, 0.0]
    tags[6] = (b"rTRC", make_para_tag(func_type=4, params=params))
    tags[7] = (b"gTRC", make_para_tag(func_type=4, params=params))
    tags[8] = (b"bTRC", make_para_tag(func_type=4, params=params))
    return build_profile(tags)


def synth_para_bad_type():
    """parametricCurveType invalid function type 5 — should trigger CF-023."""
    tags = mntr_tags("para bad functype")
    tags[6] = (b"rTRC", make_para_tag(func_type=5, params=[2.2]))
    return build_profile(tags)


def synth_chromaticity_valid():
    """chromaticityType valid 3-channel (CF-025, CF-251, CF-253)."""
    tags = mntr_tags("chromaticity valid")
    # ITU-R BT.709 primaries
    tags.append((b"chrm", make_chromaticity_tag(3, 1, [
        (0.640, 0.330),
        (0.300, 0.600),
        (0.150, 0.060),
    ])))
    return build_profile(tags)


def synth_chromaticity_bad_count():
    """chromaticityType with wrong phosphor count — should trigger CF-025."""
    tags = mntr_tags("chromaticity bad count")
    # RGB profile but chromaticity has 4 channels
    tags.append((b"chrm", make_chromaticity_tag(4, 1, [
        (0.640, 0.330), (0.300, 0.600), (0.150, 0.060), (0.5, 0.5),
    ])))
    return build_profile(tags)


def synth_colorant_table_valid():
    """colorantTableType valid (CF-026)."""
    tags = mntr_tags("colorantTable valid")
    tags.append((b"clrt", make_colorant_table_tag([
        ("Red", [32768, 16384, 16384]),
        ("Green", [16384, 32768, 16384]),
        ("Blue", [16384, 16384, 32768]),
    ])))
    return build_profile(tags)


def synth_colorant_order_valid():
    """colorantOrderType with matching count (CF-027)."""
    tags = mntr_tags("colorantOrder valid")
    tags.append((b"clrt", make_colorant_table_tag([
        ("Red", [32768, 16384, 16384]),
        ("Green", [16384, 32768, 16384]),
        ("Blue", [16384, 16384, 32768]),
    ])))
    tags.append((b"clro", make_colorant_order_tag([0, 1, 2])))
    return build_profile(tags)


def synth_colorant_order_mismatch():
    """colorantOrderType count doesn't match colorantTable — CF-027."""
    tags = mntr_tags("colorantOrder mismatch")
    tags.append((b"clrt", make_colorant_table_tag([
        ("Red", [32768, 16384, 16384]),
        ("Green", [16384, 32768, 16384]),
        ("Blue", [16384, 16384, 32768]),
    ])))
    tags.append((b"clro", make_colorant_order_tag([0, 1])))  # 2 vs 3
    return build_profile(tags)


def synth_named_color2_valid():
    """namedColor2Type valid (CF-028)."""
    tags = base_tags("namedColor2 valid")
    tags.append((b"ncl2", make_named_color2_tag(
        n_device_coords=3,
        prefix="PANTONE ",
        suffix=" C",
        colors=[
            ("Red", [32768, 0, 0], [65535, 0, 0]),
            ("Green", [0, 32768, 0], [0, 65535, 0]),
            ("Blue", [0, 0, 32768], [0, 0, 65535]),
        ]
    )))
    return build_profile(tags, device_class=b"nmcl")


def synth_datetime_valid():
    """dateTimeType valid ranges (CF-029)."""
    tags = mntr_tags("dateTime valid")
    tags.append((b"calt", make_datetime_tag(2024, 6, 15, 12, 30, 0)))
    return build_profile(tags)


def synth_datetime_bad_month():
    """dateTimeType month=13 — should trigger CF-029."""
    tags = mntr_tags("dateTime bad month")
    tags.append((b"calt", make_datetime_tag(2024, 13, 1, 0, 0, 0)))
    return build_profile(tags)


def synth_datetime_bad_day():
    """dateTimeType day=32 — should trigger CF-029."""
    tags = mntr_tags("dateTime bad day")
    tags.append((b"calt", make_datetime_tag(2024, 1, 32, 0, 0, 0)))
    return build_profile(tags)


def synth_viewing_cond_valid():
    """viewingConditionsType valid (CF-213, CF-247)."""
    tags = mntr_tags("viewingCond valid")
    # D50 illuminant, 64 cd/m², dark surround, illuminant type D50=1
    tags.append((b"view", make_viewing_conditions_tag(
        19.572, 20.482, 16.648,  # D50 * 20.482
        3.0, 3.1, 2.5,
        1  # D50
    )))
    return build_profile(tags)


def synth_viewing_cond_bad_illum_y():
    """viewingConditionsType illuminant Y=0 — CF-213 fail."""
    tags = mntr_tags("viewingCond bad illumY")
    tags.append((b"view", make_viewing_conditions_tag(
        19.572, 0.0, 16.648,  # Y=0 is invalid
        3.0, 3.1, 2.5,
        1
    )))
    return build_profile(tags)


def synth_viewing_cond_bad_type():
    """viewingConditionsType illuminant type=99 — CF-247 fail."""
    tags = mntr_tags("viewingCond bad illumType")
    tags.append((b"view", make_viewing_conditions_tag(
        19.572, 20.482, 16.648,
        3.0, 3.1, 2.5,
        99  # Invalid type
    )))
    return build_profile(tags)


def synth_measurement_valid():
    """measurementType valid (CF-033, CF-034)."""
    tags = mntr_tags("measurement valid")
    tags.append((b"meas", make_measurement_tag(
        observer=1,  # CIE 1931
        geometry=1,  # 0/45 or 45/0
        flare=0.01,
        illuminant_type=1  # D50
    )))
    return build_profile(tags)


def synth_measurement_bad_observer():
    """measurementType observer=99 — CF-033 fail."""
    tags = mntr_tags("measurement bad observer")
    tags.append((b"meas", make_measurement_tag(observer=99)))
    return build_profile(tags)


def synth_measurement_bad_geometry():
    """measurementType geometry=99 — CF-034 fail."""
    tags = mntr_tags("measurement bad geometry")
    tags.append((b"meas", make_measurement_tag(observer=1, geometry=99)))
    return build_profile(tags)


def synth_profile_seq_desc_valid():
    """profileSequenceDescType valid (CF-036)."""
    tags = mntr_tags("profileSeqDesc valid")
    tags.append((b"pseq", make_profile_seq_desc_tag([
        (b"APPL", b"iMac", b"\x00" * 8, b"CRT ", "Apple Inc", "iMac Display"),
    ])))
    return build_profile(tags)


def synth_response_curve_valid():
    """responseCurveSet16Type valid (CF-035)."""
    tags = mntr_tags("responseCurve valid")
    tags.append((b"rcs2", make_response_curve_set_tag(n_channels=3, n_types=1)))
    return build_profile(tags)


def synth_sig_tag_valid():
    """signatureType technology tag valid."""
    tags = mntr_tags("sigTag valid")
    tags.append((b"tech", make_sig_tag(b"CRT ")))
    return build_profile(tags)


# ═══════════════════════════════════════════════════════════════════════════════
# Category 2: Required Tags Per Class (CF-040..CF-053)
# ═══════════════════════════════════════════════════════════════════════════════

def synth_mntr_complete():
    """Complete mntr profile — CF-042 pass."""
    return build_profile(mntr_tags("mntr complete"))


def synth_mntr_missing_rTRC():
    """mntr missing rTRC — CF-042 fail."""
    tags = mntr_tags("mntr missing rTRC")
    tags = [t for t in tags if t[0] != b"rTRC"]
    return build_profile(tags)


def synth_scnr_complete():
    """Complete scnr profile — CF-041 pass."""
    return build_profile(scnr_tags("scnr complete"), device_class=b"scnr")


def synth_scnr_missing_wtpt():
    """scnr missing wtpt — CF-040 fail."""
    tags = scnr_tags("scnr missing wtpt")
    tags = [t for t in tags if t[0] != b"wtpt"]
    return build_profile(tags, device_class=b"scnr")


def synth_prtr_complete():
    """Complete prtr profile — CF-043 pass."""
    return build_profile(prtr_tags("prtr complete"), device_class=b"prtr",
                         color_space=b"CMYK", pcs=b"Lab ")


def synth_prtr_missing_atob():
    """prtr missing AToB0 — CF-043 fail."""
    tags = base_tags("prtr missing AToB0")
    return build_profile(tags, device_class=b"prtr",
                         color_space=b"CMYK", pcs=b"Lab ")


def synth_link_complete():
    """Complete link profile — CF-044 pass."""
    return build_profile(link_tags("link complete"), device_class=b"link",
                         color_space=b"RGB ", pcs=b"RGB ")


def synth_link_missing_atob():
    """link missing AToB0 — CF-044 fail."""
    tags = [
        (b"desc", make_mluc_tag("link missing AToB0")),
        (b"cprt", make_mluc_tag("Copyright 2026")),
    ]
    return build_profile(tags, device_class=b"link",
                         color_space=b"RGB ", pcs=b"RGB ")


def synth_spac_complete():
    """Complete spac profile — CF-045 pass."""
    return build_profile(spac_tags("spac complete"), device_class=b"spac")


def synth_spac_missing_b2a():
    """spac missing BToA0 — CF-045 fail."""
    tags = base_tags("spac missing BToA0")
    tags.append((b"A2B0", make_lut8_tag(3, 3, grid=2)))
    return build_profile(tags, device_class=b"spac")


def synth_abst_complete():
    """Complete abst profile — CF-046 pass."""
    return build_profile(abst_tags("abst complete"), device_class=b"abst",
                         pcs=b"Lab ")


def synth_abst_missing_atob():
    """abst missing AToB0 — CF-046 fail."""
    tags = base_tags("abst missing AToB0")
    return build_profile(tags, device_class=b"abst", pcs=b"Lab ")


def synth_nmcl_complete():
    """Complete nmcl profile — CF-047 pass."""
    return build_profile(nmcl_tags("nmcl complete"), device_class=b"nmcl")


def synth_nmcl_missing_ncl2():
    """nmcl missing namedColor2 — CF-047 fail."""
    tags = base_tags("nmcl missing ncl2")
    return build_profile(tags, device_class=b"nmcl")


# ═══════════════════════════════════════════════════════════════════════════════
# Category 3: LUT/Matrix Conformance (CF-060..CF-079, CF-163..CF-168)
# ═══════════════════════════════════════════════════════════════════════════════

def synth_lut16_valid():
    """lut16Type valid structure (CF-064)."""
    tags = prtr_tags("lut16 valid")
    tags[-1] = (b"A2B0", make_lut16_tag(3, 3, grid=3,
                                         input_entries=256, output_entries=256))
    return build_profile(tags, device_class=b"prtr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_mab_b_only():
    """lutAToBType with only B curves (CF-065)."""
    tags = base_tags("mAB B-only")
    tags.append((b"A2B0", make_mab_tag(3, 3, has_b=True)))
    return build_profile(tags, device_class=b"prtr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_mab_full():
    """lutAToBType with all elements: A + CLUT + M + matrix + B (CF-065)."""
    tags = base_tags("mAB full")
    tags.append((b"A2B0", make_mab_tag(3, 3, has_b=True, has_m=True,
                                        has_matrix=True, has_a=True,
                                        has_clut=True, grid=3)))
    return build_profile(tags, device_class=b"prtr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_mba_full():
    """lutBToAType with all elements (CF-066)."""
    tags = base_tags("mBA full")
    tags.append((b"B2A0", make_mba_tag(3, 3, has_b=True, has_m=True,
                                        has_matrix=True, has_a=True,
                                        has_clut=True, grid=3)))
    return build_profile(tags, device_class=b"prtr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_lut_atob_btoa_pair():
    """Matching AToB0/BToA0 pair (CF-060, CF-061)."""
    tags = base_tags("AToB+BToA pair")
    tags.append((b"A2B0", make_lut8_tag(3, 3, grid=3)))
    tags.append((b"B2A0", make_lut8_tag(3, 3, grid=3)))
    return build_profile(tags, device_class=b"prtr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_lut_nonxyz_matrix():
    """lut8 with non-identity matrix when PCS is Lab — CF-067 warn."""
    tags = base_tags("lut nonXYZ matrix")
    non_identity = ((0.5, 0.3, 0.2), (0.1, 0.8, 0.1), (0.2, 0.1, 0.7))
    tags.append((b"A2B0", make_lut8_tag(3, 3, grid=2, matrix_values=non_identity)))
    return build_profile(tags, device_class=b"prtr",
                         color_space=b"RGB ", pcs=b"Lab ")


def synth_chad_valid():
    """chromatic adaptation (chad) valid 3x3 matrix — CF-068, CF-070."""
    tags = mntr_tags("chad valid")
    # Bradford matrix D65→D50
    chad_values = [
        1.0479, 0.0229, -0.0502,
        0.0296, 0.9904, -0.0171,
        -0.0092, 0.0151, 0.7519
    ]
    tags.append((b"chad", make_sf32_tag(chad_values)))
    return build_profile(tags)


def synth_chad_singular():
    """chad with singular (det=0) matrix — CF-068 fail."""
    tags = mntr_tags("chad singular")
    singular = [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0]
    tags.append((b"chad", make_sf32_tag(singular)))
    return build_profile(tags)


def synth_chad_wrong_count():
    """chad with 6 values instead of 9 — CF-070 fail."""
    tags = mntr_tags("chad wrong count")
    tags.append((b"chad", make_sf32_tag([1.0, 0.0, 0.0, 0.0, 1.0, 0.0])))
    return build_profile(tags)


def synth_lut_channel_mismatch():
    """LUT input channels != color space channels — CF-060 fail."""
    tags = base_tags("LUT channel mismatch")
    # RGB profile but LUT has 4 input channels
    tags.append((b"A2B0", make_lut8_tag(4, 3, grid=2)))
    return build_profile(tags, device_class=b"prtr",
                         color_space=b"RGB ", pcs=b"XYZ ")


# ═══════════════════════════════════════════════════════════════════════════════
# Category 4: Header/Metadata Extended
# ═══════════════════════════════════════════════════════════════════════════════

def synth_header_bad_version():
    """Version BCD with invalid nibble — CF-006 fail."""
    return build_profile(mntr_tags("bad version BCD"),
                         version=0x040A0000)  # 4.A.0 invalid BCD


def synth_header_bad_class():
    """Unregistered device class — CF-012 fail."""
    return build_profile(base_tags("bad device class"),
                         device_class=b"ZZZZ")


def synth_header_bad_colorspace():
    """Unregistered colour space — CF-013 fail."""
    return build_profile(mntr_tags("bad colorspace"),
                         color_space=b"ZZZZ")


def synth_header_bad_pcs():
    """Invalid PCS for non-DeviceLink — CF-014 fail."""
    return build_profile(mntr_tags("bad PCS"),
                         pcs=b"CMYK")


def synth_header_reserved_nonzero():
    """Reserved bytes 100-127 non-zero — CF-015 fail."""
    data = build_profile(mntr_tags("reserved nonzero"))
    data = bytearray(data)
    data[100] = 0xFF
    data[110] = 0xAB
    return bytes(data)


def synth_header_bad_intent():
    """Rendering intent=4 — CF-005 upper bits."""
    return build_profile(mntr_tags("bad intent"),
                         rendering_intent=4)


def synth_header_bad_d50():
    """PCS illuminant not D50 — CF-008 fail."""
    data = build_profile(mntr_tags("bad D50"))
    data = bytearray(data)
    # Set illuminant Y to 2.0 instead of 1.0
    struct.pack_into(">i", data, 72, int(2.0 * 65536))
    return bytes(data)


def synth_header_flags_reserved():
    """Profile flags with reserved bits set — CF-003 fail."""
    return build_profile(mntr_tags("flags reserved bits"),
                         flags=0xFFFF0000)


def synth_header_future_date():
    """Header with date in distant future (2099) — plausibility check."""
    data = build_profile(mntr_tags("future date"))
    data = bytearray(data)
    struct.pack_into(">H", data, 24, 2099)
    return bytes(data)


def synth_header_size_mismatch():
    """Profile size in header doesn't match actual — CF-010 fail."""
    data = build_profile(mntr_tags("size mismatch"))
    data = bytearray(data)
    # Set header size to twice actual
    struct.pack_into(">I", data, 0, len(data) * 2)
    return bytes(data)


# ═══════════════════════════════════════════════════════════════════════════════
# Category 5: Cross-Tag Consistency
# ═══════════════════════════════════════════════════════════════════════════════

def synth_gamut_tag_valid():
    """Output profile with gamutTag — CF-256 pass."""
    tags = prtr_tags("gamut tag valid")
    tags.append((b"gamt", make_lut8_tag(3, 1, grid=2)))
    return build_profile(tags, device_class=b"prtr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_atob_btoa_all_intents():
    """All 3 AToB/BToA pairs present — completeness check."""
    tags = base_tags("all intents")
    for i in range(3):
        atob_sig = f"A2B{i}".encode()
        btoa_sig = f"B2A{i}".encode()
        tags.append((atob_sig, make_lut8_tag(3, 3, grid=2)))
        tags.append((btoa_sig, make_lut8_tag(3, 3, grid=2)))
    return build_profile(tags, device_class=b"prtr",
                         color_space=b"RGB ", pcs=b"XYZ ")


def synth_atob_no_btoa():
    """AToB0 present but no BToA0 — CF-259/CF-260 warning."""
    tags = base_tags("AToB0 no BToA0")
    tags.append((b"A2B0", make_lut8_tag(3, 3, grid=2)))
    return build_profile(tags, device_class=b"prtr",
                         color_space=b"RGB ", pcs=b"XYZ ")


# ═══════════════════════════════════════════════════════════════════════════════
# Category 6: Text/Unicode
# ═══════════════════════════════════════════════════════════════════════════════

def synth_v2_text_desc():
    """v2 profile using textType for desc — valid for v2 (CF-212)."""
    tags = [
        (b"desc", make_text_tag("v2 text desc")),
        (b"cprt", make_text_tag("Copyright 2026")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0000, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags, version=0x02100000)


def synth_v4_text_desc():
    """v4 profile using textType for desc — should warn (CF-212, v4 requires mluc)."""
    tags = [
        (b"desc", make_text_tag("v4 text desc")),
        (b"cprt", make_mluc_tag("Copyright 2026")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0000, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags, version=0x04400000)


def synth_empty_desc():
    """Empty description tag — CF-275/CF-276 edge case."""
    tags = mntr_tags("")
    return build_profile(tags)


def synth_mluc_multi_record():
    """mluc with multiple language records — valid."""
    utf16_en = "English Description".encode("utf-16-be")
    utf16_de = "Deutsche Beschreibung".encode("utf-16-be")

    record_size = 12
    n_records = 2
    string_base = 16 + record_size * n_records

    data = b"mluc" + b"\x00" * 4
    data += struct.pack(">II", n_records, record_size)
    # English record
    data += b"enUS"
    data += struct.pack(">II", len(utf16_en), string_base)
    # German record
    data += b"deDE"
    data += struct.pack(">II", len(utf16_de), string_base + len(utf16_en))
    data += utf16_en + utf16_de
    data = pad4(data)

    tags = mntr_tags("mluc multi record")
    tags[0] = (b"desc", data)
    return build_profile(tags)


# ═══════════════════════════════════════════════════════════════════════════════
# Category 7: Additional Tag Types and Edge Cases
# ═══════════════════════════════════════════════════════════════════════════════

def synth_sf32_valid_count():
    """s15Fixed16ArrayType with exactly 9 elements (for chad-like tag)."""
    tags = mntr_tags("sf32 valid 9")
    identity = [1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 1.0]
    tags.append((b"chad", make_sf32_tag(identity)))
    return build_profile(tags)


def synth_xyz_multiple_triplets():
    """XYZType with multiple triplets — CF-032."""
    tags = mntr_tags("xyz multiple triplets")
    tags.append((b"bkpt", make_xyz_array_tag([
        (0.0, 0.0, 0.0),
        (0.5, 0.5, 0.5),
    ])))
    return build_profile(tags)


def synth_curve_identity():
    """curveType identity (0 entries) — CF-022."""
    tags = mntr_tags("curve identity")
    tags[6] = (b"rTRC", make_curve_tag())
    tags[7] = (b"gTRC", make_curve_tag())
    tags[8] = (b"bTRC", make_curve_tag())
    return build_profile(tags)


def synth_curve_single_gamma():
    """curveType single gamma entry — CF-022."""
    tags = mntr_tags("curve single gamma")
    tags[6] = (b"rTRC", make_curve_tag(gamma=1.8))
    tags[7] = (b"gTRC", make_curve_tag(gamma=1.8))
    tags[8] = (b"bTRC", make_curve_tag(gamma=1.8))
    return build_profile(tags)


def synth_curve_lut_table():
    """curveType with full 256-entry LUT table — CF-022."""
    values = [i / 255.0 for i in range(256)]
    tags = mntr_tags("curve lut table")
    tags[6] = (b"rTRC", make_curve_tag(values=values))
    tags[7] = (b"gTRC", make_curve_tag(values=values))
    tags[8] = (b"bTRC", make_curve_tag(values=values))
    return build_profile(tags)


def synth_prtr_cmyk():
    """CMYK output profile — exercises 4-channel LUT paths."""
    tags = [
        (b"desc", make_mluc_tag("CMYK Output")),
        (b"cprt", make_mluc_tag("Copyright 2026")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0000, 0.8249)),
        (b"A2B0", make_lut8_tag(4, 3, grid=2)),
        (b"B2A0", make_lut8_tag(3, 4, grid=2)),
    ]
    return build_profile(tags, device_class=b"prtr",
                         color_space=b"CMYK", pcs=b"Lab ")


def synth_link_rgb_to_cmyk():
    """DeviceLink RGB→CMYK — exercises cross-colorspace linking."""
    tags = [
        (b"desc", make_mluc_tag("RGB to CMYK Link")),
        (b"cprt", make_mluc_tag("Copyright 2026")),
        (b"A2B0", make_lut8_tag(3, 4, grid=2)),
        (b"clrt", make_colorant_table_tag([
            ("Cyan", [0, 32768, 32768]),
            ("Magenta", [32768, 0, 32768]),
            ("Yellow", [32768, 32768, 0]),
            ("Black", [0, 0, 0]),
        ])),
        (b"clro", make_colorant_order_tag([0, 1, 2, 3])),
    ]
    return build_profile(tags, device_class=b"link",
                         color_space=b"RGB ", pcs=b"CMYK")


def synth_gray_profile():
    """Gray monochrome profile — CF-042 alternate path."""
    tags = [
        (b"desc", make_mluc_tag("Gray Profile")),
        (b"cprt", make_mluc_tag("Copyright 2026")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0000, 0.8249)),
        (b"kTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags, color_space=b"GRAY", pcs=b"XYZ ")


def synth_v2_mntr():
    """v2.1 monitor profile — exercises version-specific paths."""
    tags = [
        (b"desc", make_text_tag("v2.1 Monitor")),
        (b"cprt", make_text_tag("Copyright 2026")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0000, 0.8249)),
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ]
    return build_profile(tags, version=0x02100000)


# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════

PROFILES = {
    # Category 1: Tag Type Validation
    "cf-para-type0-valid.icc": synth_para_valid_type0,
    "cf-para-type3-valid.icc": synth_para_valid_type3,
    "cf-para-type4-valid.icc": synth_para_valid_type4,
    "cf-para-bad-functype.icc": synth_para_bad_type,
    "cf-chromaticity-valid.icc": synth_chromaticity_valid,
    "cf-chromaticity-bad-count.icc": synth_chromaticity_bad_count,
    "cf-colorant-table-valid.icc": synth_colorant_table_valid,
    "cf-colorant-order-valid.icc": synth_colorant_order_valid,
    "cf-colorant-order-mismatch.icc": synth_colorant_order_mismatch,
    "cf-named-color2-valid.icc": synth_named_color2_valid,
    "cf-datetime-valid.icc": synth_datetime_valid,
    "cf-datetime-bad-month.icc": synth_datetime_bad_month,
    "cf-datetime-bad-day.icc": synth_datetime_bad_day,
    "cf-viewing-cond-valid.icc": synth_viewing_cond_valid,
    "cf-viewing-cond-bad-illumY.icc": synth_viewing_cond_bad_illum_y,
    "cf-viewing-cond-bad-illumType.icc": synth_viewing_cond_bad_type,
    "cf-measurement-valid.icc": synth_measurement_valid,
    "cf-measurement-bad-observer.icc": synth_measurement_bad_observer,
    "cf-measurement-bad-geometry.icc": synth_measurement_bad_geometry,
    "cf-profile-seq-desc-valid.icc": synth_profile_seq_desc_valid,
    "cf-response-curve-valid.icc": synth_response_curve_valid,
    "cf-sig-tag-valid.icc": synth_sig_tag_valid,

    # Category 2: Required Tags Per Class
    "cf-mntr-complete.icc": synth_mntr_complete,
    "cf-mntr-missing-rTRC.icc": synth_mntr_missing_rTRC,
    "cf-scnr-complete.icc": synth_scnr_complete,
    "cf-scnr-missing-wtpt.icc": synth_scnr_missing_wtpt,
    "cf-prtr-complete.icc": synth_prtr_complete,
    "cf-prtr-missing-atob.icc": synth_prtr_missing_atob,
    "cf-link-complete.icc": synth_link_complete,
    "cf-link-missing-atob.icc": synth_link_missing_atob,
    "cf-spac-complete.icc": synth_spac_complete,
    "cf-spac-missing-b2a.icc": synth_spac_missing_b2a,
    "cf-abst-complete.icc": synth_abst_complete,
    "cf-abst-missing-atob.icc": synth_abst_missing_atob,
    "cf-nmcl-complete.icc": synth_nmcl_complete,
    "cf-nmcl-missing-ncl2.icc": synth_nmcl_missing_ncl2,

    # Category 3: LUT/Matrix Conformance
    "cf-lut16-valid.icc": synth_lut16_valid,
    "cf-mab-b-only.icc": synth_mab_b_only,
    "cf-mab-full.icc": synth_mab_full,
    "cf-mba-full.icc": synth_mba_full,
    "cf-lut-atob-btoa-pair.icc": synth_lut_atob_btoa_pair,
    "cf-lut-nonxyz-matrix.icc": synth_lut_nonxyz_matrix,
    "cf-chad-valid.icc": synth_chad_valid,
    "cf-chad-singular.icc": synth_chad_singular,
    "cf-chad-wrong-count.icc": synth_chad_wrong_count,
    "cf-lut-channel-mismatch.icc": synth_lut_channel_mismatch,

    # Category 4: Header/Metadata
    "cf-header-bad-version.icc": synth_header_bad_version,
    "cf-header-bad-class.icc": synth_header_bad_class,
    "cf-header-bad-colorspace.icc": synth_header_bad_colorspace,
    "cf-header-bad-pcs.icc": synth_header_bad_pcs,
    "cf-header-reserved-nonzero.icc": synth_header_reserved_nonzero,
    "cf-header-bad-intent.icc": synth_header_bad_intent,
    "cf-header-bad-d50.icc": synth_header_bad_d50,
    "cf-header-flags-reserved.icc": synth_header_flags_reserved,
    "cf-header-future-date.icc": synth_header_future_date,
    "cf-header-size-mismatch.icc": synth_header_size_mismatch,

    # Category 5: Cross-Tag Consistency
    "cf-gamut-tag-valid.icc": synth_gamut_tag_valid,
    "cf-atob-btoa-all-intents.icc": synth_atob_btoa_all_intents,
    "cf-atob-no-btoa.icc": synth_atob_no_btoa,

    # Category 6: Text/Unicode
    "cf-v2-text-desc.icc": synth_v2_text_desc,
    "cf-v4-text-desc.icc": synth_v4_text_desc,
    "cf-empty-desc.icc": synth_empty_desc,
    "cf-mluc-multi-record.icc": synth_mluc_multi_record,

    # Category 7: Additional
    "cf-sf32-valid-count.icc": synth_sf32_valid_count,
    "cf-xyz-multi-triplet.icc": synth_xyz_multiple_triplets,
    "cf-curve-identity.icc": synth_curve_identity,
    "cf-curve-single-gamma.icc": synth_curve_single_gamma,
    "cf-curve-lut-table.icc": synth_curve_lut_table,
    "cf-prtr-cmyk.icc": synth_prtr_cmyk,
    "cf-link-rgb-to-cmyk.icc": synth_link_rgb_to_cmyk,
    "cf-gray-profile.icc": synth_gray_profile,
    "cf-v2-mntr.icc": synth_v2_mntr,
}


def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    success = 0
    fail = 0
    print(f"Generating {len(PROFILES)} conformance test profiles...\n")

    for filename, func in sorted(PROFILES.items()):
        try:
            data = func()
            write_profile(filename, data)
            success += 1
        except Exception as e:
            print(f"  FAIL {filename}: {e}")
            fail += 1

    print(f"\nDone: {success} succeeded, {fail} failed")
    print(f"Output: {OUTPUT_DIR}")
    return 0 if fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
