#!/usr/bin/env python3
"""Synthesize ICC profiles with DToB/BToD (multiProcessElementsType) tags.

Creates test profiles for extended code coverage of:
  - IccAnalyzerValidation.cpp: DToB/BToD round-trip pair detection
  - IccAnalyzerTagDetails.cpp: MPE tag display and enumeration
  - IccAnalyzerLUTTextIO.cpp: DToB/BToD tag name→signature mapping
  - IccHeuristicsDataValidation.cpp: MPE element validation
  - IccConformanceV5.cpp: CF-152 (completeness), CF-310 (element restriction)
  - IccHeuristicsExploitGap.cpp: H164/H165 LUT channel/data validation

Binary layout of multiProcessElementsType ('mpet'):
  Offset  Size  Field
  0       4     Type signature ('mpet' = 0x6D706574)
  4       4     Reserved (0x00000000)
  8       2     nInputChannels (uint16)
  10      2     nOutputChannels (uint16)
  12      4     nProcElements (uint32)
  16      8*n   Position table: [offset(4), size(4)] per element
  16+8*n  var   Element data

MPE element layout (each element):
  Offset  Size  Field
  0       4     Element type signature
  4       4     Reserved (0x00000000)
  8       2     nInputChannels (uint16)
  10      2     nOutputChannels (uint16)
  12      var   Element-specific data

Reference: ICC.1-2022-05 §10.2.14 (multiProcessElementsType)
"""

import struct
import os
import sys
import math

OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))

# --- Tag Signatures ---
SIG_D2B0 = b"D2B0"  # 0x44324230
SIG_D2B1 = b"D2B1"  # 0x44324231
SIG_D2B2 = b"D2B2"  # 0x44324232
SIG_D2B3 = b"D2B3"  # 0x44324233
SIG_B2D0 = b"B2D0"  # 0x42324430
SIG_B2D1 = b"B2D1"  # 0x42324431
SIG_B2D2 = b"B2D2"  # 0x42324432
SIG_B2D3 = b"B2D3"  # 0x42324433
SIG_BRDF_D2B0 = b"bDB0"  # 0x62444230

# --- MPE Element Signatures ---
SIG_MPET = b"mpet"     # 0x6D706574 multiProcessElementsType
SIG_CVST = b"cvst"     # 0x63767374 CurveSetElemType
SIG_MATF = b"matf"     # 0x6D617466 MatrixElemType
SIG_CLUT = b"clut"     # 0x636C7574 CLutElemType


# ──────────────────────────────────────────
# ICC Profile Infrastructure
# ──────────────────────────────────────────

def write_icc_header(
    size,
    version=0x05000000,  # v5.0.0
    device_class=b"mntr",
    color_space=b"RGB ",
    pcs=b"XYZ ",
    rendering_intent=0,
    flags=0,
):
    hdr = bytearray(128)
    struct.pack_into(">I", hdr, 0, size)
    struct.pack_into(">I", hdr, 8, version)
    hdr[12:16] = device_class
    hdr[16:20] = color_space
    hdr[20:24] = pcs
    struct.pack_into(">HHH HHH", hdr, 24, 2024, 1, 1, 0, 0, 0)
    hdr[36:40] = b"acsp"
    hdr[40:44] = b"APPL"
    struct.pack_into(">I", hdr, 44, flags)
    struct.pack_into(">I", hdr, 64, rendering_intent)
    struct.pack_into(">i", hdr, 68, int(0.9642 * 65536))
    struct.pack_into(">i", hdr, 72, int(1.0000 * 65536))
    struct.pack_into(">i", hdr, 76, int(0.8249 * 65536))
    hdr[80:84] = b"test"
    return bytes(hdr)


def make_tag_entry(sig, offset, size):
    return struct.pack(">4sII", sig, offset, size)


def make_mluc_tag(text):
    encoded = text.encode("utf-16-be")
    record_size = 12
    string_offset = 16 + record_size
    data = b"mluc" + b"\x00" * 4
    data += struct.pack(">II", 1, record_size)
    data += b"en" + b"US" + struct.pack(">II", len(encoded), string_offset)
    data += encoded
    while len(data) % 4:
        data += b"\x00"
    return data


def make_xyz_tag(x, y, z):
    data = b"XYZ " + b"\x00" * 4
    data += struct.pack(">iii", int(x * 65536), int(y * 65536), int(z * 65536))
    return data


def make_curve_tag(gamma=None, values=None):
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


def build_profile(tags_data, **header_kwargs):
    tag_count = len(tags_data)
    tag_table_size = 4 + tag_count * 12
    header_size = 128
    data_offset = header_size + tag_table_size
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

    table = struct.pack(">I", tag_count)
    for i, (sig, data) in enumerate(tags_data):
        table += make_tag_entry(sig, offsets[i], len(data))

    profile = bytearray(header)
    profile += table
    while len(profile) < data_offset:
        profile += b"\x00"
    for i, (sig, data) in enumerate(tags_data):
        while len(profile) < offsets[i]:
            profile += b"\x00"
        profile += data
        while len(profile) % 4:
            profile += b"\x00"

    struct.pack_into(">I", profile, 0, len(profile))
    return bytes(profile)


def required_tags(desc="DToB/BToD Test"):
    """Return required tags for a valid v5 display profile."""
    return [
        (b"desc", make_mluc_tag(desc)),
        (b"cprt", make_mluc_tag("Copyright 2026 ICC Test")),
        (b"wtpt", make_xyz_tag(0.9642, 1.0000, 0.8249)),
    ]


def required_tags_with_trc(desc="DToB/BToD Test"):
    """Required tags + matrix/TRC for a valid display profile baseline."""
    tags = required_tags(desc)
    tags.extend([
        (b"rXYZ", make_xyz_tag(0.4124, 0.2126, 0.0193)),
        (b"gXYZ", make_xyz_tag(0.3576, 0.7152, 0.1192)),
        (b"bXYZ", make_xyz_tag(0.1805, 0.0722, 0.9505)),
        (b"rTRC", make_curve_tag(gamma=2.2)),
        (b"gTRC", make_curve_tag(gamma=2.2)),
        (b"bTRC", make_curve_tag(gamma=2.2)),
    ])
    return tags


# ──────────────────────────────────────────
# MPE Element Builders
# ──────────────────────────────────────────

def make_identity_curveset(n_channels):
    """Build a CurveSet element with identity (formula type 0) curves.
    
    CurveSet ('cvst') element layout:
      Header:  sig(4) + reserved(4) + inCh(2) + outCh(2) = 12 bytes
      Position table: n_channels * (offset(4) + size(4)) = n_channels * 8
      Curve data: each curve is a formulaCurveSegment
      
    For identity: y = x^1.0, i.e. gamma=1, a=1, b=0, c=0, d=0
    Using segmented curve with a single formula segment.
    
    Simplified approach: use parametricCurveType within CurveSet.
    Each sub-curve is type 'parf' (parametric function).
    """
    # Use a simpler curve representation: 'curf' segmented curve
    # with a single formula segment (type 0: Y = a * X^gamma + b)
    # Identity: gamma=1.0, a=1.0, b=0.0

    # Build a single curve segment
    # segmentedCurve format:
    #   sig 'curf' (4) + reserved (4) + nSegments (2) + breakpoints (float32 * (nSeg-1))
    #   + segments: funcType(2) + reserved(2) + params(float32 * N)
    
    def make_single_curve():
        """Single identity segmented curve (curf with 1 parf segment).
        
        curf layout: sig(4) + reserved(4) + nSegments(2) + reserved(2)
        Each segment (parf): sig(4) + reserved(4) + funcType(2) + reserved(2) + params
        Type 0: Y = (a*X+b)^gamma + c  → 4 params: gamma, a, b, c
        Identity: gamma=1, a=1, b=0, c=0
        """
        curve = bytearray()
        curve += b"curf"                 # curve type signature
        curve += b"\x00" * 4            # reserved
        curve += struct.pack(">H", 1)   # nSegments = 1
        curve += b"\x00\x00"            # reserved
        # No breakpoints for 1 segment
        # Formula curve segment
        curve += b"parf"                 # segment type signature
        curve += b"\x00" * 4            # reserved
        curve += struct.pack(">H", 0)   # funcType = 0 (power law)
        curve += b"\x00\x00"            # reserved
        # 4 parameters for type 0: gamma, a, b, c
        curve += struct.pack(">f", 1.0)  # gamma
        curve += struct.pack(">f", 1.0)  # a
        curve += struct.pack(">f", 0.0)  # b
        curve += struct.pack(">f", 0.0)  # c
        return bytes(curve)

    single_curve = make_single_curve()
    
    # Build the CurveSet element
    elem = bytearray()
    elem += SIG_CVST              # 'cvst'
    elem += b"\x00" * 4          # reserved
    elem += struct.pack(">HH", n_channels, n_channels)  # in=out for CurveSet
    
    # Position table: offset and size for each curve
    # Offsets are relative to the start of the CurveSet element data
    # After header (12) + position table (n_channels * 8)
    pos_table_start = 12
    curves_start = pos_table_start + n_channels * 8
    
    for i in range(n_channels):
        offset = curves_start + i * len(single_curve)
        elem += struct.pack(">II", offset, len(single_curve))
    
    # Append curve data
    for i in range(n_channels):
        elem += single_curve
    
    while len(elem) % 4:
        elem += b"\x00"
    return bytes(elem)


def make_identity_matrix(n_in, n_out):
    """Build a Matrix element ('matf') — identity or zero-padded.
    
    Matrix element layout:
      sig(4) + reserved(4) + inCh(2) + outCh(2)
      + matrix[n_out * n_in] as float32 (row-major)
      + constants[n_out] as float32
    """
    elem = bytearray()
    elem += SIG_MATF
    elem += b"\x00" * 4
    elem += struct.pack(">HH", n_in, n_out)
    
    # Matrix data: identity where possible, zero elsewhere
    for row in range(n_out):
        for col in range(n_in):
            val = 1.0 if row == col else 0.0
            elem += struct.pack(">f", val)
    
    # Constants (bias vector)
    for _ in range(n_out):
        elem += struct.pack(">f", 0.0)
    
    return bytes(elem)


def make_scaling_matrix(n_in, n_out, scale=0.5):
    """Matrix element with uniform scaling (non-identity for testing)."""
    elem = bytearray()
    elem += SIG_MATF
    elem += b"\x00" * 4
    elem += struct.pack(">HH", n_in, n_out)
    
    for row in range(n_out):
        for col in range(n_in):
            val = scale if row == col else 0.0
            elem += struct.pack(">f", val)
    
    for _ in range(n_out):
        elem += struct.pack(">f", 0.0)
    
    return bytes(elem)


def make_gamma_curveset(n_channels, gamma=2.2):
    """CurveSet with power-law curves (non-identity)."""
    def make_gamma_curve(g):
        curve = bytearray()
        curve += b"curf"
        curve += b"\x00" * 4
        curve += struct.pack(">H", 1)  # 1 segment
        curve += b"\x00\x00"           # reserved
        # Formula curve segment
        curve += b"parf"               # segment type signature
        curve += b"\x00" * 4           # reserved
        curve += struct.pack(">H", 0)  # formula type 0
        curve += b"\x00\x00"           # reserved
        # 4 parameters: gamma, a, b, c
        curve += struct.pack(">f", g)    # gamma
        curve += struct.pack(">f", 1.0)  # a
        curve += struct.pack(">f", 0.0)  # b
        curve += struct.pack(">f", 0.0)  # c
        return bytes(curve)
    
    single_curve = make_gamma_curve(gamma)
    
    elem = bytearray()
    elem += SIG_CVST
    elem += b"\x00" * 4
    elem += struct.pack(">HH", n_channels, n_channels)
    
    curves_start = 12 + n_channels * 8
    for i in range(n_channels):
        offset = curves_start + i * len(single_curve)
        elem += struct.pack(">II", offset, len(single_curve))
    
    for _ in range(n_channels):
        elem += single_curve
    
    while len(elem) % 4:
        elem += b"\x00"
    return bytes(elem)


def make_clut_element(n_in, n_out, grid_points=3):
    """Build a CLUT element ('clut') for MPE.
    
    CLUT element layout:
      sig(4) + reserved(4) + inCh(2) + outCh(2)
      + gridPoints[16] as uint8 (padded to 16)
      + data as float32[grid^n_in * n_out]
    """
    elem = bytearray()
    elem += SIG_CLUT
    elem += b"\x00" * 4
    elem += struct.pack(">HH", n_in, n_out)
    
    # Grid points array (16 bytes, padded with zeros)
    grid_array = bytearray(16)
    for i in range(min(n_in, 16)):
        grid_array[i] = grid_points
    elem += grid_array
    
    # CLUT data: identity-ish mapping
    total_nodes = grid_points ** n_in
    for node in range(total_nodes):
        for ch in range(n_out):
            val = (node % grid_points) / max(1, grid_points - 1)
            elem += struct.pack(">f", val)
    
    return bytes(elem)


# ──────────────────────────────────────────
# MPET Tag Builder
# ──────────────────────────────────────────

def make_mpet_tag(n_in, n_out, elements):
    """Build a complete multiProcessElementsType tag.
    
    Args:
        n_in: number of input channels
        n_out: number of output channels
        elements: list of element data blobs (bytes)
    """
    n_elems = len(elements)
    
    # Header: sig(4) + reserved(4) + inCh(2) + outCh(2) + nElems(4) = 16
    header_size = 16
    pos_table_size = n_elems * 8
    
    # Element offsets are relative to start of mpet tag
    data_start = header_size + pos_table_size
    
    tag = bytearray()
    tag += SIG_MPET
    tag += b"\x00" * 4         # reserved
    tag += struct.pack(">HH", n_in, n_out)
    tag += struct.pack(">I", n_elems)
    
    # Build position table
    current_offset = data_start
    positions = []
    for elem in elements:
        aligned_size = len(elem)
        if aligned_size % 4:
            aligned_size += 4 - (aligned_size % 4)
        positions.append((current_offset, len(elem)))
        current_offset += aligned_size
    
    for offset, size in positions:
        tag += struct.pack(">II", offset, size)
    
    # Append element data
    for elem in elements:
        tag += elem
        while len(tag) % 4:
            tag += b"\x00"
    
    return bytes(tag)


def make_empty_mpet_tag(n_in=3, n_out=3):
    """MPET with zero elements (identity transform)."""
    tag = bytearray()
    tag += SIG_MPET
    tag += b"\x00" * 4
    tag += struct.pack(">HH", n_in, n_out)
    tag += struct.pack(">I", 0)  # nElements = 0
    return bytes(tag)


# ──────────────────────────────────────────
# Profile Synthesizers
# ──────────────────────────────────────────

def synth_dtob0_btod0_pair():
    """DToB0 + BToD0 pair — perceptual intent, identity CurveSet.
    Exercises round-trip pair detection in IccAnalyzerValidation.cpp.
    """
    curveset = make_identity_curveset(3)
    d2b = make_mpet_tag(3, 3, [curveset])
    b2d = make_mpet_tag(3, 3, [curveset])
    
    tags = required_tags_with_trc("DToB0+BToD0 Perceptual Pair")
    tags.append((SIG_D2B0, d2b))
    tags.append((SIG_B2D0, b2d))
    return build_profile(tags, rendering_intent=0)


def synth_dtob1_btod1_pair():
    """DToB1 + BToD1 pair — relative colorimetric.
    Uses CurveSet → Matrix → CurveSet chain.
    """
    cs_in = make_gamma_curveset(3, gamma=2.2)
    matrix = make_identity_matrix(3, 3)
    cs_out = make_gamma_curveset(3, gamma=1.0/2.2)
    
    d2b = make_mpet_tag(3, 3, [cs_in, matrix, cs_out])
    b2d = make_mpet_tag(3, 3, [cs_out, matrix, cs_in])
    
    tags = required_tags_with_trc("DToB1+BToD1 RelCol Pair")
    tags.append((SIG_D2B1, d2b))
    tags.append((SIG_B2D1, b2d))
    return build_profile(tags, rendering_intent=1)


def synth_dtob2_btod2_pair():
    """DToB2 + BToD2 pair — saturation intent.
    Uses CurveSet + CLUT + CurveSet chain for deeper coverage.
    """
    cs_in = make_identity_curveset(3)
    clut = make_clut_element(3, 3, grid_points=5)
    cs_out = make_identity_curveset(3)
    
    d2b = make_mpet_tag(3, 3, [cs_in, clut, cs_out])
    b2d = make_mpet_tag(3, 3, [cs_out, clut, cs_in])
    
    tags = required_tags_with_trc("DToB2+BToD2 Saturation Pair")
    tags.append((SIG_D2B2, d2b))
    tags.append((SIG_B2D2, b2d))
    return build_profile(tags, rendering_intent=2)


def synth_dtob3_btod3_pair():
    """DToB3 + BToD3 pair — absolute colorimetric / device gamut.
    Uses matrix-only element (no CurveSet).
    """
    matrix = make_scaling_matrix(3, 3, scale=0.8)
    
    d2b = make_mpet_tag(3, 3, [matrix])
    b2d = make_mpet_tag(3, 3, [matrix])
    
    tags = required_tags_with_trc("DToB3+BToD3 Absolute Pair")
    tags.append((SIG_D2B3, d2b))
    tags.append((SIG_B2D3, b2d))
    return build_profile(tags, rendering_intent=3)


def synth_dtob0_only():
    """DToB0 without BToD0 — tests unpaired tag detection.
    IccAnalyzerValidation.cpp:289-300 shows DToB/BToD presence check.
    """
    cs = make_identity_curveset(3)
    d2b = make_mpet_tag(3, 3, [cs])
    
    tags = required_tags_with_trc("DToB0 Only (unpaired)")
    tags.append((SIG_D2B0, d2b))
    return build_profile(tags)


def synth_btod0_only():
    """BToD0 without DToB0 — tests unpaired tag detection."""
    cs = make_identity_curveset(3)
    b2d = make_mpet_tag(3, 3, [cs])
    
    tags = required_tags_with_trc("BToD0 Only (unpaired)")
    tags.append((SIG_B2D0, b2d))
    return build_profile(tags)


def synth_all_dtob_btod():
    """All 4 DToB + all 4 BToD intents in one profile.
    Exercises complete tag enumeration in IccAnalyzerTagDetails.cpp.
    """
    cs = make_identity_curveset(3)
    mat = make_identity_matrix(3, 3)
    
    tags = required_tags_with_trc("All DToB+BToD Intents")
    for i, (d_sig, b_sig) in enumerate([
        (SIG_D2B0, SIG_B2D0),
        (SIG_D2B1, SIG_B2D1),
        (SIG_D2B2, SIG_B2D2),
        (SIG_D2B3, SIG_B2D3),
    ]):
        d2b = make_mpet_tag(3, 3, [cs, mat])
        b2d = make_mpet_tag(3, 3, [mat, cs])
        tags.append((d_sig, d2b))
        tags.append((b_sig, b2d))
    
    return build_profile(tags)


def synth_dtob_empty_mpet():
    """DToB0 with empty MPET (0 elements) — identity transform.
    Tests edge case in MPET parsing where nProcElements=0.
    """
    d2b = make_empty_mpet_tag(3, 3)
    
    tags = required_tags_with_trc("DToB0 Empty MPET")
    tags.append((SIG_D2B0, d2b))
    return build_profile(tags)


def synth_dtob_zero_channels():
    """DToB0 with zero input/output channels — malformed.
    Tests validation of channel counts in MPE.
    """
    tag = bytearray()
    tag += SIG_MPET
    tag += b"\x00" * 4
    tag += struct.pack(">HH", 0, 0)   # 0 channels
    tag += struct.pack(">I", 0)
    
    tags = required_tags_with_trc("DToB0 Zero Channels")
    tags.append((SIG_D2B0, bytes(tag)))
    return build_profile(tags)


def synth_dtob_mismatched_channels():
    """DToB0 with channel count mismatch between header and element.
    Header says 3→3, but element says 4→4. Tests H164 cross-check.
    """
    # Element has 4 in / 4 out but MPET header says 3 in / 3 out
    bad_curveset = make_identity_curveset(4)
    d2b = make_mpet_tag(3, 3, [bad_curveset])  # header says 3/3
    
    tags = required_tags_with_trc("DToB0 Channel Mismatch")
    tags.append((SIG_D2B0, d2b))
    return build_profile(tags)


def synth_dtob_oversized_elements():
    """DToB0 with huge nProcElements count — tests OOM guard.
    Profile data is too small for the claimed element count.
    """
    tag = bytearray()
    tag += SIG_MPET
    tag += b"\x00" * 4
    tag += struct.pack(">HH", 3, 3)
    tag += struct.pack(">I", 99999)  # absurd element count
    # No actual position table or element data — triggers size check
    
    tags = required_tags_with_trc("DToB0 Oversized Elements")
    tags.append((SIG_D2B0, bytes(tag)))
    return build_profile(tags)


def synth_dtob_bad_element_offset():
    """DToB0 with element offset pointing past tag boundary.
    Tests bounds checking in CIccTagMultiProcessElement::Read().
    """
    cs = make_identity_curveset(3)
    
    tag = bytearray()
    tag += SIG_MPET
    tag += b"\x00" * 4
    tag += struct.pack(">HH", 3, 3)
    tag += struct.pack(">I", 1)  # 1 element
    # Position table: offset way past end
    tag += struct.pack(">II", 0xFFFF0000, len(cs))
    # Include actual element data but offset is wrong
    tag += cs
    
    tags = required_tags_with_trc("DToB0 Bad Element Offset")
    tags.append((SIG_D2B0, bytes(tag)))
    return build_profile(tags)


def synth_dtob_bad_element_sig():
    """DToB0 with unknown element type signature.
    Tests factory dispatch failure path.
    """
    # Fake element with unknown signature
    bad_elem = bytearray()
    bad_elem += b"XXXX"          # unknown element type
    bad_elem += b"\x00" * 4     # reserved
    bad_elem += struct.pack(">HH", 3, 3)
    bad_elem += b"\x00" * 36   # 3x3 matrix of zeros (arbitrary data)
    
    d2b = make_mpet_tag(3, 3, [bytes(bad_elem)])
    
    tags = required_tags_with_trc("DToB0 Unknown Element Type")
    tags.append((SIG_D2B0, d2b))
    return build_profile(tags)


def synth_dtob_reserved_nonzero():
    """DToB0 with non-zero reserved field in MPET header.
    Tests conformance check on reserved bytes.
    """
    cs = make_identity_curveset(3)
    
    tag = bytearray()
    tag += SIG_MPET
    tag += struct.pack(">I", 0xDEADBEEF)  # non-zero reserved
    tag += struct.pack(">HH", 3, 3)
    tag += struct.pack(">I", 1)
    # Position table
    offset = 16 + 8  # header + 1 position entry
    tag += struct.pack(">II", offset, len(cs))
    tag += cs
    
    tags = required_tags_with_trc("DToB0 Reserved Non-zero")
    tags.append((SIG_D2B0, bytes(tag)))
    return build_profile(tags)


def synth_dtob_multi_element_chain():
    """DToB0 with CurveSet → Matrix → CurveSet chain.
    Full 3-element processing pipeline for deep coverage.
    """
    cs_in = make_gamma_curveset(3, gamma=2.4)
    mat = make_identity_matrix(3, 3)
    cs_out = make_gamma_curveset(3, gamma=1.0/2.4)
    
    d2b = make_mpet_tag(3, 3, [cs_in, mat, cs_out])
    b2d = make_mpet_tag(3, 3, [cs_out, mat, cs_in])
    
    tags = required_tags_with_trc("DToB0 Multi-Element Chain")
    tags.append((SIG_D2B0, d2b))
    tags.append((SIG_B2D0, b2d))
    return build_profile(tags)


def synth_dtob_with_clut():
    """DToB0 with CurveSet → CLUT → CurveSet chain.
    Exercises CLUT element parsing in MPE context.
    """
    cs_in = make_identity_curveset(3)
    clut = make_clut_element(3, 3, grid_points=9)
    cs_out = make_identity_curveset(3)
    
    d2b = make_mpet_tag(3, 3, [cs_in, clut, cs_out])
    
    tags = required_tags_with_trc("DToB0 with CLUT")
    tags.append((SIG_D2B0, d2b))
    return build_profile(tags)


def synth_dtob_matrix_only():
    """DToB0 with single matrix element (no curves).
    Tests minimal valid MPE pipeline.
    """
    mat = make_identity_matrix(3, 3)
    d2b = make_mpet_tag(3, 3, [mat])
    
    tags = required_tags_with_trc("DToB0 Matrix Only")
    tags.append((SIG_D2B0, d2b))
    return build_profile(tags)


def synth_dtob_curveset_only():
    """DToB0 with single CurveSet element.
    Tests CurveSet-only pipeline.
    """
    cs = make_gamma_curveset(3, gamma=1.8)
    d2b = make_mpet_tag(3, 3, [cs])
    
    tags = required_tags_with_trc("DToB0 CurveSet Only")
    tags.append((SIG_D2B0, d2b))
    return build_profile(tags)


def synth_dtob_high_dim():
    """DToB0 on a high-dimensional profile (6 channels).
    Tests MPE with > 3 input channels for deeper code paths.
    """
    cs = make_identity_curveset(6)
    mat = make_identity_matrix(6, 3)
    
    d2b = make_mpet_tag(6, 3, [cs, mat])
    b2d = make_mpet_tag(3, 6, [make_identity_matrix(3, 6), make_identity_curveset(6)])
    
    tags = required_tags("DToB0 High-Dim 6ch")
    tags.append((SIG_D2B0, d2b))
    tags.append((SIG_B2D0, b2d))
    return build_profile(tags, color_space=b"6CLR", pcs=b"XYZ ")


def synth_dtob_cmyk():
    """DToB0+BToD0 on CMYK output profile.
    Tests MPE in printer/output profile context.
    """
    cs_4 = make_identity_curveset(4)
    mat_4to3 = make_identity_matrix(4, 3)
    mat_3to4 = make_identity_matrix(3, 4)
    cs_3 = make_identity_curveset(3)
    
    d2b = make_mpet_tag(4, 3, [cs_4, mat_4to3])
    b2d = make_mpet_tag(3, 4, [mat_3to4, cs_4])
    
    tags = required_tags("DToB0 CMYK Profile")
    tags.append((SIG_D2B0, d2b))
    tags.append((SIG_B2D0, b2d))
    return build_profile(tags, device_class=b"prtr", color_space=b"CMYK")


def synth_dtob_lab_pcs():
    """DToB0+BToD0 with Lab PCS (instead of XYZ).
    Tests PCS-dependent code paths.
    """
    cs = make_identity_curveset(3)
    d2b = make_mpet_tag(3, 3, [cs])
    b2d = make_mpet_tag(3, 3, [cs])
    
    tags = required_tags_with_trc("DToB0 Lab PCS")
    tags.append((SIG_D2B0, d2b))
    tags.append((SIG_B2D0, b2d))
    return build_profile(tags, pcs=b"Lab ")


def synth_dtob_v4_version():
    """DToB0 on a v4 profile — tests version check.
    DToB/BToD are v5-only; v4 profile with these should trigger warnings.
    """
    cs = make_identity_curveset(3)
    d2b = make_mpet_tag(3, 3, [cs])
    
    tags = required_tags_with_trc("DToB0 on v4 Profile")
    tags.append((SIG_D2B0, d2b))
    return build_profile(tags, version=0x04400000)  # v4.4


def synth_dtob_truncated():
    """DToB0 tag with truncated MPET data.
    Tests handling of incomplete tag read.
    """
    # Only the header, no position table or elements
    tag = bytearray()
    tag += SIG_MPET
    tag += b"\x00" * 4
    tag += struct.pack(">HH", 3, 3)
    # Claim 2 elements but provide nothing
    tag += struct.pack(">I", 2)
    # Only 1 position entry (need 2)
    tag += struct.pack(">II", 24, 48)
    
    tags = required_tags_with_trc("DToB0 Truncated MPET")
    tags.append((SIG_D2B0, bytes(tag)))
    return build_profile(tags)


def synth_btod_all_intents():
    """All 4 BToD intents without any DToB — tests asymmetric detection."""
    cs = make_identity_curveset(3)
    
    tags = required_tags_with_trc("BToD All Intents (no DToB)")
    for sig in [SIG_B2D0, SIG_B2D1, SIG_B2D2, SIG_B2D3]:
        b2d = make_mpet_tag(3, 3, [cs])
        tags.append((sig, b2d))
    return build_profile(tags)


def synth_dtob_element_size_zero():
    """DToB0 where element position table has size=0.
    Tests zero-size element handling.
    """
    tag = bytearray()
    tag += SIG_MPET
    tag += b"\x00" * 4
    tag += struct.pack(">HH", 3, 3)
    tag += struct.pack(">I", 1)
    tag += struct.pack(">II", 24, 0)  # offset valid, size = 0
    
    tags = required_tags_with_trc("DToB0 Zero-Size Element")
    tags.append((SIG_D2B0, bytes(tag)))
    return build_profile(tags)


def synth_dtob_nan_matrix():
    """DToB0 with NaN values in matrix element.
    Tests NaN detection in H153 sampled curve and H166 division-by-zero.
    """
    elem = bytearray()
    elem += SIG_MATF
    elem += b"\x00" * 4
    elem += struct.pack(">HH", 3, 3)
    
    # 3x3 matrix with NaN on diagonal
    nan_bytes = struct.pack(">f", float('nan'))
    for row in range(3):
        for col in range(3):
            if row == col:
                elem += nan_bytes
            else:
                elem += struct.pack(">f", 0.0)
    # Constants
    for _ in range(3):
        elem += struct.pack(">f", 0.0)
    
    d2b = make_mpet_tag(3, 3, [bytes(elem)])
    
    tags = required_tags_with_trc("DToB0 NaN Matrix")
    tags.append((SIG_D2B0, d2b))
    return build_profile(tags)


def synth_dtob_inf_matrix():
    """DToB0 with Infinity values in matrix element."""
    elem = bytearray()
    elem += SIG_MATF
    elem += b"\x00" * 4
    elem += struct.pack(">HH", 3, 3)
    
    inf_bytes = struct.pack(">f", float('inf'))
    for row in range(3):
        for col in range(3):
            if row == col:
                elem += inf_bytes
            else:
                elem += struct.pack(">f", 0.0)
    for _ in range(3):
        elem += struct.pack(">f", 0.0)
    
    d2b = make_mpet_tag(3, 3, [bytes(elem)])
    
    tags = required_tags_with_trc("DToB0 Inf Matrix")
    tags.append((SIG_D2B0, d2b))
    return build_profile(tags)


def synth_dtob_large_clut():
    """DToB0 with a larger CLUT (17-point grid).
    Tests realistic LUT sizes for coverage of iteration paths.
    """
    cs_in = make_identity_curveset(3)
    clut = make_clut_element(3, 3, grid_points=17)
    cs_out = make_identity_curveset(3)
    
    d2b = make_mpet_tag(3, 3, [cs_in, clut, cs_out])
    
    tags = required_tags_with_trc("DToB0 Large CLUT 17pt")
    tags.append((SIG_D2B0, d2b))
    return build_profile(tags)


def synth_dtob_brdf():
    """BRDF DToB0 tag ('bDB0') — BRDF-specific MPE tag.
    Tests BRDF tag enumeration in IccAnalyzerTagDetails.cpp.
    """
    cs = make_identity_curveset(3)
    mat = make_identity_matrix(3, 3)
    
    d2b = make_mpet_tag(3, 3, [cs, mat])
    
    tags = required_tags_with_trc("BRDF DToB0 Profile")
    tags.append((SIG_BRDF_D2B0, d2b))
    return build_profile(tags)


def synth_dtob_mixed_atob():
    """Profile with both AToB/BToA AND DToB/BToD tags.
    Tests combined LUT and MPE enumeration paths.
    """
    from iccanalyzer_lite_helpers import make_lut8_tag_data
    
    cs = make_identity_curveset(3)
    d2b = make_mpet_tag(3, 3, [cs])
    b2d = make_mpet_tag(3, 3, [cs])
    
    # Simple lut8 AToB0/BToA0
    lut8 = make_simple_lut8(3, 3)
    
    tags = required_tags_with_trc("Mixed AToB + DToB")
    tags.append((b"A2B0", lut8))
    tags.append((b"B2A0", lut8))
    tags.append((SIG_D2B0, d2b))
    tags.append((SIG_B2D0, b2d))
    return build_profile(tags)


def make_simple_lut8(n_in, n_out, grid=2):
    """Build a minimal lut8Type ('mft1') tag."""
    matrix = b""
    for r in range(3):
        for c in range(3):
            val = 1.0 if r == c else 0.0
            matrix += struct.pack(">i", int(val * 65536))
    
    input_table = bytes(range(256)) * n_in
    clut_size = (grid ** n_in) * n_out
    clut = bytes([int(255 * i / max(1, clut_size - 1)) for i in range(clut_size)])
    output_table = bytes(range(256)) * n_out
    
    tag = b"mft1" + b"\x00" * 4
    tag += struct.pack("BBBB", n_in, n_out, grid, 0)
    tag += matrix + input_table + clut + output_table
    return tag


def synth_dtob_mixed_atob_real():
    """Profile with both AToB/BToA AND DToB/BToD tags.
    Uses internal lut8 builder (no external import needed).
    """
    cs = make_identity_curveset(3)
    d2b = make_mpet_tag(3, 3, [cs])
    b2d = make_mpet_tag(3, 3, [cs])
    lut8 = make_simple_lut8(3, 3)
    
    tags = required_tags_with_trc("Mixed AToB + DToB")
    tags.append((b"A2B0", lut8))
    tags.append((b"B2A0", lut8))
    tags.append((SIG_D2B0, d2b))
    tags.append((SIG_B2D0, b2d))
    return build_profile(tags)


def synth_dtob_devicelink():
    """DeviceLink profile with DToB0 tag.
    Tests DToB in non-display profile context.
    """
    cs = make_identity_curveset(3)
    d2b = make_mpet_tag(3, 3, [cs])
    
    tags = required_tags("DToB0 DeviceLink")
    tags.append((SIG_D2B0, d2b))
    return build_profile(tags, device_class=b"link", pcs=b"RGB ")


def synth_dtob_abstract():
    """Abstract profile with DToB0+BToD0 pair.
    Tests DToB in abstract profile context.
    """
    cs = make_identity_curveset(3)
    d2b = make_mpet_tag(3, 3, [cs])
    b2d = make_mpet_tag(3, 3, [cs])
    
    tags = required_tags("DToB0 Abstract")
    tags.append((SIG_D2B0, d2b))
    tags.append((SIG_B2D0, b2d))
    return build_profile(tags, device_class=b"abst", pcs=b"Lab ")


def synth_dtob_scanner():
    """Input/scanner profile with DToB/BToD pair.
    Tests DToB in scanner profile context.
    """
    cs = make_identity_curveset(3)
    d2b = make_mpet_tag(3, 3, [cs])
    b2d = make_mpet_tag(3, 3, [cs])
    
    tags = required_tags("DToB0 Scanner")
    tags.append((SIG_D2B0, d2b))
    tags.append((SIG_B2D0, b2d))
    return build_profile(tags, device_class=b"scnr")


# ──────────────────────────────────────────
# Main
# ──────────────────────────────────────────

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"Synthesizing DToB/BToD test profiles to {OUTPUT_DIR}/\n")
    
    profiles = {
        # Paired DToB/BToD for each intent
        "dtob0-btod0-perceptual.icc": synth_dtob0_btod0_pair(),
        "dtob1-btod1-relcol.icc": synth_dtob1_btod1_pair(),
        "dtob2-btod2-saturation.icc": synth_dtob2_btod2_pair(),
        "dtob3-btod3-absolute.icc": synth_dtob3_btod3_pair(),
        
        # Unpaired tags (asymmetric detection)
        "dtob0-only-unpaired.icc": synth_dtob0_only(),
        "btod0-only-unpaired.icc": synth_btod0_only(),
        "btod-all-intents-no-dtob.icc": synth_btod_all_intents(),
        
        # All intents combined
        "dtob-btod-all-intents.icc": synth_all_dtob_btod(),
        
        # Element variety
        "dtob-empty-mpet.icc": synth_dtob_empty_mpet(),
        "dtob-multi-element-chain.icc": synth_dtob_multi_element_chain(),
        "dtob-with-clut.icc": synth_dtob_with_clut(),
        "dtob-matrix-only.icc": synth_dtob_matrix_only(),
        "dtob-curveset-only.icc": synth_dtob_curveset_only(),
        "dtob-large-clut-17pt.icc": synth_dtob_large_clut(),
        
        # Malformed / edge cases
        "dtob-zero-channels.icc": synth_dtob_zero_channels(),
        "dtob-channel-mismatch.icc": synth_dtob_mismatched_channels(),
        "dtob-oversized-elements.icc": synth_dtob_oversized_elements(),
        "dtob-bad-element-offset.icc": synth_dtob_bad_element_offset(),
        "dtob-bad-element-sig.icc": synth_dtob_bad_element_sig(),
        "dtob-reserved-nonzero.icc": synth_dtob_reserved_nonzero(),
        "dtob-truncated-mpet.icc": synth_dtob_truncated(),
        "dtob-element-size-zero.icc": synth_dtob_element_size_zero(),
        "dtob-nan-matrix.icc": synth_dtob_nan_matrix(),
        "dtob-inf-matrix.icc": synth_dtob_inf_matrix(),
        
        # Profile class variety
        "dtob-high-dim-6ch.icc": synth_dtob_high_dim(),
        "dtob-cmyk-prtr.icc": synth_dtob_cmyk(),
        "dtob-lab-pcs.icc": synth_dtob_lab_pcs(),
        "dtob-v4-version.icc": synth_dtob_v4_version(),
        "dtob-devicelink.icc": synth_dtob_devicelink(),
        "dtob-abstract.icc": synth_dtob_abstract(),
        "dtob-scanner.icc": synth_dtob_scanner(),
        
        # Combined with legacy LUT tags
        "dtob-mixed-atob.icc": synth_dtob_mixed_atob_real(),
        
        # BRDF variant
        "dtob-brdf.icc": synth_dtob_brdf(),
    }
    
    for name, data in sorted(profiles.items()):
        path = os.path.join(OUTPUT_DIR, name)
        with open(path, "wb") as f:
            f.write(data)
        print(f"  {name:42s} {len(data):8d} bytes")
    
    print(f"\n{len(profiles)} profiles written to {OUTPUT_DIR}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
