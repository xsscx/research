#!/usr/bin/env python3
"""Generate monochrome grayscale TIFF images for iccSpecSepToTiff testing.

Creates multiple suites of single-channel (SamplesPerPixel=1) TIFF images
suitable for merging into multi-channel spectral TIFFs.

Usage:
    python3 generate-spectral-tiffs.py [output_dir]

Output directory defaults to iccDEV/Testing/Fuzzing/seeds/tiff/spectral/

Suites generated:
    wl_380..wl_780  — 81 files, 4×4, 16-bit, MINISBLACK (visible spectrum 5nm steps)
    lg_400..lg_700  — 31 files, 64×64, 16-bit, MINISBLACK (10nm steps)
    ch8_001..ch8_010 — 10 files, 4×4, 8-bit, MINISBLACK
    white_001..white_010 — 10 files, 4×4, 16-bit, MINISWHITE
    big_001..big_005 — 5 files, 256×256, 16-bit, MINISBLACK
    med_001..med_020 — 20 files, 32×32, 16-bit, MINISBLACK
"""

import os
import struct
import sys


def write_tiff_gray(path, width, height, bps, photo=1, data=None):
    """Write a single-channel grayscale TIFF (little-endian, uncompressed).

    Args:
        path: Output file path
        width: Image width in pixels
        height: Image height in pixels
        bps: Bits per sample (8 or 16)
        photo: 0=MINISWHITE, 1=MINISBLACK
        data: Raw pixel data bytes (auto-generated gradient if None)
    """
    bytes_per_sample = bps // 8
    row_bytes = width * bytes_per_sample
    strip_size = row_bytes * height

    if data is None:
        if bps == 8:
            data = bytes(
                min(255, (r * width + c) * 255 // max(1, width * height - 1))
                for r in range(height)
                for c in range(width)
            )
        else:
            vals = []
            for r in range(height):
                for c in range(width):
                    v = min(65535, (r * width + c) * 65535 // max(1, width * height - 1))
                    vals.append(struct.pack("<H", v))
            data = b"".join(vals)

    # IFD entries
    entries = [
        (256, 3, 1, width),       # ImageWidth
        (257, 3, 1, height),      # ImageLength
        (258, 3, 1, bps),         # BitsPerSample
        (259, 3, 1, 1),           # Compression: None
        (262, 3, 1, photo),       # PhotometricInterpretation
        (273, 4, 1, 0),           # StripOffsets (patched below)
        (277, 3, 1, 1),           # SamplesPerPixel
        (278, 3, 1, height),      # RowsPerStrip
        (279, 4, 1, strip_size),  # StripByteCounts
        (282, 5, 1, 0),           # XResolution (patched below)
        (283, 5, 1, 0),           # YResolution (patched below)
        (296, 3, 1, 2),           # ResolutionUnit: inch
    ]
    n = len(entries)
    ifd_offset = 8
    ifd_size = 2 + 12 * n + 4
    xres_off = ifd_offset + ifd_size
    yres_off = xres_off + 8
    data_off = yres_off + 8

    entries[5] = (273, 4, 1, data_off)
    entries[9] = (282, 5, 1, xres_off)
    entries[10] = (283, 5, 1, yres_off)

    with open(path, "wb") as f:
        f.write(b"II")
        f.write(struct.pack("<H", 42))
        f.write(struct.pack("<I", ifd_offset))
        f.write(struct.pack("<H", n))
        for tag, typ, cnt, val in entries:
            f.write(struct.pack("<HHII", tag, typ, cnt, val))
        f.write(struct.pack("<I", 0))  # next IFD
        f.write(struct.pack("<II", 72, 1))  # XRes
        f.write(struct.pack("<II", 72, 1))  # YRes
        f.write(data)


def main():
    if len(sys.argv) > 1:
        outdir = sys.argv[1]
    else:
        outdir = os.path.join(
            os.path.dirname(__file__),
            "..", "seeds", "tiff", "spectral"
        )

    os.makedirs(outdir, exist_ok=True)
    total = 0

    # Suite 1: Wavelength-named (380-780nm, 5nm steps = 81 channels)
    print(f"Suite 1: wl_380..wl_780 (81 files, 4×4, 16-bit)")
    for wl in range(380, 785, 5):
        data = b""
        for r in range(4):
            for c in range(4):
                v = min(65535, (wl - 380) * 163 + r * 4096 + c * 1024)
                data += struct.pack("<H", v)
        write_tiff_gray(os.path.join(outdir, f"wl_{wl:03d}.tif"), 4, 4, 16, data=data)
        total += 1

    # Suite 2: 64×64 (400-700nm, 10nm steps = 31 channels)
    print(f"Suite 2: lg_400..lg_700 (31 files, 64×64, 16-bit)")
    for wl in range(400, 710, 10):
        write_tiff_gray(os.path.join(outdir, f"lg_{wl:03d}.tif"), 64, 64, 16)
        total += 1

    # Suite 3: 8-bit (10 channels)
    print(f"Suite 3: ch8_001..ch8_010 (10 files, 4×4, 8-bit)")
    for i in range(1, 11):
        data = bytes(min(255, i * 25 + r * 64 + c * 16) for r in range(4) for c in range(4))
        write_tiff_gray(os.path.join(outdir, f"ch8_{i:03d}.tif"), 4, 4, 8, data=data)
        total += 1

    # Suite 4: MINISWHITE (10 channels)
    print(f"Suite 4: white_001..white_010 (10 files, 4×4, 16-bit, MINISWHITE)")
    for i in range(1, 11):
        data = b""
        for r in range(4):
            for c in range(4):
                v = max(0, min(65535, 65535 - (i * 6000 + r * 4096 + c * 1024)))
                data += struct.pack("<H", v)
        write_tiff_gray(os.path.join(outdir, f"white_{i:03d}.tif"), 4, 4, 16, photo=0, data=data)
        total += 1

    # Suite 5: 256×256 stress (5 channels)
    print(f"Suite 5: big_001..big_005 (5 files, 256×256, 16-bit)")
    for i in range(1, 6):
        write_tiff_gray(os.path.join(outdir, f"big_{i:03d}.tif"), 256, 256, 16)
        total += 1

    # Suite 6: 32×32 medium (20 channels, for broad coverage)
    print(f"Suite 6: med_001..med_020 (20 files, 32×32, 16-bit)")
    for i in range(1, 21):
        write_tiff_gray(os.path.join(outdir, f"med_{i:03d}.tif"), 32, 32, 16)
        total += 1

    print(f"\nGenerated {total} TIFF files in {outdir}/")


if __name__ == "__main__":
    main()
