#!/usr/bin/env python3
"""craft-seeds.py — Generate edge-case synthetic image seeds with ICC profiles.

Creates TIFF/JPEG/PNG seeds covering unusual pixel formats, compression modes,
byte orders, and structural variants that xnuimagefuzzer doesn't produce.
Each seed is embedded with an ICC profile via exiftool.

Usage:
    python3 bin/craft-seeds.py [--outdir DIR] [--profiles DIR]
"""

import argparse
import os
import subprocess
import sys

import numpy as np


def check_deps():
    """Verify required packages are available."""
    try:
        import tifffile  # noqa: F401
        from PIL import Image  # noqa: F401
    except ImportError:
        print("Error: tifffile and Pillow required", file=sys.stderr)
        print("  pip install tifffile Pillow", file=sys.stderr)
        sys.exit(1)


def find_profiles(profile_dir):
    """Load ICC profiles from directory."""
    names = [
        "sRGB_v4_ICC_preference.icc",
        "Rec2020rgbColorimetric.icc",
        "Rec2100HlgFull.icc",
        "Rec2100HlgNarrow.icc",
        "LCDDisplay.icc",
        "RgbGSDF.icc",
        "GrayGSDF.icc",
        "Rec2020rgbSpectral.icc",
        "CIccMpeToneMap_IccProfLib_IccMpeBasic.cpp-L4532.icc",
        "crash-2390a7cf.icc",
        "crash-ndlut-null-apply.icc",
        "calcOverMem_tget.icc",
        "calcUnderStack_abs.icc",
        "crash-pushXYZConvert-heap-oob-profile1.icc",
    ]
    profiles = {}
    for name in names:
        path = os.path.join(profile_dir, name)
        if os.path.exists(path):
            with open(path, "rb") as f:
                profiles[name] = f.read()
    return profiles


def embed_icc(filepath, icc_data):
    """Embed ICC profile into image file via exiftool."""
    icc_tmp = f"/tmp/_icc_craft_{os.getpid()}.icc"
    with open(icc_tmp, "wb") as f:
        f.write(icc_data)
    subprocess.run(
        ["exiftool", "-overwrite_original", f"-ICC_Profile<={icc_tmp}", filepath],
        capture_output=True,
    )
    if os.path.exists(icc_tmp):
        os.unlink(icc_tmp)


def tag(pname):
    """Short profile name for filenames."""
    return pname.replace(".icc", "").replace(" ", "_")[:30]


def main():
    check_deps()
    import tifffile
    from PIL import Image

    parser = argparse.ArgumentParser(description="Craft synthetic image seeds")
    parser.add_argument("--outdir", default="temp/icc-crafted", help="Output directory")
    parser.add_argument(
        "--profiles", default="test-profiles", help="ICC profile directory"
    )
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    profiles = find_profiles(args.profiles)
    if not profiles:
        print(f"Error: no ICC profiles found in {args.profiles}", file=sys.stderr)
        sys.exit(1)

    count = 0

    def save_tiff(arr, icc_data, filename, **kwargs):
        nonlocal count
        path = os.path.join(args.outdir, filename)
        if os.path.exists(path):
            return
        tifffile.imwrite(path, arr, **kwargs)
        embed_icc(path, icc_data)
        count += 1

    def save_pil(pil_img, icc_data, filename, fmt="TIFF"):
        nonlocal count
        path = os.path.join(args.outdir, filename)
        if os.path.exists(path):
            return
        pil_img.save(path, format=fmt, icc_profile=icc_data)
        count += 1

    print("=== Crafting synthetic seed images ===")

    # 1. Tiny 1×1 images
    s = count
    for pname, pdata in profiles.items():
        t = tag(pname)
        save_pil(Image.new("RGB", (1, 1), (128, 64, 32)), pdata, f"1x1-rgb8--{t}.tiff")
        save_pil(
            Image.new("RGBA", (1, 1), (255, 0, 0, 128)), pdata, f"1x1-rgba8--{t}.tiff"
        )
        if "Gray" in pname or "GSDF" in pname:
            save_pil(
                Image.new("L", (1, 1), 128), pdata, f"1x1-gray8--{t}.tiff"
            )
    print(f"  1×1 tiny: {count - s}")

    # 2. 16-bit depth
    s = count
    for pname, pdata in list(profiles.items())[:6]:
        t = tag(pname)
        save_tiff(
            np.random.randint(0, 65535, (4, 4, 3), dtype=np.uint16),
            pdata, f"4x4-rgb16--{t}.tiff",
        )
        save_tiff(
            np.random.randint(0, 65535, (4, 4), dtype=np.uint16),
            pdata, f"4x4-gray16--{t}.tiff",
        )
    print(f"  16-bit: {count - s}")

    # 3. 32-bit float with edge values
    s = count
    for pname, pdata in list(profiles.items())[:6]:
        t = tag(pname)
        arr = np.array(
            [
                [0.0, 0.5, 1.0],
                [-0.1, 1.5, float("inf")],
                [float("-inf"), float("nan"), 0.0],
                [1e-38, 1e38, -0.0],
            ],
            dtype=np.float32,
        ).reshape(2, 2, 3)
        save_tiff(arr, pdata, f"2x2-rgbf32-edge--{t}.tiff", photometric="rgb")
    print(f"  float32: {count - s}")

    # 4. Multi-strip
    s = count
    for pname, pdata in list(profiles.items())[:4]:
        t = tag(pname)
        arr = np.random.randint(0, 255, (16, 16, 3), dtype=np.uint8)
        save_tiff(arr, pdata, f"16x16-strip2--{t}.tiff", rowsperstrip=2)
        save_tiff(arr, pdata, f"16x16-strip1--{t}.tiff", rowsperstrip=1)
    print(f"  multi-strip: {count - s}")

    # 5. Tiled (tile must be multiple of 16)
    s = count
    for pname, pdata in list(profiles.items())[:4]:
        t = tag(pname)
        save_tiff(
            np.random.randint(0, 255, (32, 32, 3), dtype=np.uint8),
            pdata, f"32x32-tile16--{t}.tiff", tile=(16, 16),
        )
        save_tiff(
            np.random.randint(0, 255, (64, 64, 3), dtype=np.uint8),
            pdata, f"64x64-tile32--{t}.tiff", tile=(32, 32),
        )
    print(f"  tiled: {count - s}")

    # 6. Multi-page/IFD
    s = count
    for pname, pdata in list(profiles.items())[:3]:
        t = tag(pname)
        path = os.path.join(args.outdir, f"multipage--{t}.tiff")
        if not os.path.exists(path):
            with tifffile.TiffWriter(path) as tw:
                tw.write(
                    np.random.randint(0, 255, (4, 4, 3), dtype=np.uint8),
                    photometric="rgb",
                )
                tw.write(
                    np.random.randint(0, 255, (8, 8, 3), dtype=np.uint8),
                    photometric="rgb",
                )
            embed_icc(path, pdata)
            count += 1
    print(f"  multi-page: {count - s}")

    # 7. BigTIFF
    s = count
    for pname, pdata in list(profiles.items())[:3]:
        t = tag(pname)
        save_tiff(
            np.random.randint(0, 255, (4, 4, 3), dtype=np.uint8),
            pdata, f"4x4-bigtiff--{t}.tiff", bigtiff=True,
        )
    print(f"  BigTIFF: {count - s}")

    # 8. Planar (separate planes)
    s = count
    for pname, pdata in list(profiles.items())[:4]:
        t = tag(pname)
        save_tiff(
            np.random.randint(0, 255, (8, 8, 3), dtype=np.uint8),
            pdata, f"8x8-planar--{t}.tiff", planarconfig="separate",
        )
    print(f"  planar: {count - s}")

    # 9. Compressed (zlib, deflate)
    s = count
    for pname, pdata in list(profiles.items())[:4]:
        t = tag(pname)
        arr = np.random.randint(0, 255, (8, 8, 3), dtype=np.uint8)
        save_tiff(arr, pdata, f"8x8-lzw--{t}.tiff", compression="zlib")
        save_tiff(arr, pdata, f"8x8-deflate--{t}.tiff", compression="deflate")
    print(f"  compressed: {count - s}")

    # 10. Byte order variants (true little-endian)
    s = count
    for pname, pdata in list(profiles.items())[:4]:
        t = tag(pname)
        arr = np.random.randint(0, 255, (4, 4, 3), dtype=np.uint8)
        save_tiff(arr, pdata, f"4x4-le--{t}.tiff", byteorder="<")
        save_tiff(arr, pdata, f"4x4-be--{t}.tiff", byteorder=">")
    print(f"  byte-order: {count - s}")

    # 11. JPEG seeds
    s = count
    for pname, pdata in list(profiles.items())[:6]:
        t = tag(pname)
        save_pil(
            Image.new("RGB", (2, 2), (200, 100, 50)), pdata, f"2x2-rgb--{t}.jpg", "JPEG"
        )
    print(f"  JPEG: {count - s}")

    # 12. PNG seeds
    s = count
    for pname, pdata in list(profiles.items())[:6]:
        t = tag(pname)
        save_pil(
            Image.new("RGBA", (2, 2), (255, 128, 0, 200)),
            pdata, f"2x2-rgba--{t}.png", "PNG",
        )
    print(f"  PNG: {count - s}")

    print(f"\n=== Total crafted seeds: {count} in {args.outdir}/ ===")


if __name__ == "__main__":
    main()
