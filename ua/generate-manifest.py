#!/usr/bin/env python3
"""Generate manifest.json for the UA Image & ICC Fuzzer Harness.

Scans the repository for image and ICC profile files, producing a JSON
manifest consumed by ua-image-icc-fuzzer.html.

Usage:
    cd research/ua && python3 generate-manifest.py          # default scan
    python3 generate-manifest.py --root /path/to/research   # explicit root
    python3 generate-manifest.py --stats                    # print summary only
"""

import argparse
import json
import os
import sys
from pathlib import Path

IMAGE_EXTS = {
    ".png", ".jpg", ".jpeg", ".tif", ".tiff", ".gif", ".bmp",
    ".svg", ".webp", ".heic", ".heif", ".exr",
}
ICC_EXTS = {".icc", ".icm"}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "site-packages",
    "Build", "build", "Build-ASAN", "html", "doxygen",
}

SCAN_DIRS = [
    "test-profiles",
    "extended-test-profiles",
    "fuzz/graphics",
    "mangled-images",
    "iccDEV/Testing",
    "source-of-truth/Testing",
]

# Optional: scan these if --full flag is given
FULL_SCAN_DIRS = [
    "cfl/corpus-icc_dump_fuzzer",
    "cfl/corpus-icc_toxml_fuzzer",
    "cfl/corpus-icc_roundtrip_fuzzer",
    "cfl/corpus-icc_tiffdump_fuzzer",
    "cfl/corpus-icc_link_fuzzer",
    "afl/afl-dump/input",
    "afl/afl-toxml/input",
    "afl/afl-roundtrip/input",
    "afl/afl-tiffdump/input",
    "afl/afl-jpegdump/input",
    "afl/afl-pngdump/input",
]


def classify(ext):
    if ext.lower() in ICC_EXTS:
        return "icc"
    if ext.lower() in IMAGE_EXTS:
        return "image"
    if ext.lower() in {".xml"}:
        return "xml"
    if ext.lower() in {".cube"}:
        return "cube"
    return None


def scan(root, full=False):
    """Scan repository for image/ICC files."""
    entries = []
    seen = set()
    root = Path(root).resolve()

    dirs_to_scan = list(SCAN_DIRS)
    if full:
        dirs_to_scan.extend(FULL_SCAN_DIRS)

    for scan_dir in dirs_to_scan:
        target = root / scan_dir
        if not target.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(target):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
            for fname in sorted(filenames):
                fpath = Path(dirpath) / fname
                ext = fpath.suffix.lower()
                ftype = classify(ext)
                if ftype is None:
                    # Check magic for ICC files without extension
                    if fpath.stat().st_size >= 132:
                        try:
                            with open(fpath, "rb") as f:
                                hdr = f.read(40)
                                if len(hdr) >= 40 and hdr[36:40] == b"acsp":
                                    ftype = "icc"
                                    ext = ".icc"
                        except (OSError, PermissionError):
                            pass
                if ftype is None:
                    continue

                rel = "./" + str(fpath.relative_to(root))
                if rel in seen:
                    continue
                seen.add(rel)
                entries.append({
                    "path": rel,
                    "type": ftype,
                    "ext": ext if ext else fpath.suffix.lower(),
                    "size": fpath.stat().st_size,
                })

    # Also scan repo root for crash/oom/slow-unit files (ICC)
    for f in sorted(root.iterdir()):
        if not f.is_file():
            continue
        name = f.name
        if any(name.startswith(pfx) for pfx in ("crash-", "oom-", "slow-unit-", "hbo-", "sbo-", "ub-")):
            rel = "./" + name
            if rel not in seen and f.stat().st_size >= 4:
                seen.add(rel)
                entries.append({
                    "path": rel,
                    "type": "icc",
                    "ext": ".icc",
                    "size": f.stat().st_size,
                })

    return entries


def main():
    parser = argparse.ArgumentParser(description="Generate UA fuzzer manifest")
    parser.add_argument("--root", default="..", help="Repository root (default: ..)")
    parser.add_argument("--output", default="manifest.json", help="Output file")
    parser.add_argument("--stats", action="store_true", help="Print stats only")
    parser.add_argument("--full", action="store_true", help="Include CFL/AFL corpus files")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    entries = scan(root, full=args.full)

    # Sort for determinism
    entries.sort(key=lambda e: e["path"])

    # Stats
    from collections import Counter
    types = Counter(e["type"] for e in entries)
    exts = Counter(e["ext"] for e in entries)
    total_size = sum(e["size"] for e in entries)

    print(f"Scanned: {root}")
    print(f"Total files: {len(entries)}")
    print(f"Types: {dict(types)}")
    print(f"Extensions: {dict(sorted(exts.items(), key=lambda x: -x[1]))}")
    print(f"Total size: {total_size / 1024 / 1024:.1f} MB")

    if args.stats:
        return

    manifest = {
        "total": len(entries),
        "generated": __import__("datetime").datetime.now(
            __import__("datetime").timezone.utc
        ).isoformat(),
        "stats": {
            "types": dict(types),
            "extensions": dict(sorted(exts.items(), key=lambda x: -x[1])),
            "totalSizeBytes": total_size,
        },
        "files": entries,
    }

    out = Path(args.output)
    with open(out, "w") as f:
        json.dump(manifest, f, separators=(",", ":"))

    print(f"Written: {out} ({out.stat().st_size / 1024:.0f} KB)")


if __name__ == "__main__":
    main()
