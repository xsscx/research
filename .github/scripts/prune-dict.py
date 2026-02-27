#!/usr/bin/env python3
"""prune-dict.py — Remove noise entries from LibFuzzer dictionaries.

Identifies and removes:
  - Exact duplicate entries
  - C++ ABI / internal symbols (typeinfo, vtable fragments)
  - ASAN shadow memory patterns (poison bytes)
  - Address-like pointer fragments (heap/stack address leaks)
  - Entries with excessive high-entropy byte density

Usage:
  prune-dict.py INPUT_DICT [OUTPUT_DICT] [--dry-run] [--stats]

If OUTPUT_DICT is omitted, overwrites INPUT_DICT in place.

Exit codes:
  0 = success
  1 = error
  2 = no changes needed
"""

import argparse
import os
import re
import sys


def _sanitize_path(path):
    """Resolve and validate a file path to prevent path traversal."""
    resolved = os.path.realpath(path)
    repo_root = os.path.realpath(os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    if not (resolved.startswith(repo_root + os.sep)
            or resolved.startswith("/tmp" + os.sep)
            or resolved.startswith("/tmp")):
        raise ValueError(
            f"Path escapes allowed directories: {resolved}\n"
            f"Must be under {repo_root} or /tmp")
    if "\x00" in path:
        raise ValueError("Null byte in path")
    return resolved


def decode_entry(raw):
    """Decode a raw dict entry string into bytes for analysis."""
    result = bytearray()
    i = 0
    while i < len(raw):
        if raw[i] == '\\' and i + 1 < len(raw):
            nxt = raw[i + 1]
            if nxt == 'x' and i + 3 < len(raw):
                try:
                    result.append(int(raw[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            elif nxt == 'n':
                result.append(0x0a)
                i += 2
                continue
            elif nxt == 'r':
                result.append(0x0d)
                i += 2
                continue
            elif nxt == 't':
                result.append(0x09)
                i += 2
                continue
            elif nxt == '\\':
                result.append(0x5c)
                i += 2
                continue
            elif nxt == '"':
                result.append(0x22)
                i += 2
                continue
        result.append(ord(raw[i]))
        i += 1
    return bytes(result)


def is_cxx_abi(raw):
    """Detect C++ ABI / internal symbols."""
    markers = ['__cxxabi', 'St9type_info', 'N10__', '_ZN', '_ZT',
               'typeinfo', 'vtable', '_ZdlPv', '_Znwm']
    return any(m in raw for m in markers)


def is_asan_pattern(data):
    """Detect ASAN shadow memory poison byte patterns."""
    poison = [b'\xf5\xf5', b'\xfa\xfa', b'\xf1\xf1',
              b'\xf2\xf2', b'\xf3\xf3', b'\xf8\xf8',
              b'\xf4\xf5\xf5\xf5', b'\xf6\xf5\xf5\xf5']
    return any(p in data for p in poison)


def is_address_like(raw, data):
    """Detect pointer/address fragments from instrumented binaries.

    These are 7-8 byte entries ending in null bytes with patterns that
    look like memory addresses from ASAN-instrumented runs.
    """
    if len(data) not in (7, 8):
        return False
    # Must end with at least 2 null bytes
    if not data.endswith(b'\x00\x00'):
        return False
    non_null = data.rstrip(b'\x00')
    if len(non_null) < 2:
        return False
    # Check for address-space-like patterns: non-null prefix with
    # bytes in typical heap/stack address ranges
    high_bytes = sum(1 for b in non_null if b > 0x40)
    if high_bytes >= len(non_null) * 0.3:
        return True
    return False


def is_high_entropy_noise(raw, data):
    """Detect high-entropy random corpus fragments.

    These are longer entries with mostly non-ASCII bytes that appear to be
    random byte sequences extracted from corpus files rather than
    intentional fuzzer tokens.
    """
    if len(data) < 8:
        return False
    non_ascii = sum(1 for b in data if b > 127)
    if non_ascii / len(data) > 0.5:
        # But allow entries that contain valid ICC signatures
        ascii_substr = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        icc_sigs = ['acsp', 'desc', 'XYZ ', 'TRC', 'para', 'curv', 'mluc',
                    'clrt', 'A2B', 'B2A', 'D2B', 'B2D', 'gamt', 'chad',
                    'RGB ', 'CMYK', 'Lab ', 'Gray', 'mntr', 'prtr', 'scnr']
        if any(sig in ascii_substr for sig in icc_sigs):
            return False
        return True
    return False


def is_too_long(data):
    """Entries >16 decoded bytes are too specific to be useful tokens."""
    return len(data) > 16


def sanitize_escapes(line):
    """Convert C-style escapes to hex-only form for LibFuzzer compatibility.

    LibFuzzer only supports \\xNN, \\\\, and \\" in dict entries.
    Convert \\n→\\x0a, \\r→\\x0d, \\t→\\x09, \\0→\\x00.
    Also strip inline comments after the closing quote.
    """
    stripped = line.rstrip('\n')
    m = re.match(r'^((?:\w+=)?)"(.*)"(\s*#.*)?$', stripped)
    if not m:
        return line  # not a dict entry
    prefix = m.group(1)  # optional key=
    inner = m.group(2)

    # Convert C-style escapes to hex
    inner = inner.replace('\\n', '\\x0a')
    inner = inner.replace('\\r', '\\x0d')
    inner = inner.replace('\\t', '\\x09')
    inner = inner.replace('\\0', '\\x00')

    return f'{prefix}"{inner}"\n'


def classify_entry(raw):
    """Classify an entry and return (keep, reason)."""
    data = decode_entry(raw)

    if is_cxx_abi(raw):
        return False, "cxx_abi"
    if is_asan_pattern(data):
        return False, "asan_shadow"
    if is_too_long(data):
        return False, "too_long"
    if is_address_like(raw, data):
        return False, "address_ptr"
    if is_high_entropy_noise(raw, data):
        return False, "high_entropy"
    return True, "keep"


def prune_dict(input_path, output_path=None, dry_run=False, show_stats=False):
    """Prune noise from a fuzzer dictionary file."""
    safe_input = _sanitize_path(input_path)
    if not os.path.exists(safe_input):
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        return 1

    with open(safe_input) as f:
        lines = f.readlines()

    kept_lines = []
    seen_entries = set()
    stats = {
        "total": 0, "kept": 0, "duplicate": 0,
        "cxx_abi": 0, "asan_shadow": 0, "too_long": 0,
        "address_ptr": 0, "high_entropy": 0,
        "comments": 0, "blank": 0
    }

    for line in lines:
        stripped = line.rstrip('\n')

        # Preserve blank lines (up to 1 between sections)
        if not stripped.strip():
            stats["blank"] += 1
            if kept_lines and kept_lines[-1].strip():
                kept_lines.append(line)
            continue

        # Preserve comments
        if stripped.strip().startswith('#'):
            stats["comments"] += 1
            kept_lines.append(line)
            continue

        # Sanitize escapes (convert \n/\r/\t to \xNN, strip inline comments)
        line = sanitize_escapes(line)
        stripped = line.rstrip('\n')

        # Extract entry content
        m = re.match(r'^(?:\w+=)?"(.*)"$', stripped)
        if not m:
            kept_lines.append(line)
            continue

        raw = m.group(1)
        stats["total"] += 1

        # Deduplicate
        if raw in seen_entries:
            stats["duplicate"] += 1
            continue
        seen_entries.add(raw)

        # Classify
        keep, reason = classify_entry(raw)
        if keep:
            stats["kept"] += 1
            kept_lines.append(line)
        else:
            stats[reason] += 1

    # Strip trailing blank lines
    while kept_lines and not kept_lines[-1].strip():
        kept_lines.pop()
    kept_lines.append('\n')

    removed = stats["total"] - stats["kept"]

    if show_stats or dry_run:
        print(f"Dictionary: {input_path}")
        print(f"  Total entries:    {stats['total']}")
        print(f"  Kept:             {stats['kept']}")
        print(f"  Removed:          {removed}")
        print(f"    Duplicates:     {stats['duplicate']}")
        print(f"    C++ ABI:        {stats['cxx_abi']}")
        print(f"    ASAN shadow:    {stats['asan_shadow']}")
        print(f"    Too long (>16): {stats['too_long']}")
        print(f"    Address ptrs:   {stats['address_ptr']}")
        print(f"    High entropy:   {stats['high_entropy']}")
        print(f"  Comments:         {stats['comments']}")

    if removed == 0:
        if show_stats:
            print("  No changes needed.")
        return 2

    if dry_run:
        print(f"\n  Would write {stats['kept']} entries"
              f" (removed {removed})")
        return 0

    # Write output
    out_path = _sanitize_path(output_path or input_path)
    with open(out_path, 'w') as f:
        f.writelines(kept_lines)

    total_in_file = sum(1 for l in kept_lines
                        if l.strip().startswith('"'))
    print(f"Written: {out_path} ({total_in_file} entries,"
          f" removed {removed})")
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Prune noise entries from LibFuzzer dictionaries"
    )
    parser.add_argument("input", help="Input dictionary file")
    parser.add_argument("output", nargs="?",
                        help="Output file (default: overwrite input)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show what would be removed without writing")
    parser.add_argument("--stats", action="store_true",
                        help="Show detailed statistics")
    parser.add_argument("--all", action="store_true",
                        help="Process all *_fuzzer.dict files in cfl/")
    args = parser.parse_args()

    if args.all:
        import glob
        dict_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__)))), "cfl")
        dicts = sorted(glob.glob(os.path.join(dict_dir, "*_fuzzer.dict")))
        if not dicts:
            print("No *_fuzzer.dict files found", file=sys.stderr)
            return 1
        total_removed = 0
        for d in dicts:
            result = prune_dict(d, dry_run=args.dry_run,
                                show_stats=args.stats)
            if result == 0:
                total_removed += 1
            print()
        print(f"Processed {len(dicts)} dictionaries,"
              f" {total_removed} modified")
        return 0

    return prune_dict(args.input, args.output,
                      dry_run=args.dry_run, show_stats=args.stats)


if __name__ == "__main__":
    sys.exit(main())
