#!/usr/bin/env python3
"""convert-libfuzzer-dict.py — Convert LibFuzzer recommended dictionary output to proper dict format.

Usage:
  # From a saved file (LibFuzzer stdout or CI log):
  convert-libfuzzer-dict.py  INPUT_FILE  OUTPUT_DICT  [--append]

  # From stdin (pipe from gh CLI):
  gh run view 12345 --log | convert-libfuzzer-dict.py -  cfl/icc_link_fuzzer.dict --append

The script:
  1. Extracts entries between "Recommended dictionary" markers (or all quoted lines)
  2. Converts octal escapes (\\NNN) to hex (\\xNN)
  3. Strips inline comments (# Uses: ...)
  4. Deduplicates against existing entries in the output dict
  5. Validates every entry parses correctly

Exit codes:
  0 = success (entries written)
  1 = error
  2 = no new entries found
"""

import argparse
import os
import re
import sys


def _sanitize_path(path):
    """Resolve and validate a file path to prevent path traversal."""
    resolved = os.path.realpath(path)
    # Must be under the repo root or /tmp
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


# ── Fuzzer → dict mapping ──────────────────────────────────────────────
# Mirrors the lookup order in cfl-libfuzzer-parallel.yml:
#   1. ${FUZZER_NAME}.dict   (fuzzer-specific)
#   2. icc_core.dict         (fallback)
#   3. icc.dict              (legacy fallback)
DICT_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__)))), "cfl")

FUZZER_DICT_MAP = {
    "icc_apply_fuzzer":         "icc_apply_fuzzer.dict",
    "icc_applynamedcmm_fuzzer": "icc_applynamedcmm_fuzzer.dict",
    "icc_applyprofiles_fuzzer": "icc_applyprofiles_fuzzer.dict",
    "icc_calculator_fuzzer":    "icc_calculator_fuzzer.dict",
    "icc_deep_dump_fuzzer":     "icc_deep_dump_fuzzer.dict",
    "icc_dump_fuzzer":          "icc_dump_fuzzer.dict",
    "icc_fromxml_fuzzer":       "icc_fromxml_fuzzer.dict",
    "icc_io_fuzzer":            "icc_io_fuzzer.dict",
    "icc_link_fuzzer":          "icc_link_fuzzer.dict",
    "icc_multitag_fuzzer":      "icc_multitag_fuzzer.dict",
    "icc_profile_fuzzer":       "icc_profile_fuzzer.dict",
    "icc_roundtrip_fuzzer":     "icc_roundtrip_fuzzer.dict",
    "icc_specsep_fuzzer":       "icc_specsep_fuzzer.dict",
    "icc_spectral_fuzzer":      "icc_spectral_fuzzer.dict",
    "icc_tiffdump_fuzzer":      "icc_tiffdump_fuzzer.dict",
    "icc_toxml_fuzzer":         "icc_toxml_fuzzer.dict",
    "icc_v5dspobs_fuzzer":      "icc_v5dspobs_fuzzer.dict",
}


def octal_to_hex(match):
    """Convert a single octal escape \\NNN to hex \\xNN."""
    val = int(match.group(1), 8)
    return "\\x{:02x}".format(val)


def normalize_entry(line):
    """Convert a raw LibFuzzer dict line to clean format.

    Handles:
      - Double-escaped octal from CI logs: \\\\NNN  → \\xNN
      - Single-escaped octal from files:   \\NNN    → \\xNN
      - Inline comments:  "..." # Uses: N  → "..."
      - Escaped quotes inside entries: \\" → \\x22
    """
    line = line.strip()
    if not line.startswith('"'):
        return None

    # Strip inline comment after closing quote
    # Match: "..." then optional whitespace then # ...
    entry_match = re.match(r'^("(?:[^"\\]|\\.)*")\s*(?:#.*)?$', line)
    if not entry_match:
        return None
    entry = entry_match.group(1)

    # Convert double-escaped octal (from CI logs): \\NNN
    entry = re.sub(r'\\\\(\d{3})', octal_to_hex, entry)

    # Convert single-escaped octal: \NNN (but not \xNN which is already hex)
    entry = re.sub(r'\\(\d{3})', octal_to_hex, entry)

    # Convert escaped quotes inside entries to \x22
    # Match \" that is NOT at the start or end of the entry
    inner = entry[1:-1]  # strip surrounding quotes
    inner = inner.replace('\\"', '\\x22')
    entry = '"' + inner + '"'

    return entry


def extract_entries(text):
    """Extract dict entries from LibFuzzer output or CI log text."""
    lines = text.splitlines()
    entries = []
    in_dict_block = False

    for line in lines:
        # Strip ANSI escape codes and CI timestamp prefixes
        line = re.sub(r'\x1b\[[0-9;]*m', '', line)
        line = re.sub(r'^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s*', '', line)

        if "Recommended dictionary" in line and "End" not in line:
            in_dict_block = True
            continue
        if "End of recommended dictionary" in line:
            in_dict_block = False
            continue

        # Only process lines that look like dict entries
        stripped = line.strip()
        if stripped.startswith('"'):
            if in_dict_block or not any(
                kw in text for kw in ["Recommended dictionary"]
            ):
                entry = normalize_entry(stripped)
                if entry:
                    entries.append(entry)

    return entries


def load_existing(path):
    """Load existing entries from a dict file."""
    safe_path = _sanitize_path(path)
    if not os.path.exists(safe_path):
        return set()
    existing = set()
    with open(safe_path) as f:
        for line in f:
            line = line.strip()
            if line.startswith('"'):
                existing.add(line)
    return existing


def validate_entry(entry):
    """Basic validation that entry is well-formed."""
    if not entry.startswith('"') or not entry.endswith('"'):
        return False
    if len(entry) < 2:
        return False
    # Check for unescaped quotes in the middle
    inner = entry[1:-1]
    i = 0
    while i < len(inner):
        if inner[i] == '"':
            return False  # unescaped quote
        if inner[i] == '\\':
            i += 1  # skip escaped char
        i += 1
    return True


def _decode_entry_bytes(raw):
    """Decode a raw dict entry string into bytes for quality filtering."""
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
        result.append(ord(raw[i]))
        i += 1
    return bytes(result)


def is_noise_entry(entry):
    """Filter out corpus noise: address pointers, ASAN patterns, C++ ABI.

    Returns (is_noise, reason) tuple.
    """
    inner = entry[1:-1]  # strip surrounding quotes
    data = _decode_entry_bytes(inner)

    # C++ ABI symbols
    cxx_markers = ['__cxxabi', 'St9type_info', 'N10__', '_ZN', '_ZT']
    if any(m in inner for m in cxx_markers):
        return True, "cxx_abi"

    # ASAN shadow memory patterns
    poison = [b'\xf5\xf5', b'\xfa\xfa', b'\xf1\xf1', b'\xf2\xf2',
              b'\xf3\xf3', b'\xf8\xf8']
    if any(p in data for p in poison):
        return True, "asan_shadow"

    # Too long (>16 decoded bytes rarely useful as fuzzer tokens)
    if len(data) > 16:
        return True, "too_long"

    # Address-like pointers (7-8 byte entries ending in null bytes)
    if len(data) in (7, 8) and data.endswith(b'\x00\x00'):
        non_null = data.rstrip(b'\x00')
        if len(non_null) >= 2:
            high_bytes = sum(1 for b in non_null if b > 0x40)
            if high_bytes >= len(non_null) * 0.3:
                return True, "address_ptr"

    # High-entropy noise (>= 8 bytes, mostly non-ASCII)
    if len(data) >= 8:
        non_ascii = sum(1 for b in data if b > 127)
        if non_ascii / len(data) > 0.5:
            return True, "high_entropy"

    return False, None


def main():
    parser = argparse.ArgumentParser(
        description="Convert LibFuzzer recommended dictionary to proper dict format"
    )
    parser.add_argument(
        "input", help="Input file (LibFuzzer output, CI log, or - for stdin)"
    )
    parser.add_argument("output", help="Output dictionary file path")
    parser.add_argument(
        "--append", action="store_true",
        help="Append to existing dict (default: create/overwrite)"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be added without writing"
    )
    parser.add_argument(
        "--list-dicts", action="store_true",
        help="List all fuzzer→dict mappings and exit"
    )
    args = parser.parse_args()

    if args.list_dicts:
        print("Fuzzer → Dictionary mappings:")
        print(f"  Dict directory: {DICT_DIR}")
        print()
        for fuzzer, dictfile in sorted(FUZZER_DICT_MAP.items()):
            path = os.path.join(DICT_DIR, dictfile)
            exists = "[OK]" if os.path.exists(path) else "[FAIL]"
            count = 0
            if os.path.exists(path):
                with open(_sanitize_path(path)) as f:
                    count = sum(1 for l in f if l.strip().startswith('"'))
            print(f"  {exists} {fuzzer:36s} → {dictfile} ({count} entries)")
        return 0

    # Read input
    if args.input == "-":
        text = sys.stdin.read()
    else:
        safe_input = _sanitize_path(args.input)
        if not os.path.exists(safe_input):
            print(f"Error: input file not found: {args.input}", file=sys.stderr)
            return 1
        with open(safe_input) as f:
            text = f.read()

    # Extract and normalize entries
    entries = extract_entries(text)
    if not entries:
        print("No dictionary entries found in input", file=sys.stderr)
        return 2

    # Deduplicate within input
    seen = []
    seen_set = set()
    for e in entries:
        if e not in seen_set:
            seen_set.add(e)
            seen.append(e)
    entries = seen

    # Validate
    invalid = [e for e in entries if not validate_entry(e)]
    if invalid:
        print(f"Warning: {len(invalid)} invalid entries skipped:", file=sys.stderr)
        for e in invalid:
            print(f"  {e}", file=sys.stderr)
        entries = [e for e in entries if validate_entry(e)]

    # Quality filter: remove corpus noise
    noise_count = 0
    clean_entries = []
    for e in entries:
        is_noise, reason = is_noise_entry(e)
        if is_noise:
            noise_count += 1
        else:
            clean_entries.append(e)
    if noise_count:
        print(f"Filtered: {noise_count} noise entries removed"
              " (address ptrs, ASAN, C++ ABI, high entropy)")
    entries = clean_entries

    # Deduplicate against existing dict
    existing = load_existing(args.output) if args.append else set()
    new_entries = [e for e in entries if e not in existing]

    print(f"Input:    {len(entries)} valid entries extracted")
    if args.append:
        print(f"Existing: {len(existing)} entries in {args.output}")
    print(f"New:      {len(new_entries)} unique entries to add")

    if not new_entries:
        print("No new entries to add")
        return 2

    if args.dry_run:
        print("\nEntries that would be added:")
        for e in new_entries:
            print(f"  {e}")
        return 0

    # Write output
    safe_output = _sanitize_path(args.output)
    if args.append and os.path.exists(safe_output):
        with open(safe_output, "a") as f:
            f.write("\n# --- added by convert-libfuzzer-dict.py ---\n")
            for e in new_entries:
                f.write(e + "\n")
    else:
        header = os.path.basename(safe_output).replace(".dict", "")
        with open(safe_output, "w") as f:
            f.write(f"# {header} dictionary — LibFuzzer tokens\n")
            f.write("# Generated by .github/scripts/convert-libfuzzer-dict.py\n")
            f.write("\n")
            for e in new_entries:
                f.write(e + "\n")

    # Count total
    total = len(load_existing(args.output))
    print(f"Written:  {args.output} ({total} total entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
