#!/bin/bash
# afl/startup-roots.sh - Inspect ELF/C++ startup roots for reachability audits
#
# Usage: ./afl/startup-roots.sh <elf-or-object> [symbol-pattern]

set -euo pipefail

INPUT="${1:-}"
PATTERN="${2:-GLOBAL__sub_I|__cxx_global_var_init|CIccSimpleMatrix}"

usage() {
    sed -n '2,5p' "$0" | sed 's/^# \?//'
}

if [[ -z "$INPUT" || "$INPUT" == "--help" || "$INPUT" == "-h" ]]; then
    usage
    if [[ -z "$INPUT" ]]; then
        exit 1
    fi
    exit 0
fi

if [[ ! -e "$INPUT" ]]; then
    echo "ERROR: input not found: $INPUT" >&2
    exit 1
fi

for tool in readelf objdump nm c++filt; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "ERROR: required tool not found in PATH: $tool" >&2
        exit 1
    fi
done

echo "# AFL Startup Root Audit"
echo ""
echo "- Input: $INPUT"
echo "- Pattern: $PATTERN"
echo ""

echo "## Startup Sections"
readelf -S "$INPUT" | awk '/\.(preinit_array|init_array|fini_array|init)[[:space:]]/ {print}'
echo ""

echo "## Startup Relocations"
readelf -Wr "$INPUT" | awk '
    /^Relocation section/ {
        section=$3
        gsub(/\047/, "", section)
    }
    section ~ /\.rela\.(preinit_array|init_array|fini_array)/ && /^[[:xdigit:]]/ {
        print section "\t" $0
    }
'
echo ""

echo "## Matching Symbols"
nm -an "$INPUT" 2>/dev/null | c++filt | grep -E "$PATTERN" || true
echo ""

echo "## Matching Disassembly"
objdump -d --demangle "$INPUT" | grep -E -A8 -B4 "$PATTERN" || true
