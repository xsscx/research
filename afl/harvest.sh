#!/usr/bin/env bash
# harvest.sh — Download AFL++ CI artifacts, deduplicate, seed local fuzzing, report
#
# Usage:
#   ./afl/harvest.sh                          # latest run, download + report
#   ./afl/harvest.sh --run-id 12345           # specific run
#   ./afl/harvest.sh --seed-local             # download + inject into local AFL/CFL
#   ./afl/harvest.sh --seed-ssd /mnt/g/fuzz-ssd  # download + inject into SSD
#   ./afl/harvest.sh --list                   # list available artifacts
#   ./afl/harvest.sh --report-only            # report on existing harvest dir
#
set -euo pipefail

REPO="xsscx/research"
HARVEST_DIR="${HARVEST_DIR:-/tmp/afl-harvest}"
TARGET="fromcube"
SEED_LOCAL=0
SEED_SSD=""
LIST_ONLY=0
REPORT_ONLY=0
RUN_ID=""

usage() {
    cat <<EOF
AFL++ Harvest — Download CI artifacts, deduplicate, seed, report

Usage: $0 [OPTIONS]

Options:
  --run-id ID        Download from specific workflow run
  --seed-local       Inject into local cfl/ corpus + AFL seed dirs
  --seed-ssd PATH    Inject into SSD fuzzing directory
  --harvest-dir DIR  Override harvest directory (default: /tmp/afl-harvest)
  --list             List available AFL artifacts
  --report-only      Report on existing harvest directory
  -h, --help         Show this help

Examples:
  $0                              # Download latest, generate report
  $0 --seed-local                 # Download + inject into cfl/corpus
  $0 --seed-ssd /mnt/g/fuzz-ssd  # Download + inject into SSD
  $0 --list                       # Show available artifacts
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --run-id)     RUN_ID="$2"; shift 2 ;;
        --seed-local) SEED_LOCAL=1; shift ;;
        --seed-ssd)   SEED_SSD="$2"; shift 2 ;;
        --harvest-dir) HARVEST_DIR="$2"; shift 2 ;;
        --list)       LIST_ONLY=1; shift ;;
        --report-only) REPORT_ONLY=1; shift ;;
        -h|--help)    usage ;;
        *)            echo "Unknown option: $1"; usage ;;
    esac
done

# --- List available artifacts ---
if [[ "$LIST_ONLY" -eq 1 ]]; then
    echo "=== AFL Artifacts in $REPO ==="
    gh run list --repo "$REPO" \
        --workflow=libfuzzer-smoke-test.yml --limit 5 \
        --json databaseId,status,conclusion,displayTitle,createdAt \
        --jq '.[] | "\(.databaseId) | \(.conclusion) | \(.createdAt) | \(.displayTitle)"'
    echo ""
    gh run list --repo "$REPO" \
        --workflow=cfl-libfuzzer-parallel.yml --limit 5 \
        --json databaseId,status,conclusion,displayTitle,createdAt \
        --jq '.[] | "\(.databaseId) | \(.conclusion) | \(.createdAt) | \(.displayTitle)"'
    exit 0
fi

# --- Find latest successful run with AFL artifacts ---
if [[ -z "$RUN_ID" ]]; then
    echo "[*] Finding latest run with AFL corpus artifact..."
    RUN_ID=$(gh run list --repo "$REPO" \
        --workflow=libfuzzer-smoke-test.yml --limit 10 --status completed \
        --json databaseId,conclusion \
        --jq '.[] | select(.conclusion == "success") | .databaseId' | head -1)

    if [[ -z "$RUN_ID" ]]; then
        # Try parallel workflow
        RUN_ID=$(gh run list --repo "$REPO" \
            --workflow=cfl-libfuzzer-parallel.yml --limit 10 --status completed \
            --json databaseId,conclusion \
            --jq '.[] | select(.conclusion == "success") | .databaseId' | head -1)
    fi

    if [[ -z "$RUN_ID" ]]; then
        echo "[!] No successful runs found with AFL artifacts"
        exit 1
    fi
fi
echo "[+] Using run ID: $RUN_ID"

# --- Download artifacts ---
if [[ "$REPORT_ONLY" -eq 0 ]]; then
    mkdir -p "$HARVEST_DIR"/{corpus,crashes,hangs,stats,report}

    echo "[*] Downloading AFL corpus artifact..."
    gh run download "$RUN_ID" --repo "$REPO" \
        --name "afl-fromcube-corpus-${RUN_ID}" \
        --dir "$HARVEST_DIR/corpus" 2>/dev/null || \
    gh run download "$RUN_ID" --repo "$REPO" \
        --pattern "afl-fromcube-corpus-*" \
        --dir "$HARVEST_DIR/corpus" 2>/dev/null || \
    echo "[!] No corpus artifact found (may be older run format)"

    echo "[*] Downloading AFL crashes/stats artifact..."
    gh run download "$RUN_ID" --repo "$REPO" \
        --name "afl-fromcube-crashes-${RUN_ID}" \
        --dir "$HARVEST_DIR/crashes" 2>/dev/null || \
    gh run download "$RUN_ID" --repo "$REPO" \
        --pattern "afl-fromcube-crashes-*" \
        --dir "$HARVEST_DIR/crashes" 2>/dev/null || \
    # Legacy format (single artifact)
    gh run download "$RUN_ID" --repo "$REPO" \
        --pattern "afl-fromcube-*" \
        --dir "$HARVEST_DIR/crashes" 2>/dev/null || \
    echo "[!] No crashes artifact found"
fi

# --- Deduplicate corpus ---
echo ""
echo "=== Deduplication ==="

CORPUS_FILES=$(find "$HARVEST_DIR/corpus" -type f ! -name '.gitignore' ! -name 'README*' 2>/dev/null | wc -l)
echo "[*] Downloaded corpus files: $CORPUS_FILES"

if [[ "$CORPUS_FILES" -gt 0 ]]; then
    # Deduplicate by content hash
    DEDUP_DIR="$HARVEST_DIR/corpus-dedup"
    mkdir -p "$DEDUP_DIR"
    DUPES=0
    UNIQUE=0

    while IFS= read -r -d '' file; do
        HASH=$(sha256sum "$file" | cut -c1-16)
        EXT="${file##*.}"
        DEST="$DEDUP_DIR/afl-ci-${HASH}"
        if [[ ! -f "$DEST" ]]; then
            cp "$file" "$DEST"
            UNIQUE=$((UNIQUE + 1))
        else
            DUPES=$((DUPES + 1))
        fi
    done < <(find "$HARVEST_DIR/corpus" -type f ! -name '.gitignore' ! -name 'README*' -print0 2>/dev/null)

    echo "[+] Unique corpus entries: $UNIQUE"
    echo "[+] Duplicates skipped: $DUPES"
else
    UNIQUE=0
    echo "[!] No corpus files to deduplicate"
fi

# --- Crashes ---
CRASH_FILES=$(find "$HARVEST_DIR/crashes" -type f -name 'id:*' 2>/dev/null | wc -l)
HANG_FILES=$(find "$HARVEST_DIR/crashes" -path '*/hangs/*' -type f 2>/dev/null | wc -l)
echo ""
echo "=== Findings ==="
echo "[*] Crashes: $CRASH_FILES"
echo "[*] Hangs: $HANG_FILES"

# --- Stats ---
STATS_FILE=$(find "$HARVEST_DIR" -name 'fuzzer_stats' -type f 2>/dev/null | head -1)
if [[ -n "$STATS_FILE" ]]; then
    echo ""
    echo "=== CI Fuzzer Stats ==="
    grep -E 'execs_done|execs_per|corpus_count|saved_crashes|saved_hangs|bitmap_cvg|cycles_done|stability' \
        "$STATS_FILE" 2>/dev/null || true
fi

# --- Seed local corpora ---
if [[ "$SEED_LOCAL" -eq 1 && "$UNIQUE" -gt 0 ]]; then
    echo ""
    echo "=== Seeding Local Corpora ==="

    # Seed CFL LibFuzzer corpus
    CFL_CORPUS="cfl/icc_fromcube_fuzzer_seed_corpus"
    if [[ -d "$CFL_CORPUS" ]]; then
        BEFORE=$(ls "$CFL_CORPUS" | wc -l)
        cp -n "$HARVEST_DIR/corpus-dedup/"* "$CFL_CORPUS/" 2>/dev/null || true
        AFTER=$(ls "$CFL_CORPUS" | wc -l)
        echo "[+] CFL seed corpus: $BEFORE → $AFTER files"
    fi

    # Seed local AFL input
    AFL_INPUT="/mnt/g/fuzz-ssd/afl-fromcube/input"
    if [[ -d "$AFL_INPUT" ]]; then
        BEFORE=$(ls "$AFL_INPUT" | wc -l)
        cp -n "$HARVEST_DIR/corpus-dedup/"* "$AFL_INPUT/" 2>/dev/null || true
        AFTER=$(ls "$AFL_INPUT" | wc -l)
        echo "[+] AFL local input: $BEFORE → $AFTER files"
    fi
fi

# --- Seed SSD ---
if [[ -n "$SEED_SSD" && "$UNIQUE" -gt 0 ]]; then
    echo ""
    echo "=== Seeding SSD ==="
    AFL_SSD_INPUT="$SEED_SSD/afl-fromcube/input"
    mkdir -p "$AFL_SSD_INPUT"
    BEFORE=$(ls "$AFL_SSD_INPUT" 2>/dev/null | wc -l)
    cp -n "$HARVEST_DIR/corpus-dedup/"* "$AFL_SSD_INPUT/" 2>/dev/null || true
    AFTER=$(ls "$AFL_SSD_INPUT" | wc -l)
    echo "[+] SSD AFL input: $BEFORE → $AFTER files"
fi

# --- Generate report ---
REPORT="$HARVEST_DIR/report/harvest-report.md"
{
    echo "# AFL++ Harvest Report"
    echo ""
    echo "| Field | Value |"
    echo "|-------|-------|"
    echo "| Run ID | $RUN_ID |"
    echo "| Date | $(date -u '+%Y-%m-%d %H:%M UTC') |"
    echo "| Target | iccFromCube |"
    echo "| Downloaded | $CORPUS_FILES files |"
    echo "| Unique (dedup) | $UNIQUE files |"
    echo "| Crashes | $CRASH_FILES |"
    echo "| Hangs | $HANG_FILES |"

    if [[ -n "$STATS_FILE" ]]; then
        echo ""
        echo "## CI Fuzzer Stats"
        echo '```'
        grep -E 'execs_done|execs_per|corpus_count|saved_crashes|saved_hangs|bitmap_cvg|cycles_done|stability' \
            "$STATS_FILE" 2>/dev/null || true
        echo '```'
    fi

    if [[ "$CRASH_FILES" -gt 0 ]]; then
        echo ""
        echo "## Crash Files"
        echo '```'
        find "$HARVEST_DIR/crashes" -type f -name 'id:*' 2>/dev/null | while read f; do
            echo "$(basename "$f") ($(stat -c%s "$f" 2>/dev/null || stat -f%z "$f" 2>/dev/null) bytes)"
        done
        echo '```'
    fi

    echo ""
    echo "## Seeding Status"
    if [[ "$SEED_LOCAL" -eq 1 ]]; then
        echo "- ✅ Seeded local CFL corpus and AFL input"
    fi
    if [[ -n "$SEED_SSD" ]]; then
        echo "- ✅ Seeded SSD at $SEED_SSD"
    fi
    if [[ "$SEED_LOCAL" -eq 0 && -z "$SEED_SSD" ]]; then
        echo "- ⏭️ No seeding requested (use --seed-local or --seed-ssd)"
    fi

    echo ""
    echo "## Corpus Location"
    echo "- Raw: \`$HARVEST_DIR/corpus/\`"
    echo "- Deduplicated: \`$HARVEST_DIR/corpus-dedup/\`"

} > "$REPORT"

echo ""
echo "=== Report ==="
cat "$REPORT"
echo ""
echo "[+] Report saved: $REPORT"
echo "[+] Harvest complete"
