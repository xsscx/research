#!/bin/bash
#
# ramdisk-cheatsheet.sh — One-liner reference commands for ramdisk fuzzing
#
# Quick-reference commands you can copy/paste. Not meant to be run as a script.
# For the full automated workflow, use: sudo ./ramdisk-fuzz.sh
#

cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════╗
║               ICC Fuzzer Ramdisk — Quick Reference                 ║
╚══════════════════════════════════════════════════════════════════════╝

── 1. MOUNT A RAMDISK ─────────────────────────────────────────────────

  # Mount 4 GB tmpfs ramdisk
  sudo mkdir -p /tmp/fuzz-ramdisk && sudo mount -t tmpfs -o size=4G,noatime tmpfs /tmp/fuzz-ramdisk

  # Mount 8 GB ramdisk (longer campaigns)
  sudo mkdir -p /tmp/fuzz-ramdisk && sudo mount -t tmpfs -o size=8G,noatime tmpfs /tmp/fuzz-ramdisk

  # Verify mount
  df -h /tmp/fuzz-ramdisk

── 2. SEED CORPUS TO RAMDISK ──────────────────────────────────────────

  # Copy all seed corpora to ramdisk
  for f in cfl/bin/icc_*_fuzzer; do name=$(basename "$f"); mkdir -p /tmp/fuzz-ramdisk/corpus-${name}; [ -d "cfl/${name}_seed_corpus" ] && cp cfl/${name}_seed_corpus/* /tmp/fuzz-ramdisk/corpus-${name}/; done

  # Copy existing on-disk corpus too
  for d in cfl/corpus-*; do [ -d "$d" ] && cp -r "$d" /tmp/fuzz-ramdisk/; done

  # Seed xif/ ICC profiles into all ICC fuzzers (1852 profiles)
  for d in /tmp/fuzz-ramdisk/corpus-icc_*; do find xif/ -maxdepth 1 -type f -exec sh -c 'file -b "$1" | grep -qi "color profile"' _ {} \; -exec cp -n {} "$d/" \; ; done

  # Seed xif/ TIFF files into tiffdump fuzzer (254 TIFFs)
  find xif/ -maxdepth 1 -type f -exec sh -c 'file -b "$1" | grep -qi tiff' _ {} \; -exec cp -n {} /tmp/fuzz-ramdisk/corpus-icc_tiffdump_fuzzer/ \;

── 3. RUN A SINGLE FUZZER ─────────────────────────────────────────────

  # Quick 60-second smoke test on ramdisk
  cfl/bin/icc_profile_fuzzer -max_total_time=60 -detect_leaks=0 -timeout=30 -rss_limit_mb=4096 -use_value_profile=1 -max_len=65536 -artifact_prefix=/tmp/fuzz-ramdisk/ -dict=cfl/icc.dict /tmp/fuzz-ramdisk/corpus-icc_profile_fuzzer

  # 5-minute run with coverage stats
  cfl/bin/icc_profile_fuzzer -max_total_time=300 -print_final_stats=1 -detect_leaks=0 -timeout=30 -rss_limit_mb=4096 -use_value_profile=1 -max_len=65536 -artifact_prefix=/tmp/fuzz-ramdisk/ -dict=cfl/icc.dict /tmp/fuzz-ramdisk/corpus-icc_profile_fuzzer

  # 4-hour XML toxml fuzzer run on ramdisk
  FUZZ_TMPDIR=/tmp/fuzz-ramdisk LLVM_PROFILE_FILE=/dev/null \
    /tmp/fuzz-ramdisk/bin/icc_toxml_fuzzer -max_total_time=14400 -detect_leaks=0 \
    -timeout=30 -rss_limit_mb=4096 -use_value_profile=1 -max_len=65536 \
    -artifact_prefix=/tmp/fuzz-ramdisk/ \
    -dict=/tmp/fuzz-ramdisk/dict/icc_toxml_fuzzer.dict \
    /tmp/fuzz-ramdisk/corpus-icc_toxml_fuzzer/

── 4. RUN ALL FUZZERS IN PARALLEL ─────────────────────────────────────

  # All 17 fuzzers, 300s each, parallel jobs per fuzzer
  sudo ./cfl/ramdisk-fuzz.sh 300

  # All 17 fuzzers, 60s smoke test
  sudo ./cfl/ramdisk-fuzz.sh 60

  # Only specific fuzzers
  sudo ./cfl/ramdisk-fuzz.sh 120 icc_profile_fuzzer icc_io_fuzzer icc_fromxml_fuzzer

── 5. CORPUS MERGE / MINIMIZE ON RAMDISK ──────────────────────────────

  # Merge corpus (deduplicate, keep only coverage-increasing inputs)
  mkdir -p /tmp/fuzz-ramdisk/merged-icc_profile_fuzzer && cfl/bin/icc_profile_fuzzer -merge=1 -detect_leaks=0 /tmp/fuzz-ramdisk/merged-icc_profile_fuzzer /tmp/fuzz-ramdisk/corpus-icc_profile_fuzzer cfl/icc_profile_fuzzer_seed_corpus

  # Minimize a crashing input
  cfl/bin/icc_profile_fuzzer -minimize_crash=1 -detect_leaks=0 -max_total_time=120 -artifact_prefix=/tmp/fuzz-ramdisk/ /tmp/fuzz-ramdisk/crash-XXXX

── 6. SYNC CORPUS BACK TO DISK ────────────────────────────────────────

  # Sync all ramdisk corpora back to cfl/
  for d in /tmp/fuzz-ramdisk/corpus-*; do name=$(basename "$d"); rsync -a "$d/" "cfl/$name/"; done

  # Copy any crash artifacts
  cp /tmp/fuzz-ramdisk/crash-* /tmp/fuzz-ramdisk/oom-* /tmp/fuzz-ramdisk/timeout-* cfl/findings/ 2>/dev/null; echo "Done"

── 7. UNMOUNT RAMDISK ─────────────────────────────────────────────────

  # Unmount (WARNING: all unsaved data is lost!)
  sudo umount /tmp/fuzz-ramdisk && sudo rmdir /tmp/fuzz-ramdisk

── 8. macOS RAMDISK (alternative) ─────────────────────────────────────

  # Create 4 GB RAM disk on macOS (4GB = 4*1024*1024*1024/512 = 8388608 sectors)
  DISK=$(hdiutil attach -nomount ram://8388608) && diskutil erasevolume HFS+ FuzzRamdisk $DISK && export RAMDISK="/Volumes/FuzzRamdisk"

  # Eject macOS ramdisk
  hdiutil detach /Volumes/FuzzRamdisk

══════════════════════════════════════════════════════════════════════
EOF
