# Multi-Agent Coordination — Instructions

## Purpose

This document defines how multiple Copilot agents (WSL-2/Linux, macOS, Cloud CI)
coordinate when working on this repository. It prevents file conflicts, ensures
efficient division of labor, and establishes handoff protocols.

## Environment Detection

Agents must identify their platform at session start:

```bash
# Linux/WSL-2
uname -s  # → Linux
cat /etc/os-release | grep -q Ubuntu && echo "WSL/Ubuntu"
ls iccanalyzer-lite/iccanalyzer-lite 2>/dev/null && echo "Binary available"

# macOS
uname -s  # → Darwin
xcodebuild -version 2>/dev/null && echo "Xcode available"
xcrun simctl list devices 2>/dev/null | head -3 && echo "iOS Simulator available"
```

## WSL-2 Agent Setup

### Prerequisites
- Ubuntu 24.04 on WSL 2
- clang-18, clang++-18, cmake 3.15+
- libxml2-dev, libtiff-dev, libclang-rt-18-dev
- Python 3.10+ with pip

### First-Run Build
```bash
# Build iccanalyzer-lite (ASAN+UBSAN+coverage)
cd iccanalyzer-lite && ./build.sh

# Build CFL fuzzers (clones iccDEV, applies patches, builds 18 fuzzers)
cd cfl && ./build.sh

# Build colorbleed_tools
cd colorbleed_tools && make setup && make

# Install MCP server
cd mcp-server && pip install -e .
```

### WSL-2 Performance Tuning
- **Ramdisk**: `sudo mount -t tmpfs -o size=4G tmpfs /tmp/fuzz-ramdisk`
  (WSL 2 tmpfs is backed by host RAM — very fast)
- **Sequential fuzzing**: Use `fuzz-local.sh` (1 fuzzer at a time, prevents OOM)
- **Parallel workers per fuzzer**: `-workers=4` (default in fuzz-local.sh)
- **Git operations**: Use `/home/` paths, NOT `/mnt/c/` (10× slower on NTFS)

## Data Flow Between Agents

```
macOS Agent                    WSL-2 Agent                  Cloud CI
────────────                   ──────────                   ────────
iOS Image Generator ──→ fuzz/graphics/icc/ios-gen-*
                         fuzz/graphics/tif/xig-*
                              │
                              ├─ git push ─────────────────→ CI triggers
                              │                              CodeQL scan
                              ▼                              Docker build
                         WSL-2 pulls ──→ Seeds into
                         cfl/corpus-*/
                              │
                         Fuzzing campaign ──→ crash-*.icc
                         Analysis ──→ analysis-reports/
                              │
                              ├─ git push ─────────────────→ CI triggers
                              ▼
macOS pulls ──→ Test crashes
               against ColorSync
               sips / ImageIO
```

## Analysis Report Gap — Current State (Updated 2026-03-08)

**Analyzed**: ~30 profiles/images with full 141-heuristic reports
**Recent batch**: 3 iOS-gen ICC profiles, 1 printer profile, 12 TIFFs (fuzzed + catalyst)
**Gap**: ~70 ICC profiles in `fuzz/graphics/icc/` still need analysis (mostly CVE variant PoCs)

### Completed Analysis (this session)

| Profile/Image | Type | Source | Findings |
|---------------|------|--------|----------|
| ios-gen-AdobeRGB1998.icc | ICC v2.1 | macOS iOS Image Generator | 0 ASAN/UBSAN |
| ios-gen-DisplayP3.icc | ICC v4.0 | macOS iOS Image Generator | 0 ASAN/UBSAN |
| ios-gen-sRGB-IEC61966.icc | ICC v2.1 | macOS iOS Image Generator | 0 ASAN/UBSAN |
| fuzzed-prtr-Lab-414k.icc | ICC v2.0 | macOS xnuimagefuzzer harvest | 7 WARN, 0 ASAN |
| catalyst-16bit-ITU2020.tiff | TIFF+ICC | macOS Catalyst batch 195825 | 0 ASAN/UBSAN |
| catalyst-32bit-ITU709.tiff | TIFF+ICC | macOS Catalyst batch 195825 | 0 ASAN/UBSAN |
| catalyst-8bit-ACESCG.tiff | TIFF+ICC | macOS Catalyst batch 195825 | 0 ASAN/UBSAN |
| catalyst-alpha-ROMMRGB.tiff | TIFF+ICC | macOS Catalyst batch 195825 | 0 ASAN/UBSAN |
| catalyst-LE-DisplayP3.tiff | TIFF+ICC | macOS Catalyst batch 195825 | 0 ASAN/UBSAN |
| catalyst-16bit-mutated.tiff | TIFF+ICC | macOS Catalyst batch 195825 | 0 ASAN/UBSAN |
| catalyst-16bit-mismatch.tiff | TIFF+ICC | macOS Catalyst batch 195825 | 0 ASAN/UBSAN |

### Priority Analysis Targets (remaining)

| Priority | Profile Pattern | Count | Reason |
|----------|----------------|-------|--------|
| Critical | CVE PoCs (`cve-*`) | ~15 | Security validation |
| Critical | Crash PoCs (`hbo-*`, `sbo-*`, `segv-*`) | ~20 | Bug coverage |
| High | Calculator variants (`calc*`) | ~60 | CWE-400 timeout patterns |
| High | Multi-channel (`*Chan*`, `*MVIS*`) | ~20 | High-dimensional fuzzing |
| Medium | Standard profiles (`sRGB*`, `Display*`) | ~10 | Baseline validation |
| Medium | v5/iccMAX profiles | ~180 | New spec coverage |
| Low | Malformed/PoC profiles | ~30 | Edge case validation |

## Corpus Seeding Gaps — Current State

### Starved Fuzzers (WSL-2 action items)

| Fuzzer | Seeds | Size | Source for New Seeds |
|--------|-------|------|---------------------|
| `icc_spectral_fuzzer` | 1 | 32K | `test-profiles/*MVIS*`, `*Spectral*` (6+ profiles) |
| `icc_fromxml_fuzzer` | 3 | 24K | `fuzz/xml/icc/*.xml` (42 files) + `minimized/` (74 files) |
| `corpus-xml` (shared) | 5 | 48K | Same XML sources |
| `icc_apply_fuzzer` | 8 | 5.5M | Diverse classes: `abst`, `link`, `nmcl` from test-profiles/ |
| `icc_link_fuzzer` | 9 | 5.5M | `test-profiles/*link*`, deviceLink profiles |
| `icc_applyprofiles_fuzzer` | 12 | 308K | Multi-channel profiles + TIFF inputs |

### Well-Seeded Fuzzers (no action needed)
- `icc_profile_fuzzer`: 24 files (5.7M)
- `icc_toxml_fuzzer`: 25 files (5.7M)
- `icc_dump_fuzzer`: 22 files (5.7M)
- `icc_fromcube_fuzzer`: 35 files (268K)

## Profile Class Distribution (test-profiles/)

| Class | Count | In CFL Corpora? | Notes |
|-------|-------|-----------------|-------|
| spac (ColorSpace) | 182 | Few | v5/iccMAX, needs `icc_v5_fuzzer` seeds |
| mntr (Display) | 47 | Well-seeded | Dominant class in most corpora |
| scnr (Input/Scanner) | 13 | Some | Add to profile/dump/apply fuzzers |
| prtr (Output/Printer) | 11 | ✅ Fixed (4 seeds × 7 fuzzers) | Session 2026-03-08 |
| mid (Material ID) | 8 | Rare | v5-specific, needs `icc_v5_fuzzer` |
| cenc (Color Encoding) | 8 | Rare | v5-specific |
| link (DeviceLink) | 8 | Few | Critical for `icc_link_fuzzer` |
| abst (Abstract) | 6 | Rare | Lab→Lab transforms |
| nmcl (NamedColor) | 5 | Rare | Named color palettes |
| mvis (MultiVisualization) | 3 | Rare | Spectral profiles |
| Malformed/PoC | ~30 | Most seeded | CVE/crash PoCs |

## Coverage Collection Protocol

### WSL-2 Coverage Workflow
```bash
# 1. Mount ramdisk
.github/scripts/ramdisk-seed.sh --mount

# 2. Run fuzzers with coverage
for fuzzer in /tmp/fuzz-ramdisk/bin/icc_*_fuzzer; do
  name=$(basename "$fuzzer" _fuzzer)
  LLVM_PROFILE_FILE="/tmp/fuzz-ramdisk/profraw/${name}_%m_%p.profraw" \
  ASAN_OPTIONS=detect_leaks=0 \
    "$fuzzer" -max_total_time=300 -detect_leaks=0 -timeout=30 \
    -rss_limit_mb=4096 -use_value_profile=1 \
    "/tmp/fuzz-ramdisk/corpus-$(basename $fuzzer)/"
done

# 3. Merge and report
.github/scripts/merge-profdata.sh
.github/scripts/generate-coverage-report.sh

# 4. Commit summary (NOT raw profdata)
git add analysis-reports/coverage-summary.md
git commit -m "coverage: $(date +%Y-%m-%d) CFL coverage update"
```

### macOS Coverage Workflow
```bash
# Native xnuimagefuzzer coverage
LLVM_PROFILE_FILE=/tmp/profraw/fuzzer-%m_%p.profraw \
  /tmp/native-build/xnuimagetools --iterations 50
llvm-profdata merge -sparse /tmp/profraw/*.profraw -o /tmp/merged.profdata
llvm-cov report /tmp/native-build/xnuimagetools -instr-profile=/tmp/merged.profdata
```

## Commit Message Convention for Multi-Agent Work

```
<type>: <description>

<body>

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```

Types:
- `analysis:` — Profile analysis reports
- `cfl:` — Fuzzer seeds, patches, dictionaries
- `coverage:` — Coverage data updates
- `fuzz:` — Corpus additions to fuzz/
- `docs:` — Documentation, prompts, instructions
- `fix:` — Bug fixes
- `call-graph:` — Call graph regeneration
