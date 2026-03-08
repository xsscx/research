# Multi-Agent Coordination — Instructions

## Purpose

This document defines how multiple Copilot agents (WSL-2/Linux, macOS, Cloud CI)
coordinate when working on this repository. It prevents file conflicts, ensures
efficient division of labor, and establishes handoff protocols.

## Quick Start for Any Agent

1. Detect your platform (see Environment Detection)
2. `git fetch --all && git pull` to sync with other agents
3. Check `git --no-pager log --oneline -10` for recent agent activity
4. Read this file + `cooperative-development.prompt.md` for current priorities
5. Before modifying shared files, check `git log -3 -- <file>` for recent edits

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

# Cloud CI / Coding Agent
[ -f /workspace/.copilot-setup-complete ] && echo "Cloud CI (pre-built)"
```

## WSL-2 Agent Setup

### Prerequisites
- Ubuntu 24.04 on WSL 2
- clang-18, clang++-18, cmake 3.15+
- libxml2-dev, libtiff-dev, libclang-rt-18-dev, libssl-dev
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

## macOS Agent Setup

### Prerequisites
- macOS with Xcode 15+ and iOS Simulator
- Apple Silicon or Intel Mac
- Homebrew: `brew install libxml2 libtiff`

### Primary Tools
- **iOS Image Generator** (v1.9.0+): Generates ICC-bearing images across 13 contexts × 5 dimensions × 6 formats × 3 ICC profiles
- **xnuimagefuzzer**: Mutates images with ICC injection, mismatch, and strip variants
- **sips / ImageIO**: Test ICC/TIFF files against Apple's native parsers
- **ColorSync**: Validate crash files against macOS color management

### macOS Key Commands
```bash
# Build iOS Image Generator
cd xnuimagetools
xcodebuild -scheme 'XNU Image Generator for iOS' \
  -destination 'platform=iOS Simulator,id=<DEVICE_ID>'

# Run xnuimagefuzzer (native ASAN build)
cd xnuimagefuzzer && ./build-native.sh --build-only
FUZZ_ICC_DIR=../test-profiles /tmp/native-build/xnuimagetools --iterations 50

# Test crash PoC against ColorSync
sips --getProperty all crash-file.icc

# Extract ICC profiles from images
python3 contrib/scripts/extract-icc-seeds.py --input fuzzed-images/ --output /tmp/seeds
```

## Cloud CI Agent Setup

The cloud agent runs in Docker via `copilot-setup-steps.yml`. Binaries are pre-built.
**Do NOT run** `build.sh`, `cmake`, or `git clone` — everything is ready.

Pre-built binaries:
- `iccanalyzer-lite/iccanalyzer-lite`
- `colorbleed_tools/iccToXml_unsafe`
- `colorbleed_tools/iccFromXml_unsafe`

## Data Flow Between Agents

### Git-Based Flow (Default)

```
macOS Agent                    WSL-2 Agent                  Cloud CI
────────────                   ──────────                   ────────
iOS Image Generator ──→ fuzz/graphics/icc/ios-gen-*
xnuimagefuzzer      ──→ fuzz/graphics/tif/xig-*
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

### MCP Docker API Flow (Remote Analysis — Reduced Commit Traffic)

For profile analysis, any agent can use the MCP Docker API instead of committing
raw profiles + pulling reports via git. This avoids 2 commits per profile.

```
macOS/Cloud Agent                     WSL-2 Host (or any Docker host)
─────────────────                     ──────────────────────────────
                                      docker run -p 8080:8080 \
  curl -F file=@profile.icc  ───────→  ghcr.io/xsscx/icc-profile-mcp web
    POST /api/upload                    │
                                        ├── iccanalyzer-lite -a (141 heuristics)
  ← JSON {path: "/tmp/uploads/..."}     ├── iccanalyzer-lite --json
                                        └── colorbleed_tools/iccToXml_unsafe
  curl /api/security-json?path=... ──→  Returns structured JSON analysis
  curl /api/full?path=...          ──→  Returns full combined analysis
  curl /api/xml?path=...           ──→  Returns ICC→XML conversion
```

**API Endpoints for Remote Analysis**:

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/upload` | POST | Upload ICC/TIFF file (20MB max, multipart/form-data) |
| `/api/health` | GET | Liveness check (`{ok: true, tools: 24}`) |
| `/api/security?path=...` | GET | 141-heuristic scan (text) |
| `/api/security-json?path=...` | GET | 141-heuristic scan (structured JSON) |
| `/api/security-report?path=...` | GET | Severity-sorted professional report |
| `/api/inspect?path=...` | GET | Profile structure inspection |
| `/api/roundtrip?path=...` | GET | AToB/BToA tag pair validation |
| `/api/full?path=...` | GET | Combined analysis (all modes) |
| `/api/xml?path=...` | GET | ICC → XML conversion |
| `/api/xml/download?path=...` | GET | ICC → XML as file download |
| `/api/compare?path_a=...&path_b=...` | GET | Side-by-side profile diff |
| `/api/list?directory=...` | GET | List profiles in a directory |

**macOS Agent Usage Example**:
```bash
# Start MCP API server on WSL-2 host (one-time)
docker run --rm -d -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp web

# From macOS: upload and analyze a profile
curl -s -F "file=@harvested-profile.icc" http://<wsl-ip>:8080/api/upload
# → {"ok":true,"path":"/tmp/mcp-uploads/a1b2c3_harvested-profile.icc","filename":"harvested-profile.icc","size":41234}

curl -s "http://<wsl-ip>:8080/api/security-json?path=/tmp/mcp-uploads/a1b2c3_harvested-profile.icc"
# → Full 141-heuristic JSON analysis

curl -s "http://<wsl-ip>:8080/api/full?path=/tmp/mcp-uploads/a1b2c3_harvested-profile.icc"
# → Combined analysis (inspect + security + roundtrip)
```

**When to use API vs Git**:
- **Use API**: Quick analysis of individual profiles, triage, spot-checks
- **Use Git**: Batch analysis reports (preserved in `analysis-reports/`), crash PoCs,
  seed corpus additions, anything that should be version-controlled

**Docker Image Availability**:
- `ghcr.io/xsscx/icc-profile-mcp:latest` — built by `.github/workflows/mcp-server-docker.yml`
- Platforms: `linux/amd64`, `linux/arm64` (native on Apple Silicon — no QEMU needed)
- Two modes: `mcp` (default, stdio for MCP clients), `web` (REST API + HTML UI)
- Container binary built WITHOUT ASAN/UBSAN for multi-arch compatibility

## Analysis Report Gap — Current State (Updated 2026-03-08)

**Analyzed**: 46 profiles/images with full 141-heuristic reports in `analysis-reports/`
**Total test profiles**: 336 ICC/TIFF/XML profiles in `test-profiles/` (329 + 7 crash PoCs moved)
**Gap**: ~290 profiles still need analysis
**macOS agent activity**: Seeded 6 starved fuzzer corpora, organized docs, added cross-refs

### Completed Analysis (sessions to date)

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

## Corpus Seeding Status — Current State (Updated 2026-03-08)

### Recently Seeded (macOS agent, commit ae5f141)
The macOS agent seeded 6 previously-starved fuzzer corpora from test-profiles/
and fuzz/xml/icc/ — these are no longer urgent:

| Fuzzer | Before | After | Source |
|--------|--------|-------|--------|
| `icc_spectral_fuzzer` | 1 file | 7 files | `test-profiles/*MVIS*`, `*Spectral*` |
| `icc_fromxml_fuzzer` | 3 files | 120 files | `fuzz/xml/icc/*.xml` + `minimized/` |
| `icc_apply_fuzzer` | 8 files | 14 files | Diverse class profiles |
| `icc_applyprofiles_fuzzer` | 12 files | 17 files | Multi-channel profiles |
| `icc_link_fuzzer` | 9 files | 13 files | DeviceLink profiles |
| `corpus-xml` (shared) | 5 files | 48 files | XML sources |

### Well-Seeded Fuzzers
- `icc_profile_fuzzer`: 24+ files (5.7M)
- `icc_toxml_fuzzer`: 25+ files (5.7M)
- `icc_dump_fuzzer`: 22+ files (5.7M)
- `icc_fromcube_fuzzer`: 35 files (268K)

### Remaining Seed Opportunities
- Add more `abst` (Abstract) and `nmcl` (NamedColor) profiles — rare classes
- Add v5/iccMAX `spac` and `cenc` profiles to `icc_v5_fuzzer`
- Generate TIFF+ICC test images for `icc_tiff_fuzzer` (H139-H141 coverage)

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
- `chore:` — File moves, cleanup, organization

## Cross-Repository Structure

This project spans multiple git repositories. All are siblings under the same workspace:

| Repository | Path | Branch | Purpose |
|-----------|------|--------|---------|
| `xsscx/research` | `/research/` | `main` | Main repo: analyzer, CFL, call-graph, analysis |
| `xsscx/fuzz` | `/research/fuzz/` | `master` | Curated malicious input corpus (1,139 files) |
| `xsscx/xnuimagetools` | `/research/xnuimagetools/` | `main` | iOS Image Generator + xnuimagefuzzer |
| `xsscx/xnuimagefuzzer` | `/research/xnuimagefuzzer/` | `main` | iOS image fuzzer (submodule of xnuimagetools) |

**Important**: `fuzz/` is a separate git repo on branch `master` — commit/push directly
inside `fuzz/`. It is NOT a submodule. Similarly `xnuimagetools/` and `xnuimagefuzzer/`.

## Key Documentation Index

For any agent starting a session, these are the essential docs to read:

| Document | Path | Purpose |
|----------|------|---------|
| Main instructions | `.github/copilot-instructions.md` | Build commands, tool paths, spec references |
| This file | `.github/instructions/multi-agent.instructions.md` | Agent coordination |
| Cooperative dev | `.github/prompts/cooperative-development.prompt.md` | Task lists, coverage roadmap |
| Remote analysis | `.github/prompts/remote-analysis.prompt.md` | MCP Docker API workflow |
| iccanalyzer-lite | `.github/instructions/iccanalyzer-lite.instructions.md` | Analyzer build/test/heuristics |
| CFL fuzzers | `.github/instructions/cfl.instructions.md` | Fuzzer build/run/patch conventions |
| Corpus management | `.github/prompts/corpus-management.prompt.md` | Ramdisk/SSD lifecycle |
| Upstream sync | `.github/prompts/upstream-sync.prompt.md` | iccDEV patch reconciliation |
| Fuzzer optimization | `.github/prompts/fuzzer-optimization.prompt.md` | Per-fuzzer coverage strategies |
| CFL seed pipeline | xnuimagetools `.github/instructions/cfl-seed-pipeline.instructions.md` | macOS→CFL seeding |

## See Also
- [cooperative-development.prompt.md](../prompts/cooperative-development.prompt.md) — Task lists and coverage roadmap
- [remote-analysis.prompt.md](../prompts/remote-analysis.prompt.md) — MCP Docker API for remote analysis
- [upstream-sync.prompt.md](../prompts/upstream-sync.prompt.md) — Patch reconciliation workflow
- [corpus-management.prompt.md](../prompts/corpus-management.prompt.md) — Corpus storage operations
- [cve-enrichment.prompt.md](../prompts/cve-enrichment.prompt.md) — CVE-to-heuristic mapping
