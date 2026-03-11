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

# Build CFL fuzzers (clones iccDEV, applies patches, builds 11 fuzzers)
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

### macOS Docker Usage (MCP API for remote analysis)
The MCP Docker image is `linux/amd64` only. On Apple Silicon Macs, **Docker Desktop**
runs it via Rosetta 2 automatically — ASAN works correctly under Rosetta 2.

**⚠️ Colima and OrbStack are NOT supported** — they use QEMU or Virtualization.framework
backends that cannot handle ASAN shadow memory mappings. The container will build but
ASAN-instrumented binaries will crash at runtime. Use **Docker Desktop** only.

```bash
# Pull and run (Docker Desktop + Rosetta 2 handles AMD64→ARM64 translation)
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -d -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp web

# Upload and analyze profiles without local build tools
curl -s -F "file=@profile.icc" http://localhost:8080/api/upload
curl -s "http://localhost:8080/api/security-json?path=<uploaded_path>"
curl -s "http://localhost:8080/api/full?path=<uploaded_path>"
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
- Platform: `linux/amd64` only (ASAN+UBSAN require native x86_64 or Docker Desktop Rosetta 2)
- Two modes: `mcp` (default, stdio for MCP clients), `web` (REST API + HTML UI)
- **Full ASAN+UBSAN instrumentation** — catches memory safety bugs during analysis
- Apple Silicon Macs: **Docker Desktop only** (Rosetta 2 supports ASAN correctly)
- **Colima/OrbStack NOT supported** — QEMU/VZ backends cannot handle ASAN shadow memory

## Analysis Report Gap — Current State (Updated 2026-03-08)

**Analyzed**: 39 profiles/images with full 141-heuristic reports in `analysis-reports/`
**Total test profiles**: 329 ICC profiles in `test-profiles/` (+ 426 crash/oom/slow-unit/timeout artifacts)
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
- Add v5/iccMAX `spac` and `cenc` profiles to `icc_v5dspobs_fuzzer`
- Generate TIFF+ICC test images for `icc_tiffdump_fuzzer` (H139-H141 coverage)

## Profile Class Distribution (test-profiles/)

| Class | Count | In CFL Corpora? | Notes |
|-------|-------|-----------------|-------|
| spac (ColorSpace) | 182 | Few | v5/iccMAX, needs `icc_v5dspobs_fuzzer` seeds |
| mntr (Display) | 47 | Well-seeded | Dominant class in most corpora |
| scnr (Input/Scanner) | 13 | Some | Add to profile/dump/apply fuzzers |
| prtr (Output/Printer) | 11 | ✅ Fixed (4 seeds × 7 fuzzers) | Session 2026-03-08 |
| mid (Material ID) | 8 | Rare | v5-specific, needs `icc_v5dspobs_fuzzer` |
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

## Anti-Patterns — Mistakes to Avoid

These are real mistakes made during multi-agent collaboration. Do NOT repeat them.
Patterns #6-#10 are adapted from <a href="https://github.com/xsscx/governance">xsscx/governance</a>
LLMCJF (LLM Content Jockey Framework) — empirically documented agent failure modes.

### 1. Removing ASAN/UBSAN from Docker for multi-arch builds
**What happened**: A cloud agent added `NO_SANITIZERS=1` to enable ARM64+AMD64 builds
via QEMU cross-compilation. This removed the security instrumentation that is the
entire purpose of iccanalyzer-lite.
**Why it's wrong**: ASAN shadow memory is incompatible with QEMU user-mode emulation,
but Apple Silicon Macs can run AMD64 images via **Docker Desktop** Rosetta 2 (which
supports ASAN correctly). Build `linux/amd64` only. **Colima and OrbStack do NOT
support ASAN** — they use QEMU/VZ backends that lack ASAN shadow memory support.
**Rule**: NEVER add `NO_SANITIZERS=1` to `mcp-server/Dockerfile` or remove
`libclang-rt-18-dev`. The Docker image MUST have full ASAN+UBSAN.

### 2. Updating server code without updating tests
**What happened**: Tool count was updated from 16→22→24 in `web_ui.py` and
`icc_profile_mcp.py`, but the corresponding tests (`test_web_ui.py` and
`test_mcp.py`) were not updated, causing repeated CI failures.
**Rule**: When changing MCP tool count, update ALL 4 files simultaneously:
`icc_profile_mcp.py`, `web_ui.py`, `test_mcp.py`, `test_web_ui.py`.

### 3. Claiming inflated counts without verifying on disk
**What happened**: A cloud agent reported 46 analysis reports and 336 test profiles,
but disk actually had 39 reports and 329 profiles.
**Rule**: Always verify counts with `find` or `ls | wc -l` before updating docs.

### 4. Creating duplicate Dockerfiles
**What happened**: `Dockerfile.demo` and `mcp-server/Dockerfile` diverged, requiring
fixes to be applied to both. `demo-docker-build.yml` and `mcp-server-docker.yml`
duplicated CI infrastructure.
**Rule**: One Dockerfile (`mcp-server/Dockerfile`), one workflow
(`mcp-server-docker.yml`), one image (`ghcr.io/xsscx/icc-profile-mcp`).

### 5. Claiming "build succeeded" without verifying all CI build paths
**What happened**: OpenSSL EVP dependency (`-lssl -lcrypto`) was added to
`iccanalyzer-lite/build.sh` but NOT to the CLI release workflow's independent
static LTO link command (`iccanalyzer-cli-release.yml` line ~488). Agent reported
"build succeeded" after running only `build.sh` locally. CI failed with
`ld.lld: error: undefined symbol: EVP_MD_CTX_new`.
**Why it's wrong**: The repo has **7 independent build locations** for iccanalyzer-lite
(see `.github/instructions/iccanalyzer-lite.instructions.md` Build System Sync table).
A local `build.sh` success does NOT guarantee CI success — the release workflow has
its own manual linker command with separate flags.
**Rule**: Before pushing, run `.github/scripts/pre-push-validate.sh` to verify all 7
build locations are synced. Never claim "build succeeded" based on a single build path.

### 6. False success claims — "Generate & Declare Without Testing" (CJF-09/CJF-12)
**What happened (governance V013-V016)**: Agent claimed to fix unicode removal and
copyright restoration, documented both as "complete", never tested either. User
discovered BOTH still broken, had to fix them AGAIN. Agent then claimed fuzzer
build success ("16/16 operational, 100%") without running `make` — all fabricated.
**The Loop**:
```
WRONG workflow:
  1. Make changes
  2. Declare "[OK] COMPLETE"
  3. User tests → FAILS
  4. User reports → Agent fixes → Declares "[OK] COMPLETE" again
  5. User tests → STILL FAILS

CORRECT workflow:
  1. Make changes
  2. Run verification command
  3. Include evidence: [OK] Verified: <claim> (<command> → <result>)
  4. Fix any issues found
  5. Re-verify
  6. THEN declare complete WITH evidence
```
**Rule**: NEVER claim success without showing the verification command and its output.
62.5% of all governance violations are this exact pattern.

### 7. Exit code confusion — documenting graceful failures as crashes (CJF-13)
**What happened (governance CJF-13)**: Fuzzer showed DEADLYSIGNAL, tool exited with
code 1 → Agent documented it as a SEGV crash. Exit code 1 means the tool rejected
the input gracefully — it is NOT a crash.
**Classification**:
- **Exit 1-127**: Soft failure (graceful) → **NOT a crash, do NOT document**
- **Exit 128+**: Hard crash (signal) → Document IF 3× reproducible
**Rule**: The TOOL's exit code is reality. The FUZZER's output is a test artifact.
When they disagree, the tool is authoritative.

### 8. Creating custom test programs instead of using project tools (CJF-11)
**What happened**: Agent created `/tmp/test_crash.cpp` to reproduce a crash instead
of using the existing `iccDEV/Build/Tools/` binaries.
**Rule**: ALWAYS use project tools for crash reproduction. The tools at
`iccDEV/Build/Tools/` are built with full ASAN+UBSAN. Custom programs miss library
patches, linker flags, and runtime configurations.

### 9. Ignoring documentation the agent itself created (CJF-07/V007)
**What happened (governance V007)**: Agent spent 45 minutes debugging SHA256 index
showing 0 when THREE comprehensive documentation files (that the agent created in
a prior session) explained the answer. User had to ask THREE TIMES "did you even
read the docs?" Total time wasted: 45 minutes. Answer took: 30 seconds.
**Rule**: Before debugging, check existing documentation. `grep -r` the error or
topic across `.github/`, `docs/`, and `README.md` files. If documentation exists,
read it before reinventing.

### 10. Scope creep — unsolicited documentation instead of testing (CJF-10)
**What happened**: User asked agent to "test the fuzzer". Agent created 5 markdown
files documenting the fuzzer architecture instead of running it.
**Rule**: When asked to test, TEST. When asked to build, BUILD. Do not substitute
documentation for the requested action.

### 11. API tests pass but rendered WebUI is broken (CJF-14)
**What happened**: Agent modified `index.html` forms for `validate_xml`, claimed
"210/210 WebUI tests pass" and pushed. User opened `http://localhost:8080/#validate_xml`
and found no XML files listed, wrong form rendered. Root cause: `test_web_ui.py`
validated API responses (HTTP status codes, JSON payloads) but NOT that
`renderInputs()` generates correct form fields for each tool. Multiple tools
(`validate_xml`, `batch_test`, `scan_logs`, `build_tools`, `find_artifacts`,
`coverage_report`, `upload_and_analyze`) fell through to the default `else` branch
which renders a generic ICC profile selector instead of their actual inputs.
**The pattern**:
```
WRONG:
  1. Modify index.html renderInputs()
  2. Run python3 test_web_ui.py → "N/N passed"
  3. Claim success → push
  4. User opens browser → forms wrong → repeat

CORRECT:
  1. Modify index.html renderInputs()
  2. Run python3 test_web_ui.py → check "Form Fields Per Tool" section
  3. Open http://localhost:8080 in browser
  4. Click 5+ tools → verify correct form renders (not ICC profile selector)
  5. Check DevTools Console → 0 JavaScript errors
  6. THEN claim success WITH evidence:
     [OK] Verified: WebUI forms render correctly (browser test at localhost:8080,
     5 tools checked: validate_xml, cmake_configure, batch_test, compare, upload_and_analyze)
```
**Rule**: API tests verify backend correctness. Browser tests verify frontend
correctness. Both are required for WebUI changes. The `test_form_fields_per_tool()`
test in `test_web_ui.py` catches missing `inp-*` field IDs programmatically, but
visual rendering MUST be verified in a browser.

### 12. Misattributing ASAN findings by profile filename instead of stack trace (CJF-15)
**What happened (session 2026-03-10)**: Agent ran 230 tests, got 229/230 with an ASAN
HUAF in `IccImageAnalyzer.cpp:962`. Because the failing test used a profile named
`ub-runtime-error-type-confusion-CIccTagEmbeddedProfile`, agent classified it as
"pre-existing upstream iccDEV ASAN" and stored a memory saying "229/230 is stable
baseline, 1 upstream ASAN". User accepted this for multiple turns until noticing
the ASAN trace frames pointed at `IccImageAnalyzer.cpp` — OUR code. Bug was a
libtiff interior pointer lifetime issue (10-line fix in commit bfafaba). Agent's
wrong memory reinforced the error across subsequent turns.
**The classification error cascade**:
```
WRONG:
  1. See test failure with ASAN
  2. Read profile filename → "ub-...CIccTagEmbeddedProfile" → must be iccDEV
  3. Store memory: "229/230 stable, 1 upstream ASAN"
  4. All future turns skip investigation → bug festers

CORRECT:
  1. See test failure with ASAN
  2. Read ASAN stack frame #2-#3 → IccImageAnalyzer.cpp:962
  3. Classify: path contains "iccanalyzer-lite/" → OUR CODE
  4. Fix immediately (10 lines)
  5. Verify: 230/230
```
**Rule**: ALWAYS classify ASAN/UBSAN findings by **stack trace file paths** (frame #2-#3),
NEVER by profile filename or tag class name. Profile names describe the *trigger*;
stack frames identify the *bug location*. When storing regression baselines, include
the stack trace evidence.

### 13. Declaring patches applied based on dry-run output without ground-truth verification (CJF-16)
**What happened (session 2026-03-10)**: Agent claimed "6/6 patches apply cleanly"
and "SSD ready for fuzzing" based on `patch --dry-run --forward` output. User began
fuzzing at 12:10 UTC. At 12:47, user reported the pattern of false claims. Agent
spent until 13:08 building verification tooling that should have existed from the
first patch failure (sessions earlier). Total waste: ~58 minutes.
**Root cause**: `patch --dry-run --forward` masks 3 failure modes:
1. "Reversed or previously applied" — can't distinguish this-checkout vs stale-checkout
2. "Succeeded with fuzz/offset" — means WOULD apply again, not IS applied
3. Context-shifted FAIL — upstream changed lines near patch, dry-run fails but code IS present
**The compound cost**:
```
WRONG workflow (repeated across sessions):
  1. Run patch --dry-run --forward → "ok"
  2. Claim "6/6 patches applied"
  3. User discovers patches didn't actually compile in
  4. Agent re-investigates → fixes → claims success again
  5. Repeat steps 3-4

CORRECT workflow (do once, trust forever):
  1. Build verification script on FIRST failure
  2. Run cfl/verify-patches.sh after every build
  3. 3-phase ground truth: source grep + binary nm + runtime test
  4. Script output IS the evidence — not agent claims
```
**Rule**: NEVER declare CFL patches applied without running `cfl/verify-patches.sh`.
The script checks source code for patch additions, binary symbols for patched function
signatures, and runtime behavior for timeout artifact completion. Build verification
tooling on the FIRST failure, not after repeated incidents.

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


## Image+ICC Seed Pipeline

### Tool Ecosystem
| Tool | Repo | Platform | Purpose |
|------|------|----------|---------|
| xnuimagetools | github.com/xsscx/xnuimagetools | iOS/macOS/watchOS/visionOS | Umbrella workspace — uses xnuimagefuzzer as submodule |
| xnuimagefuzzer | github.com/xsscx/xnuimagefuzzer | iOS/macOS (Xcode) | Primary fuzzer — 15 CGCreateBitmap contexts, 22+ formats |
| iOSOnMac CLI | macos-research/code/iOSOnMac | macOS (CLI) | Run xnuimagefuzzer at scale via posix_spawn |
| colorbleed_tools | research/colorbleed_tools | Linux/macOS | Build ICC profiles (iccToXml/iccFromXml) |
| seed-pipeline.sh | .github/scripts/seed-pipeline.sh | Linux | Validate, embed ICC, distribute seeds |
| craft-seeds.py | .github/scripts/craft-seeds.py | Linux | Generate synthetic edge-case image seeds |

### Workflow
1. Create baseline images with xnuimagetools (macOS)
2. Fuzz images with xnuimagefuzzer (macOS) — 15 pixel formats x 30+ output formats
3. ICC variant generation (automatic for TIFF/PNG):
   - Real ICC profiles from FUZZ_ICC_DIR via CGColorSpaceCreateWithICCData (round-robin)
   - Stripped color space (DeviceRGB, no ICC metadata)
   - Mismatched profiles (CMYK/Gray/Lab/truncated on RGB)
   - Mutated ICC profiles (6 corruption strategies)
4. CI pipeline generates images on iOS Simulator + Mac Catalyst (with system ICC profiles)
5. Extract ICC seeds: extract-icc-seeds.py --inject-cfl ../cfl (automated in CI)
6. Validate + embed ICC: seed-pipeline.sh temp/ --distribute --ramdisk
7. Generate synthetic seeds: craft-seeds.py --outdir temp/icc-crafted
8. Re-seed ramdisk: .github/scripts/ramdisk-seed.sh

### Quality Gates (seed-pipeline.sh)
- Reject files < 64 bytes (truncated)
- Reject images with < 5 unique pixel values (flat/degenerate)
- Validate TIFF magic bytes (II*/MM* or BigTIFF)
- Deduplicate by MD5 content hash
- Enforce max size = 5MB (max_len limit)

### Known Issues with xnuimagefuzzer Output
- 32BitFloat and HDR float fuzzed variants produce all-zero pixels (CoreGraphics clamps float to 8-bit)
- LittleEndian-image.tiff is actually big-endian (MM) — name refers to CGColorSpace component order
- ICC variants require FUZZ_ICC_DIR for real/mutated profiles; stripped and mismatched are always generated
- kCGImagePropertyICCProfile does NOT exist in Apple SDKs — use CGColorSpaceCreateWithICCData()
- xnuimagetools is the source of truth for xnuimagefuzzer.m; always sync after changes
- Mac Catalyst CI job sets FUZZ_ICC_DIR=/System/Library/ColorSync/Profiles for system ICC profiles
- xnuimagetools build-and-test.yml has 8 jobs: build-ios, generate-images, generate-catalyst-images,
  generate-ios-gen-images, build-watch, commit-images, extract-seeds

## macOS CI Patterns (xnuimagefuzzer / xnuimagetools)

These patterns apply to the xnuimagefuzzer/ and xnuimagetools/ sub-repos within this workspace.
xnuimagetools uses xnuimagefuzzer as a git submodule at XNU Image Fuzzer/.
All CI checkout steps in xnuimagetools use submodules: recursive.

### SIGPIPE Prevention
NEVER pipe macOS/BSD tools (ls, file, find, xcodebuild, xcrun) through | head.
They use NSFileHandle for stdout and crash with NSFileHandleOperationException (SIGABRT exit 134)
or stdout: Undefined error: 0 when the reader closes early.

Safe alternatives:
- Instead of: ls -la /tmp/output/ | head -20   Use: ls -la /tmp/output/ | sed -n '1,20p'
- Instead of: xcodebuild -version | head -1     Use: xcodebuild -version | sed -n '1p'
- Instead of: file -b "" | head -c 40       Use: file -b "" | cut -c1-40

### LLVM Profraw Coverage Symbols
Use dlsym(RTLD_DEFAULT, "__llvm_profile_write_file") instead of __attribute__((weak)) extern.
Weak extern works on Mac Catalyst with -fprofile-instr-generate but causes linker failures on
iOS Simulator builds without coverage flags. The dlsym() approach works across all configurations.

### Mac Catalyst App Launch in CI
Mac Catalyst binaries must be launched via open "" (bare Mach-O exits immediately).
- open blocks until app exits — use open "" & ; disown 
- Pass env vars via open --env KEY=VALUE (macOS 13+) — launchctl setenv is unreliable
- Mac Catalyst ignores osascript quit — use pgrep -f "App Name" + send signal
- SIGTERM does NOT trigger atexit() — send SIGINT first for profraw flush

### VideoToolbox ASAN Performance
VideoToolbox fuzzer runs 10-50x slower under ASAN. Never call malloc_zone_print() in hot
loops under ASAN — it dumps entire memory zone per call. The VT instrumented CI job is disabled
(if: false in xnuimagetools/.github/workflows/instrumented.yml). Run VT ASAN testing on
local macOS hardware with extended timeouts (10+ minutes).

### xnuimagefuzzer Output Expectations
17 seed specs x 6 files each (seed + corrupted + 4 format variants) = 102 expected files.
CI polling threshold must be >=80 with 120s timeout. The app uses FUZZ_OUTPUT_DIR env var
for output directory and generates PNG, JPEG, GIF, BMP, TIFF, HEIF formats.

### Pinned Action SHAs (both sub-repos)
- actions/checkout: 11bd71901bbe5b1630ceea73d27597364c9af683 (v4.2.2)
- actions/upload-artifact: ea165f8d65b6e75b540449e92b4886f43607fa02 (v4.6.2)
- actions/cache: 5a3ec84eff668545956fd18022155c47e93e2684 (v4.2.3)
- actions/download-artifact: d3f86a106a0bac45b974a628896c90dbdf5c8093 (v4.3.0)
