# Cooperative Multi-Agent Development — Prompt

## Overview

This research repo is developed by multiple Copilot agents running on different platforms.
Each agent has different capabilities determined by its OS, toolchain, and hardware.
This prompt defines roles, handoff protocols, and efficiency strategies.

## Agent Roles

| Agent | Platform | Primary Tools | Responsibilities |
|-------|----------|--------------|------------------|
| **WSL-2** | Ubuntu 24.04 on WSL 2 | iccanalyzer-lite, CFL fuzzers, colorbleed_tools, MCP server, clang-18 | Fuzzing campaigns, profile analysis, coverage collection, call-graph generation |
| **macOS** | Darwin (Apple Silicon) | Xcode, iOS Simulator, xnuimagefuzzer, native builds | iOS image generation, iOS fuzzing, ICC profile extraction, TIFF/image corpus creation |
| **Cloud** | GitHub Actions (Linux) | Docker, CI workflows, CodeQL | Automated builds, security scanning, release packaging, artifact hosting |

## Platform Capability Matrix

| Capability | WSL-2 | macOS | Cloud CI |
|-----------|-------|-------|----------|
| Build iccanalyzer-lite | ✅ | ❌ (Linux-only ASAN) | ✅ |
| Run CFL fuzzers | ✅ | ❌ (clang-18 + fuzzer) | ✅ (limited time) |
| Build xnuimagefuzzer (native) | ❌ | ✅ | ❌ |
| Run iOS Simulator | ❌ | ✅ | ✅ (macOS runners) |
| Generate call graphs | ✅ | ❌ | ✅ |
| Analyze ICC profiles | ✅ | Partial (no binary) | ✅ |
| Collect LLVM coverage | ✅ | ✅ (native builds) | ✅ |
| Extract ICC from images | ✅ (libtiff) | ✅ (libtiff + ImageIO) | ✅ |
| Run MCP server | ✅ | ✅ | ✅ |
| Create TIFF test images | ❌ | ✅ (ImageIO/CoreGraphics) | ❌ |

## Handoff Protocols

### macOS → WSL-2: New Seeds
When macOS agent generates new images or extracts ICC profiles:
1. Place ICC profiles in `fuzz/graphics/icc/` (staging)
2. Place TIFF images in `fuzz/graphics/tif/` (staging)
3. Commit with message: `fuzz: add <N> <type> seeds from <source>`
4. WSL-2 agent pulls and seeds into CFL corpora:
   ```bash
   cp fuzz/graphics/icc/ios-gen-*.icc cfl/corpus-icc_profile_fuzzer/
   cp fuzz/graphics/tif/*.tif cfl/corpus-icc_tiff_fuzzer/
   ```

### WSL-2 → macOS: Crash Artifacts
When WSL-2 fuzzer finds a crash:
1. Minimize: `cfl/bin/<fuzzer> -minimize_crash=1 <crash_file>`
2. Triage with upstream: `iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <crash>`
3. Commit crash file to repo root: `crash-<sha>.icc`
4. Run analysis: `.github/scripts/analyze-profile.sh <crash>`
5. Commit report to `analysis-reports/`
6. macOS agent can test crash against ColorSync/ImageIO

### WSL-2 → Repository: Analysis Reports
When analyzing test profiles:
1. Run: `.github/scripts/analyze-profile.sh test-profiles/<name>.icc`
2. Commit report to `analysis-reports/<name>-analysis.md`
3. Use batch mode for bulk analysis (see below)

### Shared: Coverage Data
Both agents collect LLVM coverage:
- WSL-2: `LLVM_PROFILE_FILE=/tmp/profraw/<tool>_%m_%p.profraw`
- macOS: `LLVM_PROFILE_FILE=/tmp/profraw/fuzzer-%m_%p.profraw`
- Do NOT commit `.profraw` / `.profdata` files (gitignored)
- Commit coverage summaries to `analysis-reports/coverage-summary.md`

## File Ownership (Conflict Prevention)

| Path | Owner | Other Agents |
|------|-------|-------------|
| `cfl/` (fuzzers, patches, corpora) | WSL-2 | macOS seeds into `corpus-*/` only |
| `iccanalyzer-lite/` | WSL-2 | macOS read-only |
| `analysis-reports/` | WSL-2 | macOS read-only |
| `call-graph/` | WSL-2 | macOS read-only |
| `fuzz/graphics/icc/ios-gen-*` | macOS | WSL-2 consumes for seeding |
| `fuzz/graphics/tif/xig-*` | macOS | WSL-2 consumes for seeding |
| `xnuimagetools/` | macOS | WSL-2 read-only |
| `.github/prompts/` | Both | Coordinate via PR if conflicts |
| `.github/instructions/` | Both | Coordinate via PR if conflicts |
| `.github/copilot-instructions.md` | Both | High conflict risk — merge carefully |
| `test-profiles/` | Both | WSL-2 adds crash PoCs, macOS adds extracted profiles |

## Efficiency Strategies

### WSL-2 Agent — Prioritized Task List

#### High Priority (Coverage & Analysis Gaps)
1. **Batch-analyze ~300 unanalyzed test profiles** (currently 28/329 = 8.5%):
   ```bash
   for f in test-profiles/*.icc; do
     bn=$(basename "$f" .icc)
     [ -f "analysis-reports/${bn}-analysis.md" ] && continue
     .github/scripts/analyze-profile.sh "$f"
   done
   ```
   Commit in batches of 50 to avoid giant commits.

2. **Regenerate coverage data** (current profdata is out of sync):
   ```bash
   .github/scripts/ramdisk-seed.sh --mount
   # Run all 18 fuzzers for 300s each
   cfl/fuzz-local.sh -t 300
   .github/scripts/merge-profdata.sh
   .github/scripts/generate-coverage-report.sh
   ```

3. **Seed starved corpora** — These fuzzers have minimal seeds:
   | Fuzzer | Current Seeds | Action |
   |--------|--------------|--------|
   | `icc_spectral_fuzzer` | 1 file (32K) | Add spectral/MVIS profiles from test-profiles/ |
   | `icc_fromxml_fuzzer` | 3 files (24K) | Add XML from `fuzz/xml/icc/` (42 files available) |
   | `corpus-xml` (shared) | 5 files (48K) | Merge with `fuzz/xml/icc/minimized/` (74 files) |
   | `icc_apply_fuzzer` | 8 files (5.5M) | Add diverse class profiles |
   | `icc_link_fuzzer` | 9 files (5.5M) | Add deviceLink profiles |
   | `icc_applyprofiles_fuzzer` | 12 files (308K) | Add multi-channel + TIFF inputs |

4. **Run targeted fuzzing on weak coverage areas** (from coverage-summary.md):
   - `IccCmmSearch`: 0% coverage → needs `icc_applynamedcmm_fuzzer` seeds
   - `IccEnvVar`: 23-50% → exercise environment variable paths
   - `IccApplyBPC`: 33% → needs BPC-enabled profiles
   - Target: 65%+ line coverage (current: 59.01%)

#### Medium Priority (Infrastructure)
5. **Upstream sync check** — Verify CFL patches against latest iccDEV:
   ```bash
   cd cfl/iccDEV && git fetch origin
   git --no-pager log --oneline HEAD..origin/master | head -10
   ```

6. **Refresh call graphs** after any code changes:
   ```bash
   python3 call-graph/scripts/generate-callgraphs.py
   ```

#### Low Priority (Nice to Have)
7. **Cross-validate iOS-extracted profiles** with iccanalyzer-lite:
   - `fuzz/graphics/icc/ios-gen-sRGB-IEC61966-2.1.icc`
   - `fuzz/graphics/icc/ios-gen-Display-P3.icc`
   - `fuzz/graphics/icc/ios-gen-Adobe-RGB-1998.icc`

8. **Generate TIFF-with-ICC test images** for H139-H141 testing

### macOS Agent — Prioritized Task List

#### High Priority
1. **Generate diverse ICC-bearing images** via iOS Image Generator:
   - Target under-represented classes: `abst`, `nmcl`, `link`
   - Use `--iterations 100` for statistical diversity
   - Stage outputs to `fuzz/graphics/icc/` and `fuzz/graphics/tif/`

2. **Test CFL crash files against ColorSync**:
   ```bash
   for crash in crash-*.icc; do
     sips --getProperty all "$crash" 2>&1 | head -5
   done
   ```

3. **Run xnuimagefuzzer against new seeds**:
   ```bash
   cd xnuimagetools && ./build-native.sh --build-only
   FUZZ_ICC_DIR=../fuzz/graphics/icc /tmp/native-build/xnuimagetools --iterations 50
   ```

#### Medium Priority
4. **Collect native coverage** to compare with WSL fuzzer coverage
5. **Test TIFF images from fuzz/graphics/tif/** against ImageIO

## Batch Analysis Script for WSL-2

The WSL-2 agent should use this pattern for bulk profile analysis:

```bash
#!/bin/bash
# Batch-analyze all unanalyzed test profiles
# Run on WSL-2 where iccanalyzer-lite binary exists

BATCH_SIZE=50
COUNT=0
TOTAL=0

for f in test-profiles/*.icc; do
  bn=$(basename "$f" .icc)
  [ -f "analysis-reports/${bn}-analysis.md" ] && continue
  TOTAL=$((TOTAL + 1))
done

echo "Found $TOTAL unanalyzed profiles"

for f in test-profiles/*.icc; do
  bn=$(basename "$f" .icc)
  [ -f "analysis-reports/${bn}-analysis.md" ] && continue

  .github/scripts/analyze-profile.sh "$f"
  COUNT=$((COUNT + 1))

  if [ $((COUNT % BATCH_SIZE)) -eq 0 ]; then
    git add analysis-reports/
    git commit -m "analysis: batch ${COUNT}/${TOTAL} profile reports

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
    git push
  fi
done

# Final commit for remainder
if [ $((COUNT % BATCH_SIZE)) -ne 0 ]; then
  git add analysis-reports/
  git commit -m "analysis: final batch ${COUNT}/${TOTAL} profile reports

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>"
  git push
fi
```

## Coverage Target Roadmap

| Milestone | Functions | Lines | Branches | How |
|-----------|-----------|-------|----------|-----|
| Current | 59.81% | 59.01% | 56.76% | — |
| +5% | 65% | 64% | 62% | Seed starved corpora, 4h fuzzing runs |
| +10% | 70% | 69% | 67% | Targeted seeds for 0% modules, new dict entries |
| +15% | 75% | 74% | 72% | New harness for uncovered tool paths |

## Communication Protocol

1. **Before modifying shared files** (instructions, prompts, copilot-instructions.md):
   - Check `git --no-pager log --oneline -5 -- <file>` to see recent changes
   - If other agent modified within last commit, coordinate via PR

2. **After pushing changes**: Leave a descriptive commit message so other agent
   can `git log --oneline -5` and understand what changed

3. **Conflict resolution**: If merge conflict occurs, the agent that encounters
   it resolves by preserving both agents' additions (append, don't replace)

## See Also
- [upstream-sync.prompt.md](upstream-sync.prompt.md) — Patch reconciliation workflow
- [corpus-management.prompt.md](corpus-management.prompt.md) — Corpus storage operations
- [cve-enrichment.prompt.md](cve-enrichment.prompt.md) — CVE-to-heuristic mapping
