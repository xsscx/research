# Cooperative Multi-Agent Development -- Prompt

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
| Build iccanalyzer-lite | Yes | No (Linux-only ASAN) | Yes |
| Run CFL fuzzers | Yes | No (clang-18 + fuzzer) | Yes (limited time) |
| Build xnuimagefuzzer (native) | No | Yes | No |
| Run iOS Simulator | No | Yes | Yes (macOS runners) |
| Generate call graphs | Yes | No | Yes |
| Analyze ICC profiles (local) | Yes | Partial (no binary) | Yes |
| Analyze ICC profiles (remote) | N/A | Yes (via MCP Docker API) | Yes (via MCP Docker API) |
| Collect LLVM coverage | Yes | Yes (native builds) | Yes |
| Extract ICC from images | Yes (libtiff) | Yes (libtiff + ImageIO) | Yes |
| Run MCP server (local) | Yes | Yes | Yes |
| Run MCP Docker API | Yes (host) | Yes (client) | Yes (client) |
| Create TIFF test images | No | Yes (ImageIO/CoreGraphics) | No |

## Handoff Protocols

### macOS -> WSL-2: New Seeds
When macOS agent generates new images or extracts ICC profiles:
1. Place ICC profiles in `fuzz/graphics/icc/` (staging)
2. Place TIFF images in `fuzz/graphics/tif/` (staging)
3. Commit with message: `fuzz: add <N> <type> seeds from <source>`
4. WSL-2 agent pulls and seeds into CFL corpora:
   ```bash
   cp fuzz/graphics/icc/ios-gen-*.icc cfl/corpus-icc_profile_fuzzer/
   cp fuzz/graphics/tif/*.tif cfl/corpus-icc_tiffdump_fuzzer/
   ```

### WSL-2 -> macOS: Crash Artifacts
When WSL-2 fuzzer finds a crash:
1. Minimize: `cfl/bin/<fuzzer> -minimize_crash=1 <crash_file>`
2. Triage with upstream: `iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <crash>`
3. Commit crash file to repo root: `crash-<sha>.icc`
4. Run analysis: `.github/scripts/analyze-profile.sh <crash>`
5. Commit report to `analysis-reports/`
6. macOS agent can test crash against ColorSync/ImageIO

### WSL-2 -> Repository: Analysis Reports
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

### Any Agent -> MCP Docker API: Remote Analysis (No Git Required)

When an agent needs ICC profile analysis but lacks the binary (macOS) or wants
to avoid commit overhead:

1. Ensure the MCP Docker API is running on a reachable host:
   ```bash
   docker run --rm -d -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp web
   ```
2. Upload the profile via REST:
   ```bash
   curl -s -F "file=@profile.icc" http://<host>:8080/api/upload
   ```
3. Retrieve analysis (choose one or more):
   ```bash
   curl -s "http://<host>:8080/api/security-json?path=<uploaded_path>"  # JSON
   curl -s "http://<host>:8080/api/full?path=<uploaded_path>"           # combined
   curl -s "http://<host>:8080/api/xml?path=<uploaded_path>"            # ICC->XML
   ```
4. If the result warrants preservation, commit the report via git.

**Benefits**: Eliminates 2 git commits per profile (upload + report). Only
final noteworthy results get committed. Ideal for triage of many profiles.

See `.github/prompts/remote-analysis.prompt.md` for the full workflow.

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
| `.github/copilot-instructions.md` | Both | High conflict risk -- merge carefully |
| `test-profiles/` | Both | WSL-2 adds crash PoCs, macOS adds extracted profiles |

## Efficiency Strategies

### WSL-2 Agent -- Prioritized Task List

#### High Priority (Coverage & Analysis Gaps)
1. **Batch-analyze ~280 unanalyzed test profiles** (currently 49/329 = 14.9%):
   ```bash
   for f in test-profiles/*.icc; do
     bn=$(basename "$f" .icc)
     [ -f "analysis-reports/${bn}-analysis.md" ] && continue
     .github/scripts/analyze-profile.sh "$f"
   done
   ```
   Commit in batches of 50 to avoid giant commits.

2. **Expand `icc_fromcube_fuzzer.dict`** -- currently **282 lines** (critically small vs
   1500-6000+ for other dicts). Auto-extract from corpus + add .cube edge cases.

3. ~~**Create CFL-011 patch**~~ -- Yes Done. `iccSpecSepToTiff.cpp:207-208,232`
   alloc-dealloc-mismatch fixed (CFL-011 in active patches).

4. **Seed spectral TIFFs into CFL corpora**:
   ```bash
   cp test-profiles/spectral/spec_*.tif cfl/corpus-icc_specsep_fuzzer/
   cp test-profiles/spectral/spec_*.tif cfl/corpus-icc_tiffdump_fuzzer/
   ```

5. **Run targeted fuzzing on weak coverage areas** (from coverage-summary.md):
   - `IccCmmSearch`: 0% coverage -> needs `icc_applynamedcmm_fuzzer` seeds
   - `IccEnvVar`: 23-50% -> exercise environment variable paths
   - `IccApplyBPC`: 33% -> needs BPC-enabled profiles
   - Target: 65%+ line coverage (current: 59.01%)

6. **Fix remaining iccDEV CI test failures** (~7 of 89):
   - v5-001/002/003: Generate/locate v5 observer profiles for iccV5DspObsToV4Dsp
   - dump-08 + xmlrt-named: Verify NamedColor.icc seed is valid (cascading failure)
   - ncm-05: Fix encoding=4 data format mismatch
   - search-04: Debug 3-profile chain initialization

#### Medium Priority (Infrastructure)
5. **Upstream sync check** -- Verify CFL patches against latest iccDEV:
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

8. ~~**Generate TIFF-with-ICC test images**~~ -- Yes Done. H139-H141 + H149-H150 tests
   added (9 tests), including corrupt TIFF edge cases (239/239 total).

### macOS Agent -- Prioritized Task List

#### High Priority
1. **Use MCP Docker API for ICC analysis** (avoids git commit overhead):
   ```bash
   # Upload and analyze profiles remotely -- see remote-analysis.prompt.md
   curl -s -F "file=@profile.icc" http://<host>:8080/api/upload
   curl -s "http://<host>:8080/api/security-json?path=<path>"
   ```

2. **Generate diverse ICC-bearing images** via iOS Image Generator:
   - Target under-represented classes: `abst`, `nmcl`, `link`
   - Use `--iterations 100` for statistical diversity
   - Stage outputs to `fuzz/graphics/icc/` and `fuzz/graphics/tif/`

3. **Test CFL crash files against ColorSync**:
   ```bash
   for crash in test-profiles/crash-*.icc test-profiles/hbo-*.icc test-profiles/sbo-*.icc; do
     sips --getProperty all "$crash" 2>&1 | head -5
   done
   ```

4. **Run xnuimagefuzzer against new seeds**:
   ```bash
   cd xnuimagetools && ./build-native.sh --build-only
   FUZZ_ICC_DIR=../test-profiles /tmp/native-build/xnuimagetools --iterations 50
   ```

#### Medium Priority
5. **Collect native coverage** to compare with WSL fuzzer coverage
6. **Test TIFF images from fuzz/graphics/tif/** against ImageIO
7. **Extract ICC profiles from Catalyst batch outputs** and seed into fuzz/

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

## Communication Protocol

1. **Before modifying shared files** (instructions, prompts, copilot-instructions.md):
   - Check `git --no-pager log --oneline -5 -- <file>` to see recent changes
   - If other agent modified within last commit, coordinate via PR

2. **After pushing changes**: Leave a descriptive commit message so other agent
   can `git log --oneline -5` and understand what changed

3. **Conflict resolution**: If merge conflict occurs, the agent that encounters
   it resolves by preserving both agents' additions (append, don't replace)

## See Also
- [upstream-sync.prompt.md](upstream-sync.prompt.md) -- Patch reconciliation workflow
- [corpus-management.prompt.md](corpus-management.prompt.md) -- Corpus storage operations
- [cve-enrichment.prompt.md](cve-enrichment.prompt.md) -- CVE-to-heuristic mapping
