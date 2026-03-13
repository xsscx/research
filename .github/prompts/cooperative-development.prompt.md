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
| Analyze ICC profiles (local) | ✅ | Partial (no binary) | ✅ |
| Analyze ICC profiles (remote) | N/A | ✅ (via MCP Docker API) | ✅ (via MCP Docker API) |
| Collect LLVM coverage | ✅ | ✅ (native builds) | ✅ |
| Extract ICC from images | ✅ (libtiff) | ✅ (libtiff + ImageIO) | ✅ |
| Run MCP server (local) | ✅ | ✅ | ✅ |
| Run MCP Docker API | ✅ (host) | ✅ (client) | ✅ (client) |
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
   cp fuzz/graphics/tif/*.tif cfl/corpus-icc_tiffdump_fuzzer/
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

### Any Agent → MCP Docker API: Remote Analysis (No Git Required)

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
   curl -s "http://<host>:8080/api/xml?path=<uploaded_path>"            # ICC→XML
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
| `.github/copilot-instructions.md` | Both | High conflict risk — merge carefully |
| `test-profiles/` | Both | WSL-2 adds crash PoCs, macOS adds extracted profiles |

## Efficiency Strategies

### WSL-2 Agent — Prioritized Task List

#### High Priority (Coverage & Analysis Gaps)
1. **Batch-analyze ~290 unanalyzed test profiles** (currently 39/329 = 11.9%):
   ```bash
   for f in test-profiles/*.icc; do
     bn=$(basename "$f" .icc)
     [ -f "analysis-reports/${bn}-analysis.md" ] && continue
     .github/scripts/analyze-profile.sh "$f"
   done
   ```
   Commit in batches of 50 to avoid giant commits.

2. **Expand `icc_fromcube_fuzzer.dict`** — currently **282 lines** (critically small vs
   1500-6000+ for other dicts). Auto-extract from corpus + add .cube edge cases.

3. **Create CFL-011 patch** for `iccSpecSepToTiff.cpp:207-208,232` alloc-dealloc-mismatch:
   `unique_ptr<T>(new T[])` uses `delete` instead of `delete[]`. CWE-762.

4. **Seed spectral TIFFs into CFL corpora**:
   ```bash
   cp test-profiles/spectral/spec_*.tif cfl/corpus-icc_specsep_fuzzer/
   cp test-profiles/spectral/spec_*.tif cfl/corpus-icc_tiffdump_fuzzer/
   ```

5. **Run targeted fuzzing on weak coverage areas** (from coverage-summary.md):
   - `IccCmmSearch`: 0% coverage → needs `icc_applynamedcmm_fuzzer` seeds
   - `IccEnvVar`: 23-50% → exercise environment variable paths
   - `IccApplyBPC`: 33% → needs BPC-enabled profiles
   - Target: 65%+ line coverage (current: 59.01%)

6. **Fix remaining iccDEV CI test failures** (~7 of 89):
   - v5-001/002/003: Generate/locate v5 observer profiles for iccV5DspObsToV4Dsp
   - dump-08 + xmlrt-named: Verify NamedColor.icc seed is valid (cascading failure)
   - ncm-05: Fix encoding=4 data format mismatch
   - search-04: Debug 3-profile chain initialization

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
1. **Use MCP Docker API for ICC analysis** (avoids git commit overhead):
   ```bash
   # Upload and analyze profiles remotely — see remote-analysis.prompt.md
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

## Recent Session Accomplishments (2026-03-09)

### XML Reporting & WebUI Session
- H142-H145 XML safety heuristics fully integrated into all output modes
- XML export (`-xml`) uses ComprehensiveAnalyze with multi-line detail capture
- XSLT dark-themed stylesheet: 4 summary cards, specRef column, CVE cross-refs
- All stale heuristic counts synced to 150 across 10+ files
- All stale advisory counts synced to 93 across 6+ files

### MCP Server / WebUI Fixes
- `/api/security-json` stderr contamination fixed — `_run()` has `include_stderr` param
- CVE PoC crash recovery returns structured `crashRecovery` JSON (not empty/broken)
- Docker image uses `-O0 -g3` + coverage (not `-O1 -g` + `NO_COVERAGE=1`)
- `LLVM_PROFILE_FILE=/dev/null` prevents profraw permission errors
- Published image validated: all 11 endpoints return correct output

### CodeQL Alert Resolution
- 7 CodeQL alerts fixed: `cpp/new-free-mismatch` (std::nothrow in fork),
  `cpp/comparison-always-true` (loop→if), `cpp/use-after-expired-lifetime`
  (cached iterators→range-based for)
- Local CodeQL analysis workflow documented in `iccanalyzer-lite.instructions.md`
- Remaining alerts are custom query informational findings (not bugs)

## Coverage Target Roadmap

| Milestone | Functions | Lines | Branches | How |
|-----------|-----------|-------|----------|-----|
| Current | 59.81% | 59.01% | 56.76% | — |
| +5% | 65% | 64% | 62% | Seed starved corpora, 4h fuzzing runs |
| +10% | 70% | 69% | 67% | Targeted seeds for 0% modules, new dict entries |
| +15% | 75% | 74% | 72% | New harness for uncovered tool paths |

## Commit Discipline — Lessons from 50-Commit Analysis (March 2026)

Analysis of 50 consecutive commits showed only 26% was core mission work (CFL patches,
findings, analyzer improvements). The rest was infrastructure churn: CI fixes (28%),
housekeeping (20%), documentation (14%), test framework (12%).

### Rules

1. **≥50% of commits MUST be core mission** — CFL patches, crash findings, analyzer
   heuristics, fuzzer coverage improvements. If a session produces 10 commits, at
   least 5 must advance security research.

2. **Batch all housekeeping into 1 commit** — Artifact sorting (crash/oom/timeout
   file moves), gitignore updates, cleanup operations. Use scripts, not manual
   multi-commit work. Script: sort artifacts → stage → 1 commit.

3. **Batch all CI/workflow fixes into 1 commit** — Validate locally BEFORE pushing:
   `shellcheck --severity=warning *.sh`, `yamllint *.yml`. The push→fail→fix→push
   cycle wastes commits. Target: ≤2 CI commits per session.

4. **Bundle docs with code** — Documentation changes (patch tables, README updates,
   instruction files) go in the same commit as the code they describe. Exception:
   standalone docs (new prompt files, analysis plans).

5. **Develop/test in ./research first** — Prove changes locally with full test suite,
   THEN onboard to iccDEV cfl branch. Never commit to iccDEV without local validation.

### Anti-Pattern: Artifact Sorting Sprawl

5 commits (10%) were manual file moves between directories. Fix:
```bash
# ONE script, ONE commit
.github/scripts/sort-artifacts.sh   # crash→fuzz/graphics/icc/
                                     # timeout/slow-unit→test-profiles/cwe-400/
                                     # empty/stale→delete
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
- [upstream-sync.prompt.md](upstream-sync.prompt.md) — Patch reconciliation workflow
- [corpus-management.prompt.md](corpus-management.prompt.md) — Corpus storage operations
- [cve-enrichment.prompt.md](cve-enrichment.prompt.md) — CVE-to-heuristic mapping
