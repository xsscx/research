---
mode: agent
description: Multi-agent coordination protocol for WSL-2, macOS, and Cloud CI agents
---

# Cooperative Multi-Agent Development

Coordination protocol for agents sharing this repo across platforms.

## Agent Roles

| Agent | Platform | Primary Tools | Responsibilities |
|-------|----------|--------------|------------------|
| **WSL-2** | Ubuntu 24.04 on WSL 2 | AFL/CFL fuzzers, colorbleed_tools, iccDEV CLIs, clang-18 | Fuzzing campaigns, profile analysis, coverage collection, call-graph generation |
| **macOS** | Darwin (Apple Silicon) | Xcode, iOS Simulator, xnuimagefuzzer, native builds | iOS image generation, iOS fuzzing, ICC profile extraction, TIFF/image corpus creation |
| **Cloud** | GitHub Actions (Linux) | CI workflows, CodeQL | Automated builds, security scanning, artifact hosting |

## Platform Capability Matrix

| Capability | WSL-2 | macOS | Cloud CI |
|-----------|-------|-------|----------|
| Build retired analyzer | No | No | No |
| Run CFL fuzzers | Yes | No (clang-18 + fuzzer) | Yes (limited time) |
| Build xnuimagefuzzer (native) | No | Yes | No |
| Run iOS Simulator | No | Yes | Yes (macOS runners) |
| Generate call graphs | Yes | No | Yes |
| Analyze ICC profiles (local) | Yes | Partial (no binary) | Yes |
| Analyze ICC profiles (remote) | N/A | Use shared reports/artifacts | Use workflow artifacts |
| Collect LLVM coverage | Yes | Yes (native builds) | Yes |
| Extract ICC from images | Yes (`iccTiffDump_unsafe`) | Yes (libtiff + ImageIO) | Yes |
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

For a ProfilePlot seed, record whether `iccProfilePlot SEED list` contains
`chroma:xy`, `clut:A2B0`, or both. The AFL graph/raster lanes screen for these
stable IDs; CFL can consume the same raw ICC file through the `profileplot`
alias.

Before seeding a TIFF on WSL-2, retain a structure log and byte-exact profile:

```bash
colorbleed_tools/iccTiffDump_unsafe fuzz/graphics/tif/<seed>.tif /tmp/<seed>.icc
```

### WSL-2 -> macOS: Crash Artifacts
When WSL-2 fuzzer finds a crash:
1. Minimize: `cfl/bin/<fuzzer> -minimize_crash=1 <crash_file>`
2. Triage with upstream: `iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <crash>`
3. Commit crash file to repo root: `crash-<sha>.icc`
4. Run analysis with active `iccDEV/Build/Tools/` CLIs
5. Commit report to `analysis-reports/`
6. macOS agent can test crash against ColorSync/ImageIO

### WSL-2 -> Repository: Analysis Reports
When analyzing test profiles:
1. Run active `iccDEV/Build/Tools/` CLIs on `test-profiles/<name>.icc`
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
| `analysis-reports/` | WSL-2 | macOS read-only |
| `call-graph/` | WSL-2 | macOS read-only |
| `fuzz/graphics/icc/ios-gen-*` | macOS | WSL-2 consumes for seeding |
| `fuzz/graphics/tif/xig-*` | macOS | WSL-2 consumes for seeding |
| `xnuimagetools/` | macOS | WSL-2 read-only |
| `.github/prompts/` | Both | Coordinate via PR if conflicts |
| `.github/instructions/` | Both | Coordinate via PR if conflicts |
| `.github/copilot-instructions.md` | Both | High conflict risk -- merge carefully |
| `test-profiles/` | Both | WSL-2 adds crash PoCs, macOS adds extracted profiles |

## Communication Protocol

1. **Before modifying shared files**: check `git log -5 -- <file>` for recent changes
2. **After pushing**: use descriptive commit messages so other agents can catch up
3. **Conflict resolution**: preserve both agents' additions (append, not replace)
4. **Remote analysis**: use committed reports or workflow artifacts to avoid
   repeated local setup for triage work

## Fast Correction Protocol

Use this protocol when a user says the task is a repeated attempt, regression
fix, or needs to wrap up:

1. Restate the single failure being corrected in one sentence.
2. Patch only the files needed to prevent that failure from recurring.
3. Run the smallest decisive validation set; do not restart broad discovery.
4. After user approval, freeze scope and commit and push immediately when
   requested. Do not start a new review, broad validation, or adjacent cleanup
   unless the user asks or the handoff command fails.
5. Report the commit SHA, pushed branch, and validation evidence.
