---
mode: agent
description: Multi-agent coordination protocol for WSL-2, macOS, and Cloud CI agents
---

# Cooperative Multi-Agent Development

Coordination protocol for agents sharing this repo across platforms.

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

## Communication Protocol

1. **Before modifying shared files**: check `git log -5 -- <file>` for recent changes
2. **After pushing**: use descriptive commit messages so other agents can catch up
3. **Conflict resolution**: preserve both agents' additions (append, not replace)
4. **Remote analysis**: use MCP Docker API (`/api/upload` + `/api/security-json`)
   to avoid commit overhead for triage work
