# Multi-Agent Coordination Instructions

Defines how multiple Copilot agents (WSL-2/Linux, macOS, Cloud CI) coordinate.

## Quick Start

1. `git fetch --all && git pull` to sync with other agents
2. `git --no-pager log --oneline -10` for recent agent activity
3. Before modifying shared files, check `git log -3 -- <file>` for recent edits

## Platform Setup

### WSL-2 / Linux

Prerequisites: Ubuntu 24.04, clang-18/clang++-18, cmake 3.15+,
libxml2-dev, libtiff-dev, libclang-rt-18-dev, libssl-dev, Python 3.10+.

```bash
cd iccanalyzer-lite && ./build.sh    # ASAN+UBSAN+coverage
cd cfl && ./build.sh                 # 13 LibFuzzer harnesses
cd colorbleed_tools && make setup && make
cd mcp-server && pip install -e .
```

Performance: use `/home/` paths (NOT `/mnt/c/`), ramdisk for fuzzing
(`sudo mount -t tmpfs -o size=4G tmpfs /tmp/fuzz-ramdisk`).

### macOS

Prerequisites: Xcode 15+, iOS Simulator, `brew install libxml2 libtiff`.
Primary tools: xnuimagetools (iOS Image Generator), xnuimagefuzzer, sips/ImageIO.

Docker: MCP image is `linux/amd64` only. Apple Silicon requires **Docker Desktop**
(Rosetta 2 supports ASAN). Colima/OrbStack NOT supported (QEMU/VZ lack ASAN support).

### Cloud CI

Pre-built via `copilot-setup-steps.yml`. Do NOT run `build.sh` or `cmake`.

## Agent Handoff

- **Incoming**: `git --no-pager log --oneline -10` for recent changes
- **Outgoing**: Commit with scope prefix (`analysis:`, `cfl:`, `afl:`, `cli:`, `docs:`, `fix:`)
- **Shared files**: Always `git pull` before editing `.github/instructions/`, `.github/prompts/`
- **Fuzzer artifacts**: AFL crashes in `afl/afl-*/output/default/crashes/`,
  CFL crashes in repo root as `crash-*` files

## MCP Docker API (Remote Analysis)

Any agent can analyze profiles via the MCP Docker API instead of git round-trips:

```bash
docker run --rm -d -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp web
curl -s -F "file=@profile.icc" http://localhost:8080/api/upload
curl -s "http://localhost:8080/api/security-json?path=<returned_path>"
```

- **Use API**: Quick analysis, triage, spot-checks
- **Use Git**: Batch reports, crash PoCs, seed corpus, version-controlled artifacts

Full endpoint list: see `mcp-server.instructions.md`.

## Cross-Repository Structure

| Repository | Path | Branch | Purpose |
|-----------|------|--------|---------|
| xsscx/research | `/research/` | main | Analyzer, CFL, call-graph, analysis |
| InternationalColorConsortium/iccDEV | `~/bisect/iccDEV-bisect-60bbb8c-json` | bisect-60bbb8c-json | Active JSON/config bisect fixes |
| xsscx/fuzz | `/research/fuzz/` | master | Curated malicious input corpus |
| xsscx/xnuimagetools | `/research/xnuimagetools/` | main | iOS Image Generator + xnuimagefuzzer |
| xsscx/xnuimagefuzzer | `/research/xnuimagefuzzer/` | main | iOS image fuzzer (submodule) |

`fuzz/` and `xnuimagetools/` are separate git repos, NOT submodules.

Latest iccDEV JSON/config reports are in `~/bisect/`. Before pushing that
branch, run the parser regression script, JSON config suite, and JSON CLI
exercise from the iccDEV worktree.

## Anti-Patterns (Mandatory Rules)

These rules derive from real multi-agent failures. Source: xsscx/governance LLMCJF.

| # | Rule | What Goes Wrong If Violated |
|---|------|-----------------------------|
| 1 | NEVER add `NO_SANITIZERS=1` to Docker. Image MUST have ASAN+UBSAN. | Removes security instrumentation. Build linux/amd64 only. |
| 2 | When changing MCP tool count, update ALL sync locations simultaneously. | Server/test mismatch causes CI failures. |
| 3 | Verify counts with `find`/`wc -l` before updating docs. | Inflated counts propagate. |
| 4 | One Dockerfile, one workflow, one image. | Duplicate Dockerfiles diverge. |
| 5 | Run `pre-push-validate.sh` before pushing. 7 build locations must sync. | Local build.sh success != CI success. |
| 6 | NEVER claim success without showing verification command + output. | 62.5% of governance violations are this pattern. |
| 7 | Exit 1-127 = graceful (NOT a crash). Exit 128+ = signal (crash). Tool exit code is authoritative, not fuzzer output. | False crash reports. |
| 8 | ALWAYS use project tools (`iccDEV/Build/Tools/`) for crash repro. No custom test programs. | Missing patches/flags/runtime config. |
| 9 | Before debugging, `grep -r` the error across `.github/`, `docs/`, `README.md`. | Reinventing what docs already explain. |
| 10 | When asked to test, TEST. When asked to build, BUILD. No unsolicited docs. | Scope creep wastes user turns. |
| 11 | WebUI changes require BOTH API tests AND browser verification. | API passes but rendered forms are wrong. |
| 12 | Classify ASAN/UBSAN by **stack trace file paths** (frame #2-#3), NEVER by profile filename. | Misattribution delays real fixes. |
| 13 | NEVER declare patches applied based on `patch --dry-run`. Run `cfl/verify-patches.sh`. | 3 masked failure modes in dry-run. |
| 14 | >=50% of commits must be core mission. Batch CI fixes into 1 commit. | Infrastructure churn drowns findings. |
| 15 | After upstream sync: delete `Build/`, rebuild, verify ASAN with `nm | grep __asan`. | Stale cmake cache retains wrong flags. |
| 16 | Test CLI script fixes with the exact failing command end-to-end. | Unit-logic tests miss design intent. |
| 17 | JSON parsers fail closed: no silent truncation, skipped members, ignored nested failures, or stale reset state. | Invalid profiles get saved and regressions look like success. |

## Image+ICC Seed Pipeline

macOS generates images (xnuimagetools) -> fuzzes them (xnuimagefuzzer with ICC injection)
-> CI extracts ICC seeds (extract-icc-seeds.py) -> Linux validates+distributes
(seed-pipeline.sh) -> ramdisk-seed.sh populates fuzzer corpora.

Quality gates: reject <64 bytes, reject <5 unique pixel values, validate TIFF magic,
deduplicate by MD5, enforce 5MB max.

## macOS CI Patterns

- **SIGPIPE**: NEVER pipe macOS tools through `| head`. Use `| sed -n '1,20p'` instead.
  NSFileHandle crashes with SIGABRT when reader closes early.
- **Profraw symbols**: Use `dlsym(RTLD_DEFAULT, "__llvm_profile_write_file")` not weak extern.
- **Mac Catalyst launch**: Use `open <app> & ; disown`. Send SIGINT (not SIGTERM) for profraw flush.
- **VideoToolbox ASAN**: 10-50x slower. VT instrumented CI job disabled. Use local hardware.
- **CodeQL on macOS**: DISABLED. SIP strips DYLD_INSERT_LIBRARIES. Upstream: codeql-action#2506.

## Commit Convention

```
<type>: <description>

Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>
```

Types: `analysis:` `cfl:` `afl:` `cli:` `coverage:` `fuzz:` `docs:` `fix:` `call-graph:` `chore:`

## Session Governance

Core workflow: VERIFY -> CITE -> CLAIM. No success claims without evidence.
All agent file output MUST be ASCII. Use `edit`/`create` tools, never heredocs.
Verify with `file FILENAME`. See `AGENTS.md` for TUI encoding defect details.
