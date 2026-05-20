# Copilot Instructions -- ICC Security Research

Cross-cutting rules for ALL components. Component-specific details live in
path-specific instruction files that auto-load when you touch those paths.
Task-specific workflows are available as skills in `.github/skills/`. Invoke a
skill by name when a task matches, then follow `.github/skills/<name>/SKILL.md`.

## Skills

| Skill | Use When |
|-------|----------|
| `corpus-management` | Manage fuzzing corpus lifecycle, ramdisk/SSD setup, merges, dedup, and artifact preservation |
| `icc-crash-triage` | Triage ASAN/UBSAN fuzzer crashes, classify exit codes, attribute stack traces, and map CWE ownership |
| `icc-security-analysis` | Run full ICC/TIFF/PNG/JPEG security analysis with structural, registry, round-trip, and report steps |
| `iccdev-linear-stack` | Rebase an iccDEV feature branch onto upstream master and stack commits without merge commits |
| `mcp-health-check` | Verify MCP server health, binaries, dependencies, and test profile access |
| `upstream-sync` | Sync `cfl/iccDEV/` to upstream and reconcile/rebuild/verify CFL security patches |
| `version-bump` | Synchronize iccDEV version numbers across upstream and research repo locations |

## Architecture

| Component | Purpose |
|-----------|---------|
| **iccanalyzer-lite/** | Security analyzer (ASAN+UBSAN). Links **unpatched** upstream iccDEV. |
| **cfl/** | 13 LibFuzzer harnesses + security patches on a separate iccDEV clone. |
| **mcp-server/** | MCP server (FastMCP) + REST API + WebUI wrapping the analyzer. |
| **colorbleed_tools/** | Intentionally unsafe ICC-to-XML converters (no ASAN). |
| **fuzz/** | Curated malicious input files (CVE PoCs, injection sigs, malformed media). |
| **afl/** | AFL++ tool-level fuzzing of unpatched upstream iccDEV CLI tools. |

**CRITICAL -- Two iccDEV checkouts with DIFFERENT purposes:**

| Path | Purpose | Patched? |
|------|---------|----------|
| `iccDEV/` | Upstream reference (UNPATCHED, Debug+ASAN+UBSAN+Coverage) | No |
| `cfl/iccDEV/` | CFL fuzzer build (security patches applied) | Yes |

For crash fidelity, ALWAYS use `iccDEV/Build/Tools/` (unpatched).

**Unpatched analyzer policy:** `iccanalyzer-lite/`, `iccanalyzer-lite/icctest/`,
and `colorbleed_tools/` link unpatched upstream iccDEV. Harden those components
with analyzer/tool-owned defensive programming: input validation, bounds and
overflow checks, allocation caps, signal handling, recoverable sanitizer paths,
and explicit error handling around every iccDEV API call. Do NOT move those
runtime hardening fixes into `cfl/patches/`.

## Key Counts

Do NOT hardcode counts in documentation. Use `./iccanalyzer-lite --registry | jq`
for authoritative heuristic, CVE, and GHSA counts. When updating counts, sync
ALL locations listed in the relevant path-specific instructions file.

## Build Commands

```bash
# Prerequisites: clang/clang++ 18+, cmake 3.15+, libxml2-dev, libtiff-dev,
#   libpng-dev, libjpeg-dev, libssl-dev, libclang-rt-18-dev
cd iccanalyzer-lite && ./build.sh       # analyzer (ASAN+UBSAN+coverage)
cd cfl && ./build.sh                    # 13 fuzzers (clones iccDEV, applies patches)
cd colorbleed_tools && make setup && make # unsafe tools (no ASAN)
./afl/build.sh                          # AFL-instrumented upstream tools
cd mcp-server && pip install -e .       # MCP server
```

- **Cloud CI**: `copilot-setup-steps.yml` pre-builds everything. Do NOT run build scripts.
- **Local/WSL-2**: Build before use.

## Windows and WSL Notes

- Prefer WSL for Bash-first build and fuzzing flows (`build.sh`, `make`, AFL/CFL helpers).
- Use `python mcp-server/launch.py mcp` for MCP stdio and
  `python mcp-server/launch.py web --host 127.0.0.1 --port 8000` for Web UI.
- On Windows, `launch.py` auto-delegates into WSL in this order:
  `~/work/codex/current/research`, `~/work/codex/research`, then `~/po/research`.
  Override with `ICC_MCP_WSL_ROOT=/some/wsl/path` or disable with `ICC_MCP_NO_WSL=1`.
- Windows-native upstream iccDEV build notes live in
  `docs/iccDEV/shell-helpers/windows.md`.

## Test Commands

```bash
# Full suites
python3 iccanalyzer-lite/tests/run_tests.py                    # analyzer tests
cd mcp-server && python test_mcp.py && python test_web_ui.py   # MCP tests
cd iccanalyzer-lite/icctest && ctest --test-dir build --output-on-failure  # V2 parity
ASAN_OPTIONS=detect_leaks=0 cfl/bin/icc_dump_fuzzer \
  -max_total_time=60 -timeout=30 -rss_limit_mb=4096 \
  cfl/corpus-icc_dump_fuzzer/                                   # CFL smoke (60s)

# Single test
python3 iccanalyzer-lite/tests/run_tests.py -k json            # match by name
python3 iccanalyzer-lite/tests/run_tests.py --list              # list sections
python3 -m pytest mcp-server/test_web_ui.py::test_health -x     # one MCP test
```

## Repo Workflow Scripts

```bash
.github/scripts/batch-test-external.sh /path/to/profiles [--timeout N] [--max N] [--csv]
bash .github/scripts/test-iccdev-all.sh [--quick] [--asan] [--tool=NAME]
.github/scripts/pre-push-gate.sh
```

- `batch-test-external.sh` sweeps an external ICC corpus with `iccDumpProfile`,
  `iccToXml`, and `iccRoundTrip` without committing results.
- `test-iccdev-all.sh` runs the checked-in per-tool iccDEV shell test suite;
  use `--quick` for shorter envelope passes and `--tool=` to isolate one tool.
- `pre-push-gate.sh` is the unified pre-push validation gate. It dispatches
  component-specific checks and calls `pre-push-validate.sh` for the analyzer
  build-sync check.

## iccDEV Upstream Build

```bash
cd iccDEV/Build && cmake Cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_TOOLS=ON \
  && make -j$(nproc)
# V2 icctest
cd iccanalyzer-lite/icctest && ./build.sh
```

After branch switches or upstream syncs, delete `Build/CMakeCache.txt` and
`Build/CMakeFiles/` to avoid stale cmake cache errors.

## icctest V2 Quick Reference

`iccanalyzer-lite/icctest/` is the V2 analyzer rewrite and parity engine. Build
with `cd iccanalyzer-lite/icctest && ./build.sh`, run all registered tests with
`ctest --test-dir build --output-on-failure`, and smoke the CLI with:

```bash
iccanalyzer-lite/icctest/build/cli/icctest --registry
iccanalyzer-lite/icctest/build/tools/icctest-parity --help
```

Parity helpers live under `iccanalyzer-lite/icctest/tools/`; use
`verifyParity.py` and `verifyPawg.py` when checking V1/V2 behavior.

## Latest iccDEV JSON/config bisect

- Branch: `InternationalColorConsortium/iccDEV` `bisect-60bbb8c-json`.
- Local worktree: `~/bisect/iccDEV-bisect-60bbb8c-json`.
- Reports: `~/bisect/iccdev-json-it8-srcType-report.txt` and
  `~/bisect/iccdev-json-parser-regression-report.txt`.
- Latest pushed fixes: `4ffcba5` (IT8 srcType + missing pccWeights) and
  `0eca71b` (JSON parser/config fail-closed hardening).
- Regression gate on that branch:
  `.github/scripts/iccdev-json-parser-regression-tests.sh`,
  `.github/scripts/iccdev-json-cfg-tests.sh`, and
  `.github/scripts/json-cli-exercise.sh`.
- Rule: JSON parser/config helpers fail closed. Do not truncate short arrays,
  skip bad struct members, attach failed nested MPEs, or retain stale reset state.

## Coding Conventions

### Exit codes
- **0**: Success. **1-127**: Soft failure (NOT a crash).
- **128+**: Signal termination (crash). 134=SIGABRT, 139=SIGSEGV.
- The tool exit code is authoritative. The fuzzer DEADLYSIGNAL is a test artifact.

### Sanitizer flags
- **Fuzzers**: `-fsanitize=fuzzer,address,undefined`
- **Analyzer**: `-fsanitize=address,undefined,float-divide-by-zero,float-cast-overflow,integer -g3 -O0`
- Both iccDEV libs AND the linking tool must use matching sanitizer flags
- `-fsanitize=integer` required for unsigned overflow detection

### Analyzer heuristic output
- All V1 analyzer heuristics use `HeuristicCollector::instance()`.
- Use `begin()`, `info()`, `warn()`, `critical()`, `cweNote()`, `end()`, and
  `skip()` for structured output; do not add raw `printf("[H##]...")`.
- Structured modes reset the collector, run analysis in quiet/captured mode,
  then format `HeuristicCollector::results()` as JSON, reports, XML, or PAWG.

### Style
- No emojis in code/CI/reports. Use `[OK]`, `[WARN]`, `[FAIL]`, `[SKIP]`, `[CRITICAL]`.
- All C++ requires clang/clang++. C++ types use `CIcc*` prefix.
- `snake_case` in Python. Test files: `test_*.py` / `test_*.cpp`.
- 4-space indent in C++ and Python. Tabs only in Makefiles.

### Commit messages
Short imperative subjects with component scope:
`fix:`, `docs:`, `ci:`, `cfl:`, `afl:`, `call-graph:`, `analysis:`, `coverage:`.
Scope to one component. PRs name area, list commands run, link issues.

### CI
- All actions 100% SHA-pinned.
- Every `run:` step: `set -euo pipefail` first line.
- Source `.github/scripts/sanitize-sed.sh` for `GITHUB_STEP_SUMMARY` writes.
- See `workflow-governance.instructions.md` for full shell hardening details.

### File output encoding
All generated files MUST be ASCII. Verify with `file FILENAME`.
Use `edit`/`create` tools for file writes (exact byte control),
never shell heredocs. See `AGENTS.md` for TUI encoding defect details.

## Documentation Map

- `docs/INDEX.md` -- task-based navigation
- `.github/instructions/*.instructions.md` -- path-specific (auto-loaded per file)
- `.github/skills/*/SKILL.md` -- on-demand task workflows (7 skills)
- `.github/prompts/` -- prompt templates (17 prompts)
- `.github/agents/` -- custom agents (3 agents)
- `.github/hooks/` -- session hooks (2 hook configs)
- `AGENTS.md` -- agent session rules, multi-platform notes

### Documentation shortcuts

| Task | Start Here |
|------|------------|
| Build or run repo tools | `README.md`, `docs/iccDEV/shell-helpers/README.md`, `docs/iccDEV/Tools/README.md` |
| Run AFL++ tool fuzzing | `docs/afl/index.md` |
| Run CFL LibFuzzer harnesses | `cfl/README.md` |
| Investigate a bug or security issue | `docs/pocs/`, `docs/analysis/`, `docs/cve/iccDEV-CVE-Report.md` |
| File an upstream issue | `.github/prompts/upstream-issue-filing.prompt.md` |
| Reproduce or bisect an iccDEV bug | `.github/prompts/iccdev-bisect-reproduction.prompt.md` |
| Run or review tests | `docs/Testing/README.md` |
| Study ICC binary structure | `docs/icc-format/ICC-Binary-Format-Reference.md` |
| Review call graph notes | `docs/callgraph/CALLGRAPH_EXAMINATION_INDEX.md` |
| Set up Apple Silicon host flow | `docs/LOCAL_MACOS_ARM64_ONBOARDING.md` |

Vendor mirrors (`opencv/`) and archived dirs (`demo-rit/`, `issue-711/`) are
read-only unless a task explicitly targets them.

## Custom Agents

Invoke with `@agent-name` or `--agent=agent-name` from the CLI:

| Agent | Purpose | Model |
|-------|---------|-------|
| `@security-scan` | Full ICC profile security analysis | claude-sonnet-4.6 |
| `@crash-triage` | ASAN/UBSAN crash finding triage | claude-sonnet-4.6 |
| `@upstream-issue` | Draft iccDEV bug reports (gold format) | claude-sonnet-4.6 |

## Hooks

| Hook | Event | Purpose |
|------|-------|---------|
| `protect-upstream` | preToolUse | Deny writes to `iccDEV/` (upstream read-only) |
| `session-lifecycle` | sessionStart, notification | OTel init, shell completion logging |

## Programmatic Scripts

```bash
# Non-interactive security scan with transcript
.github/scripts/copilot-security-scan.sh profile.icc /tmp/scan-output

# Non-interactive crash triage with transcript
.github/scripts/copilot-crash-triage.sh crash-file /tmp/triage-output
```

## ASAN/UBSAN Attribution

Classify by **stack frame file path** (frame #2-#3), NEVER by profile filename:
- Path contains `iccanalyzer-lite/`, `colorbleed_tools/`, `cfl/` -- **OUR CODE**
- Path contains `iccDEV/` -- **UPSTREAM** -- cite file:line and upstream issue#

## Pre-push Verification

```bash
.github/scripts/pre-push-gate.sh             # unified component-aware gate
```

For analyzer-only validation, the gate runs the same required sequence: build,
tests, ASAN spot-check, and `.github/scripts/pre-push-validate.sh`. The
`pre-push-validate.sh` check is mandatory because a local `build.sh` success does
NOT guarantee CI success.

### iccanalyzer-lite build sync

When adding/removing analyzer sources or linker flags, keep all 7 build locations
in sync:

| # | File | What to Sync |
|---|------|--------------|
| 1 | `iccanalyzer-lite/build.sh` | `SOURCES=` and `LIBS=` |
| 2 | `iccanalyzer-lite/CMakeLists.txt` | executable sources and linker flags |
| 3 | `.github/workflows/codeql-security-analysis.yml` | `SRCS=` and linker flags |
| 4 | `.github/workflows/iccanalyzer-cli-release.yml` | `SRCS=` and linker flags |
| 5 | `.github/workflows/iccanalyzer-lite-coverage-report.yml` | `SOURCES=` and linker flags |
| 6 | `.github/workflows/iccanalyzer-lite-debug-sanitizer-coverage.yml` | `SOURCES=` and linker flags |
| 7 | `.github/workflows/mcp-server-test.yml` | `SRCS=` and linker flags |

## OpenTelemetry Monitoring

OTel is OFF by default (zero overhead). Activate with:

```bash
source .github/scripts/otel-setup.sh   # file exporter to ~/.copilot/otel/
```

Traces capture spans (invoke_agent, chat, execute_tool), token usage, and tool
call durations. Full content capture is enabled for research/debugging.
Review traces: `cat ~/.copilot/otel/traces-$(date +%Y-%m-%d).jsonl | jq .`
