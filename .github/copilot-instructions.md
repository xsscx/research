# Copilot Instructions -- ICC Security Research

Cross-cutting rules for ALL components. Component-specific details live in
path-specific instruction files that auto-load when you touch those paths.
Task-specific workflows are available as skills in `.github/skills/`.

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

## iccDEV Upstream Build

```bash
cd iccDEV/Build && cmake Cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_TOOLS=ON \
  && make -j$(nproc)
# V2 icctest
cd iccanalyzer-lite/icctest && ./build.sh
```

After branch switches or upstream syncs, delete `Build/CMakeCache.txt` and
`Build/CMakeFiles/` to avoid stale cmake cache errors.

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
- `.github/skills/*/SKILL.md` -- on-demand task workflows (6 skills)
- `.github/prompts/` -- prompt templates (17 prompts)
- `.github/agents/` -- custom agents (3 agents)
- `.github/hooks/` -- session hooks (2 hook configs)
- `AGENTS.md` -- agent session rules, multi-platform notes

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
cd iccanalyzer-lite && ./build.sh           # 1. Build
python3 tests/run_tests.py                   # 2. Test
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  ./iccanalyzer-lite -a ../test-profiles/sRGB_D65_MAT-500lx.icc  # 3. ASAN check
.github/scripts/pre-push-validate.sh         # 4. Verify all build locations
```

Step 4 is mandatory. A local `build.sh` success does NOT guarantee CI success.

## OpenTelemetry Monitoring

OTel is OFF by default (zero overhead). Activate with:

```bash
source .github/scripts/otel-setup.sh   # file exporter to ~/.copilot/otel/
```

Traces capture spans (invoke_agent, chat, execute_tool), token usage, and tool
call durations. Full content capture is enabled for research/debugging.
Review traces: `cat ~/.copilot/otel/traces-$(date +%Y-%m-%d).jsonl | jq .`
