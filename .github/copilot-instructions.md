# Copilot Instructions -- ICC Security Research

Cross-cutting rules for ALL components. Component-specific details live in
path-specific instruction files that auto-load when you touch those paths.
Task-specific workflows are available as skills in `.github/skills/`. Invoke a
skill by name when a task matches, then follow `.github/skills/<name>/SKILL.md`.

## Skills

| Skill | Use When |
|-------|----------|
| `corpus-management` | Manage fuzzing corpus lifecycle, SSD/scratch setup, merges, dedup, and artifact preservation |
| `icc-crash-triage` | Triage ASAN/UBSAN fuzzer crashes, classify exit codes, attribute stack traces, and map CWE ownership |
| `icc-security-analysis` | Run full ICC/TIFF/PNG/JPEG security analysis with structural, registry, round-trip, and report steps |
| `iccdev-linear-stack` | Rebase an iccDEV feature branch onto upstream master and stack commits without merge commits |
| `upstream-pr-readiness` | Verify explicit PR authorization and complete pre-PR grooming before any upstream PR is opened or reviewed |
| `upstream-sync` | Sync `cfl/iccDEV/` to upstream and reconcile/rebuild/verify CFL security patches |
| `version-bump` | Synchronize iccDEV version numbers across upstream and research repo locations |

## Architecture

| Component | Purpose |
|-----------|---------|
| **cfl/** | LibFuzzer harnesses on a separate unpatched upstream iccDEV clone. |
| **colorbleed_tools/** | Sandboxed unsafe ICC XML/JSON and TIFF extraction tools. |
| **fuzz/** | Curated malicious input files (CVE PoCs, injection sigs, malformed media). |
| **afl/** | AFL++ tool-level fuzzing of unpatched upstream iccDEV CLI tools. |

**CRITICAL -- Two iccDEV checkouts with DIFFERENT purposes:**

| Path | Purpose | Patched? |
|------|---------|----------|
| `iccDEV/` | Upstream reference (UNPATCHED, Debug+ASAN+UBSAN+Coverage) | No |
| `cfl/iccDEV/` | CFL fuzzer build (security patches applied) | Yes |

For crash fidelity, ALWAYS use `iccDEV/Build/Tools/` (unpatched).
Do NOT create standalone `.cpp` PoCs or custom test programs for reproductions.
Use existing project tools with durable input artifacts (`.icc`, XML, TIFF, PNG,
JPEG, JSON config, `.cube`) and exact one-line replay commands.

`colorbleed_tools/` links unpatched upstream iccDEV. Keep hardening local to
the tool wrapper when the behavior is converter-owned. Do not move those runtime
guardrails into `cfl/patches/`.

## Build Commands

```bash
# Prerequisites: clang/clang++ 18+, cmake 3.15+, libxml2-dev, libtiff-dev,
#   libpng-dev, libjpeg-dev, libssl-dev, libclang-rt-18-dev
cd cfl && ./build.sh                    # LibFuzzer harnesses against unpatched upstream
cd colorbleed_tools && make setup && make # unsafe tools (clang defaults to sanitizer build)
./afl/build-afl-runtime.sh              # pinned AFL++ stable runtime, LLVM 21, 4 MiB ceiling
./afl/build.sh                          # AFL-instrumented upstream tools
```

- **Local/WSL-2**: Build the component you are changing before use.

## Windows and WSL Notes

- Prefer WSL for Bash-first build and fuzzing flows (`build.sh`, `make`, AFL/CFL helpers).
- Windows-native upstream iccDEV build notes live in
  `docs/iccDEV/shell-helpers/windows.md`.

## Test Commands

```bash
# Full suites
ASAN_OPTIONS=detect_leaks=0 cfl/bin/icc_dump_fuzzer \
  -max_total_time=60 -timeout=30 -rss_limit_mb=4096 \
  cfl/corpus-icc_dump_fuzzer/                                   # CFL smoke (60s)
```

## Repo Workflow Scripts

```bash
.github/scripts/batch-test-external.sh /path/to/profiles [--timeout N] [--max N] [--csv]
bash .github/scripts/test-iccdev-all.sh [--quick] [--asan] [--tool=NAME]
.github/scripts/validate-afl-jpeg-seeds.sh
.github/scripts/validate-afl-profileplot-targets.sh
.github/scripts/pre-push-gate.sh
```

- `batch-test-external.sh` sweeps an external ICC corpus with `iccDumpProfile`,
  `iccToXml`, and `iccRoundTrip` without committing results.
- `test-iccdev-all.sh` runs the checked-in per-tool iccDEV shell test suite;
  use `--quick` for shorter envelope passes and `--tool=` to isolate one tool.
- `pre-push-gate.sh` is the unified pre-push validation gate for active
  GitHub/workflow and documentation checks.
- AFL `jpegdump` and `jpegdump-inject` seed only up to 200 `.jpg`/`.jpeg`
  files from `fuzz/graphics/jpg` with embedded ICC profiles. Never seed those
  JPEG lanes with raw `.icc` corpora.
- AFL `profileplot`, `profileplot-graph`, and `profileplot-raster` own the real
  `iccProfilePlot` CLI modes. CFL's `icc_profilevisualize_fuzzer` owns the
  in-memory `IccVizModel` enumeration and render API.

## iccDEV Upstream Build

```bash
cd iccDEV/Build && cmake Cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_TOOLS=ON \
  && make -j$(nproc)
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

## Latest iccTiffDump regression context

- Merged upstream `master`: `3e348201` (`fix: preserve embedded TIFF profiles
  on parse failure`, #2188).
- Historical branch: `ci-qa-fix-regression-800ac41-tiff-read`.
- Local worktree: `~/bisect/iccDEV-ci-qa-fix-regression-800ac41-tiff-read`.
- Report: `~/bisect/iccdev-icctiffdump-nested-profile-bisect-pickaxe-report-20260817.txt`.
- Regression gate: run the upstream checkout's
  `.github/scripts/iccdev-tiffdump-output-hardening-tests.sh`.
- Extraction is forensic: preserve TIFF ICC bytes before parser validation.

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

### Repeated correction workflow
- If the user says this is a repeated attempt, regression fix, or time to wrap
  up, stop broad repository sweeps and exploratory cleanup.
- Make the smallest scoped change that directly addresses the named failure.
- Run only decisive validation for that change, then commit and push when the
  user requested it.
- Report command evidence and the commit SHA. Do not claim completion from
  intent, partial inspection, or stale assumptions.

### Upstream pull request boundary

- Pushing a branch, triggering CI, or requesting review does not authorize PR
  creation. Ask before opening or reopening a PR.
- If a CI workflow requires an open PR, report that prerequisite and wait for
  explicit authorization instead of creating the PR under the user's account.
- Run `.github/skills/upstream-pr-readiness/SKILL.md` before opening a PR.
- Rebase on current `master`, review `git range-diff`, verify no merge commits,
  run build/CTest plus negative configuration checks, and inspect suppressed
  review findings before declaring the branch review-ready.
- Record a configuration-contract matrix for every changed workflow,
  Dockerfile, dependency manifest, or build setting: defaults, explicit
  overrides, failure paths, and exact local evidence. Inventory review
  summaries as well as threads because suppressed comments may have no thread.
- Before pushing a PR branch, reconcile its stated requirement with the complete
  diff and map all equivalent platform entry points and producer-consumer paths.
  Fixture work must cover generators, generated outputs, baselines, and CTest
  dependencies on every supported platform. Cloud Agent review is final
  confirmation, never the discovery mechanism for omitted counterparts.
- Do not request serial automated reviews to discover basic readiness defects.
  A second review cycle with any new blocker, including one in the repair, is a
  stop signal: return to branch-only grooming, report the review-cycle count,
  and complete the contract audit before another review.

### File output encoding
All generated files MUST be ASCII. Verify with `file FILENAME`.
Use `edit`/`create` tools for file writes (exact byte control),
never shell heredocs. See `AGENTS.md` for TUI encoding defect details.

## Documentation Map

- `docs/INDEX.md` -- task-based navigation
- `.github/copilot-instructions.md` -- repository-wide custom instructions
- `.github/instructions/*.instructions.md` -- path-specific custom instructions;
  each file must include `applyTo` frontmatter
- `.github/skills/*/SKILL.md` -- on-demand task workflows
- `.github/prompts/` -- prompt templates (19 prompts)
- `.github/agents/` -- custom agents (4 agents)
- `.github/hooks/` -- session hooks (2 hook configs)
- `AGENTS.md` -- agent instructions; nearest file in the directory tree takes
  precedence for AI agents

### Documentation shortcuts

| Task | Start Here |
|------|------------|
| Build or run repo tools | `README.md`, `docs/iccDEV/shell-helpers/README.md`, `docs/iccDEV/Tools/README.md` |
| Run AFL++ tool fuzzing | `docs/afl/index.md` |
| Run CFL LibFuzzer harnesses | `cfl/README.md` |
| Investigate a bug or security issue | `docs/pocs/`, `docs/analysis/`, `docs/cve/iccDEV-CVE-Report.md` |
| File an upstream issue | `.github/prompts/upstream-issue-filing.prompt.md` |
| Reproduce or bisect an iccDEV bug | `.github/prompts/iccdev-bisect-reproduction.prompt.md` |
| Verify an upstream branch is PR-ready | `.github/prompts/upstream-pr-readiness.prompt.md` |
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
| `@pr-readiness` | Read-only upstream PR authorization and readiness audit | claude-sonnet-4.6 |

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
- Path contains `colorbleed_tools/`, `cfl/`, or `afl/` -- **OUR CODE**
- Path contains `iccDEV/` -- **UPSTREAM** -- cite file:line and upstream issue#

## Pre-push Verification

```bash
.github/scripts/pre-push-gate.sh             # unified component-aware gate
```

For PR/CI status reports, the GitHub `Pre-flight checks` job and
`ci-risk-analysis` workflow are required success gates. Do not report a PR as
green or successful while either is failing, skipped unexpectedly, or still
pending, even if all build/test jobs pass.

## OpenTelemetry Monitoring

OTel is OFF by default (zero overhead). Activate with:

```bash
source .github/scripts/otel-setup.sh   # file exporter to ~/.copilot/otel/
```

Traces capture spans (invoke_agent, chat, execute_tool), token usage, and tool
call durations. Full content capture is enabled for research/debugging.
Review traces: `cat ~/.copilot/otel/traces-$(date +%Y-%m-%d).jsonl | jq .`
