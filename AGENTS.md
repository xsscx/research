# Repository Guidelines

## Project Structure
Security-research monorepo for ICC color-profile tooling. Main components:
`iccDEV/` (unpatched upstream reference tooling), `cfl/` (LibFuzzer harnesses),
`afl/` (AFL++ tool-level fuzzing), and `colorbleed_tools/` (sandboxed unsafe
ICC representation and TIFF extraction tools). Shared corpora live in
`test-profiles/`, `extended-test-profiles/`, and `cfl/corpus-*`. Retired
analyzer history was removed from tracking; use the Git backup in `~/retired/`
if archaeology is required. Current analyzer and server work lives upstream as
`iccPawgReport` and `iccdev-mcp`; use `docs/ICCDEV_UPSTREAM_INTEROP.md` and the
`iccdev-pawg-mcp` skill. Vendor mirrors (`opencv/`) and archived dirs
(`demo-rit/`, `issue-711/`) are read-only.

## Documentation Map
- `docs/INDEX.md` -- task-based navigation
- `.github/copilot-instructions.md` -- cross-cutting rules (always loaded)
- `.github/instructions/*.instructions.md` -- path-specific; include
  `applyTo` frontmatter so Copilot can select the right file
- `.github/skills/*/SKILL.md` -- on-demand task workflows
- `.github/prompts/` -- prompt templates
- `AGENTS.md` -- agent instructions; nearest file in the directory tree wins
- `docs/ICCDEV_UPSTREAM_INTEROP.md` -- current PAWG, MCP, container, and
  maintainer-tool contract

## Build and Test
See `.github/copilot-instructions.md` for build/test commands per component.
Additional repo workflows in active use:
- `./afl/build-afl-runtime.sh`
  -- install pinned AFL++ stable commit `45bb74bd3a6591e6853b704c390ab6156c0a3c88`
     with LLVM 21 wrappers, `-j32`, and the 4 MiB testcase ceiling required by
     the full-size hybrid TIFF lane.
- `.github/ci/quality-assurance/scripts/iccApplyProfiles_sanitizer_qa.sh --seconds 300`
  -- run bounded deterministic sanitizer QA from a native Linux scratch tree.
- `.github/ci/quality-assurance/scripts/iccApplyProfiles_valgrind_qa.sh --tool memcheck --seconds 300 --binary /path/to/non-sanitized/iccApplyProfiles`
  -- run bounded Memcheck or Helgrind QA without stacking Valgrind on ASAN.
- `ICCDEV_TOOLS_DIR=$PWD/iccDEV/Build/Tools ICCDEV_TESTING_DIR=$PWD/iccDEV/Testing .github/scripts/iccdev-tool-coverage-baseline.sh --asan`
  -- full iccDEV CLI coverage baseline; CI runs this script from `.github/workflows/iccdev-tool-tests.yml`.
- `.github/scripts/batch-test-external.sh /path/to/profiles [--timeout N] [--max N] [--csv]`
  -- sweep an external ICC corpus with `iccDumpProfile`, `iccToXml`, and `iccRoundTrip` without committing results.
- `bash .github/scripts/test-iccdev-all.sh [--quick] [--asan] [--tool=NAME]`
  -- run the checked-in per-tool iccDEV shell test suite locally, with `--quick` for shorter envelope passes or `--tool=` to isolate one tool.
- `.github/scripts/pre-push-gate.sh`
  -- run the unified pre-push validation gate for active GitHub and
     documentation checks.

For upstream PAWG and MCP work, discover current runtime capabilities rather
than copying historical analyzer totals. The published runtime is the unified
`ghcr.io/internationalcolorconsortium/iccdev:latest` image; start its MCP mode
with `iccdev-mcp-entrypoint mcp`.

## AFL JPEG Seed Rule
`jpegdump` and `jpegdump-inject` must seed only `.jpg`/`.jpeg` files from
`fuzz/graphics/jpg` that contain an embedded ICC profile. Do not seed either
JPEG lane with raw `.icc` files from `test-profiles/`, `extended-test-profiles/`,
or `fuzz/graphics/icc/`. Keep the JPEG seed cap at 200 and run
`.github/scripts/validate-afl-jpeg-seeds.sh` after changing AFL JPEG seeding.

## Latest iccDEV Bisect Context
JSON/config parser fixes live on upstream `InternationalColorConsortium/iccDEV`
branch `bisect-60bbb8c-json` (local worktree:
`~/bisect/iccDEV-bisect-60bbb8c-json`). Reports stay in `~/bisect/`; run
`.github/scripts/iccdev-json-parser-regression-tests.sh` plus the JSON config
suite before touching that branch again.

## Latest iccTiffDump Regression Context

TIFF raw-extraction and nested-profile fixes were merged to upstream `master`
in `3e348201` (`fix: preserve embedded TIFF profiles on parse failure`, #2188).
The historical branch is `ci-qa-fix-regression-800ac41-tiff-read` and its local
worktree is `~/bisect/iccDEV-ci-qa-fix-regression-800ac41-tiff-read`. The
supporting pickaxe report is
`~/bisect/iccdev-icctiffdump-nested-profile-bisect-pickaxe-report-20260817.txt`.
Run the upstream checkout's
`.github/scripts/iccdev-tiffdump-output-hardening-tests.sh` for regression work.

## Coding Style
4-space indent in C++ and Python. Tabs only in Makefiles. `snake_case` for
Python, `test_*.py`/`test_*.cpp` for tests, `CIcc*` for C++ types.

## Known Copilot CLI Defect -- TUI Output Encoding

The TUI emits BOM, smart quotes, em-dashes that corrupt pasted commands.

**Rule**: All generated files MUST be ASCII. Verify: `file FILENAME` must say
`ASCII text`. Use `edit`/`create` tools only, never heredocs or Python escaping.
ALWAYS verify after writing.

## Agent Session Rules

1. **File writes**: `create`/`edit` tools only. Verify `file FILENAME` = `ASCII text`.
2. **Claims**: VERIFY -> CITE -> CLAIM. No success without command output evidence.
   PR/CI success also requires the GitHub `Pre-flight checks` job and
   `ci-risk-analysis` workflow to pass; do not call a PR green while either is
   failing or pending.
3. **The loop**: If fixing the same thing twice, stop and switch approach.
4. **Tool convergence**: Use proven winners -- do not re-evaluate each session.
5. **PoC policy**: Do not create standalone `.cpp` PoCs. Reproduce bugs with
   existing project tools and durable input artifacts (`.icc`, XML, TIFF, PNG,
   JPEG, JSON config, `.cube`) plus exact one-line commands.

## Pull Request Authorization and Readiness

1. A request to push a branch, trigger CI, request review, or monitor checks is
   NOT authorization to create or reopen a pull request.
2. If the requested workflow requires an open PR and the user did not
   explicitly authorize one, stop and ask. Do not infer consent from the
   workflow name.
3. Do not use a PR or repeated automated reviews as the development loop.
   Groom the branch first: rebase on current base, review the complete diff,
   run positive and negative tests, inspect active and suppressed findings,
   verify scope documentation, produce a linear range-diff, and record a
   `base...HEAD` contract matrix for every changed cross-cutting surface.
   The matrix identifies producer, consumer, build/runtime behavior, platform
   or toolchain boundary, CI trigger, dependency owner, and local evidence.
   A no-rebase instruction is not a readiness waiver when the branch diverges
   from its required base or stack parent: report FAIL and wait for direction
   to rebase, use independent branches or stacks, or defer publication.
   Before every PR-branch push, compare the stated requirement with the complete
   diff and review all equivalent platform paths and producer-consumer edges.
   For fixture changes, prove every generator, generated output, baseline, and
   CTest dependency locally; do not use Cloud Agent review to discover omissions.
4. Before opening a PR, run the `upstream-pr-readiness` skill and record its
   PASS result. A failed or incomplete gate keeps the work branch-only.
5. After a second review identifies any new blocker, including one in the
   repair, set `review-stop: FAIL - maintainer direction required`. Do not
   launch a local or cloud reviewer, publish another repair, resolve findings
   as closure, or claim readiness. Return to branch-only grooming, complete
   the cumulative audit, and ask the user before continuing PR activity.
6. Once a user approves a branch-only documentation, configuration, or UI
   revision and authorizes commit or push, freeze scope and perform only that
   action. Do not start another review or broad validation unless asked or
   blocked by a command failure. A requested small-diff review is limited to
   named files and direct consumers, 25 tool calls, and 10 minutes; cancellation
   or timeout does not block the remaining user authorization.
7. Before the first cloud review, record one local cumulative review and the
   exact reviewed SHA. Package, protocol, and subprocess-launch changes also
   require a platform-by-installation-mode matrix that separately proves
   source-tree and installed-package child-process imports.

## Repeated Correction Rule

When the user says a task is a repeated attempt, a regression fix, or time to
wrap up, stop broad discovery. Make the smallest scoped edit that directly
addresses the named failure, run only the decisive validation commands, commit,
push if requested, and report the exact commit and evidence. Do not continue
iterating through adjacent cleanup, stale docs, or exploratory scans unless the
user explicitly asks for that broader work.

## Testing
Update tests in nearest suite for behavior changes. Do not commit `.profraw`,
coverage HTML, virtualenv contents, or crash artifacts unless the change is
explicitly about test data.

## Commit Guidelines
Short imperative subjects: `fix:`, `docs:`, `ci:`, `cfl:`, `afl:`, `call-graph:`.
Scope to one component. PRs name area, list commands run, link issues.
