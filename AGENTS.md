# Repository Guidelines

## Project Structure
Security-research monorepo for ICC color-profile tooling. Main components:
`iccanalyzer-lite/` (instrumented analyzer + V2 rewrite in `icctest/`),
`cfl/` (LibFuzzer harnesses), `colorbleed_tools/` (unsafe XML converters),
`mcp-server/` (MCP server + Web UI). Shared corpora in `test-profiles/`,
`extended-test-profiles/`, `cfl/corpus-*`. Vendor mirrors (`opencv/`) and
archived dirs (`demo-rit/`, `issue-711/`) are read-only.

## Documentation Map
- `docs/INDEX.md` -- task-based navigation
- `.github/copilot-instructions.md` -- cross-cutting rules (always loaded)
- `.github/instructions/*.instructions.md` -- path-specific (auto-loaded)
- `.github/skills/*/SKILL.md` -- on-demand task workflows
- `.github/prompts/` -- prompt templates

## Build and Test
See `.github/copilot-instructions.md` for build/test commands per component.
Additional repo workflows in active use:
- `ICCDEV_TOOLS_DIR=$PWD/iccDEV/Build/Tools ICCDEV_TESTING_DIR=$PWD/iccDEV/Testing .github/scripts/iccdev-tool-coverage-baseline.sh --asan`
  -- full iccDEV CLI coverage baseline; CI runs this script from `.github/workflows/iccdev-tool-tests.yml`.
- `.github/scripts/batch-test-external.sh /path/to/profiles [--timeout N] [--max N] [--csv]`
  -- sweep an external ICC corpus with `iccDumpProfile`, `iccToXml`, and `iccRoundTrip` without committing results.
- `bash .github/scripts/test-iccdev-all.sh [--quick] [--asan] [--tool=NAME]`
  -- run the checked-in per-tool iccDEV shell test suite locally, with `--quick` for shorter envelope passes or `--tool=` to isolate one tool.
- `.github/scripts/pre-push-gate.sh`
  -- run the unified pre-push validation gate; it dispatches component-specific checks and calls `.github/scripts/pre-push-validate.sh` for iccanalyzer-lite build-sync verification.

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
3. **The loop**: If fixing the same thing twice, stop and switch approach.
4. **Tool convergence**: Use proven winners -- do not re-evaluate each session.

## Testing
Update tests in nearest suite for behavior changes. Do not commit `.profraw`,
coverage HTML, virtualenv contents, or crash artifacts unless the change is
explicitly about test data.

## Commit Guidelines
Short imperative subjects: `fix:`, `docs:`, `ci:`, `cfl:`, `afl:`, `call-graph:`.
Scope to one component. PRs name area, list commands run, link issues.
