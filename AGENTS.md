# Repository Guidelines

## Project Structure & Module Organization
This repository is a security-research monorepo centered on ICC color-profile tooling. The main components are `iccanalyzer-lite/` (instrumented analyzer, `tests/`, and the V2 rewrite in `icctest/`), `cfl/` (ClusterFuzzLite and LibFuzzer harnesses), `colorbleed_tools/` (unsafe XML conversion tools), and `mcp-server/` (Python MCP server and Web UI). Shared corpora and fixtures live in `test-profiles/`, `extended-test-profiles/`, and `cfl/corpus-*`. Treat vendor mirrors such as `opencv/` and archived variants like `demo-rit/`, `issue-711/`, and `lto/` as read-only unless the task explicitly targets them.

## Documentation Map
Start with `docs/INDEX.md` for task-based navigation and `docs/README.md` for the directory map. Use `docs/iccDEV/Tools/` for upstream CLI behavior, `docs/iccDEV/shell-helpers/` for build and sanitizer workflows, `docs/iccDEV/codeql/` for static-analysis maintenance, `docs/afl/` for the AFL++ tool-fuzzing workflow, and `docs/analysis/` or `docs/Testing/` for repo-specific findings and test evidence.

## Build, Test, and Development Commands
- `cd iccanalyzer-lite && ./build.sh` builds the analyzer with ASAN, UBSAN, and LLVM coverage.
- `python3 iccanalyzer-lite/tests/run_tests.py -v` runs the analyzer regression suite.
- `cd iccanalyzer-lite/icctest && ./build.sh && ctest --test-dir build --output-on-failure` builds and runs V2 unit and parity tests.
- `cd cfl && ./build.sh` builds the fuzzers and applies the active security patch set to `cfl/iccDEV`.
- `./afl/build.sh && ./afl/start.sh dump` builds the AFL-instrumented upstream tools and starts fuzzing the `dump` target; `./afl/start.sh search` fuzzes `iccApplySearch`, `./afl/rebuild.sh` forces a clean AFL rebuild, `./afl/harvest.sh --list` or `./afl/harvest.sh --seed-local` pulls CI AFL artifacts, and `./afl/status.sh`, `./afl/stop.sh dump`, and `./afl/triage.sh dump` cover monitoring, shutdown, and crash triage.
- `cd colorbleed_tools && make setup && make test` builds the unsafe tools and runs the round-trip smoke test.
- `cd mcp-server && ./build.sh test` creates the virtualenv and runs the MCP and Web UI suites.
- `cd mcp-server && ./build.sh web [port] [host]` starts the Web UI locally; `cd mcp-server && ./build.sh mcp` starts the stdio MCP server.

## Coding Style & Naming Conventions
Follow the local style; there is no enforced repo-wide formatter at the root. Use 4-space indentation in C++ and Python, keep Bash portable, and use tabs only in `Makefile`s. Prefer `snake_case` for Python helpers, `test_*.py` and `test_*.cpp` for tests, and existing C++ naming patterns such as `Icc*.cpp` and `CIcc*` types.

## Known Copilot CLI Defect -- TUI Output Encoding (BOM / Non-ASCII)

The TUI emits BOM, smart quotes, em-dashes that corrupt pasted commands.

**Agent rule**: All generated files MUST be ASCII. Verify: `file FILENAME` must
say `ASCII text`. Use `edit`/`create` tools for file writes (exact byte control),
never shell heredocs or Python string escaping. ALWAYS verify after writing.

**Double anti-pattern**: Acknowledging this defect then immediately producing the
same defect in output files. The shell and Python string-escaping pipelines
re-introduce the encoding corruption the agent just documented. This pattern was
observed in session 2026-03-31 and must not recur.

**User workaround**: `clean() { sed 's/\xEF\xBB\xBF//g' "${1:--}" | LC_ALL=C tr -cd '\11\12\15\40-\176'; }`

## Agent Session Optimization (from xsscx/governance LLMCJF)

**Core principle**: The expensive part is not the work -- it is the correction loops.

1. **File writes**: Use `create`/`edit` tools only. Run `file FILENAME` after every
   write. Must say `ASCII text`. Never use heredocs or Python string escaping.
2. **Claims**: VERIFY -> CITE -> CLAIM. No success without command output evidence.
3. **THE LOOP**: If fixing the same thing twice, stop and switch approach entirely.
5. **Tool convergence**: Use proven winners -- do not re-evaluate each session.

Reference: https://github.com/xsscx/governance (LLMCJF, 374 files, 90K lines)

## Testing Guidelines
Any behavior change should update tests in the nearest suite. Analyzer tests live under `iccanalyzer-lite/tests/`; V2 library and parity tests live under `iccanalyzer-lite/icctest/`; MCP tests are `mcp-server/test_mcp.py` and `mcp-server/test_web_ui.py`. Do not commit generated `.profraw`, coverage HTML, virtualenv contents, or crash artifacts unless the change is explicitly about test data.

## Current Agent Handoff -- Docker Image Validation (2026-04-01)
Treat Linux container validation as the source of truth for `mcp-server` and the native analysis stack. Native macOS failures are not actionable for the Linux-specialized tools in this repo.

Verified image state:
- Pulled `ghcr.io/xsscx/icc-profile-mcp:latest` with digest `sha256:f2ea3cab6bd6bc533753b0df513e2e82bf2714c3889f5fd58ed49a16e2a3c6f3`.
- `GET /api/health` returned `{"ok":true,"tools":28,"engines":{"v1":true,"v2":true},"defaultAnalysisEngine":"v2","defaultStructuralEngine":"v1"}`.
- This confirms the newer image fixed the older 24-tool / missing-`/api/pawg` regression, but the image is still not release-clean.

Verified release regressions to hand off:
- `GET /api/registry?engine=v2` returned `{"ok":false,"error":"Invalid registry output"}` instead of the `200` expected by `mcp-server/test_web_ui.py`.
- `GET /api/security?path=BlacklightPoster_411039.icc` returned `{"ok":true,"result":""}`.
- `GET /api/pawg?path=BlacklightPoster_411039.icc` returned `{"ok":true,"result":""}`.
- `mcp-server/test_mcp.py` failed in `test_inspect_all_profiles()` with corpus-wide `inspect(...)` failures; see `mcp-server/test_mcp.py`.
- `mcp-server/test_web_ui.py` observed `GET /api/xml/download?path=BlacklightPoster_411039.icc` returning `400` where the test expects `200`.

Recommended reproduction path for the Windows / WSL2 agent:
- `docker pull ghcr.io/xsscx/icc-profile-mcp:latest`
- `docker run --rm -d --name research-mcp-test -p 18080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web`
- `curl -fsS http://127.0.0.1:18080/api/health`
- `curl -sS 'http://127.0.0.1:18080/api/registry?engine=v2'`
- `curl -sS 'http://127.0.0.1:18080/api/security?path=BlacklightPoster_411039.icc'`
- `curl -sS 'http://127.0.0.1:18080/api/pawg?path=BlacklightPoster_411039.icc'`
- `docker run --rm ghcr.io/xsscx/icc-profile-mcp:latest sh -lc 'cd /app/mcp-server && /app/mcp-venv/bin/python3 test_mcp.py'`
- `docker run --rm ghcr.io/xsscx/icc-profile-mcp:latest sh -lc 'cd /app/mcp-server && /app/mcp-venv/bin/python3 test_web_ui.py'`

## Commit & Pull Request Guidelines
Recent history uses short, imperative subjects with prefixes such as `fix:`, `docs:`, `ci:`, `fix(ci):`, and `call-graph:`. Keep commits scoped to one component where possible. Pull requests should name the affected area, list the commands you ran, link the issue or research note when relevant, and include screenshots or representative API output for `mcp-server` UI or API changes.
