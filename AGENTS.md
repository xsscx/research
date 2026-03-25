# Repository Guidelines

## Project Structure & Module Organization
This repository is a security-research monorepo centered on ICC color-profile tooling. The main components are `iccanalyzer-lite/` (instrumented analyzer, `tests/`, and the V2 rewrite in `icctest/`), `cfl/` (ClusterFuzzLite and LibFuzzer harnesses), `colorbleed_tools/` (unsafe XML conversion tools), and `mcp-server/` (Python MCP server and Web UI). Shared corpora and fixtures live in `test-profiles/`, `extended-test-profiles/`, and `cfl/corpus-*`. Treat vendor mirrors such as `opencv/` and archived variants like `demo-rit/`, `issue-711/`, and `lto/` as read-only unless the task explicitly targets them.

## Documentation Map
Start with `docs/INDEX.md` for task-based navigation and `docs/README.md` for the directory map. Use `docs/iccDEV/Tools/` for upstream CLI behavior, `docs/iccDEV/shell-helpers/` for build and sanitizer workflows, `docs/iccDEV/codeql/` for static-analysis maintenance, and `docs/analysis/` or `docs/Testing/` for repo-specific findings and test evidence.

## Build, Test, and Development Commands
- `cd iccanalyzer-lite && ./build.sh` builds the analyzer with ASAN, UBSAN, and LLVM coverage.
- `python3 iccanalyzer-lite/tests/run_tests.py -v` runs the analyzer regression suite.
- `cd iccanalyzer-lite/icctest && ./build.sh && ctest --test-dir build --output-on-failure` builds and runs V2 unit and parity tests.
- `cd cfl && ./build.sh` builds the fuzzers and applies the active security patch set to `cfl/iccDEV`.
- `cd colorbleed_tools && make setup && make test` builds the unsafe tools and runs the round-trip smoke test.
- `cd mcp-server && ./build.sh test` creates the virtualenv and runs the MCP and Web UI suites.

## Coding Style & Naming Conventions
Follow the local style; there is no enforced repo-wide formatter at the root. Use 4-space indentation in C++ and Python, keep Bash portable, and use tabs only in `Makefile`s. Prefer `snake_case` for Python helpers, `test_*.py` and `test_*.cpp` for tests, and existing C++ naming patterns such as `Icc*.cpp` and `CIcc*` types.

## Testing Guidelines
Any behavior change should update tests in the nearest suite. Analyzer tests live under `iccanalyzer-lite/tests/`; V2 library and parity tests live under `iccanalyzer-lite/icctest/`; MCP tests are `mcp-server/test_mcp.py` and `mcp-server/test_web_ui.py`. Do not commit generated `.profraw`, coverage HTML, virtualenv contents, or crash artifacts unless the change is explicitly about test data.

## Commit & Pull Request Guidelines
Recent history uses short, imperative subjects with prefixes such as `fix:`, `docs:`, `ci:`, `fix(ci):`, and `call-graph:`. Keep commits scoped to one component where possible. Pull requests should name the affected area, list the commands you ran, link the issue or research note when relevant, and include screenshots or representative API output for `mcp-server` UI or API changes.
