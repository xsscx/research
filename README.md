# ICC Security Research Monorepo

This repository collects tooling and research around ICC color profiles,
including analysis, parity validation, fuzzing, unsafe conversion tools, and an
MCP/Web surface for local or containerized workflows.

## Main Components

| Path | Purpose |
|------|---------|
| `iccanalyzer-lite/` | V1 analyzer, regression tests, and the `icctest/` V2 rewrite |
| `cfl/` | ClusterFuzzLite harnesses and the active patch set for fuzz builds |
| `colorbleed_tools/` | Unsafe ICC to XML conversion tools for mutation testing |
| `mcp-server/` | Python MCP server and Web UI |
| `test-profiles/` | Shared ICC fixtures and small seed inputs |
| `extended-test-profiles/` | Larger or more specialized crash and regression fixtures |

## Quick Start

```bash
# iccanalyzer-lite
cd iccanalyzer-lite && ./build.sh
python3 tests/run_tests.py -v

# icctest
cd iccanalyzer-lite/icctest && ./build.sh
ctest --test-dir build --output-on-failure

# CFL fuzzers
cd cfl && ./build.sh

# colorbleed_tools
cd colorbleed_tools && make setup && make test

# mcp-server
cd mcp-server && ./build.sh test
```

## Windows And WSL

- Prefer WSL for the Bash-first build and fuzzing flows (`build.sh`, `make`,
  AFL/CFL helpers).
- The repo now pins text files to `LF` with [`.gitattributes`](.gitattributes)
  and [`.editorconfig`](.editorconfig) so one checkout can be used from both
  Windows and WSL without constant line-ending churn.
- For editor and MCP integration on either platform, use
  `python mcp-server/launch.py mcp`. For the local Web UI, use
  `python mcp-server/launch.py web --host 127.0.0.1 --port 8000`.
- On Windows, `launch.py` auto-delegates into
  `~/work/codex/current/research` in WSL first, then falls back to
  `~/work/codex/research` or `~/po/research`. Override the target with
  `ICC_MCP_WSL_ROOT=/some/wsl/path` or disable delegation with
  `ICC_MCP_NO_WSL=1`.
- Windows-native build notes for upstream `iccDEV` live in
  `docs/iccDEV/shell-helpers/windows.md`.

## Local macOS arm64

- For Apple Silicon host setup, use
  `docs/LOCAL_MACOS_ARM64_ONBOARDING.md`.
- Treat macOS as a host for the Linux devcontainer or container workflow.
  The top-level research repo and the native analysis tools remain Linux-first.
- For editor and MCP integration, use `python mcp-server/launch.py mcp` or
  `python mcp-server/launch.py web --host 127.0.0.1 --port 8000`.

## Documentation

- Start with `docs/INDEX.md` for task-based navigation.
- Use `docs/README.md` for the directory map.
- Use `docs/Testing/README.md` for test scripts, fixtures, and saved reports.
- Use `docs/iccDEV/Tools/README.md` for the upstream tool catalog.
- Use `docs/analysis/ICCANALYZER_PARITY_AND_MCP_RELEASE_STATUS_2026-03-29.md`
  for the saved parity and release checkpoint.

## MCP and Web UI

For stdio configuration, Docker usage, upload flow, and API details, see
`mcp-server/README.md`.

## Notes

- Vendor mirrors and archived experiment trees should be treated as read-only
  unless a task explicitly targets them.
- Prefer dated reports for volatile counts or saved outcomes; this README stays
  intentionally high level.
