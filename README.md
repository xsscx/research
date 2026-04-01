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
