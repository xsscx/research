# Documentation Start Here

Use this file when you know the task and need the shortest path to the right
material. Keep volatile counts, one-off results, and raw logs out of hub docs.

## Common Tasks

| Task | Start Here |
|------|------------|
| Build or run repo tools | `../README.md`, `iccDEV/shell-helpers/README.md`, `iccDEV/Tools/README.md` |
| Run AFL++ tool fuzzing | `afl/index.md` |
| Run CFL LibFuzzer harnesses | `../cfl/README.md`, `Testing/CFL_MANUAL_FUZZER_COMMANDS.md` |
| Review fuzzing assets and A/B tracking policy | `Testing/FUZZ_CFL_INVENTORY.md` |
| Investigate a bug or security issue | `pocs/`, `analysis/`, `cve/iccDEV-CVE-Report.md` |
| File an upstream issue | `../.github/prompts/upstream-issue-filing.prompt.md` |
| Reproduce or bisect an iccDEV bug | `../.github/prompts/iccdev-bisect-reproduction.prompt.md` |
| Verify upstream PR authorization and readiness | `governance/UPSTREAM_PR_READINESS.md`, `../.github/prompts/upstream-pr-readiness.prompt.md` |
| Run or review tests | `Testing/README.md` |
| Study ICC binary structure | `icc-format/ICC-Binary-Format-Reference.md` |
| Review call graph notes | `callgraph/CALLGRAPH_EXAMINATION_INDEX.md` |
| Review TIFF-specific analysis | `tiffimg/START_HERE.md` |
| Dump TIFF structure and preserve an embedded ICC | `../colorbleed_tools/Readme.md`, `../.github/prompts/tiff-icc-colorbleed.prompt.md` |
| Set up Apple Silicon host flow | `LOCAL_MACOS_ARM64_ONBOARDING.md` |
| Configure or troubleshoot MCP servers (`.mcp.json`) | `MCP_SERVER_SETUP.md` |

## Security Research

| Area | Path |
|------|------|
| Vulnerability taxonomy | `iccDEV/vulnerability-taxonomy.md` |
| CVE and GHSA inventory | `cve/iccDEV-CVE-Report.md` |
| PoC reproductions and techniques | `pocs/` |
| Runtime analyzer findings | `analysis/` |
| Static-analysis workflow | `iccDEV/codeql/README.md` |
| ICC conformance and parser-risk overlays | `iccDEV/specifications/html/` |
| ICC specimen posters and generated images | `iccDEV/specifications/png/` |

## Notes

- Prefer authored entry docs over raw logs and saved results.
- Upstream PR creation requires explicit authorization and a passing readiness
  gate; branch push or CI requests do not imply permission to publish a PR.
- Treat `Testing/results/`, coverage output, and fuzzer runtime directories as
  evidence, not onboarding material.
- When exact inventory matters, inspect the filesystem or source scripts in the
  current checkout.
