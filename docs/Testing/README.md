# Testing Guide

This directory contains test entry points, fixtures, and saved evidence for
ICC and TIFF-related validation work in this repository.

## Start Here

- JSON tool regression scripts: `docs/Testing/test-json-tools.sh`
- JSON config fixtures: `docs/Testing/json-configs/`
- Malformed JSON fixtures: `docs/Testing/malformed-json/`
- Saved parity artifact: `docs/Testing/results/icctest-verify-parity-summary-2026-03-29.json`
- CFL manual command runbook: `docs/Testing/CFL_MANUAL_FUZZER_COMMANDS.md`
- Fuzz and CFL snapshot: `docs/Testing/FUZZ_CFL_INVENTORY.md`
- TIFF-focused investigations: `docs/Testing/TIFF_FUZZER_COMPREHENSIVE_ANALYSIS.md`

## What Lives Here

| Path | Purpose |
|------|---------|
| `json-configs/` | Valid JSON inputs for `iccApplyNamedCmm` and `iccApplySearch` |
| `malformed-json/` | Negative test cases for parser and validation behavior |
| `test-data/` | Small input files used by scripted tests |
| `results/` | Saved logs and artifacts; evidence, not onboarding material |
| `json-cli-exercise/` | Broad option-coverage exercise for the JSON-capable tools |

## Recommended Workflow

1. Build the upstream tools or local checkout you want to validate.
2. Run `./docs/Testing/test-json-tools.sh` for the focused JSON config suite.
3. Treat `results/` as supporting evidence, not the source of truth for current
   behavior.

## Notes

- This README is an index. Re-run the scripts when exact behavior matters.
- For V1/V2 parity and release checkpoints, start with
  `docs/analysis/ICCANALYZER_PARITY_AND_MCP_RELEASE_STATUS_2026-03-29.md`.
