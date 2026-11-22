# Testing Guide

This directory contains test entry points, fixtures, and saved evidence for
ICC and TIFF-related validation work in this repository.

## Start Here

- JSON tool regression scripts: `docs/Testing/test-json-tools.sh`
- JSON config fixtures: `docs/Testing/json-configs/`
- Malformed JSON fixtures: `docs/Testing/malformed-json/`
- CFL manual command runbook: `docs/Testing/CFL_MANUAL_FUZZER_COMMANDS.md`
- Fuzz and CFL snapshot: `docs/Testing/FUZZ_CFL_INVENTORY.md`
- TIFF-focused investigations: `docs/Testing/TIFF_FUZZER_COMPREHENSIVE_ANALYSIS.md`

## What Lives Here

| Path | Purpose |
|------|---------|
| `json-configs/` | Valid JSON inputs for all three apply tools, including the shared AFL/CFL complete config |
| `malformed-json/` | Negative test cases for parser and validation behavior |
| `test-data/` | Small input files used by scripted tests |
| `results/` | Saved logs and artifacts; evidence, not onboarding material |
| `json-cli-exercise/` | Broad option-coverage exercise for the JSON-capable tools |

## Recommended Workflow

1. Build the upstream tools or local checkout you want to validate.
2. Run `./docs/Testing/test-json-tools.sh` for the focused JSON config suite.
3. Treat `results/` as supporting evidence, not the source of truth for current
   behavior.

## Fuzzing Development Policy

Fuzzing research in `afl/`, `cfl/`, `fuzztest/`, and `valgrind/` is code-first.
Do not add regression source files, CTest targets, synthetic fixtures,
test-only harnesses, or new validation frameworks to prove a research change.
Correct the actual library patch, harness, launcher, configuration, dictionary,
or corpus policy, then validate it with an existing fuzzer/tool and the
preserved real artifact. Upstream regression tests belong in separately
authorized upstream work, not in this monorepo's patch stacks.

## Notes

- This README is an index. Re-run the scripts when exact behavior matters.
- Retired analyzer parity artifacts were removed from tracking. Use the backup
  in `~/retired/` for historical inspection.
