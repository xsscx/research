---
mode: agent
description: Validate V1/V2 parity and MCP container readiness for release
---

# icctest Parity + MCP Release Validation

Confirm iccanalyzer-lite, icctest, and MCP container are ready for release.

## Read First

- `docs/analysis/ICCANALYZER_PARITY_AND_MCP_RELEASE_STATUS_2026-03-29.md`
- `iccanalyzer-lite/icctest/README.md`
- `mcp-server/README.md`

## Required Validation Flow

1. Build the current native targets from the instrumented shared build path.
   - `cd iccanalyzer-lite && ./build.sh`
   - `cd iccanalyzer-lite/icctest && ./build.sh`
2. Re-run the V2 suite and parity verification.
   - `ctest --test-dir iccanalyzer-lite/icctest/build --output-on-failure`
   - `python3 iccanalyzer-lite/icctest/tools/verifyParity.py --unit-binary ...`
3. Read the resulting `verify-parity-summary.json` before making any parity
   claim.
   - Require raw ICC `delta = 0`
   - Require raw ICC `knownGap = 0`
   - Require image parity `delta = 0`
   - Require generated-image smoke `status = pass`
4. Verify fixture resolution from multiple working directories if the change
   touched test discovery or shared-path logic.
5. Build the MCP Docker image locally from `mcp-server/Dockerfile`.
6. Smoke both MCP modes.
   - `mcp` stdio: `initialize`, `tools/list`, `icctest --version`,
     `icctest --registry`
   - `web` mode: `/`, `/favicon.ico`, `/.well-known/appspecific/com.chrome.devtools.json`,
     `/static/cytoscape.min.js`, `/api/health`, `/api/health-check`,
     `/api/list`, `/api/inspect`, `/api/security-report`, `/api/pawg`,
     `/api/coverage-gaps`, and `POST /api/scan-logs`
7. If code was pushed, inspect or trigger the matching GitHub workflows and
   report the run IDs and final status.

## Current Known-Good Reference

As of 2026-03-29 the saved checkpoint is:

- raw parity `delta = 0`, `knownGap = 0`, `coverageImprovement = 17`
- image parity `delta = 0`
- V2 unit baseline `1822/1822 passed`
- MCP `/api/health` current surface: `28` tools

Do not treat those numbers as permanent ceilings. Refresh them from the current
artifact and current server response before reporting.

## Reporting Rules

- Findings first. If anything regresses, list the exact blocker before any
  summary.
- Distinguish real parity failures from intentional `quarantined` buckets.
- Distinguish container/runtime regressions from host-network quirks during
  local Docker testing.
- Quote the exact artifact path and workflow run IDs used for the conclusion.
