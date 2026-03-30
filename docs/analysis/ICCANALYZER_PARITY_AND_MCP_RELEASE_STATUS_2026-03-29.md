# ICCANALYZER PARITY AND MCP RELEASE STATUS — 2026-03-29

This note captures the verified `iccanalyzer-lite` / `icctest` parity state and
the matching MCP container/runtime validation completed on 2026-03-29.

## Current State

- Raw ICC parity is closed on the in-repo corpus: `delta = 0`,
  `knownGap = 0`, `coverageImprovement = 17`.
- Image/container parity is closed: TIFF outer image `delta = 0`, embedded raw
  `delta = 0`, generated PNG/JPEG embedded-ICC smoke `pass`.
- The current V2 unit baseline is `1822/1822 passed`.
- Shared fixtures now resolve consistently when `icctest_unit_tests` is
  launched from the monorepo root, `iccanalyzer-lite/`, or `icctest/build/`.
- `heuristic-remap.tsv` no longer contains `implementation=todo` entries.
- The MCP container build and runtime smoke are green locally and in GitHub
  Actions.

## Commits

- `b91962690` `fix: restore icctest failed-load parity fallbacks`
- `2595a2168` `fix: smooth mcp web ui browser flows`
- `edf4d068f` `fix(icctest): close remaining parity integration gaps`
- `258b5cfea` `docs: refresh root and mcp readmes`

## Local Verification

### Native parity and tests

Run from the repository root:

```bash
cd iccanalyzer-lite/icctest
cmake --build build -j"$(nproc)"
ctest --test-dir build --output-on-failure

python3 tools/verifyParity.py \
  --unit-binary build/lib/tests/icctest_unit_tests \
  --v2-binary build/tools/icctest-parity \
  --heuristic-remap tools/heuristic-remap.tsv \
  --output-dir build/parity-artifacts \
  --pretty
```

Current expected artifact summary:

- `summary.status = "pass"`
- `summary.unitTests.summaryLine = "Results: 1822/1822 passed"`
- `summary.rawParity.counts.delta = 0`
- `summary.rawParity.counts.knownGap = 0`
- `summary.rawParity.counts.coverageImprovement = 17`
- `summary.imageParity.outerImage.counts.match = 10`
- `summary.generatedImageSmoke.status = "pass"`

Saved reference artifact:

- `docs/Testing/results/icctest-verify-parity-summary-2026-03-29.json`

### MCP Docker validation

Local image used:

```bash
docker build -f mcp-server/Dockerfile -t icc-profile-mcp-local:parity-check .
```

Validated modes:

- `mcp` stdio mode
  - `initialize` returned `serverInfo.name = "icc-profile-analyzer"`
  - `tools/list` returned the full tool surface
  - `/app/iccanalyzer-lite/icctest/build/cli/icctest --version` succeeded
  - `/app/iccanalyzer-lite/icctest/build/cli/icctest --registry` succeeded
- `web` mode
  - `GET /`
  - `GET /favicon.ico`
  - `GET /.well-known/appspecific/com.chrome.devtools.json`
  - `GET /static/cytoscape.min.js`
  - `GET /api/health`
  - `GET /api/health-check`
  - `GET /api/list?directory=test-profiles`
  - `GET /api/inspect?path=sRGB_D65_MAT.icc`
  - `GET /api/security-report?path=sRGB_D65_MAT.icc`
  - `GET /api/pawg?path=sRGB_D65_MAT.icc`
  - `GET /api/coverage-gaps`
  - `POST /api/scan-logs`

Specific browser/runtime regressions confirmed fixed:

- `/favicon.ico` served
- `/.well-known/appspecific/com.chrome.devtools.json` returns `204`, not `404`
- local `/static/cytoscape.min.js` served
- CSP admits the graph-viewer path Cytoscape needs
- default `coverage-gaps` requests work without a mandatory severity filter
- empty `scan-logs` directories return `[OK] No .log files found ...`, not a
  hard failure

Environment note:

- During local Docker validation in this WSL environment, alternate host port
  bindings were unreliable from the host shell even while the container itself
  was healthy. In that case, validate the fresh container over HTTP from inside
  the container and confirm the same requests in the container log before
  treating it as a product regression.

Reference docs refreshed during the same checkpoint:

- `README.md`
- `mcp-server/README.md`
- `.github/prompts/analyze-icc-profile.prompt.yml`
- `.github/prompts/health-check.prompt.yml`
- `.github/prompts/icctest-parity-release.prompt.md`

## Workflow Reference

Successful runs recorded for the parity-closure pass:

- `23716881503` `Fuzz Corpus Sanitizer Scan` — push — success
- `23716881523` `iccAnalyzer-lite Unit Tests` — push — success
- `23716881508` `MCP Server Tests` — push — success
- `23717053304` `iccAnalyzer-lite` — workflow_dispatch — success
- `23717086419` `iccAnalyzer CLI Test Suite → Release` — workflow_dispatch — success
- `23717053316` `MCP Server Docker Build` — workflow_dispatch — success

## Interpretation Notes

- `quarantined` counts still appear in raw/image parity summaries. They are
  intentional collision-suppression buckets, not open `knownGap` parity work.
- Do not claim parity from README text alone. Re-read the current
  `verify-parity-summary.json` and the active workflow results first.
- Do not hardcode tool totals from old MCP docs. The current `/api/health`
  response and `health_check` output are the source of truth for current tool
  surface and engine defaults.
