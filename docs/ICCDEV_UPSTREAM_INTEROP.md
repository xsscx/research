# Current iccDEV PAWG, MCP, and Container Interoperability

This is the active contract for the work formerly tracked as
`iccanalyzer-lite` and the standalone MCP server. Those retired paths are
historical. Their maintained upstream equivalents are `iccPawgReport` and
`iccdev-mcp` in `InternationalColorConsortium/iccDEV`.

## Sources of truth

- Upstream source: <https://github.com/InternationalColorConsortium/iccDEV>
- Unified package: <https://github.com/InternationalColorConsortium/iccDEV/pkgs/container/iccdev>
- PAWG CLI: `Tools/CmdLine/IccPawgReport/Readme.md` in the current checkout
- MCP server: `iccdev-mcp/README.md` and `iccdev-mcp/docs/` in the current
  checkout
- Maintainer scans: `docs/maintainer-qa-scans.md` in the current checkout

Do not copy old heuristic, conformance, or MCP tool totals into active guidance.
Use the current source revision and runtime discovery output.

## Unified container

```bash
docker pull ghcr.io/internationalcolorconsortium/iccdev:latest
docker run --rm ghcr.io/internationalcolorconsortium/iccdev:latest iccPawgReport --help
docker run --rm -i ghcr.io/internationalcolorconsortium/iccdev:latest iccdev-mcp-entrypoint mcp
docker run --rm -p 127.0.0.1:8080:8080 ghcr.io/internationalcolorconsortium/iccdev:latest iccdev-mcp-entrypoint rest
```

Record the pulled `RepoDigest` with the validation evidence. A moving `latest`
tag is convenient for local use but is not a reproducible release reference.

## PAWG validation

Use a profile from the current upstream `Testing/` tree:

```bash
iccPawgReport Testing/sRGB_v4_ICC_preference.icc
iccPawgReport --json Testing/sRGB_v4_ICC_preference.icc
```

When QA flags are enabled, also run:

```bash
iccPawgReport --qa-flags --evidence-json Testing/sRGB_v4_ICC_preference.icc
```

Treat `PASS`, `WARN`, `FAIL`, `GAP`, `N/A`, and `NOT RUN` as report states,
not process-crash classifications. Preserve sanitizer output and signal exits
separately.

## MCP and REST validation

For stdio, send a real MCP `initialize` request, the initialized notification,
and `tools/list`. Validate the returned server identity and discovered tool
names. Then call `health_check`; keep stdin open until each requested response
arrives. Closing the stream while a tool call is in flight can discard its
response. Do not assert a fixed total because optional native libraries and CLI
binaries affect availability.

For REST, require successful responses from:

- `/api/health` for native, CLI, and service capability state
- `/api/tools` for the runtime inventory

Mount extra profile directories read-only and set `ICCDEV_PROFILE_DIRS` when a
test needs files outside the image.

## Local source checkout

Keep the unpatched upstream checkout at `iccDEV/` for fidelity. Build and point
the pip-installed MCP server at it with:

```bash
export ICCDEV_TOOLS_DIR="$PWD/iccDEV/Build/Tools"
export ICCDEV_BUILD_DIR="$PWD/iccDEV/Build"
export ICCDEV_TESTING_DIR="$PWD/iccDEV/Testing"
```

Run `pytest iccDEV/iccdev-mcp/tests -v` after MCP source changes. For PAWG or
maintainer changes, use the current upstream scan scripts under
`iccDEV/.github/scripts/` and follow `iccDEV/docs/maintainer-qa-scans.md`.

## Research integration

- CFL and AFL builds continue to consume current upstream source through their
  documented refresh flows.
- ColorBleed remains the sandboxed mutation and byte-preserving extraction
  surface.
- Security summaries should combine structural validation, PAWG output,
  relevant round-trip/conversion evidence, and sanitizer evidence.
- Historical analyzer reports may explain provenance, but they are not active
  commands, dependencies, or release gates.
