---
name: iccdev-pawg-mcp
description: >
  Validate current upstream iccDEV PAWG reporting, MCP and REST runtime
  capabilities, the unified GHCR image, and maintainer QA tools. Use for
  interoperability, release evidence, or migration from retired analyzer and
  standalone MCP paths.
allowed-tools:
  - bash
  - read
  - grep
  - glob
---

# iccDEV PAWG and MCP Validation

Use `docs/ICCDEV_UPSTREAM_INTEROP.md` as the research-repo entry point and the
current upstream checkout as the interface source of truth.

## Workflow

1. Record the research and upstream revisions plus both worktree states. Do not
   overwrite a dirty checkout or force-update it.
2. Read the current upstream `Tools/CmdLine/IccPawgReport/Readme.md`,
   `iccdev-mcp/README.md`, and `docs/maintainer-qa-scans.md` before selecting
   commands.
3. Pull `ghcr.io/internationalcolorconsortium/iccdev:latest` and record its
   `RepoDigest`.
4. Run `iccPawgReport` in text and JSON modes on a current `Testing/` profile.
5. Perform a real MCP initialize handshake, send the initialized notification,
   request `tools/list`, and call `health_check`. Keep stdio open until each
   requested response arrives.
6. When REST is in scope, validate `/api/health` and `/api/tools`, then stop and
   remove the test container.
7. For maintainer work, run the smallest relevant current upstream QA scan.
   Use broad registry scans only when the request requires them.
8. Report the discovered capabilities, unavailable optional features, exact
   revisions/digests, exit codes, and sanitizer or signal evidence.

## Invariants

- `iccPawgReport` and `iccdev-mcp` are the active upstream surfaces. Treat
  `iccanalyzer-lite`, its V2 parity files, and the old standalone MCP package as
  historical unless archaeology is explicitly requested.
- The published MCP runtime comes from the unified `iccdev` image and starts
  with `iccdev-mcp-entrypoint mcp`.
- Never hardcode a healthy MCP tool total. Compare runtime discovery with the
  capabilities advertised by that exact image or build.
- PAWG report states are not crash classifications. Exit 128+, a sanitizer
  diagnostic, or equivalent signal evidence is required for a crash claim.
- Do not copy credentials into a VM or container. Public image pulls and
  read-only profile mounts do not require repository credentials.
