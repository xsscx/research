# MCP Server Setup (`.mcp.json`)

Use this path when configuring or troubleshooting the repo's Model Context
Protocol (MCP) servers defined in `.mcp.json` at the repo root.

## What This Covers

- Cross-platform, portable `stdio` MCP server commands (no hardcoded local
  user paths or per-machine binaries)
- Container-based servers (`docker run`) that work identically on
  Windows, macOS, and Linux/WSL hosts with Docker installed
- Secret handling for the `github` MCP server without committing tokens

## Principles

- Every server command in `.mcp.json` MUST be resolvable on any contributor's
  machine. Do not point `command` at a personal path such as
  `/home/<user>/...` or `C:\Users\<user>\...`; prefer a tool on `PATH`
  (`docker`, `npx`, `uvx`) or a pinned container image reference.
- Secrets (tokens, keys) MUST NOT be written as literal values in
  `.mcp.json`. Reference them via `env` substitution, e.g.
  `"${GITHUB_PERSONAL_ACCESS_TOKEN}"`, and set the underlying environment
  variable locally (never commit it).

## `github` Server

The `github` entry runs the official GitHub MCP Server container:

```json
"github": {
  "type": "stdio",
  "command": "docker",
  "args": [
    "run", "--rm", "-i",
    "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
    "ghcr.io/github/github-mcp-server:latest",
    "stdio"
  ],
  "env": {
    "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_PERSONAL_ACCESS_TOKEN}"
  }
}
```

Set the token once per machine from an already-authenticated `gh` CLI
session (Windows PowerShell example; use the POSIX equivalent on
macOS/Linux/WSL):

```powershell
$token = gh auth token
[Environment]::SetEnvironmentVariable("GITHUB_PERSONAL_ACCESS_TOKEN", $token, "User")
```

```bash
# macOS/Linux/WSL
export GITHUB_PERSONAL_ACCESS_TOKEN="$(gh auth token)"
```

Do not hardcode a personal-access-token literal in `.mcp.json` or in any
committed file. Restart the MCP client (or run `/mcp` reload) after setting
the variable so the new value is picked up.

## iccDEV Container Servers

`iccdev` runs the MCP server from the unified published iccDEV image, so no
local build or path is required:

- `iccdev` -> `ghcr.io/internationalcolorconsortium/iccdev:latest`
  (<https://github.com/InternationalColorConsortium/iccDEV/pkgs/container/iccdev>)
- `iccdev-ci-regression` -> `ghcr.io/internationalcolorconsortium/iccdev-ci-regression:latest`
  (<https://github.com/InternationalColorConsortium/iccDEV/pkgs/container/iccdev-ci-regression>)

The unified image includes the MCP and REST server, CLI tools, runtime
libraries, maintainer utilities, and `Testing/` profiles. Start its stdio mode
with `iccdev-mcp-entrypoint mcp`.

Verify interoperability locally with a real MCP handshake instead of raw
stdin, since an empty/invalid payload will produce a misleading JSON-RPC
parse error:

```bash
INIT_MSG='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1.0"}}}'
echo "$INIT_MSG" | docker run --rm -i ghcr.io/internationalcolorconsortium/iccdev:latest iccdev-mcp-entrypoint mcp
echo "$INIT_MSG" | docker run --rm -i ghcr.io/internationalcolorconsortium/iccdev-ci-regression:latest iccdev-mcp
```

A successful response includes `"serverInfo":{"name":"iccdev-mcp", ...}` and
non-empty `capabilities`.

After initialization, issue `tools/list` and use `health_check` rather than
assuming a fixed tool total. Optional native and CLI-backed capabilities differ
between local builds and container variants. For REST mode, run
`iccdev-mcp-entrypoint rest` and inspect `/api/health` plus `/api/tools`.

### Known benign warning

Both iccDEV container servers may emit a `pydantic_settings`
`IncompleteFieldDefinitionWarning` about a `lifespan` forward reference on
stderr at startup. This is a known upstream issue in the third-party
`modelcontextprotocol/python-sdk` dependency
(<https://github.com/modelcontextprotocol/python-sdk/issues/3294>), not a
defect in this repo or the iccDEV packages. It does not affect protocol
responses; ignore it.

## Sanity Checklist Before Committing `.mcp.json` Changes

- [ ] No `command`/`args` value contains a personal home directory or
      machine-specific absolute path.
- [ ] No literal token, key, or credential value appears anywhere in the
      file; secrets are referenced only via `"${VAR_NAME}"`.
- [ ] Every `stdio` server starts cleanly and responds to a real
      `initialize` handshake (see command above) before merging.
