---
mode: agent
description: Validate current iccDEV PAWG, MCP, REST, container, and maintainer-tool interoperability
---

# Validate iccDEV PAWG and MCP Interoperability

Use `.github/skills/iccdev-pawg-mcp/SKILL.md` for `TARGET`, where `TARGET` is a
local checkout, WSL host, VM, or container environment.

Record the exact upstream revision and container digest. Validate
`iccPawgReport` with text and JSON output, perform a real MCP initialize and
`tools/list` exchange, keep stdio open through the `health_check` response, and
check `/api/health` plus
`/api/tools` when REST is in scope. Discover capabilities from the runtime; do
not assume a fixed tool count.

Report:

- source revision and worktree state
- image reference and digest
- PAWG commands, input profile, exit codes, and report states
- MCP server identity and discovered tool names
- native, CLI, and service capability gaps
- maintainer QA command and result, if requested
- sanitizer, signal, timeout, or host-integration exceptions
