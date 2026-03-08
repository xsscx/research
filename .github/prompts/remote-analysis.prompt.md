# Remote ICC Profile Analysis via MCP Docker API — Prompt

## Overview

This prompt enables any Copilot agent (macOS, Cloud CI, or remote) to perform
full ICC profile security analysis via the MCP Docker REST API, without requiring
local iccanalyzer-lite binaries or git commit round-trips.

## Prerequisites

1. MCP Docker image running on a reachable host:
   ```bash
   docker run --rm -d -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp web
   ```
2. Network access from the agent to the Docker host (port 8080)
3. `curl` available on the agent machine

## Workflow

### Step 1: Verify Server Health

```bash
curl -s http://<host>:8080/api/health
# Expected: {"ok":true,"tools":24}
```

### Step 2: Upload ICC/TIFF File

```bash
curl -s -F "file=@profile.icc" http://<host>:8080/api/upload
```

Response:
```json
{
  "ok": true,
  "path": "/tmp/mcp-uploads/a1b2c3_profile.icc",
  "filename": "profile.icc",
  "size": 41234
}
```

Save the `path` value for subsequent API calls.

### Step 3: Run Analysis

Choose one or more analysis endpoints:

| Endpoint | Purpose | Best For |
|----------|---------|----------|
| `/api/security?path=...` | 141-heuristic scan (text) | Human-readable report |
| `/api/security-json?path=...` | 141-heuristic scan (JSON) | Programmatic processing |
| `/api/security-report?path=...` | Severity-sorted report | Professional output |
| `/api/inspect?path=...` | Profile structure | Header/tag examination |
| `/api/roundtrip?path=...` | AToB/BToA validation | LUT completeness check |
| `/api/full?path=...` | Combined analysis | Complete one-shot analysis |
| `/api/xml?path=...` | ICC → XML conversion | Human-readable profile data |

```bash
# Full analysis (recommended for triage)
PROFILE_PATH="/tmp/mcp-uploads/a1b2c3_profile.icc"
curl -s "http://<host>:8080/api/full?path=${PROFILE_PATH}"

# JSON analysis (for automated processing)
curl -s "http://<host>:8080/api/security-json?path=${PROFILE_PATH}"

# Profile comparison
curl -s "http://<host>:8080/api/compare?path_a=${PATH_A}&path_b=${PATH_B}"
```

### Step 4: List Available Profiles

```bash
# List profiles in test-profiles/
curl -s "http://<host>:8080/api/list?directory=test-profiles"

# List profiles in extended-test-profiles/
curl -s "http://<host>:8080/api/list?directory=extended-test-profiles"
```

## Batch Analysis Script (macOS Agent)

```bash
#!/bin/bash
# Batch-analyze ICC profiles via MCP Docker API
# Run from macOS agent — no local binary needed

HOST="http://<wsl-ip>:8080"

for f in fuzz/graphics/icc/*.icc; do
  echo "=== Analyzing: $(basename "$f") ==="

  # Upload
  RESPONSE=$(curl -s -F "file=@$f" "${HOST}/api/upload")
  REMOTE_PATH=$(echo "$RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['path'])")

  # Analyze
  curl -s "${HOST}/api/security-json?path=${REMOTE_PATH}" > "/tmp/analysis-$(basename "$f" .icc).json"

  echo "  → Saved to /tmp/analysis-$(basename "$f" .icc).json"
done
```

## When to Use Remote vs Local Analysis

| Scenario | Method | Reason |
|----------|--------|--------|
| macOS agent triage | Remote API | No local binary available |
| Quick spot-check of 1-5 profiles | Remote API | Avoids commit overhead |
| Batch analysis of 50+ profiles | Local (WSL-2) | Faster, results committed to repo |
| CI pipeline analysis | Remote API | Docker image has everything pre-built |
| Crash PoC triage | Either | Remote for quick check, local for full ASAN trace |

## Security Notes

- The API has no authentication — only expose on trusted networks
- Upload limit: 20MB per file
- Uploaded files persist in `/tmp/mcp-uploads/` until container restart
- 4 concurrent analysis tasks max (semaphore-limited)

## Docker Image Details

- Image: `ghcr.io/xsscx/icc-profile-mcp`
- Built by: `.github/workflows/mcp-server-docker.yml`
- Platforms: `linux/amd64`, `linux/arm64` (native on Apple Silicon — no QEMU needed)
- Two modes: `mcp` (default, stdio for MCP clients), `web` (REST API + HTML UI)
- Contains: iccanalyzer-lite (debug, no sanitizers), colorbleed_tools, MCP server, test-profiles
- Note: Container binary is built WITHOUT ASAN/UBSAN for multi-arch compatibility.
  ASAN uses platform-specific shadow memory mappings incompatible with QEMU emulation.
  For ASAN-instrumented analysis, use native WSL-2/Linux builds.

## See Also
- [cooperative-development.prompt.md](cooperative-development.prompt.md) — Multi-agent task lists
- [analyze-icc-profile.prompt.yml](analyze-icc-profile.prompt.yml) — Full local analysis workflow
- [health-check.prompt.yml](health-check.prompt.yml) — MCP server verification
- [corpus-management.prompt.md](corpus-management.prompt.md) — Corpus lifecycle
