# ICC Profile MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io/) server that lets AI assistants interactively analyze ICC color profiles for security research, validation, and forensic inspection.

<img width="3742" height="1936" alt="ICC Profile MCP Server WebUI" src="https://github.com/user-attachments/assets/30a8c93f-6c78-4d1e-a67e-c38eb0cb8186" />

---

## Quick Start — Docker (No Build Required)

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web
```

Open <http://127.0.0.1:8080> — that's it. 126 test profiles are pre-loaded, no dependencies needed.

### Verify

```bash
curl -s http://127.0.0.1:8080/api/health
# {"ok":true,"tools":16}
```

---

## What This Does

ICC color profiles control how colors are translated between devices (cameras, monitors, printers). Malformed profiles have been the source of real-world vulnerabilities (CVE-2022-26730, CVE-2023-46602, CVE-2024-38427). This MCP server connects your AI assistant to purpose-built analysis tools so you can inspect, compare, and security-scan ICC profiles through natural conversation.

**You say:**
> "Analyze the security of the CVE-2022-26730 proof-of-concept profile"

**Your AI assistant calls** `analyze_security("cve-2022-26730-poc-sample-004.icc")` and returns a 32-heuristic report covering header validation, tag anomalies, overflow indicators, malicious patterns, date validation, signature analysis, spectral range checks, technology signatures, tag overlap detection, deep content analysis, and raw file boundary checks.

---

## Ways to Use It

### Option A: WebUI (browser-based)

```bash
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web
```

Open `http://127.0.0.1:8080`:
1. Click **Security Scan** (or any tool button)
2. Click **📋 Server Profiles** and select a profile, or **📂 Choose File** to upload your own
3. Click **Run**
4. Read the report — click **Copy** or **Save As** to keep it

Deep link to any tool: `http://127.0.0.1:8080/#security`, `#inspect`, `#compare`, `#xml`, etc.

### Option B: REST API

```bash
# Health check
curl -s http://127.0.0.1:8080/api/health

# List available profiles
curl -s 'http://127.0.0.1:8080/api/list?directory=test-profiles'

# 32-heuristic security scan
curl -s 'http://127.0.0.1:8080/api/security?path=sRGB_D65_MAT.icc'

# Structural inspection
curl -s 'http://127.0.0.1:8080/api/inspect?path=sRGB_D65_MAT.icc'

# Round-trip validation
curl -s 'http://127.0.0.1:8080/api/roundtrip?path=sRGB_D65_MAT.icc'

# Full analysis (all modes combined)
curl -s 'http://127.0.0.1:8080/api/full?path=sRGB_D65_MAT.icc'

# XML conversion
curl -s 'http://127.0.0.1:8080/api/xml?path=sRGB_D65_MAT.icc'

# Compare two profiles
curl -s 'http://127.0.0.1:8080/api/compare?path_a=sRGB_D65_MAT.icc&path_b=sRGB_v4_ICC_preference.icc'

# Upload your own profile
curl -s -X POST -F 'file=@myprofile.icc' http://127.0.0.1:8080/api/upload
```

### Option C: GitHub Issue (easiest — no Docker)

1. Rename your file from `profile.icc` to `profile.icc.txt` (GitHub blocks `.icc` attachments)
2. Open an issue at [github.com/xsscx/research/issues](https://github.com/xsscx/research/issues)
3. Attach the `.icc.txt` file and describe the analysis you want
4. The Copilot coding agent picks up the issue, runs the tools, and posts a full report as a PR

### Option D: MCP stdio (for AI assistants)

```bash
# Docker (any MCP client — Claude Desktop, Copilot CLI, VS Code, Cursor)
docker run --rm -i ghcr.io/xsscx/icc-profile-mcp:latest
```

Client config (Claude Desktop, Copilot CLI, etc.):
```json
{
  "mcpServers": {
    "icc-profile-analyzer": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "ghcr.io/xsscx/icc-profile-mcp:latest"]
    }
  }
}
```

### Option E: Reusable Prompts (GitHub Models)

Four pre-built prompt templates in [`.github/prompts/`](../.github/prompts/):

| Prompt | Purpose | Variables |
|---|---|---|
| `analyze-icc-profile` | Full 32-heuristic security scan | `{{profile_path}}` |
| `compare-icc-profiles` | Side-by-side structural diff | `{{profile_a}}`, `{{profile_b}}` |
| `triage-cve-poc` | CVE PoC analysis with CVE mapping | `{{profile_path}}` |
| `health-check` | MCP server verification | (none) |

---

## Reproduce the Demo — Step by Step

Start the server, then follow each step with curl or the WebUI.

```bash
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web
```

### 1. Health Check

```bash
curl -s http://127.0.0.1:8080/api/health | python3 -m json.tool
```

Expected: `{"ok": true, "tools": 16}`

**WebUI:** Open <http://127.0.0.1:8080>

### 2. List Profiles

```bash
curl -s 'http://127.0.0.1:8080/api/list?directory=test-profiles'
```

**WebUI:** <http://127.0.0.1:8080/#list>

### 3. Security Scan — Clean Profile

```bash
curl -s 'http://127.0.0.1:8080/api/security?path=sRGB_D65_MAT.icc'
```

All 32 heuristics should show `[OK]`. **WebUI:** <http://127.0.0.1:8080/#security>

### 4. Security Scan — CVE PoC

```bash
curl -s 'http://127.0.0.1:8080/api/security?path=cve-2022-26730-poc-sample-004.icc'
```

Look for `[WARN]` and `[CRITICAL]` flags — this profile triggers multiple heuristic warnings.

### 5. Structural Inspection

```bash
curl -s 'http://127.0.0.1:8080/api/inspect?path=sRGB_D65_MAT.icc'
```

**WebUI:** <http://127.0.0.1:8080/#inspect>

### 6. Full Analysis

```bash
curl -s 'http://127.0.0.1:8080/api/full?path=sRGB_D65_MAT.icc'
```

**WebUI:** <http://127.0.0.1:8080/#full>

### 7. Round-Trip Validation

```bash
curl -s 'http://127.0.0.1:8080/api/roundtrip?path=sRGB_D65_MAT.icc'
```

**WebUI:** <http://127.0.0.1:8080/#roundtrip>

### 8. XML Conversion

```bash
curl -s 'http://127.0.0.1:8080/api/xml?path=sRGB_D65_MAT.icc'
```

**WebUI:** <http://127.0.0.1:8080/#xml>

### 9. Compare Two Profiles

```bash
curl -s 'http://127.0.0.1:8080/api/compare?path_a=sRGB_D65_MAT.icc&path_b=sRGB_v4_ICC_preference.icc'
```

**WebUI:** <http://127.0.0.1:8080/#compare> — click Profile A, select a file, then click Profile B and select another.

### 10. Upload Your Own Profile

```bash
curl -s -X POST -F 'file=@myprofile.icc' http://127.0.0.1:8080/api/upload
curl -s 'http://127.0.0.1:8080/api/security?path=myprofile.icc'
```

**WebUI:** Click **📂 Choose File** on any tool page.

---

## Developer Demo Container

A self-contained demo with an interactive HTML report, live REST API, and 218 pre-loaded test profiles:

```bash
docker pull ghcr.io/xsscx/icc-profile-demo:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-demo
```

| Route | Description |
|-------|-------------|
| `/` | Demo report — static showcase with sample outputs |
| `/ui` | Interactive WebUI — select profiles, run tools |
| `/api` | REST API index (JSON) |
| `/api/*` | All analysis endpoints |

Custom port: `docker run --rm -p 8083:8083 ghcr.io/xsscx/icc-profile-demo --port 8083`

---

## All 16 MCP Tools

| # | Tool | Type | Description |
|---|------|------|-------------|
| 1 | `health_check` | Analysis | Server status, binary availability, profile counts |
| 2 | `inspect_profile` | Analysis | Header, tag table, field values |
| 3 | `analyze_security` | Analysis | 32-heuristic security scan (H1–H32) |
| 4 | `validate_roundtrip` | Analysis | AToB/BToA tag pair completeness |
| 5 | `full_analysis` | Analysis | All modes combined in one pass |
| 6 | `profile_to_xml` | Analysis | Binary ICC → XML conversion |
| 7 | `compare_profiles` | Analysis | Unified diff of two profiles |
| 8 | `list_test_profiles` | Analysis | Browse available profiles by directory |
| 9 | `upload_and_analyze` | Analysis | Base64 upload + any analysis mode |
| 10 | `build_tools` | Maintainer | Build C++ analysis tools from source |
| 11 | `cmake_configure` | Maintainer | Configure iccDEV cmake |
| 12 | `cmake_build` | Maintainer | Compile cmake build |
| 13 | `create_all_profiles` | Maintainer | Generate ~80+ ICC test profiles |
| 14 | `run_iccdev_tests` | Maintainer | Validate generated profiles |
| 15 | `cmake_option_matrix` | Maintainer | Test 17 cmake toggles |
| 16 | `windows_build` | Maintainer | MSVC + vcpkg cross-platform build |

---

## API Reference

| Method | Endpoint | Parameters | Description |
|--------|----------|------------|-------------|
| `GET` | `/api/health` | — | Health check: `{"ok": true, "tools": 16}` |
| `GET` | `/api/list` | `directory` | List profiles: `test-profiles`, `extended-test-profiles`, `xif` |
| `GET` | `/api/inspect` | `path` | Structural dump (header + tag table) |
| `GET` | `/api/security` | `path` | 32-heuristic security scan |
| `GET` | `/api/roundtrip` | `path` | Round-trip transform validation |
| `GET` | `/api/full` | `path` | Combined analysis (security + round-trip + structure) |
| `GET` | `/api/xml` | `path` | Binary ICC → XML conversion |
| `GET` | `/api/compare` | `path_a`, `path_b` | Unified diff of two profiles |
| `POST` | `/api/upload` | `file` (multipart) | Upload `.icc` file (20 MB max) |
| `POST` | `/api/output/download` | `text`, `filename` (JSON) | Download tool output as file |

---

## Security Model

This server processes untrusted binary files (fuzzer-generated crash samples, CVE PoCs):

| Protection | Detail |
|------------|--------|
| **Path traversal prevention** | `Path.resolve()` + `relative_to()` validation |
| **Symlink boundary enforcement** | Resolved target must remain within the repository |
| **Null byte rejection** | Paths containing null bytes are rejected |
| **Command injection prevention** | `exec` (argument list), never `shell=True` |
| **Output size cap** | 10 MB limit on subprocess output |
| **Process timeout** | 60–120s with proper cleanup |
| **Upload limits** | 20 MB max, filename sanitization |
| **CSP nonce rotation** | Per-request nonce, strict security headers |

---

## Profile Path Resolution

Reference profiles by:
- **Filename:** `sRGB_D65_MAT.icc` — searches `test-profiles/`, `extended-test-profiles/`, and repo root
- **Directory-qualified:** `extended-test-profiles/cve-2023-46602.icc`
- **Mounted directory:** `my-profiles/custom.icc` (via `-v` Docker mount)

Paths attempting to escape the repository are blocked.

---

## Troubleshooting

### "Profile not found"
The server searches `test-profiles/`, `extended-test-profiles/`, `xif/`, and the repo root. Mount your own directory:
```bash
docker run --rm -p 8080:8080 -v /path/to/profiles:/app/my-profiles:ro \
  ghcr.io/xsscx/icc-profile-mcp:latest web
```
Then: `curl 'http://127.0.0.1:8080/api/security?path=my-profiles/custom.icc'`

### ASAN/UBSAN output in stderr
This is **expected** — analysis binaries use AddressSanitizer instrumentation. ASAN output means the profile triggered a real memory safety bug — that's a finding, not an error.

### Large profiles produce truncated XML
XML output is capped at 50,000 characters. The full size is reported in the truncation notice.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings |
| `1` | Finding — security heuristic triggered |
| `2` | Error — malformed input (profile fails to load) |
| `3` | Usage — incorrect arguments |
