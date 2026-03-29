# ICC Profile MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io/) server that lets AI assistants interactively analyze ICC color profiles for security research, validation, and forensic inspection.

<img width="3742" height="1936" alt="ICC Profile MCP Server WebUI" src="https://github.com/user-attachments/assets/30a8c93f-6c78-4d1e-a67e-c38eb0cb8186" />

---

## Quick Start — Docker (No Build Required)

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web
```

Open <http://127.0.0.1:8080> — that's it. The bundled test corpus is pre-loaded, no dependencies needed.

### Verify

```bash
curl -s http://127.0.0.1:8080/api/health
# {"ok":true,"tools":26,"engines":{"v1":true,"v2":true},"defaultAnalysisEngine":"v2","defaultStructuralEngine":"v1"}
```

---

## What This Does

ICC color profiles control how colors are translated between devices (cameras, monitors, printers). Malformed profiles have been the source of real-world vulnerabilities (CVE-2022-26730, CVE-2023-46602, CVE-2024-38427). This MCP server connects your AI assistant to purpose-built analysis tools so you can inspect, compare, and security-scan ICC profiles through natural conversation.

**You say:**
> "Analyze the security of the CVE-2022-26730 proof-of-concept profile"

**Your AI assistant calls** `analyze_security("cve-2022-26730-poc-sample-004.icc")` and returns a 173-check report covering header validation, tag anomalies, overflow indicators, malicious patterns, date validation, signature analysis, spectral range checks, technology signatures, tag overlap detection, deep content analysis, NaN/float safety, AddXform UAF patterns, TIFF image security, XML serialization safety, and raw file boundary checks.

In the published container, security-oriented endpoints default to the V2 engine (`icctest`). Structural inspection and round-trip validation remain on the legacy engine until V2 grows dedicated equivalents. Override any request with `engine=v1`, `engine=v2`, or `engine=auto`.

`/api/pawg` and `/api/security-report` are intentionally rendered as
conformance-only PAWG views in the WebUI/API for now: they use the native V1/V2
PAWG checklist output as the source, then present only the `[ CONFORMANCE ]`
section plus coverage/spec references.

The published container also bundles the source trees and Linux build toolchain required by the maintainer/operations endpoints exposed in the WebUI, so checks like `check_dependencies` reflect the container itself rather than your host OS. The safe `iccDEV` non-GUI CLI set includes `iccToXml`, `iccFromXml`, `iccDumpProfile`, `iccRoundTrip`, and `iccApplyNamedCmm`, while the XML fallback path still exposes the unsafe `colorbleed_tools` binaries (`iccToXml_unsafe`, `iccFromXml_unsafe`).

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

Deep link to any tool: `http://127.0.0.1:8080/#security`, `#security_report`, `#pawg`, `#inspect`, `#compare`, `#xml`, etc.

### Option B: REST API

```bash
# Health check
curl -s http://127.0.0.1:8080/api/health

# List available profiles
curl -s 'http://127.0.0.1:8080/api/list?directory=test-profiles'

# 173-check V2 security scan
curl -s 'http://127.0.0.1:8080/api/security?path=sRGB_D65_MAT.icc'

# PAWG-oriented conformance report with checklist/spec references
curl -s 'http://127.0.0.1:8080/api/pawg?path=sRGB_D65_MAT.icc'

# Structured V2 security JSON object
curl -s 'http://127.0.0.1:8080/api/security-json?path=sRGB_D65_MAT.icc'

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

Ten pre-built prompt templates in [`.github/prompts/`](../.github/prompts/):

| Prompt | Purpose | Variables |
|---|---|---|
| `analyze-icc-profile` | Full 173-check security scan | `{{profile_path}}` |
| `compare-icc-profiles` | Side-by-side structural diff | `{{profile_a}}`, `{{profile_b}}` |
| `triage-cve-poc` | CVE PoC analysis with CVE mapping | `{{profile_path}}` |
| `triage-fuzzer-crash` | ASAN/UBSAN crash triage workflow | (none) |
| `triage-fuzzer-oom` | LibFuzzer OOM triage and patch workflow | (none) |
| `improve-fuzzer-coverage` | Coverage gap analysis and seed creation | (none) |
| `upstream-sync` | CFL iccDEV patch reconciliation | (none) |
| `health-check` | MCP server verification | (none) |
| `image-fuzzer-quality` | xnuimagefuzzer output quality assessment | (none) |
| `mac-catalyst-ci` | Mac Catalyst CI debugging guide | (none) |

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

Expected: `ok: true`, `tools: 26`, `defaultAnalysisEngine: "v2"`, `defaultStructuralEngine: "v1"`

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

The clean profile should come back without findings in the V2 report. **WebUI:** <http://127.0.0.1:8080/#security>

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

A self-contained demo with the interactive WebUI and live REST API over the bundled test corpus:

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp web
```

| Route | Description |
|-------|-------------|
| `/` | Interactive WebUI — select profiles, run tools |
| `/api/*` | All analysis endpoints |

Custom port: `docker run --rm -p 8083:8083 ghcr.io/xsscx/icc-profile-mcp web --port 8083`

---

## All 24 MCP Tools

| # | Tool | Type | Description |
|---|------|------|-------------|
| 1 | `health_check` | Analysis | Server status, binary availability, profile counts |
| 2 | `inspect_profile` | Analysis | Header, tag table, field values |
| 3 | `analyze_security` | Analysis | 173-check security scan (H1–H173) |
| 4 | `validate_roundtrip` | Analysis | AToB/BToA tag pair completeness |
| 5 | `full_analysis` | Analysis | All modes combined in one pass |
| 6 | `profile_to_xml` | Analysis | Binary ICC → XML conversion |
| 7 | `compare_profiles` | Analysis | Unified diff of two profiles |
| 8 | `list_test_profiles` | Analysis | Browse available profiles by directory |
| 9 | `upload_and_analyze` | Analysis | Base64 upload + any analysis mode |
| 10 | `security_json` | Analysis | Structured JSON security analysis |
| 11 | `security_report` | Analysis | Professional severity-sorted report |
| 12 | `build_tools` | Maintainer | Build C++ analysis tools from source |
| 13 | `cmake_configure` | Maintainer | Configure iccDEV cmake |
| 14 | `cmake_build` | Maintainer | Compile cmake build |
| 15 | `create_all_profiles` | Maintainer | Generate ~80+ ICC test profiles |
| 16 | `run_iccdev_tests` | Maintainer | Validate generated profiles |
| 17 | `cmake_option_matrix` | Maintainer | Test 17 cmake toggles |
| 18 | `windows_build` | Maintainer | MSVC + vcpkg cross-platform build |
| 19 | `check_dependencies` | Operations | Check build dependency availability |
| 20 | `find_build_artifacts` | Operations | Find binaries, checksums, linkage |
| 21 | `batch_test_profiles` | Operations | Run tools over all .icc files |
| 22 | `validate_xml` | Operations | xmllint validation of ICC XML |
| 23 | `coverage_report` | Operations | Merge profraw + llvm-cov report |
| 24 | `scan_logs` | Operations | Grep logs for errors/crashes/sanitizer |

---

## API Reference

| Method | Endpoint | Parameters | Description |
|--------|----------|------------|-------------|
| `GET` | `/api/health` | — | Health check with tool and engine metadata (current container baseline: 26 tools) |
| `GET` | `/api/list` | `directory` | List profiles: `test-profiles`, `extended-test-profiles` |
| `GET` | `/api/inspect` | `path` | Structural dump (header + tag table) |
| `GET` | `/api/security` | `path` | 173-check security scan |
| `GET` | `/api/security-json` | `path` | Structured JSON security object |
| `GET` | `/api/security-report` | `path` | PAWG-aligned conformance-only report with checklist/spec references |
| `GET` | `/api/pawg` | `path` | PAWG conformance-section view with bundled ICC spec PDF references |
| `GET` | `/api/roundtrip` | `path` | Round-trip transform validation |
| `GET` | `/api/full` | `path` | Combined analysis (security + round-trip + structure) |
| `GET` | `/api/xml` | `path` | Binary ICC → XML conversion |
| `GET` | `/api/compare` | `path_a`, `path_b` | Unified diff of two profiles |
| `GET` | `/api/registry` | `engine` (optional) | Analyzer registry JSON |
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
The server searches `test-profiles/`, `extended-test-profiles/`, and the repo root. Mount your own directory:
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
