# mcp-server/ — Path-Specific Instructions

## What This Is

A [Model Context Protocol](https://modelcontextprotocol.io/) server (Python, FastMCP)
exposing 24 tools (11 analysis + 7 maintainer + 6 operations) for AI-assisted ICC
profile security research. Supports MCP stdio, REST API, and interactive WebUI modes.

**Docker image**: `ghcr.io/xsscx/icc-profile-mcp` — built with full ASAN+UBSAN
instrumentation. Two modes: `mcp` (default, stdio) and `web` (REST API + HTML UI
on port 8080).

## File Structure

```
mcp-server/
├── icc_profile_mcp.py      # Main MCP server — 24 tools via FastMCP
├── web_ui.py                # REST API + interactive HTML WebUI
├── test_mcp.py              # MCP server tests
├── test_web_ui.py           # WebUI tests
├── Dockerfile               # Docker container (ASAN+UBSAN, linux/amd64)
├── build.sh                 # Build script for Docker image
├── pyproject.toml           # Python packaging (hatchling)
├── requirements.txt         # Python dependencies
├── index.html               # Demo report template
├── codeql-config.yml        # CodeQL security scanning config
└── codeql-queries/          # 7 custom CodeQL queries for MCP security
    ├── api-path-traversal.ql
    ├── missing-output-sanitization.ql
    ├── path-traversal-build-dir.ql
    ├── subprocess-command-injection.ql
    ├── unsafe-env-server-bind.ql
    ├── unvalidated-file-upload.ql
    ├── security-research-suite.qls
    └── qlpack.yml
```

## Build and Run

### Local Development

```bash
cd mcp-server && pip install -e .
python3 icc_profile_mcp.py        # MCP stdio mode
python3 web_ui.py                  # REST API + WebUI on port 8080
```

Prerequisites: `iccanalyzer-lite/iccanalyzer-lite` and `colorbleed_tools/iccToXml_unsafe`
must be built first. See `iccanalyzer-lite.instructions.md` and
`colorbleed_tools.instructions.md`.

### Docker

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp web    # REST + WebUI
docker run --rm -i ghcr.io/xsscx/icc-profile-mcp                   # MCP stdio
```

### Docker Validation Gate (MANDATORY)

Before pushing ANY Dockerfile or MCP server changes, build and test locally:

```bash
# 1. Build local image
cd mcp-server && docker build -t icc-mcp-local:test -f Dockerfile ..

# 2. Start local container
docker run --rm -d -p 8081:8080 --name mcp-test icc-mcp-local:test web

# 3. Validate endpoints
curl -s http://localhost:8081/api/health          # → {"ok":true,"tools":24}
curl -s http://localhost:8081/api/registry | python3 -c "
import json,sys; r=json.load(sys.stdin)['registry']
print(f'heuristics:{r[\"totalHeuristics\"]} CVEs:{r[\"uniqueCVEs\"]} GHSAs:{r[\"uniqueGHSAs\"]}')"
curl -s 'http://localhost:8081/api/health-check' | python3 -c "
import json,sys; d=json.load(sys.stdin); print(d['result'][:200])"
docker exec mcp-test which xmllint               # → /usr/bin/xmllint

# 4. Upload and analyze a test profile
curl -s -F "file=@test-profiles/sRGB_D65_MAT.icc" http://localhost:8081/api/upload
# Use the returned path for:
# curl -s "http://localhost:8081/api/security-json?path=<path>" | python3 -m json.tool

# 5. Stop test container
docker stop mcp-test

# 6. Only then: git push
```

After CI rebuilds the image, pull and re-validate:

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -d -p 8080:8080 --name mcp-verify ghcr.io/xsscx/icc-profile-mcp web
curl -s http://localhost:8080/api/health          # → {"ok":true,"tools":24}
curl -s http://localhost:8080/api/registry | python3 -c "
import json,sys; r=json.load(sys.stdin)['registry']
print(f'heuristics:{r[\"totalHeuristics\"]} CVEs:{r[\"uniqueCVEs\"]} GHSAs:{r[\"uniqueGHSAs\"]}')"
docker stop mcp-verify
```

## Test

```bash
cd mcp-server && python3 test_mcp.py     # MCP tool tests
cd mcp-server && python3 test_web_ui.py  # WebUI/API tests
```

## The 24 MCP Tools

### Analysis Tools (11)

| # | Tool | Description |
|---|------|-------------|
| 1 | `health_check` | Server status, binary availability, profile counts |
| 2 | `inspect_profile` | Header, tag table, field values |
| 3 | `analyze_security` | 148-heuristic security scan (H1–H148) |
| 4 | `validate_roundtrip` | AToB/BToA tag pair completeness |
| 5 | `full_analysis` | All modes combined in one pass |
| 6 | `profile_to_xml` | Binary ICC → XML conversion |
| 7 | `compare_profiles` | Unified diff of two profiles |
| 8 | `list_test_profiles` | Browse available profiles by directory |
| 9 | `upload_and_analyze` | Base64 upload + any analysis mode |
| 10 | `security_json` | Structured JSON security analysis |
| 11 | `security_report` | Professional severity-sorted report |

### Maintainer Tools (7)

| # | Tool | Description |
|---|------|-------------|
| 12 | `build_tools` | Build C++ analysis tools from source |
| 13 | `cmake_configure` | Configure iccDEV cmake |
| 14 | `cmake_build` | Compile cmake build |
| 15 | `create_all_profiles` | Generate ~80+ ICC test profiles |
| 16 | `run_iccdev_tests` | Validate generated profiles |
| 17 | `cmake_option_matrix` | Test 17 cmake toggles |
| 18 | `windows_build` | MSVC + vcpkg cross-platform build |

### Operations Tools (6)

| # | Tool | Description |
|---|------|-------------|
| 19 | `check_dependencies` | Check build dependency availability |
| 20 | `find_build_artifacts` | Find binaries, checksums, linkage |
| 21 | `batch_test_profiles` | Run tools over all .icc files |
| 22 | `validate_xml` | xmllint validation of ICC XML |
| 23 | `coverage_report` | Merge profraw + llvm-cov report |
| 24 | `scan_logs` | Grep logs for errors/crashes/sanitizer |

## Tool Count Sync — 4 Locations

**CRITICAL**: When changing the tool count, ALL 4 files must be updated simultaneously:

| # | File | Location |
|---|------|----------|
| 1 | `icc_profile_mcp.py` | `health_check()` return value comment |
| 2 | `web_ui.py` | `/api/health` endpoint response |
| 3 | `test_mcp.py` | `test_health_check()` assertion |
| 4 | `test_web_ui.py` | `test_health()` assertion |

Anti-Pattern #2 in `multi-agent.instructions.md` documents the consequences of
updating server code without updating tests.

## Security Model

This server processes **untrusted binary files** (fuzzer crash samples, CVE PoCs):

| Protection | Implementation |
|------------|---------------|
| Path traversal prevention | `Path.resolve()` + `relative_to()` validation |
| Symlink boundary enforcement | Resolved target must stay within repository |
| Null byte rejection | Paths containing `\x00` are rejected |
| Command injection prevention | `exec` (argument list), never `shell=True` |
| Output size cap | 10 MB limit on subprocess output |
| Process timeout | 60–120s with proper cleanup |
| Upload limits | 20 MB max, filename sanitization |
| CSP nonce rotation | Per-request nonce, strict security headers |
| Output sanitization | Strip ANSI escapes + C0 control chars (except LF/tab) |

### CodeQL Coverage

7 custom CodeQL queries in `codeql-queries/` targeting MCP-specific security:
- Path traversal in API routes and build directories
- Missing output sanitization
- Subprocess command injection
- Unsafe environment variable server binding
- Unvalidated file upload handling

## Profile Path Resolution

Profiles can be referenced by:
- **Filename**: `sRGB_D65_MAT.icc` — searches `test-profiles/`, `extended-test-profiles/`, repo root
- **Directory-qualified**: `extended-test-profiles/cve-2023-46602.icc`
- **Mounted directory**: `my-profiles/custom.icc` (via Docker `-v` mount)

All paths are validated against `_ALLOWED_BASES` — traversal attempts are blocked.

## Docker Image Policy

- **MUST** include full ASAN+UBSAN instrumentation — NEVER add `NO_SANITIZERS=1`
- **MUST** include `libclang-rt-18-dev` for sanitizer runtimes
- **MUST** use `-O0 -g3` compiler flags (not `-O1 -g`) — maximum debug info, no optimization
- **MUST** enable coverage instrumentation (never set `NO_COVERAGE=1`)
- **MUST** set `LLVM_PROFILE_FILE=/dev/null` in runtime stage — prevents profraw
  permission errors when running as non-root `mcp` user
- Build `linux/amd64` only — ASAN shadow memory is incompatible with QEMU cross-arch
- Apple Silicon Macs: **Docker Desktop only** (Rosetta 2 supports ASAN)
- **Colima and OrbStack NOT supported** — QEMU/VZ backends lack ASAN support
- colorbleed_tools use `make CONFIG=release` in Docker (runtime stage lacks libclang-rt)
- Binary size ~43MB confirms ASAN instrumentation (non-instrumented ~5MB)

See Anti-Pattern #1 in `multi-agent.instructions.md` for the full history.

## REST API Endpoints

| Method | Endpoint | Parameters | Description |
|--------|----------|------------|-------------|
| `GET` | `/api/health` | — | `{"ok": true, "tools": 24}` |
| `GET` | `/api/health-check` | — | Full health check (binary availability, profile counts) |
| `GET` | `/api/list` | `directory` | List profiles in directory |
| `GET` | `/api/inspect` | `path` | Structural dump |
| `GET` | `/api/security` | `path` | 148-heuristic scan (text) |
| `GET` | `/api/security-json` | `path` | 148-heuristic scan (JSON) |
| `GET` | `/api/security-report` | `path` | Severity-sorted report |
| `GET` | `/api/roundtrip` | `path` | Round-trip validation |
| `GET` | `/api/full` | `path` | Combined analysis |
| `GET` | `/api/xml` | `path` | ICC → XML conversion |
| `GET` | `/api/xml/download` | `path` | ICC → XML as file download |
| `GET` | `/api/compare` | `path_a`, `path_b` | Side-by-side diff |
| `GET` | `/api/check-dependencies` | — | Check build dependency availability |
| `GET` | `/api/find-artifacts` | `build_dir` | Find binaries, checksums, linkage |
| `POST` | `/api/upload` | `file` (multipart) | Upload ICC file (20 MB max) |
| `POST` | `/api/output/download` | `text`, `filename` | Download output as file |
| `POST` | `/api/build-tools` | `target` | Build C++ analysis tools from source |
| `POST` | `/api/batch-test` | `build_dir`, `tool` | Run tools over all .icc files |
| `POST` | `/api/validate-xml` | `directory`, `checks` | xmllint validation of ICC XML |
| `POST` | `/api/coverage-report` | `build_dir` | Merge profraw + llvm-cov report |
| `POST` | `/api/scan-logs` | `directory`, `pattern` | Grep logs for errors/crashes |
| `POST` | `/api/upload-and-analyze` | `data_base64`, `filename`, `mode` | Base64 upload + analysis |
| `GET` | `/api/registry` | — | Full heuristic registry JSON (dynamic counts) |

## Exit Codes (iccanalyzer-lite)

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings |
| `1` | Finding — security heuristic triggered |
| `2` | Error — malformed input (profile fails to load) |
| `3` | Usage — incorrect arguments |

Exit code 1 is NOT a crash — it means findings were detected. See CJF-13 in
`copilot-instructions.md`.

## Adding a New MCP Tool

1. Add the `@mcp.tool()` decorated async function in `icc_profile_mcp.py`
2. Add the REST API route in `web_ui.py` if the tool should be web-accessible
3. Update tool count (24→25) in ALL 4 locations (see Tool Count Sync table)
4. Add test in `test_mcp.py`
5. Add WebUI test in `test_web_ui.py` if web-accessible
6. Update `.github/copilot-instructions.md` tool count references
7. Update this instructions file

## Common Pitfalls

- **Tool count mismatch** — The #1 recurring CI failure. When changing tools, update
  all 4 files simultaneously. See Anti-Pattern #2.
- **Heuristic count mismatch** — The #2 recurring issue. When heuristic count changes
  (currently 148), update ALL locations: `icc_profile_mcp.py` docstrings,
  `web_ui.py` endpoint descriptions, `index.html` meta, `README.md`, this file's
  REST API table. See `iccanalyzer-lite.instructions.md` for the full sync list.
- **Docker ASAN removal** — NEVER remove ASAN from the Docker image. The entire
  purpose is security analysis with sanitizer instrumentation.
- **stderr contamination of JSON** — `_run()` in `icc_profile_mcp.py` appends stderr
  to stdout by default. Any tool returning structured JSON (e.g., `analyze_security_json`)
  MUST call `_run()` with `include_stderr=False`. The `web_ui.py` handler has
  defense-in-depth stripping as a secondary guard.
- **CVE PoC crash recovery** — When iccanalyzer-lite hits SIGSEGV on malicious
  profiles, signal recovery produces a banner on stderr but NO JSON on stdout.
  The `/api/security-json` endpoint returns a structured `crashRecovery` JSON
  fallback: `{"summary":{"crashRecovery":true,...},"results":[]}`. Any new JSON
  endpoint that processes untrusted profiles must implement this pattern.
- **Output sanitization** — All subprocess output passes through `_sanitize_output()`
  which strips ANSI escapes and C0 control chars. If adding a new tool that produces
  binary output, handle it before sanitization.
- **Path validation** — All profile paths must go through `_resolve_profile_path()`.
  Never construct paths from user input without validation.
- **README sync** — The README lists 22 tools (historical) in the API table but the
  actual count is 24. Keep the README's tool list and count synchronized.

## Relationship to Other Components

| Component | Relationship |
|-----------|-------------|
| `iccanalyzer-lite/` | MCP server wraps this binary for all analysis tools |
| `colorbleed_tools/` | MCP server uses `iccToXml_unsafe` for XML conversion |
| `test-profiles/` | Default profile search directory |
| `extended-test-profiles/` | Additional profiles (CVE PoCs, v5/iccMAX) |
| `.github/workflows/mcp-server-docker.yml` | Builds and pushes Docker image |
| `.github/workflows/mcp-server-test.yml` | CI tests for MCP server |
| `.github/copilot-mcp-config.json` | Coding agent MCP configuration (11 analysis tools) |
| `.vscode/mcp.json` | VS Code Copilot Chat integration |
