# ICC Profile MCP Server

A [Model Context Protocol](https://modelcontextprotocol.io/) server for ICC
profile security analysis, structural inspection, parity-oriented validation,
and maintainer workflows.

<img width="3742" height="1936" alt="ICC Profile MCP Server WebUI" src="https://github.com/user-attachments/assets/30a8c93f-6c78-4d1e-a67e-c38eb0cb8186" />

## Quick Start — Docker

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web
curl -s http://127.0.0.1:8080/api/health
```

Open <http://127.0.0.1:8080>. The bundled test corpus is pre-loaded.

Health is the source of truth for the live surface, for example:

```json
{"ok":true,"tools":28,"engines":{"v1":true,"v2":true},"defaultAnalysisEngine":"v2","defaultStructuralEngine":"v1"}
```

## Current Surface

- Security-oriented analysis defaults to V2 (`icctest`).
- Structural inspection and round-trip validation still default to V1.
- The Web UI lives at `/` and supports deep links such as `#security`,
  `#security_report`, `#pawg`, `#profile_overlay`, `#inspect`, `#graph_viewer`,
  `#coverage_gaps`, and `#scan_logs`.
- `/api/pawg` and `/api/security-report` intentionally expose the
  conformance-focused PAWG view only.
- Use `/api/health` or the `health_check` MCP tool as the source of truth for
  the current tool total and default engine split.

## Common Commands

```bash
# List bundled profiles
curl -s 'http://127.0.0.1:8080/api/list?directory=test-profiles'

# Current-engine security scan
curl -s 'http://127.0.0.1:8080/api/security?path=sRGB_D65_MAT.icc'

# Structured security JSON
curl -s 'http://127.0.0.1:8080/api/security-json?path=sRGB_D65_MAT.icc'

# PAWG-oriented conformance report
curl -s 'http://127.0.0.1:8080/api/pawg?path=sRGB_D65_MAT.icc'

# Three-layer profile overlay JSON for the Web UI
curl -s 'http://127.0.0.1:8080/api/profile-overlay?path=sRGB_v4_ICC_preference.icc'

# Structural inspection and combined output
curl -s 'http://127.0.0.1:8080/api/inspect?path=sRGB_D65_MAT.icc'
curl -s 'http://127.0.0.1:8080/api/full?path=sRGB_D65_MAT.icc'

# Upload your own profile
curl -s -X POST -F 'file=@myprofile.icc' http://127.0.0.1:8080/api/upload
```

## Ways to Use It

### Web UI

Run the container in `web` mode, open <http://127.0.0.1:8080>, pick a bundled
profile or upload your own, then use the tool-specific pages.

### REST API

Call the `/api/*` routes directly from scripts, notebooks, CI jobs, or remote
agents. The Web UI uses the same routes.

### MCP stdio

```bash
docker run --rm -i ghcr.io/xsscx/icc-profile-mcp:latest
```

Client config:

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

### Local repo checkout

```bash
python mcp-server/launch.py mcp
python mcp-server/launch.py web --host 127.0.0.1 --port 8000
```

`launch.py` prefers `mcp-server/.venv` when it exists, so Windows and WSL
editor integrations can target the same repo-local launcher instead of hard
coding platform-specific interpreter paths.

### GitHub issue workflow

If you do not want to run Docker locally, attach `profile.icc.txt` to a repo
issue and request analysis there.

## Key Routes

| Route | Purpose |
|-------|---------|
| `/` | Interactive Web UI |
| `/favicon.ico` | Browser favicon |
| `/.well-known/appspecific/com.chrome.devtools.json` | Browser probe path (`204`) |
| `/static/cytoscape.min.js` | Graph viewer asset |
| `/api/health` | Health plus current tool and engine metadata |
| `/api/health-check` | Full bundled-tool health verification |
| `/api/list`, `/api/list-xml` | Browse bundled ICC or XML fixtures |
| `/api/inspect`, `/api/roundtrip`, `/api/full`, `/api/xml`, `/api/compare` | Core structural workflows |
| `/api/security`, `/api/security-json`, `/api/security-report`, `/api/pawg`, `/api/profile-overlay` | Security, PAWG, and overlay reporting |
| `/api/upload`, `/api/upload-and-analyze`, `/api/output/download`, `/api/xml/download` | File upload and output export |
| `/api/check-dependencies`, `/api/find-artifacts`, `/api/build-tools`, `/api/cmake/*`, `/api/create-profiles`, `/api/run-tests`, `/api/batch-test`, `/api/validate-xml`, `/api/coverage-report`, `/api/scan-logs` | Maintainer and operations endpoints |
| `/api/attack-surface`, `/api/coverage-gaps`, `/api/knowledge-graph.json` | Graph and coverage workflows |

## Tool Families

The current 28 MCP tools are grouped into four families:

- Analysis (13): `health_check`, `inspect_profile`, `analyze_security`,
  `validate_roundtrip`, `analyze_security_json`,
  `analyze_security_report`, `full_analysis`, `profile_to_xml`,
  `compare_profiles`, `list_test_profiles`, `upload_and_analyze`,
  `dump_all`, `diagnostic_load`
- Maintainer (7): `build_tools`, `cmake_configure`, `cmake_build`,
  `create_all_profiles`, `run_iccdev_tests`, `cmake_option_matrix`,
  `windows_build`
- Operations (6): `check_dependencies`, `find_build_artifacts`,
  `batch_test_profiles`, `validate_xml`, `coverage_report`, `scan_logs`
- Graph (2): `query_attack_surface`, `coverage_gaps`

## API Reference

| Method | Endpoint | Parameters | Description |
|--------|----------|------------|-------------|
| `GET` | `/api/health` | — | Health check with tool and engine metadata |
| `GET` | `/api/health-check` | — | Full bundled-tool health verification |
| `GET` | `/api/list` | `directory` | List profiles from `test-profiles` or `extended-test-profiles` |
| `GET` | `/api/list-xml` | `directory` | List XML fixtures |
| `GET` | `/api/inspect` | `path` | Structural dump (header + tag table) |
| `GET` | `/api/security` | `path` | Current-engine security scan |
| `GET` | `/api/security-json` | `path` | Structured JSON security object |
| `GET` | `/api/security-report` | `path` | PAWG-aligned conformance-only report with checklist/spec references |
| `GET` | `/api/pawg` | `path` | PAWG conformance-section view with bundled ICC spec references |
| `GET` | `/api/profile-overlay` | `path` | Three-layer conformance, mind-map, and secure-parsing JSON model for the Web UI |
| `GET` | `/api/roundtrip` | `path` | Round-trip transform validation |
| `GET` | `/api/full` | `path` | Combined analysis (security + round-trip + structure) |
| `GET` | `/api/xml` | `path` | Binary ICC → XML conversion |
| `GET` | `/api/xml/download` | `path` | Download XML conversion as a file |
| `GET` | `/api/compare` | `path_a`, `path_b` | Unified diff of two profiles |
| `GET` | `/api/registry` | `engine` (optional) | Analyzer registry JSON |
| `GET` | `/api/attack-surface` | `top_n` (optional) | Graph-centrality view of attack-surface nodes |
| `GET` | `/api/coverage-gaps` | `severity_filter` (optional) | Uncovered heuristics/CVEs/patches from the knowledge graph |
| `GET` | `/api/dump-all` | `path`, `verbosity`, `use_read`, `diag` | Deep tag dump via `iccDumpAll` |
| `GET` | `/api/diagnostic-load` | `path`, `mode` | Deep diagnostic-load analysis |
| `GET` | `/api/knowledge-graph.json` | — | Raw knowledge-graph data for the viewer |
| `POST` | `/api/upload` | `file` (multipart) | Upload `.icc` file (20 MB max) |
| `POST` | `/api/upload-and-analyze` | multipart/form-data | Upload and analyze in one request |
| `POST` | `/api/output/download` | `text`, `filename` (JSON) | Download tool output as a file |
| `POST` | `/api/build-tools` | form/json | Build native tools inside the container |
| `POST` | `/api/cmake/configure` | form/json | Configure `iccDEV` CMake build |
| `POST` | `/api/cmake/build` | form/json | Build configured CMake targets |
| `POST` | `/api/create-profiles` | form/json | Generate the full ICC profile corpus |
| `POST` | `/api/run-tests` | form/json | Run `iccDEV` tests |
| `POST` | `/api/cmake/option-matrix` | form/json | Exercise CMake option combinations |
| `POST` | `/api/cmake/windows-build` | form/json | Run the MSVC/vcpkg build workflow |
| `POST` | `/api/batch-test` | form/json | Batch-run analysis over a directory |
| `POST` | `/api/validate-xml` | form/json | Run XML validation |
| `POST` | `/api/coverage-report` | form/json | Merge profraw and generate coverage |
| `POST` | `/api/scan-logs` | form/json | Scan build/test logs for failures |

## Security and Runtime Notes

- The server processes untrusted binary files. Path traversal, symlink escape,
  null-byte input, and shell injection are blocked.
- Output is capped at 10 MB. Long-running subprocesses use bounded timeouts.
- Uploads are capped at 20 MB and filenames are sanitized.
- CSP headers use per-request nonces; the graph viewer explicitly allows the
  inline style behavior Cytoscape requires.
- The published container bundles the repo source tree and Linux build
  toolchain for the maintainer endpoints.
- Safe `iccDEV` non-GUI CLIs remain preferred. XML fallback still exposes the
  unsafe `colorbleed_tools` binaries when requested.
- Reference profiles may be given by filename (`sRGB_D65_MAT.icc`),
  repo-relative path (`extended-test-profiles/cve-2023-46602.icc`), or a
  mounted directory (`my-profiles/custom.icc`).

## Prompt Library

The repo currently ships 22 prompt templates in [`.github/prompts/`](../.github/prompts/).
Recommended starting points:

- `analyze-icc-profile` for full scans
- `health-check` for MCP verification
- `remote-analysis` for REST-only workflows
- `icctest-parity-release` for parity and Docker release validation
- `triage-cve-poc` for PoC triage

## Troubleshooting

### "Profile not found"

The server searches `test-profiles/`, `extended-test-profiles/`, and the repo
root. Mount your own directory if needed:

```bash
docker run --rm -p 8080:8080 -v /path/to/profiles:/app/my-profiles:ro \
  ghcr.io/xsscx/icc-profile-mcp:latest web
```

Then call `http://127.0.0.1:8080/api/security?path=my-profiles/custom.icc`.

### ASAN/UBSAN output in stderr

This is expected. The analysis binaries are ASAN/UBSAN-instrumented, so
sanitizer output is a finding signal, not a transport failure.

### Empty `scan_logs` result

If no `.log` files exist in the requested directory, the endpoint now returns
`[OK] No .log files found ...` with guidance instead of a hard failure.

### Large profiles produce truncated XML

XML output is capped at 50,000 characters. The truncation notice reports the
full size.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Clean — no findings |
| `1` | Finding — security heuristic triggered |
| `2` | Error — malformed input (profile fails to load) |
| `3` | Usage — incorrect arguments |
