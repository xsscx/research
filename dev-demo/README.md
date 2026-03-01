# ICC Profile MCP Server — Developer Demo

## Quick Start

Copy and paste these two commands to get started:

```bash
docker pull ghcr.io/xsscx/icc-profile-demo:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-demo:latest
```

Then open <http://127.0.0.1:8080> in your browser. That's it — no build steps, no dependencies.

Use `--port N` to listen on a custom port:

```bash
docker run --rm -p 8083:8083 ghcr.io/xsscx/icc-profile-demo:latest --port 8083
```

## Demo Routes

| Route | Description |
|-------|-------------|
| `/` | Demo report — static showcase with sample outputs |
| `/ui` | Interactive analysis WebUI — select profiles, run tools |
| `/api` | REST API index (JSON) |
| `/api/*` | Analysis endpoints (health, list, inspect, security, roundtrip, full, xml, compare, upload) |

## Other Modes

| Mode | Command | Description |
|------|---------|-------------|
| **api** | `docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-demo api` | Interactive WebUI at `/` with REST API at `/api/*` |
| **mcp** | `docker run --rm -i ghcr.io/xsscx/icc-profile-demo mcp` | MCP stdio server (for AI agent integration) |

## Build Locally (Optional)

```bash
# From repository root
docker build -f Dockerfile.demo -t icc-profile-demo .
```

## API Endpoints

All endpoints are available under `/api/` in both `demo` and `api` modes:

```bash
# API index (list all endpoints)
curl http://127.0.0.1:8080/api

# Health check
curl http://127.0.0.1:8080/api/health

# List available profiles
curl 'http://127.0.0.1:8080/api/list?directory=test-profiles'

# Security scan (32 heuristics H1–H32)
curl 'http://127.0.0.1:8080/api/security?path=sRGB_D65_MAT.icc'

# Profile inspection
curl 'http://127.0.0.1:8080/api/inspect?path=sRGB_D65_MAT.icc'

# Round-trip validation
curl 'http://127.0.0.1:8080/api/roundtrip?path=sRGB_D65_MAT.icc'

# Compare two profiles
curl 'http://127.0.0.1:8080/api/compare?path_a=sRGB_D65_MAT.icc&path_b=sRGB_D65_MAT.icc'

# Convert to XML
curl 'http://127.0.0.1:8080/api/xml?path=sRGB_D65_MAT.icc'

# Upload a profile
curl -X POST -F 'file=@myprofile.icc' http://127.0.0.1:8080/api/upload
```

## Container Contents

- **126 test profiles** in `/app/test-profiles/`
- **95 extended test profiles** in `/app/extended-test-profiles/`
- Self-contained HTML demo report at `/app/dev-demo/index.html`
- Developer guide markdown at `/app/dev-demo/dev-demo.md`
- iccanalyzer-lite with ASAN+UBSAN instrumentation
- 16 MCP tools (9 analysis + 7 maintainer build)

## Files

| File | Description |
|------|-------------|
| `index.html` | 63 KB self-contained HTML report with 16 sections, embedded API output, WebUI mockup |
| `dev-demo.md` | 18 KB developer guide: 3 integration paths, 6 use cases, API reference |
| `README.md` | This file |

## Security

The WebUI includes 10 security headers:
- CSP with per-request nonce rotation
- `X-Frame-Options: DENY`
- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: no-referrer`
- `Cache-Control: no-store`
- `Cross-Origin-Opener-Policy: same-origin`
