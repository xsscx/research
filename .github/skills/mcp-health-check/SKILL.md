---
name: mcp-health-check
description: >
  Quick verification that the ICC Profile MCP server is operational,
  binaries are available, and test profiles are accessible.
allowed-tools:
  - bash
  - read
  - iccTest
---

# MCP Server Health Check

## Overview

Verify the ICC Profile MCP server is operational with all analysis tools,
test profiles, and build dependencies available.

## Workflow

### 1. Server Status

Call `health_check` or GET `/api/health`.
Verify: `{"ok": true}` with expected tool count.
Confirm engine split: analysis=v2, structural=v1.

### 2. Profile Access

Call `list_test_profiles` or GET `/api/list`.
Confirm test profiles are accessible.

### 3. Smoke Test

Call `inspect_profile` on `sRGB_D65_MAT.icc` or:
```bash
curl -s 'http://localhost:8080/api/inspect?path=sRGB_D65_MAT.icc'
```

### 4. Dependencies

Call `check_dependencies` or GET `/api/check-dependencies`.
Verify build dependencies (cmake, clang, libxml2, libtiff, libpng).

## Docker Validation

```bash
docker run --rm -d -p 8080:8080 --name mcp-test ghcr.io/xsscx/icc-profile-mcp web
curl -s http://localhost:8080/api/health
curl -s 'http://localhost:8080/api/inspect?path=sRGB_D65_MAT.icc' | head -5
docker stop mcp-test
```

## Pass/Fail Criteria

- Server returns ok=true with correct tool count
- Test profiles are listed and accessible
- Smoke test returns valid ICC profile structure
- Build dependencies are present (or identified as missing)

## References

- `.github/instructions/mcp-server.instructions.md` -- Full MCP details
- `.github/skills/icc-security-analysis/SKILL.md` -- Full analysis workflow
