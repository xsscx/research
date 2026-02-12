# Security Research Tools for ICC Color Profiles

Last Updated: 2026-02-12 06:45:00 UTC by David Hoyt

## Tools

| Tool | LOC | Description |
|------|-----|-------------|
| **iccanalyzer-lite** | 6,228 | 19-heuristic security analyzer with ASAN/UBSAN, OOM protection, Ninja mode |
| **cfl** (17 fuzzers) | 4,537 | LibFuzzer harnesses targeting iccDEV (deep_dump, roundtrip, spectral, etc.) |
| **colorbleed_tools** | 224 | Unsafe ICC↔XML converters for mutation testing |
| **mcp-server** | — | ICC Profile MCP server with web UI |

## Build

```bash
# iccanalyzer-lite (ASAN + UBSAN + coverage)
cd iccanalyzer-lite && ./build.sh

# CFL fuzzers
cd cfl && ./build.sh

# colorbleed_tools
cd colorbleed_tools && make setup && make
```

## Fuzzing (ramdisk)

```bash
cd cfl && ./ramdisk-fuzz.sh     # automated tmpfs workflow
cat ramdisk-cheatsheet.sh       # copy-paste one-liners
```

## CodeQL

3 targets × 15 custom queries + security-and-quality + security-experimental = 45 total queries.
Run via Actions → CodeQL Security Analysis.

## iccAnalyzer Web UI

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:dev
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:dev icc-profile-web --host 0.0.0.0 --port 8080
```

Open http://localhost:8080/

<img width="3742" height="1936" alt="image" src="https://github.com/user-attachments/assets/30a8c93f-6c78-4d1e-a67e-c38eb0cb8186" />
