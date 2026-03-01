# Security Research Tools for ICC Color Profiles

Last Updated: 2026-02-24 21:24:00 UTC by David Hoyt

## Tools

| Tool | LOC | Description |
|------|-----|-------------|
| **iccanalyzer-lite** | 6,228 | 32-heuristic security analyzer with ASAN/UBSAN, OOM protection, Ninja mode |
| **cfl** (17 fuzzers) | 4,537 | LibFuzzer harnesses targeting iccDEV (deep_dump, roundtrip, spectral, etc.) |
| **colorbleed_tools** | 224 | Unsafe ICC↔XML converters for mutation testing |
| **mcp-server** | — | ICC Profile MCP server with web UI |

## Security Posture

| Check | Status | Details |
|-------|--------|---------|
| **CodeQL** | 0 alerts | v4, 3 targets × 14 custom queries + security-and-quality |
| **scan-build** | 0 bugs | 14 modules (12 iccanalyzer-lite + 2 colorbleed_tools) |
| **Action Pinning** | 100% | All actions SHA-pinned (actions/checkout v4.2.2: `11bd7190`) |
| **Fuzzers** | 17/17 | Build + smoke test pass, aligned to project tool scope |
| **OOM Patches** | 60 patches | Security fixes in cfl/patches/ |

## Build

```bash
# iccanalyzer-lite (ASAN + UBSAN + coverage)
cd iccanalyzer-lite && ./build.sh

# CFL fuzzers (auto-applies OOM patches to iccDEV)
cd cfl && ./build.sh

# colorbleed_tools
cd colorbleed_tools && make setup && make
```

## Fuzzing (ramdisk)

```bash
cd cfl && ./ramdisk-fuzz.sh     # automated tmpfs workflow
cat .github/scripts/ramdisk-cheatsheet.sh  # copy-paste one-liners
```

## OOM Patch Kit

The `cfl/patches/` directory contains 60 security patches for iccDEV (OOM caps, OOB reads, UBSAN fixes, null-deref guards, heap-buffer-overflow fixes, stack-overflow fixes). Applied automatically by `cfl/build.sh`. See `cfl/patches/README.md` for the full catalog.

## Fuzzer → Tool Mapping

| Fuzzers | Project Tool | API Scope |
|---------|-------------|-----------|
| dump, deep_dump, profile, calculator, multitag | IccDumpProfile | Describe, Validate, FindTag |
| io, roundtrip | IccRoundTrip | Read, Write, EvaluateProfile |
| apply, applyprofiles | IccApplyProfiles | CIccCmm: AddXform, Begin, Apply |
| applynamedcmm | IccApplyNamedCmm | CIccNamedColorCmm: all Apply variants |
| link | IccApplyToLink | CIccCmm 2-profile link |
| spectral, v5dspobs | IccV5DspObsToV4Dsp | MPE: Begin, GetNewApply, Apply |
| fromxml, toxml | XML tools | LoadXml, ToXml, Validate |
| specsep | IccSpecSepToTiff | CTiffImg pipeline |
| tiffdump | IccTiffDump | CTiffImg, OpenIccProfile, FindTag |

## CodeQL

3 targets × 14 custom queries + security-and-quality + security-experimental = 42 total queries.
Run via Actions → CodeQL Security Analysis.

## iccAnalyzer Web UI

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:dev
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:dev web
```

Open http://localhost:8080/

<img width="3742" height="1936" alt="image" src="https://github.com/user-attachments/assets/30a8c93f-6c78-4d1e-a67e-c38eb0cb8186" />

## Developer Demo Container

Self-contained demo with interactive HTML report, live API, and pre-loaded test profiles:

```bash
docker pull ghcr.io/xsscx/icc-profile-demo:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-demo
# Custom port: docker run --rm -p 8083:8083 ghcr.io/xsscx/icc-profile-demo --port 8083
```

Routes: `/` (demo report), `/ui` (interactive WebUI), `/api` (endpoint index), `/api/*` (analysis).

```bash
curl http://localhost:8080/api/health
curl 'http://localhost:8080/api/security?path=sRGB_D65_MAT.icc'
```

Other modes: `api` (WebUI at `/` + REST API), `mcp` (stdio server for AI agents).
See [dev-demo/README.md](dev-demo/README.md) for full usage.

## Reusable Prompts

Pre-built prompt templates for AI-assisted analysis in [`.github/prompts/`](.github/prompts/):

- **analyze-icc-profile** — Full 32-heuristic security scan
- **compare-icc-profiles** — Side-by-side structural diff
- **triage-cve-poc** — CVE PoC analysis with CVE cross-referencing
- **health-check** — MCP server verification
