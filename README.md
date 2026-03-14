# Security Research Tools for ICC Color Profiles

Last Updated: 2026-03-08 15:44:00 UTC by David Hoyt

## Tools

| Tool | LOC | Description |
|------|-----|-------------|
| **iccanalyzer-lite** | 22,400+ | 153-heuristic security analyzer with ASAN/UBSAN, TIFF image analysis, JSON/XML/Report output, callgraph, OOM protection, Ninja mode |
| **cfl** (12 fuzzers) | ~2,500 | LibFuzzer harnesses targeting iccDEV (dump, roundtrip, apply, etc.) |
| **colorbleed_tools** | 224 | Unsafe ICC↔XML converters for mutation testing |
| **mcp-server** | — | ICC Profile MCP server with web UI (24 tools) |

## Related Projects

| Project | Repository | Description |
|---------|-----------|-------------|
| **xnuimagetools** | [xsscx/xnuimagetools](https://github.com/xsscx/xnuimagetools) | Umbrella workspace — image generation + VideoToolbox fuzzer. Uses xnuimagefuzzer as git submodule |
| **xnuimagefuzzer** | [xsscx/xnuimagefuzzer](https://github.com/xsscx/xnuimagefuzzer) | Primary iOS/macOS image fuzzer (15 bitmap contexts, 22+ formats) |

## Security Posture

| Check | Status | Details |
|-------|--------|---------|
| **CodeQL** | 0 alerts | v4, 3 targets × 14 custom queries + security-and-quality |
| **scan-build** | 0 bugs | 14 modules (12 iccanalyzer-lite + 2 colorbleed_tools) |
| **Action Pinning** | 100% | All actions SHA-pinned (actions/checkout v4.2.2: `11bd7190`) |
| **Fuzzers** | 12/12 | Build + smoke test pass, aligned to project tool scope |
| **CFL Patches** | 18 active patches | Security fixes in cfl/patches/ (CFL-001 through CFL-022) |

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

The `cfl/patches/` directory contains 18 active security patches for iccDEV (CFL-001 through CFL-022, with 012/013/015/016 retired: HBO fixes, integer overflow guards, alloc-dealloc mismatch, UBSAN enum/NaN fixes, recursion depth limits, unsigned underflow guards, null pointer dereference guards, stack buffer overflow guards). Applied automatically by `cfl/build.sh`. 62 legacy patches retired March 2026 — see `cfl/patches/README.md` for the full catalog.

## Fuzzer → Tool Mapping

| Fuzzers | Project Tool | API Scope |
|---------|-------------|-----------|
| dump, deep_dump, profile, calculator, multitag | IccDumpProfile | Describe, Validate, FindTag |
| io, roundtrip | IccRoundTrip | Read, Write, EvaluateProfile |
| apply, applyprofiles | IccApplyProfiles | CIccCmm: AddXform, Begin, Apply |
| applynamedcmm | IccApplyNamedCmm | CIccNamedColorCmm: all Apply variants |
| link | IccApplyToLink | CIccCmm 2-profile link |
| spectral, spectral_b, v5dspobs | IccV5DspObsToV4Dsp | MPE: Begin, GetNewApply, Apply |
| fromxml, toxml | XML tools | LoadXml, ToXml, Validate |
| fromcube | IccFromCube | CUBE LUT import pipeline |
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

## Docker Container

MCP server with interactive WebUI, REST API, and pre-loaded test profiles:

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp web
```

Routes: `/` (demo report), `/ui` (interactive WebUI), `/api` (endpoint index), `/api/*` (analysis).

```bash
curl http://localhost:8080/api/health
curl 'http://localhost:8080/api/security?path=sRGB_D65_MAT.icc'
```

Two modes: `mcp` (default, stdio server for AI agents), `web` (REST API + HTML UI).
See [dev-demo/README.md](dev-demo/README.md) for full usage.

## Reusable Prompts

Pre-built prompt templates for AI-assisted analysis in [`.github/prompts/`](.github/prompts/):

- **analyze-icc-profile** — Full 153-heuristic security scan
- **compare-icc-profiles** — Side-by-side structural diff
- **triage-cve-poc** — CVE PoC analysis with CVE cross-referencing
- **health-check** — MCP server verification

## ICC Specification References

Analysis heuristics are validated against the official ICC specification and technical notes:

| Document | Description |
|----------|-------------|
| [ICC.1-2022-05](https://www.color.org/specification/ICC.1-2022-05.pdf) | Profile specification v4.4 (primary reference) |
| [TN-06-2025 Tristimulus](https://archive.color.org/files/technotes/ICC_TN-06-2025_Recommendations_on_calculation_of_tristimulus_values.pdf) | Tristimulus value calculation |
| [Profile Embedding](https://archive.color.org/files/technotes/ICC-Technote-ProfileEmbedding.pdf) | Embedding in TIFF/JPEG/EPS |
| [Partial Adaptation](https://archive.color.org/files/technotes/ICC-Technote-PartialAdaptation.pdf) | Chromatic adaptation tag |
| [Negative PCS XYZ](https://archive.color.org/files/technotes/Guidelines_on_the_use_of_negative_PCSXYZ_values.pdf) | Wide-gamut XYZ ranges |
| [V4 Matrix Entries](https://archive.color.org/files/v4_matrix_entries.pdf) | Matrix precision constraints |
| [V2 in V4](https://archive.color.org/files/v2profiles_v4.pdf) | Version interoperability |
| [PSD TechNote](https://archive.color.org/files/PSD_TechNote.pdf) | Profile sequence description |
| [RFC 1321](https://www.ietf.org/rfc/rfc1321.txt) | MD5 (profile ID calculation) |
