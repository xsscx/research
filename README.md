# Security Research Tools for ICC Color Profiles

## [Fuzzer Harness](ua)

Last Updated: 2026-03-18 03:34:17 UTC by David Hoyt

<img width="3672" height="1917" alt="image" src="https://github.com/user-attachments/assets/8092db67-8705-4cef-8aef-f2a25afaa421" />

## Tools

| Tool | LOC | Description |
|------|-----|-------------|
| **iccanalyzer-lite** | 22,400+ | 180-heuristic security analyzer with ASAN/UBSAN, TIFF image analysis, JSON/XML/Report output, callgraph, OOM protection, Ninja mode |
| **cfl** (13 fuzzers) | ~2,800 | LibFuzzer harnesses targeting iccDEV (dump, roundtrip, apply, cfg, etc.) |
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
| **Action Pinning** | 100% | All actions SHA-pinned (actions/checkout v5.0.0: `08c6903`) |
| **Fuzzers** | 13/13 | Build + smoke test pass, aligned to project tool scope |
| **CFL Patches** | 45 active, 93 retired | Security fixes in cfl/patches/ (CFL-004 through CFL-077, see patch table below) |

## Build

```bash
# iccanalyzer-lite (ASAN + UBSAN + coverage)
cd iccanalyzer-lite && ./build.sh

# CFL fuzzers (auto-applies security patches to iccDEV)
cd cfl && ./build.sh

# colorbleed_tools
cd colorbleed_tools && make setup && make
```

## Fuzzing (ramdisk)

```bash
cd cfl && ./ramdisk-fuzz.sh     # automated tmpfs workflow
cat .github/scripts/ramdisk-cheatsheet.sh  # copy-paste one-liners
```

## CFL Patch Kit

The `cfl/patches/` directory contains **45 active** security patches for iccDEV, applied automatically by `cfl/build.sh` and `afl/build.sh`. **93 legacy patches** retired to `cfl/patches-retired/` after upstream acceptance or supersession (March 2026).

### Active Patches (45)

| # | Patch | CWE | Bug Class |
|---|-------|-----|-----------|
| 004 | ToneMapFunc Read parameter count | CWE-122 | HBO via Describe() with insufficient params |
| 005 | CalculatorFunc Read enum UBSAN | CWE-681 | Enum out-of-range |
| 006 | SpectralMatrix Describe iteration bounds | CWE-122 | HBO via Describe() row iteration |
| 007 | TagArray Read overflow guard | CWE-190 | Integer overflow in element count |
| 008 | TagCurve Apply NaN-to-unsigned | CWE-681 | NaN bypasses clamp, UB cast |
| 009 | EnvVar Exec enum UBSAN | CWE-681 | Enum out-of-range |
| 014 | SequenceNeedTempReset recursion depth | CWE-674 | Unbounded recursion |
| 017 | GetEnvSig parse enum UBSAN | CWE-681 | Enum out-of-range (XML path) |
| 019 | PCC getReflectanceObserver null guard | CWE-476 | Null pointer deref |
| 021 | SingleSampledCurve OOM size validation | CWE-400 | Oversized allocation |
| 022 | Calc Trunc/Floor/Ceil/Round/Mod int overflow | CWE-681 | Float-to-int overflow (5 ops) |
| 023 | Sampled curve NaN-to-unsigned cast | CWE-681 | 3 NaN-to-unsigned casts |
| 025 | CLUT InterpNd null Apply guard | CWE-476 | Null CIccApplyCLUT deref |
| 028 | MatrixMath SetRange NaN guard | CWE-681 | NaN-to-unsigned-short |
| 029 | TagArray operator= loop var | CWE-824 | Loop variable modified inside body |
| 040 | fromIt8 CMYK missing push_back | CWE-787 | Missing sample accumulation |
| 041 | fromIt8 LAB/XYZ val(4) OOB | CWE-125 | Wrong index (4 vs 3) |
| 042 | ParseNumbers 'n' vs '\n' typo | CWE-20 | Character literal typo |
| 043 | Tool toJson is_object vs is_array | CWE-697 | JSON type confusion |
| 044 | NDLut Apply missing interp dispatch | CWE-476 | Missing dispatch in NDLut |
| 046 | PCS step src matrix delete[] | CWE-762 | delete vs delete[] mismatch |
| 047 | pushXYZNormalize null PCC guard | CWE-476 | Null PCC pointer deref |
| 050 | FormulaCurve Describe param bounds | CWE-125 | OOB read in Describe |
| 051 | ParametricCurve Describe param bounds | CWE-125 | OOB read in Describe |
| 052 | fromIt8 wrong index variable | CWE-125 | Wrong loop index |
| 053 | FormulaCurve Describe format specifiers | CWE-134 | Wrong printf format |
| 054 | ParametricCurve Describe format specifiers | CWE-134 | Wrong printf format |
| 055 | fromIt8 signed-unsigned mismatch | CWE-681 | Signed/unsigned comparison |
| 056 | Spectral Describe null pointer guards | CWE-476 | Null pointer deref |
| 057 | SearchApply uninitialized members | CWE-908 | Uninitialized members |
| 059 | TagCurve Begin nMaxIndex underflow | CWE-681 | Implicit -1 to unsigned |
| 061 | icF16toF unsigned underflow | CWE-191 | Unsigned subtraction underflow |
| 062 | icGetSig implicit char conversion | CWE-681 | Implicit int-to-char |
| 063 | Bounds check unsigned overflow | CWE-190 | offset+size overflow |
| 064 | Segmented curve subtraction underflow | CWE-191 | pos-startPos underflow |
| 067 | icIsS15Fixed16NumberNear float overflow | CWE-681 | Float-to-unsigned cast |
| 068 | MpeCurveSet operator= self-assignment | CWE-824 | Self-assignment crash |
| 069 | operator= self-assignment guards | CWE-824 | Self-assignment (multiple classes) |
| 070 | Missing member copies in operator=/copy-ctor | CWE-665 | Incomplete copy |
| 071 | Uninitialized default ctor members | CWE-908 | Uninitialized members |
| 072 | printf format + unused function | CWE-134 | Format specifier mismatch |
| 073 | IccProfileXml implicit fallthrough | CWE-484 | Missing break in switch |
| 074 | IccUtilXml clipTypeRange if-constexpr | CWE-681 | Signed comparison fix |
| 075 | IccCmmConfig uninit + format fixes | CWE-908 | Uninitialized + format |
| 077 | CAM CalcCoefficients div-by-zero | CWE-369 | 3 division-by-zero chains |

### Upstream Status

- **CFL-077**: PR [#754](https://github.com/InternationalColorConsortium/iccDEV/pull/754) — open, Merge Ready
- **CFL-076**: Accepted upstream in v2.3.1.6 — retired
- **CFL-002, CFL-036, CFL-065**: Accepted upstream — retired
- **93 legacy patches** in `cfl/patches-retired/` (timeout caps, OOM guards, alloc caps — superseded by LibFuzzer `-timeout=30 -rss_limit_mb=4096`)

## Fuzzer → Tool Mapping

| Fuzzers | Project Tool | API Scope |
|---------|-------------|-----------|
| dump | IccDumpProfile | Describe, Validate, FindTag |
| roundtrip | IccRoundTrip | Read, Write, EvaluateProfile |
| applyprofiles | IccApplyProfiles | CIccCmm: AddXform, Begin, Apply |
| applynamedcmm | IccApplyNamedCmm | CIccNamedColorCmm: all Apply variants |
| applysearch | IccApplySearch | CIccCmmSearch optimization |
| link | IccApplyToLink | CIccCmm 2-profile link |
| v5dspobs | IccV5DspObsToV4Dsp | MPE: Begin, GetNewApply, Apply |
| fromxml, toxml | XML tools | LoadXml, ToXml, Validate |
| fromcube | IccFromCube | CUBE LUT import pipeline |
| specsep | IccSpecSepToTiff | CTiffImg pipeline |
| tiffdump | IccTiffDump | CTiffImg, OpenIccProfile, FindTag |
| cfg | IccApplyNamedCmm | JSON config parsing (IccCmmConfig) |

## CodeQL

3 targets × 14 custom queries + security-and-quality + security-experimental = 42 total queries.
Run via Actions → CodeQL Security Analysis.

## iccAnalyzer Web UI

```bash
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp:latest web
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
docker pull ghcr.io/xsscx/icc-profile-mcp:latest
docker run --rm -p 8080:8080 ghcr.io/xsscx/icc-profile-mcp web
curl -fsS "http://127.0.0.1:8080/api/pawg?path=sRGB_D65_MAT.icc" | jq -r '.result'
curl http://localhost:8080/api/health
```

Two modes: `mcp` (default, stdio server for AI agents), `web` (REST API + HTML UI).

## Reusable Prompts

Pre-built prompt templates for AI-assisted analysis in [`.github/prompts/`](.github/prompts/):

- **analyze-icc-profile** — Full 180-heuristic security scan
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
