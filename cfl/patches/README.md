# CFL Library Patches — Active Security Fixes

Last Updated: 2026-03-13

18 active patches targeting verified security vulnerabilities in iccDEV library code,
discovered during LibFuzzer and AFL++ fuzzing campaigns.

**Architecture**: Post-retirement minimal patch set. 62 legacy patches (CFL-001 through
CFL-083, with gaps) were retired in March 2026. Only verified, targeted fixes remain.

**On the `cfl` branch**: All 18 patches are applied directly to the source code.
The CI workflow iterates these `.patch` files for verification — all will show as
`[SKIP] (already applied)`.

## Active Patches (18)

| # | Patch File | Bug | CWE | Files Modified |
|---|-----------|-----|-----|----------------|
| 001 | `001-icAnsiToUtf8-null-termination.patch` | HBO via strlen on unterminated 32-byte name | CWE-125/CWE-170 | IccTagBasic.cpp, IccUtilXml.cpp |
| 002 | `002-gamutboundary-triangles-signed-overflow.patch` | Signed int overflow: m_NumberOfTriangles*3 | CWE-190 | IccTagLut.cpp |
| 003 | `003-tagarray-alloc-dealloc-mismatch.patch` | new[] in copy ctor, free() in Cleanup() | CWE-762 | IccTagComposite.cpp |
| 004 | `004-ToneMapFunc-Read-parameter-count-validation.patch` | HBO via Describe() accessing m_params[0..2] with only 1 allocated | CWE-122 | IccMpeBasic.cpp |
| 005 | `005-calculatorfunc-read-enum-ubsan.patch` | Enum out-of-range in calculator op read | CWE-681 | IccMpeCalc.cpp |
| 006 | `006-SpectralMatrix-Describe-iteration-bounds.patch` | HBO via Describe() iterating m_nOutputChannels rows | CWE-122 | IccMpeSpectral.cpp |
| 007 | `007-TagArray-Read-overflow-guard.patch` | Integer overflow in TagArray element count | CWE-190 | IccTagComposite.cpp |
| 008 | `008-TagCurve-Apply-NaN-to-unsigned-UBSAN.patch` | NaN bypasses [0,1] clamp, cast to unsigned is UB | CWE-681 | IccTagLut.cpp |
| 009 | `009-envvar-exec-enum-ubsan.patch` | Enum out-of-range in CIccOpDefEnvVar::Exec() | CWE-681 | IccMpeCalc.cpp |
| 010 | `010-checkunderflow-recursion-depth.patch` | Unbounded recursion in CheckUnderflowOverflow | CWE-674 | IccMpeCalc.cpp, IccMpeCalc.h |
| 011 | `011-specseptotiff-unique-ptr-array.patch` | unique_ptr\<T\> with new T[] uses delete not delete[] | CWE-762 | iccSpecSepToTiff.cpp |
| 012 | `012-ndlut-interpnd-null-applyclut.patch` | Null ptr deref in NdLut InterpND ApplyCLUT | CWE-476 | IccTagLut.cpp |
| 013 | `013-tagarray-cleanup-uninit-guard.patch` | Uninitialized member in TagArray Cleanup | CWE-908 | IccTagComposite.cpp |
| 014 | `014-sequenceneedtempreset-recursion-depth.patch` | SequenceNeedTempReset recursion depth limit | CWE-674 | IccMpeCalc.cpp |
| 015 | `015-specsep-bps-validation.patch` | SpecSep BPS validation bounds check | CWE-20 | IccApplyBPC.cpp |
| 016 | `016-nan-guard-unsigned-cast-ubsan.patch` | NaN/Inf guard before unsigned casts in Apply | CWE-681 | IccMpeBasic.cpp, IccMatrixMath.cpp |
| 017 | `017-envvar-getEnvSig-parse-enum-ubsan.patch` | Enum out-of-range in GetEnvSig() XML parse path | CWE-681 | IccMpeCalc.cpp, IccMpeCalc.h |
| 018 | `018-tagunknown-describe-hbo-underflow.patch` | HBO in icMemDump via m_nSize-4 underflow when tag data < 4 bytes | CWE-125/CWE-191 | IccTagBasic.cpp |

## CWE Distribution

| CWE | Count | Category |
|-----|-------|----------|
| CWE-681 | 4 | Incorrect Type Conversion (UBSAN enum/NaN) |
| CWE-125 | 2 | Out-of-bounds Read |
| CWE-122 | 2 | Heap Buffer Overflow |
| CWE-190 | 2 | Integer Overflow |
| CWE-674 | 2 | Uncontrolled Recursion |
| CWE-762 | 2 | Mismatched Memory Management |
| CWE-191 | 1 | Integer Underflow |
| CWE-170 | 1 | Missing Null Termination |
| CWE-476 | 1 | Null Pointer Dereference |
| CWE-908 | 1 | Uninitialized Resource |
| CWE-20 | 1 | Improper Input Validation |

## Patch Lifecycle

1. **Discover** — Fuzzer finds crash/UB via ASAN+UBSAN
2. **Reproduce** — Confirm with upstream `iccDEV/Build/Tools/` (unpatched, ASAN)
3. **Fix** — Minimal targeted patch in `cfl/iccDEV/`
4. **Generate** — `cd cfl/iccDEV && git diff > ../patches/NNN-name.patch`
5. **Verify** — Rebuild fuzzer, confirm PoC exits clean
6. **Report** — File upstream issue at InternationalColorConsortium/iccDEV
7. **Retire** — When upstream adopts fix, move patch to retired-patches/

## Related Files

- `../seeds/icc/` — Seed corpus for CFL fuzzers (206 ICC profiles)
- `../seeds/tiff/` — TIFF test images (5 Catalyst-generated)
- `../seeds/images/` — PNG/JPG CVE PoCs for image parser testing
- `../../CreateAllProfiles.sh` — Generates ICC profiles from XML sources
