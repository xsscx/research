# CFL Library Patches — Active Security Fixes

Last Updated: 2026-03-14

21 active patches targeting verified security vulnerabilities in iccDEV library code,
discovered during LibFuzzer and AFL++ fuzzing campaigns.

**Architecture**: Post-retirement minimal patch set. 62 legacy patches (CFL-001 through
CFL-083, with gaps) were retired in March 2026. Only verified, targeted fixes remain.

**On the `cfl` branch**: All 21 patches are applied directly to the source code.
The CI workflow iterates these `.patch` files for verification — all will show as
`[SKIP] (already applied)`.

## Active Patches (21)

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
| 019 | `019-pcc-null-spectral-viewing-conditions.patch` | NPD when PCC profile lacks spectralViewingConditionsTag | CWE-476 | IccPcc.cpp |
| 020 | `020-sampledcalculatorcurve-begin-channel-validation.patch` | SampledCalculatorCurve::Begin missing channel count validation | CWE-20 | IccMpeBasic.cpp |
| 021 | `021-singlesampled-curve-oom-size-validation.patch` | SingleSampledCurve::Read OOM via unchecked nCount before SetSize() | CWE-770 | IccMpeBasic.cpp |

### CFL-019 Detail — Cross-Tool Validation

**Bug**: `getPccViewingConditions()` returns NULL when PCC profile lacks `svcn` tag.
Two NPD sites: line 294 (`getReflectanceObserver`) and line 322-337
(`CIccCombinedConnectionConditions` constructor). Lines 164, 200, 233 in the same
file already had proper NULL checks — pattern inconsistency.

**Trigger requirements** (ALL must be true):
1. Transform profile has `multiProcessElementType` tags (creates `CIccXformMpe`)
2. MPE contains late-binding spectral elements (`emtx`/`iemx`) → `IsLateBinding()` = true
3. `CIccNamedColorCmm::Begin()` calls `SetLateBindingCC()` → `SetAppliedCC()`
4. PCC profile lacks `spectralViewingConditionsTag` (`svcn`)

**Affected tools**: `iccApplyNamedCmm` (only tool using `CIccNamedColorCmm`)
**Affected profiles**: Any with late-binding elements — `Rec2020rgbSpectral.icc`, `LCDDisplay.icc` (2 of 416 testing profiles)

**1-liner reproduction** (from repo root):
```bash
printf "'RGB '\t; Data Format\nicEncodeFloat\t; Encoding\n\n0.5 0.5 0.5\n" > /tmp/pcc-test-data.txt && ASAN_OPTIONS=halt_on_error=1,detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1,print_stacktrace=1 LD_LIBRARY_PATH=source-of-truth/Build/IccProfLib:source-of-truth/Build/IccXML source-of-truth/Build/Tools/IccApplyNamedCmm/iccApplyNamedCmm /tmp/pcc-test-data.txt 0 0 iccDEV/Testing/Display/Rec2020rgbSpectral.icc 0 -PCC test-profiles/npd-CIccCombinedConnectionConditions-IccPcc_cpp-Line337.icc
```

**Not affected**: `iccDumpProfile`, `iccToXml`, `iccRoundTrip`, `iccV5DspObsToV4Dsp`,
`iccApplyToLink` (rejects before Begin), `iccApplyProfiles` (requires TIFF I/O),
`iccApplySearch` (requires 2-3 profiles). Non-spectral profiles have 0 late-binding
elements so `SetAppliedCC()` is never called.

**PoC profile**: `test-profiles/npd-CIccCombinedConnectionConditions-IccPcc_cpp-Line337.icc`
(832-byte v5 MPE profile with A2B0/B2A0 but no `svcn` tag)

### CFL-020 Detail — SampledCalculatorCurve Channel Validation

**Bug**: `CIccSampledCalculatorCurve::Begin()` in IccMpeBasic.cpp does not validate
`m_nDesiredSize` or channel parameters before allocating calculator evaluator resources.
A crafted profile can supply invalid channel counts that bypass the calculator's
internal validation, leading to out-of-bounds access during curve application.

**Fix**: Added channel count validation against profile-declared values before
proceeding with calculator evaluation setup.

**Files Modified**: `IccProfLib/IccMpeBasic.cpp`

### CFL-021 Detail — SingleSampledCurve OOM Size Validation

**Bug**: `CIccSingleSampledCurve::Read()` at IccMpeBasic.cpp:~1638 calls
`SetSize(m_nCount)` → `malloc(nCount * sizeof(icFloatNumber))` BEFORE validating
nCount against the remaining stream size. A crafted profile with
`nCount = 0xEB001000` (14.7 GB) or `nCount = 0xDA000002` (13.6 GB) triggers
immediate OOM abort (SIGABRT).

**Fix**: Added stream-remaining-size check before `SetSize()`:
```cpp
icUInt64Number allocBytes = (icUInt64Number)m_nCount * sizeof(icFloatNumber);
if (allocBytes > 256*1024*1024 || (nEnd > nStart && allocBytes > (icUInt64Number)(nEnd - nStart) * 64))
  return false;
```

**Trigger**: Any profile containing a `sngf` (SingleSampledCurve) element with
nCount field set to a value requiring > 256 MB allocation.

**1-liner reproduction** (from repo root):
```bash
ASAN_OPTIONS=allocator_may_return_null=1:halt_on_error=0 iccDEV/Build/Tools/IccRoundTrip/iccRoundTrip "crash-file.icc"
```

**Files Modified**: `IccProfLib/IccMpeBasic.cpp`

## CWE Distribution

| CWE | Count | Category |
|-----|-------|----------|
| CWE-681 | 4 | Incorrect Type Conversion (UBSAN enum/NaN) |
| CWE-125 | 2 | Out-of-bounds Read |
| CWE-122 | 2 | Heap Buffer Overflow |
| CWE-190 | 2 | Integer Overflow |
| CWE-674 | 2 | Uncontrolled Recursion |
| CWE-762 | 2 | Mismatched Memory Management |
| CWE-476 | 2 | Null Pointer Dereference |
| CWE-20  | 2 | Improper Input Validation |
| CWE-191 | 1 | Integer Underflow |
| CWE-170 | 1 | Missing Null Termination |
| CWE-908 | 1 | Uninitialized Resource |
| CWE-770 | 1 | Allocation without Limits (OOM) |

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
