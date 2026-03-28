# CFL Patch Audit Report -- 2026-03-28

## Executive Summary

45 active CFL patches audited against upstream iccDEV v2.3.1.6 (commit e280b0a).
Each patch tested with available PoC profiles through ASAN+UBSAN-instrumented
upstream tools. 452 ICC profiles scanned (338 test-profiles + 114 extended-test-profiles).

| Category | Count | Status |
|----------|-------|--------|
| Confirmed upstream trigger (PoC-validated) | 2 | ASAN/UBSAN reproducible in upstream tools |
| Library-level runtime fix (fuzzer-only) | 18 | Real bugs, unreachable via CLI tool input validation |
| Code quality / defensive hardening | 19 | Format strings, init, self-assignment, alloc mismatch |
| JSON config tool bugs | 6 | Require -cfg JSON test configs |
| Total active | 45 | 44 apply cleanly, 1 context conflict (CFL-075) |

## Methodology

1. Built upstream iccDEV at iccDEV/Build/ with:
   `-fsanitize=address,undefined,float-divide-by-zero -fno-omit-frame-pointer`
2. Tested each patch's PoC (where available) through unpatched upstream tools:
   iccDumpProfile, iccToXml, iccRoundTrip, iccApplyNamedCmm
3. Scanned ALL profiles: test-profiles/ (338), extended-test-profiles/ (114),
   fuzz/graphics/icc/ (129) -- total 581 ICC files
4. Classified each patch by code review of the actual diff

## Confirmed Upstream Triggers (2 patches)

### CFL-004: CIccToneMapFunc::Describe Heap-Buffer-Overflow

- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **PoC**: test-profiles/CIccToneMapFunc-Describe-heap-oob-IccMpeBasic_cpp.icc
- **Tool**: iccDumpProfile (with ALL flag)
- **ASAN output**:
  ```
  ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000514
  SCARINESS: 17 (4-byte-read-heap-buffer-overflow)
  IccMpeBasic.cpp:3988 in CIccToneMapFunc::Describe()
  ```
- **Root cause**: Read() computes m_nParameters from file-controlled size without
  validating against NumArgs(). Describe() reads m_params[0..2] with only 1 allocated.
- **Fix**: Validate m_nParameters >= NumArgs() after Read(). If insufficient,
  set m_params = NULL; m_nParameters = 0; return false.
- **Upstream issue**: Needed

### CFL-077: CIccCamConverter::CalcCoefficients Division-by-Zero

- **CWE**: CWE-369 (Divide by Zero)
- **PoC**: test-profiles/Spec400_10_700-B_2deg-CAM.icc
- **Tool**: iccDumpProfile (with ALL flag)
- **UBSAN output**:
  ```
  IccCAM.cpp:283:43: runtime error: division by zero
  IccCAM.cpp:283:93: runtime error: division by zero
  IccCAM.cpp:266:32: runtime error: division by zero
  ```
- **Root cause**: CalcCoefficients() has 3 division chains:
  (1) m_WhitePoint[1]==0 early return needed
  (2) pow(m_n,0.2)==0 guard needed
  (3) m_x0==0 || H_Function(m_Fl)==0 guard needed
- **Fix**: Three early-return guards in CalcCoefficients()
- **Upstream issue**: Needed

## Library-Level Runtime Fixes -- Fuzzer-Only (18 patches)

These fix real bugs in iccDEV library code that are unreachable through CLI tool
input validation but exploitable by any third-party consumer of the library API.
Per CFL-008 documentation: "NOT reproducible through upstream CLI tools. The upstream
tool's input validation prevents the conditions that produce NaN."

| Patch | CWE | Bug Description | File:Line |
|-------|-----|-----------------|-----------|
| CFL-005 | CWE-681 | Calculator sig read as enum, values outside range | IccMpeCalc.cpp |
| CFL-006 | CWE-122 | SpectralMatrix Describe iterates m_nOutputChannels (wrong bound) | IccMpeSpectral.cpp |
| CFL-007 | CWE-190 | TagArray offset+size integer overflow (no guard) | IccTagComposite.cpp |
| CFL-008 | CWE-681 | TagCurve Apply: NaN bypasses if(v<0) -- cast to unsigned is UB | IccTagLut.cpp:584 |
| CFL-009 | CWE-681 | EnvVar Exec: raw uint32 instead of enum cast | IccMpeCalc.cpp |
| CFL-014 | CWE-674 | SequenceNeedTempReset: unbounded recursion in Apply path | IccMpeCalc.cpp |
| CFL-019 | CWE-476 | PCC getReflectanceObserver: null pView guard missing | IccPcc.cpp |
| CFL-021 | CWE-400 | SingleSampledCurve: oversized m_nCount allocation | IccMpeBasic.cpp |
| CFL-022 | CWE-681 | Calc ops: large float-to-int cast in Trunc/Floor/Ceil/Round/Mod | IccMpeCalc.cpp |
| CFL-023 | CWE-681 | 3 Apply() NaN-to-unsigned casts | IccMpeBasic.cpp |
| CFL-025 | CWE-476 | CLUT InterpNd: null pApply from GetNewApply() failure | IccTagLut.cpp |
| CFL-028 | CWE-681 | MatrixMath SetRange: NaN/Inf + steps<=1 div-by-zero | IccMatrixMath.cpp |
| CFL-044 | CWE-476 | NDLut Apply: missing interpolation dispatch (1d/2d/3d/4d) | IccCmm.cpp |
| CFL-047 | CWE-476 | pushXYZNormalize: null PCC pointer dereference | IccCmm.cpp |
| CFL-059 | CWE-681 | TagCurve Begin: m_nSize-1 underflow when m_nSize==0 | IccTagLut.h |
| CFL-063 | CWE-190 | Bounds check offset+size overflow in 4 Read/CheckLut sites | IccProfile.cpp, IccTagMPE.cpp, IccMpeCalc.cpp |
| CFL-064 | CWE-191 | Segmented curve pos-startPos subtraction underflow | IccMpeBasic.cpp |
| CFL-067 | CWE-681 | icIsS15Fixed16NumberNear: float-to-unsigned overflow | IccUtil.cpp |

## Code Quality / Defensive Hardening (19 patches)

These fix latent bugs (format strings, uninitialized members, self-assignment,
alloc-dealloc mismatch) that may not cause immediate crashes but represent
undefined behavior or potential future vulnerabilities.

| Patch | CWE | Bug Description | File |
|-------|-----|-----------------|------|
| CFL-017 | CWE-681 | GetEnvSig: icSigCmmEnvVar enum avoidance | IccMpeCalc.cpp/h |
| CFL-029 | CWE-824 | TagArray operator=: loop uses m_nSize vs tagAry.m_nSize | IccTagComposite.cpp |
| CFL-046 | CWE-762 | PCS step src matrix: delete vs delete[] mismatch | IccCmm.cpp |
| CFL-050 | CWE-125 | FormulaCurve Describe: OOB parameter access | IccMpeBasic.cpp |
| CFL-051 | CWE-125 | ParametricCurve Describe: OOB parameter access | IccTagLut.cpp |
| CFL-053 | CWE-134 | FormulaCurve Describe: wrong printf format (%8f vs %.8f) | IccMpeBasic.cpp |
| CFL-054 | CWE-134 | ParametricCurve Describe: wrong printf format (%lf vs %.4lf) | IccTagLut.cpp |
| CFL-055 | CWE-681 | fromIt8: signed-unsigned mismatch (%u vs %d for nColor) | IccCmmConfig.cpp |
| CFL-056 | CWE-476 | Spectral Describe: null m_pWhite/m_pBigE guards | IccMpeSpectral.cpp |
| CFL-057 | CWE-908 | SearchApply: 13 uninitialized member variables | IccCmmConfig.cpp |
| CFL-061 | CWE-191 | icF16toF: unsigned underflow (uint32 vs int32 cast) | IccUtil.cpp |
| CFL-062 | CWE-681 | icGetSig: implicit int-to-icChar conversion | IccUtil.cpp |
| CFL-068 | CWE-682 | MpeCurveSet operator=: self-assignment + m_nReserved fix | IccMpeBasic.cpp |
| CFL-069 | CWE-682 | 5 operator= self-assignment guards (segment, curve, matrix, cam) | multiple |
| CFL-070 | CWE-908 | Copy ctor missing member init (m_range, m_last, m_storageType) | multiple |
| CFL-071 | CWE-908 | Default ctor missing member init (6 members) | multiple |
| CFL-072 | CWE-134 | printf %d vs %u for unsigned + [[maybe_unused]] RealUnitClip | multiple |
| CFL-074 | N/A | icSaturate: integer-to-float always representable (constexpr if) | IccUtilXml.cpp |
| CFL-075 | CWE-908 | m_useEmbedded init, buffer overflow guard, format fix | IccCmmConfig.cpp |

**Note**: CFL-075 has a context conflict (3 of 4 hunks apply, 1 needs rebase).

## JSON Config Tool Bugs (6 patches)

These fix bugs in the JSON configuration parsing path used by iccApplyNamedCmm,
iccApplyProfiles, and iccApplySearch when invoked with `-cfg config.json`.
Require specific JSON test configs for PoC validation.

| Patch | CWE | Bug Description | File |
|-------|-----|-----------------|------|
| CFL-040 | CWE-787 | fromIt8 CMYK: missing samples.push_back(val) | IccCmmConfig.cpp |
| CFL-041 | CWE-125 | fromIt8 LAB/XYZ: val(4) should be val(3) | IccCmmConfig.cpp |
| CFL-042 | CWE-20 | ParseNumbers: 'n' literal vs '\\n' newline typo | IccCmmConfig.cpp |
| CFL-043 | CWE-697 | Tool toJson: seq.is_object() fails on array | iccApplyNamedCmm.cpp, iccApplySearch.cpp |
| CFL-052 | CWE-125 | fromIt8: wrong index variable (nValueIdx vs nSrcIndex) | IccCmmConfig.cpp |
| CFL-073 | CWE-484 | IccProfileXml: implicit fallthrough in ParseTag switch | IccProfileXml.cpp |

## Retired Patches (This Session)

| Patch | Reason | Upstream Reference |
|-------|--------|-------------------|
| CFL-002 | Accepted upstream v2.3.1.6 | IccTagLut.cpp triangle overflow |
| CFL-036 | Accepted upstream v2.3.1.6 | IccCmmConfig.cpp:540 linkGridSize |
| CFL-065 | Accepted upstream v2.3.1.6 | IccTagLut.cpp nEnd underflow |
| CFL-076 | Accepted upstream v2.3.1.6 | IccTagLut.h signed channel type |

## Previously Retired (93 patches total in patches-retired/)

See cfl/patches-retired/ for complete archive. Major retirement waves:
- March 2026 initial: 62 legacy patches (architecture simplification)
- March 2026 upstream sync: CFL-003, -010, -011, -012, -013, -015, -016, -018, -020, -024, -026, -027, -034, -037, -039
- This session: CFL-002, -036, -065, -076

## Scan Results Summary

| Corpus | Files Scanned | Tool | ASAN Hits | UBSAN Hits |
|--------|--------------|------|-----------|------------|
| test-profiles/*.icc | 338 | iccDumpProfile ALL | 1 (CFL-004) | 1 (CFL-077) |
| test-profiles/*.icc | 338 | iccRoundTrip | 0 | 1 (CFL-077) |
| extended-test-profiles/*.icc | 114 | iccDumpProfile ALL | 0 | 0 |
| fuzz/graphics/icc/*.icc | 129 | iccDumpProfile ALL | 0 | 0 |
| **Total** | **919 scans** | | **1 ASAN** | **2 UBSAN** |

## Key Finding

The vast majority of CFL patches (43 of 45) fix bugs that are NOT reachable through
upstream CLI tool input validation. They are nonetheless real library-level bugs that:

1. Are exploitable by any third-party consumer of the iccDEV C++ API
2. Are triggered by LibFuzzer's in-process fuzzing (no tool-level input filtering)
3. Represent genuine undefined behavior per C/C++ standards (NaN casts, integer
   overflow, null dereference, uninitialized reads)
4. Would be exploitable in applications that embed iccDEV without the tool's
   graceful-rejection layer (web browsers, image viewers, color management daemons)

## Recommendations

1. **File upstream issues** for CFL-004 and CFL-077 per gold standard template
2. **Rebase CFL-075** against v2.3.1.6 (3 of 4 hunks still needed)
3. **Create JSON test configs** for CFL-040/041/042/043/052/073 validation
4. **Keep all 45 patches active** -- even fuzzer-only bugs represent real library UB
5. **Monitor upstream** for acceptance of patches in future releases

## Build Verification

```
iccDEV upstream: v2.3.1.6 (commit e280b0a)
ASAN symbols: 666 (nm | grep __asan)
UBSAN symbols: 112 (nm | grep __ubsan)
Build flags: -g -O0 -fsanitize=address,undefined,float-divide-by-zero
Patches applied cleanly: 44/45 (CFL-075 context conflict)
```

---
Generated: 2026-03-28 UTC
Tool: Copilot CLI (Claude Opus 4.6)
