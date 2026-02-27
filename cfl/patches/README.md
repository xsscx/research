# CFL Library Patches — Fuzzing Security Fixes

Last Updated: 2026-02-26 00:28:00 UTC

These patches fix security vulnerabilities and harden iccDEV library code
found during LibFuzzer and ClusterFuzzLite fuzzing campaigns.

**Scope:** CFL/LibFuzzer Testing — intended as potential upstream PRs.

## Patches

| # | File | Function | Root Cause |
|---|------|----------|------------|
| 1 | `IccTagLut.cpp` | `CIccCLUT::Init` | `new icFloatNumber[nSize]` — grid dims multiply exponentially with nInput (up to 15 dims); no cap when `nMaxSize=0` |
| 2 | `IccMpeBasic.cpp` | `CIccSampledCurveSegment::SetSize` | `calloc(nCount, sizeof(icFloatNumber))` — nCount from profile with no upper bound |
| 3 | `IccTagLut.cpp` | `CIccTagGamutBoundaryDesc::Read` | `new icFloatNumber[channels*vertices]` — products can exceed RSS limit |
| 4 | `IccTagBasic.cpp` | `CIccTagNamedColor2::SetSize` | `calloc(nSize, entrySize)` — nSize from profile tag data |
| 5 | `IccUtil.cpp` | `icMemDump` | `string::reserve(lines*79)` — hex-dump output proportional to tag data size; 21 GB alloc observed |
| 6 | `IccProfile.cpp`, `IccUtil.cpp`, `IccSignatureUtils.h` | `LoadTag`, `icGetSig`, `icF16toF`, `DescribeColorSpaceSignature` | UBSAN: unsigned integer overflow in offset+size, left-shift overflow, implicit uint32→char narrowing |
| 7 | `IccTagBasic.cpp` | `CIccTagData::SetSize` | `icRealloc(m_pData, nSize)` — nSize from profile tag data; 4 GB allocation observed |
| 8 | `IccMpeCalc.cpp` | `CIccCalculatorFunc::Read` | `pIO->Read32(&m_Op[i].sig)` — raw uint32 loaded into `icSigCalcOp` enum; UBSAN invalid-enum-load |
| 9 | `IccTagBasic.cpp` | `CIccTagUnknown::Describe` | Heap-buffer-overflow: `m_pData+4` OOB and `m_nSize-4` unsigned underflow when `m_nSize ≤ 4` |
| 10 | `IccTagComposite.cpp` | `CIccTagArray` copy ctor / `operator=` | Uninitialized `m_TagVals`/`m_nSize` when source has 0 elements → SEGV in `Cleanup()`; wrong loop var in `operator=` |
| 11 | `IccTagBasic.cpp` | `CIccTagFloatNum/TagNum/FixedNum/XYZ/NamedColor2::SetSize` | `icRealloc()` with uncapped nSize from profile — 11.5 GB allocation in calculator fuzzer |
| 12 | `IccTagComposite.cpp` | `CIccTagArray::Read` | Mismatched `new[]`/`free` in `Cleanup()` — ASAN alloc-dealloc-mismatch |
| 13 | `IccMpeCalc.cpp` | `CIccCalculatorFunc::Read` | UBSAN invalid-enum-load: `icChannelFuncSignature` loaded with arbitrary uint32 values (0xFFFFFFFF, 0xA3E00000, etc.) |
| 14 | `IccMpeCalc.cpp` | `CIccCalcOpMgr::IsValidOp` | Infinite loop when `SeqNeedTempReset()` called with `nOps==0` |
| 15 | `IccMpeBasic.cpp` | `CIccSingleSampledCurve::SetSize` | `malloc(nCount * sizeof(icFloatNumber))` — nCount from profile; 17 GB allocation in multitag fuzzer |
| 16 | `IccTagLut.cpp` | `CIccTagCurve::Apply` | UBSAN: `-nan` cast to `unsigned int` — NaN bypasses `<0`/`>1` clamp, reaches `(icUInt32Number)(v * m_nMaxIndex)` |
| 17 | `IccTagLut.cpp` | `CIccTagCurve::SetSize` | `malloc(nSize * sizeof(icFloatNumber))` — nSize from XML/profile data; 12.4 GB allocation in fromxml fuzzer |
| 18 | `IccMpeSpectral.cpp` | `CIccMpeSpectralMatrix::SetSize` | `calloc(m_size, sizeof(icFloatNumber))` — numVectors()*range.steps uncapped; 8 GB RSS accumulation in multitag fuzzer |
| 19 | `IccTagBasic.cpp` | `CIccTagColorantTable::Describe` | Heap-buffer-overflow: `strlen(m_pData[i].name)` on non-null-terminated `name[32]` reads 7 bytes past 38-byte `icColorantTableEntry` allocation |
| 20 | `IccTagXml.cpp` | `CIccTagXmlColorantTable::ToXml`, `CIccTagXmlNamedColor2::ToXml` | Same strlen OOB via `icAnsiToUtf8()` on `name[32]`/`rootName[32]` in XML serialization path |
| 21 | `IccMpeSpectral.cpp` | `CIccMpeSpectralMatrix::Describe` | Heap-buffer-overflow: `data[i]` reads past `m_pMatrix` when `m_size==0` (from `numVectors()==0`) or stride mismatch between loop dimensions and allocation |
| 22 | `IccTagLut.cpp` | `CIccTagLut8::Validate`, `CIccTagLut16::Validate` | UBSAN signed integer overflow: `int sum += m_XYZMatrix[i]` accumulating 9 `icS15Fixed16Number` values overflows `int` |
| 23 | `IccMpeCalc.cpp` | `CIccCalculatorFunc::InitSelectOp` | Heap-buffer-overflow: `ops[n+1]` reads 1 past `m_Op` array end when `n+1 == nOps` |
| 24 | `IccMpeCalc.cpp` | `CIccOpDefEnvVar::Exec` | UBSAN invalid-enum-load: `(icSigCmmEnvVar) op->data.size` loads arbitrary uint32 (e.g. 3782042188) into enum type |
| 25 | `IccTagLut.cpp` | `CIccTagGamutBoundaryDesc::Read`, `Write` | UBSAN signed integer overflow: `m_NumberOfTriangles*3` overflows `int` when `m_NumberOfTriangles` is large (e.g. 2004119668*3) |
| 26 | `IccTagLut.h` | `CIccTagCurve::operator[]`, `GetData` | UBSAN reference binding to null: `m_Curve[index]` when `m_Curve` is null |
| 27 | `IccTagBasic.cpp` | `CIccTagNum::GetValues`, `CIccTagFixedNum::GetValues`, `CIccTagFloatNum::GetValues` | Stack-buffer-overflow: loop uses `m_nSize` instead of `nVectorSize` |
| 28 | `IccTagBasic.cpp` | `CIccTagNum::Interpolate`, `CIccTagFixedNum::Interpolate`, `CIccTagFloatNum::Interpolate` | Heap-buffer-overflow: loop uses `m_nSize` instead of `nVectorSize` (13 instances) |
| 29 | `IccTagLut.cpp` | `CIccCLUT::Interp1d/3dTetra/3d/4d/5d/6d/ND` | UBSAN+SEGV: negative float→unsigned cast in CLUT grid index when `NoClip` passes negative values |
| 30 | `IccMpeBasic.cpp` | `CIccSampledCurveSegment::Apply`, `CIccSingleSampledCurve::Apply`, `CIccSampledCalculatorCurve::Apply` | UBSAN: NaN/negative `pos` cast to `unsigned int` — division by zero `m_range` produces NaN; clamp `pos` to `[0, m_last]` before cast |
| 31 | `IccMatrixMath.cpp` | `CIccMatrixMath::SetRange` | Heap-buffer-overflow: `r[srcRange.steps-1]` OOB when `srcRange.steps < 2` (uint16 underflow to 65535); also clamp interpolation index `p` to `[0, srcRange.steps-2]` to prevent `r[p+1]` OOB |
| 32 | `IccMpeCalc.cpp` | `CIccCalculatorFunc::ApplySequence` | Heap-buffer-overflow: `select`/`case`/`default` op sub-sequence bounds not validated before recursive `ApplySequence` call; `ops[nDefOff].data.size` can exceed remaining ops, reading past `m_Op` buffer |
| 33 | `TiffImg.cpp` | `CTiffImg::Open` | Multiplication overflow: `m_nStripSize * m_nStripSamples` overflow to small value, causing too-small malloc and heap-buffer-overflow |
| 34 | `IccMpeCalc.cpp` | `CIccOpDefModulus::Exec` | UBSAN: float→int overflow in manual modulus `(int)(temp/tempN)` when quotient exceeds INT_MAX; replaced with `std::fmod` |
| 35 | `IccTagLut.cpp` | `CIccTagSegmentedCurve::Read` | Memory leak: `new CIccSegmentedCurve` leaked when `pCurve->Read()` fails |
| 36 | `IccMpeCalc.cpp` | `CIccMpeCalculator::Read` | Memory leak: `new CIccMultiProcessElement` leaked when `pElem->Read()` fails |
| 37 | `IccTagComposite.cpp` | `CIccTagArray::Read` | Memory leak: `CIccTagCreator::CreateTag()` result leaked when `pTag->Read()` fails |
| 38 | `IccTagDict.cpp` | `CIccTagDict::Read` | Memory leak: `new CIccTagMultiLocalizedUnicode` leaked when `pTag->Read()` fails (two sites: NameLocalized + ValueLocalized) |
| 39 | `IccCmm.cpp` | `CIccCmm::CheckPCSConnections` | Memory leak: `new CIccPcsXform` leaked when `pPcs->Connect()` returns error (missing `delete pPcs` — compare ConnectFirst/ConnectLast which had it) |
| 40 | `IccCmm.cpp` | `CIccPcsXform::Optimize` | Memory leak: identity PCS steps skipped from `newSteps` but never deleted — pointer dropped silently (two sites: inner loop + final element) |
| 41 | `IccTagLut.cpp` | `CIccCLUT::Interp1d/2d/3dTetra/3d/4d/5d/6d/ND` | Heap-buffer-overflow: `NoClip` allows values > 1.0 producing grid indices past allocation; add upper clamp `x = min(x, mx)` for all dimensions in all 8 interpolation functions |
| 42 | `IccMpeCalc.cpp` | `CIccOpDefTruncate::Exec` | UBSAN: float→int overflow in `(int)temp` when value (e.g. 1.58914e+10) exceeds INT_MAX; replaced with `std::trunc()` |
| 43 | `IccMpeCalc.cpp` | `CIccCalculatorFunc::SequenceNeedTempReset` | Timeout: crafted calculator ops cause excessive iteration; add 1M ops-processed counter to bound computation |
| 44 | `IccTagBasic.cpp` | `CIccTagSparseMatrixArray::Read` | OOM: `Reset()` allocates `nNumMatrices * nChannels * 4` bytes uncapped; add 16 MB allocation cap |
| 54 | `IccMpeCalc.cpp` | `CIccFuncTokenizer::GetEnvSig` | UBSAN invalid-enum-load: `(icSigCmmEnvVar)sig` loads arbitrary uint32 (e.g. 2254504802) into 2-member enum |

## Allocation Cap

Patches 001–005, 007, 011, 015, 017–018 add allocation-size caps to prevent
out-of-memory conditions during fuzzing.

Patch 001 uses a 16 MB per-allocation cap (`16777216` bytes) for CLUT
tables because `CIccCLUT::Init()` can be called many times per profile
(175+ allocations observed in fuzzing), causing cumulative OOM even at
128 MB per-call. Patches 002–004 use 128 MB (`134217728` bytes) since
those allocate once per profile read.

Patch 005 caps the hex-dump input at 256 KB (`262144` bytes).
This limits output to ~1.3 MB while still dumping the first 256 KB of
any oversized tag — sufficient for forensic analysis of crafted profiles.

Patch 006 fixes UBSAN-detected undefined behavior:
- `IccProfile.cpp:LoadTag` — overflow-safe `offset + size` bounds check
- `IccUtil.cpp:icGetSig` — left-shift overflow via 64-bit widening
- `IccUtil.cpp:icF16toF` — unsigned underflow in exponent calc via signed cast
- `IccSignatureUtils.h:DescribeColorSpaceSignature` — uint32→char narrowing

Patch 007 caps `CIccTagData::SetSize()` at 128 MB.  Triggered by
`icc_multitag_fuzzer` — peak RSS 4,557 MB from a crafted tag size.

Patch 008 fixes UBSAN `invalid-enum-load` in `CIccCalculatorFunc::Read()`.
Reads `m_Op[i].sig` into a `uint32` first, then casts to `icSigCalcOp`,
avoiding undefined behavior from loading arbitrary values into an enum type.

Patch 009 guards `CIccTagUnknown::Describe()` against `m_nSize ≤ 4`.
Without this, `m_pData+4` points past the 3-byte buffer and `m_nSize-4`
underflows to `0xFFFFFFFF`, causing heap-buffer-overflow in `icMemDump()`.

Patch 010 fixes two bugs in `CIccTagArray`:
- Copy constructor: `m_TagVals` and `m_nSize` uninitialized when source
  `m_nSize == 0` → ASAN fill pattern `0xBEBEBEBE` → SEGV in `Cleanup()`
- `operator=`: loop uses `m_nSize` (stale after `Cleanup()`) instead of
  `tagAry.m_nSize` → zero iterations → tags not copied

Patch 011 caps all remaining uncapped `SetSize()` variants at 128 MB:
- `CIccTagFloatNum<T>::SetSize()` — triggered via `CIccMpeTintArray::Read()`
  in `icc_calculator_fuzzer` with 11,573 MB peak RSS
- `CIccTagNum<T>::SetSize()`, `CIccTagFixedNum<T>::SetSize()` — same pattern
- `CIccTagXYZ::SetSize()`, `CIccTagNamedColor2::SetSize()` — defensive cap

Patch 013 fixes UBSAN `invalid-enum-load` in `CIccCalculatorFunc::Read()` for
`icChannelFuncSignature`.  After reading the `icSigCalcOp` opcode (patch 008),
the code reads a second `uint32` into `m_Op[i].extra` and casts it to
`icChannelFuncSignature`.  Crafted profiles can set this field to arbitrary
values (observed: `0xFFFFFFFF` = 4294967295, `0xA3E00000` = 2748792704,
`0xD7EC9F57` = 3621246935, `0xFA78A56E` = 4201018734) which are not valid
enumerators.  Fix: read into `icUInt32Number rawChSig`, compare directly
against `static_cast<icUInt32Number>(GetType())` without ever casting the
untrusted value into the enum type.  The original patch 013 used
`static_cast<icChannelFuncSignature>(rawChSig)` which is itself UB when the
value is out of enum range — this revision eliminates the cast entirely.

Patch 015 caps `CIccSingleSampledCurve::SetSize()` at 128 MB.  Triggered
by `icc_multitag_fuzzer` — `malloc(17179689408)` (17 GB) from a crafted
A2B0 tag with nested `CIccMpeCalculator::Read()` calling
`CIccMpeCurveSet::Read()` → `CIccSingleSampledCurve::Read()`.
Same pattern as patch 002 (`CIccSampledCurveSegment`) but different class.

Patch 016 guards `CIccTagCurve::Apply()` against NaN input.  The existing
clamp (`if(v<0.0) ... else if(v>1.0)`) does not catch NaN because IEEE 754
comparisons with NaN are always false.  NaN propagates to the cast
`(icUInt32Number)(v * m_nMaxIndex)` which is undefined behavior.
Fix: `if (std::isnan(v)) v = 0.0;` before the clamp.

Patch 017 caps `CIccTagCurve::SetSize()` at 128 MB.  Triggered by
`icc_fromxml_fuzzer` — `malloc(12408970272)` (12.4 GB) from a crafted
XML profile with oversized curve entry count parsed via
`CIccTagXmlCurve::ParseXml()` → `icMBBFromXml()`.

Patch 018 caps `CIccMpeSpectralMatrix::SetSize()` at 128 MB.  Triggered
by `icc_multitag_fuzzer` — RSS grew to 8,129 MB over 19M iterations via
119,197 allocations (~1 MB each, 90% of heap) in `calloc(m_size, ...)`.
`m_size = numVectors() * range.steps` where both are `icUInt16Number`
parsed from profile data, product up to 4.29 billion × 4 bytes = ~16 GB.

Patch 019 fixes heap-buffer-overflow in `CIccTagColorantTable::Describe()`.
`icColorantTableEntry` is `{ icInt8Number name[32]; icUInt16Number data[3]; }`
(38 bytes total).  `Read()` copies exactly 32 bytes into `name[]` via
`Read8()`.  `Describe()` calls `strlen(m_pData[i].name)` unbounded — if
`name` has no null terminator within 32 bytes, `strlen` reads 7 bytes past
the 38-byte heap allocation (`data[3]` = 6 bytes + 1 byte into next entry
or unmapped memory).  Fix: bounded scan with `strnlen()` + safe copy to a
null-terminated local buffer before use.

Patch 020 fixes the same strlen OOB class in the XML serialization path.
Three call sites in `IccTagXml.cpp`:
- `CIccTagXmlColorantTable::ToXml()` — passes `m_pData[i].name` to
  `icAnsiToUtf8()` which calls `strlen()` via `std::string::operator=`
- `CIccTagXmlNamedColor2::ToXml()` — passes `pEntry->rootName` (also
  `icUInt8Number[32]`, same struct layout) to `icAnsiToUtf8()` in both
  Lab and XYZ code paths
Fix: copy fixed-size field to `char safe[33]` with null terminator before
passing to `icAnsiToUtf8()`.  Verified: both PoC files process cleanly
with patched `iccToXml` and all 18 fuzzers (exit 0, no ASAN output).

Patch 021 fixes heap-buffer-overflow in `CIccMpeSpectralMatrix::Describe()`.
`m_pMatrix` is allocated as `calloc(m_size, sizeof(icFloatNumber))` where
`m_size = numVectors() * range.steps`.  When `numVectors()` returns 0
(e.g. `m_nInputChannels == 0` for `CIccMpeEmissionMatrix`), `calloc(0, 4)`
returns a 1-byte allocation.  `Describe()` then iterates
`m_nOutputChannels * m_Range.steps` elements, reading past the allocation.
ASAN: READ of size 4 at 1-byte region.  Additionally, even with non-zero
`m_size`, the loop advances `data` by `m_nInputChannels` per row but
accesses `m_Range.steps` elements per row — if the total accessed region
exceeds `m_size`, the read is OOB.  Fix: guard with `m_size > 0` and add
per-row bounds check `(data - m_pMatrix) + steps <= m_size` before access.

Patch 022 fixes UBSAN signed integer overflow in `CIccTagLut8::Validate()`
and `CIccTagLut16::Validate()`.  Both functions accumulate 9
`icS15Fixed16Number` (int32) `m_XYZMatrix` entries into `int sum` to check
if the matrix is identity (`sum == 3*65536`).  Crafted profiles can set
matrix entries to large values (e.g. `1668641986 + 1668641398` = `0x637574C2 +
0x63757476`) causing signed overflow.  Fix: widen `sum` and `s15dot16Unity`
to `icInt64Number`.

Patch 023 *(upstream-adopted — no-op)* fixed heap-buffer-overflow in
`CIccCalculatorFunc::InitSelectOp()`. The fix was adopted upstream using
`n<(nOps-1)` with an explicit bounds check. This patch is now a no-op.

Patch 024 fixes UBSAN `invalid-enum-load` in `CIccOpDefEnvVar::Exec()`.
`op->data.size` is an `icUInt32Number` from profile data, cast directly to
`icSigCmmEnvVar` enum via `(icSigCmmEnvVar) op->data.size`.  Crafted profiles
set this to arbitrary values (observed: 3782042188 = 0xE17B2E4C) which are
not valid enumerators.  Fix: read into `icUInt32Number rawSig`, compare against
`static_cast<icUInt32Number>(icSigTrueVar)` and `icSigNotDefVar` without
casting into the enum.  Only cast to `icSigCmmEnvVar` for the `GetEnvVar()`
call, which handles unknown values by returning false.  Same pattern as
patches 008 and 013.

Patch 025 fixes UBSAN signed integer overflow in
`CIccTagGamutBoundaryDesc::Read()` and `Write()`.  Both functions compute
`icUInt32Number nNum32 = m_NumberOfTriangles*3` where `m_NumberOfTriangles`
is `icInt32Number` (signed).  When `m_NumberOfTriangles` is large (observed:
2004119668), the product `2004119668*3 = 6,012,359,004` overflows signed
`int` (max 2,147,483,647).  The result is assigned to `icUInt32Number` but
the overflow occurs in the signed multiplication, which is undefined behavior.
Fix: cast to `(icUInt32Number)m_NumberOfTriangles*3` to perform unsigned
multiplication.  Defense-in-depth: the 128 MB allocation cap (patch 003)
limits `m_NumberOfTriangles` to ~11M, so the unsigned product fits in uint32.

Patch 026 fixes UBSAN "reference binding to null pointer" in
`CIccTagCurve::operator[]()` and `GetData()` (IccTagLut.h:142-143).
Both inline accessors dereference `m_Curve` without checking for null.
When `m_Curve` is uninitialized or `SetSize()` failed/was never called,
`m_Curve` is null and `m_Curve[index]` / `&m_Curve[index]` is undefined
behavior.  Triggered by `icc_calculator_fuzzer` via crafted profiles that
exercise `CIccTagCurve` paths before the curve data is allocated.
Fix: `operator[]` returns a static zero dummy when `m_Curve` is null;
`GetData` returns `NULL`.

Patch 027 fixes stack-buffer-overflow in `CIccTagNum::GetValues()`,
`CIccTagFixedNum::GetValues()`, and `CIccTagFloatNum::GetValues()`
(IccTagBasic.cpp).  All three loop over `m_nSize` (the total number of
elements in the tag array) instead of `nVectorSize` (the caller-requested
count), writing past the caller's buffer.  Triggered via
`GetElemNumberValue()` which passes a 1-element stack buffer.
Fix: use `nVectorSize` as the loop bound in all three template
specializations.

Patch 028 *(upstream-adopted — no-op)* fixed heap-buffer-overflow in
`CIccTagNum::Interpolate()`, `CIccTagFixedNum::Interpolate()`, and
`CIccTagFloatNum::Interpolate()`. The fix was adopted upstream; all
Interpolate loops now use `nVectorSize` instead of `m_nSize`.

Patch 029 fixes UBSAN undefined behavior and SEGV crash in all
`CIccCLUT::Interp*d()` functions (IccTagLut.cpp).  When the CLUT is
used via a Multi-Process Element (`CIccMpeCLUT`), the clip function is
set to `NoClip` which handles NaN and Inf but passes negative values
through.  A negative grid coordinate cast to `icUInt32Number` is
undefined behavior (UBSAN: "−16 is outside the range of representable
values of type 'unsigned int'") and produces a huge index, causing
SEGV on the subsequent `m_pData[]` access.  `Interp2d` already had
clamping; the fix adds `if (v < 0.0f) v = 0.0f;` guards to Interp1d,
Interp3dTetra, Interp3d, Interp4d, Interp5d, Interp6d, and InterpND.

Patch 030 fixes UBSAN NaN-to-unsigned cast in sampled curve Apply methods
(IccMpeBasic.cpp).  `CIccSingleSampledCurve::Apply()` and
`CIccSampledCalculatorCurve::Apply()` cast the result of curve evaluation
directly to unsigned, which is undefined when the value is NaN or negative.

Patch 031 fixes heap-buffer-overflow in `CIccMatrixMath::SetRange()`
(IccMatrixMath.cpp).  The `SetRange()` method miscalculated the copy
extent, reading beyond the allocated matrix buffer.

Patch 032 fixes heap-buffer-overflow in `CIccCalculatorFunc::ApplySequence()`
select/case/default operations (IccMpeCalc.cpp).  Array indexing for
multi-opcode sequences accessed `ops[n+1]` without bounds checking.

Patch 033 fixes multiplication overflow in `CTiffImg::Open()` malloc
(TiffImg.cpp).  `m_nStripSize * m_nStripSamples` are both `unsigned int`
and can overflow to a small value, causing a too-small allocation and
subsequent heap-buffer-overflow.  The fix adds an overflow check before
each of the two `malloc()` call sites.

Patch 034 fixes UBSAN float-to-int overflow in `CIccOpDefModulus::Exec()`
(IccMpeCalc.cpp).  The manual modulus `temp - (int)(temp/tempN)*tempN`
casts the quotient to `int`, which is undefined behavior when the value
exceeds INT_MAX (~2.1e9).  Replaced with `std::fmod()` which handles
the full floating-point range correctly.

Patch 035 fixes memory leak in `CIccTagSegmentedCurve::Read()`
(IccTagLut.cpp).  `new CIccSegmentedCurve` is allocated but not deleted
when `pCurve->Read()` fails — the function returns `false` without
cleanup, leaking the curve object.

Patch 036 fixes memory leak in `CIccMpeCalculator::Read()`
(IccMpeCalc.cpp).  `new CIccMultiProcessElement` (via `CreateElement()`)
is allocated but not deleted when `pElem->Read()` fails.  Same pattern
as patch 035.

Patch 037 fixes memory leak in `CIccTagArray::Read()`
(IccTagComposite.cpp).  `CIccTagCreator::CreateTag()` allocates a tag
object which is not deleted when `pTag->Read()` fails — the function
returns `false` with `delete[] tagPos` but leaks the tag.

Patch 038 fixes memory leak in `CIccTagDict::Read()` (IccTagDict.cpp).
Two sites: `new CIccTagMultiLocalizedUnicode` for NameLocalized (line
757) and ValueLocalized (line 808) — both leak when `pTag->Read()` fails
because the error path does not `delete pTag`.  The `!pTag` null check
and `!pTag->Read()` are combined in a single `if`, so `delete pTag` is
safe (pTag is non-null when Read is reached).

Patch 039 fixes memory leak in `CIccCmm::CheckPCSConnections()`
(IccCmm.cpp).  When `pPcs->Connect()` returns an error status, the
function returned without deleting `pPcs`.  The `ConnectFirst()` and
`ConnectLast()` error paths already had `delete pPcs` — only the
`Connect()` path was missing it.

Patch 040 fixes memory leak in `CIccPcsXform::Optimize()` (IccCmm.cpp).
The optimization loop identifies identity PCS steps and skips them from
the `newSteps` list.  However, the skipped step's pointer was never
deleted — it was silently dropped when `ptr.ptr = next->ptr` overwrote
it.  Two leak sites: the inner concat-failure path (line 2512) and the
final-element check after the loop (line 2518).  Fix: add `else { delete
ptr.ptr; }` at both sites.

Patch 041 fixes heap-buffer-overflow in all 8 CLUT interpolation functions
(Interp1d through InterpND) in IccTagLut.cpp.  The `NoClip` function
(used by CIccMpeCLUT) allows input values > 1.0 (including +Inf which
returns 1000).  After multiplying by `MaxGridPoint`, the resulting grid
coordinate exceeds the allocated CLUT data size, producing OOB pointer
arithmetic.  Patch 029 added lower clamps for negative values but missed
the upper bound.  Fix: add `if (x > mx) x = mx` (and similarly for y, z,
w, g0-g5, g[i]) in all 8 functions immediately after the negative clamps.

Patch 042 fixes UBSAN float→int overflow in `CIccOpDefTruncate::Exec()`
(IccMpeCalc.cpp:1215).  The truncation operator cast `(int)temp` where
`temp` can be any float from the calculator stack (e.g. 1.58914e+10).
Values outside `[INT_MIN, INT_MAX]` are undefined behavior per C++.
Fix: replace `(int)temp` with `std::trunc(temp)` which returns a float
and handles the full float range without integer overflow.

Patch 043 fixes timeout in `CIccCalculatorFunc::SequenceNeedTempReset()`
(IccMpeCalc.cpp).  Crafted calculator ops cause the function's linear
for-loop (not deep recursion — stack shows only 2 levels) to process
millions of ops.  Fix: add a shared `icUInt32Number *pOpsProcessed`
counter passed across recursion levels, capped at 1,000,000.

Patch 044 fixes OOM in `CIccTagSparseMatrixArray::Read()` (IccTagBasic.cpp).
`Reset()` calls `icRealloc(m_RawData, nNeededSize)` where `nNeededSize`
comes from the profile's declared tag size — crafted profiles trigger
4+ GB allocations via `icRealloc`.  Fix: add a 16 MB allocation cap
before the `Reset()` call.

Patch 045 fixes heap-buffer-overflow in `CIccCalculatorFunc::ApplySequence()`
(IccMpeCalc.cpp).  Bounds checks for if/else and select/case/default ops
used uint32 arithmetic that overflows with crafted `data.size` values,
allowing READ past the ops array.  Two sub-bugs: (1) the if-true branch
validated only the if-block size but not the else-block size before
advancing `os.idx` by both; (2) all bounds checks used `icUInt32Number`
addition that wraps at 2³².  Fix: use `icUInt64Number` casts in all
bounds checks and validate both block sizes unconditionally.
Crash artifact: `crash-3741ab3832437d29b96592fb2624d07367740893`.

Patch 046 fixes UBSAN float→int overflow in `CIccOpDefRound::Exec()`
(IccMpeCalc.cpp:1274).  The round operator cast `(int)(temp+0.5)` /
`(int)(temp-0.5)` where `temp` can be any float from the calculator
stack (e.g. 4.61169e+19).  The `std::isinf` guard only caught infinity,
not large finite floats.  Same class of bug as patch 042 (truncate).
Fix: replace with `std::round(temp)` which returns a float and handles
the full range without integer overflow.

Patch 047 fixes stack-overflow (infinite recursion) in
`CIccCalculatorFunc::SequenceNeedTempReset()` (IccMpeCalc.cpp).
Patch 043 added a 1M ops-processed counter to limit computation, but
deeply nested `icSigIfOp`/`icSigElseOp` chains cause unbounded recursion
(246+ frames) that exhausts the stack before the ops counter triggers.
Each recursive frame allocates heap (`malloc(nMaxTemp)`) plus a large
stack frame.  ASAN: `stack-overflow` on address in `malloc`.
Fix: add `nRecurseDepth` parameter (default 0) with a 100-level cap.
Recursive calls pass `nRecurseDepth + 1`; returns `true` when exceeded.

Patch 048 fixes stack-overflow (infinite recursion) in
`CIccCalculatorFunc::CheckUnderflowOverflow()` (IccMpeCalc.cpp:4082).
Crafted ICC profiles with deeply nested `if/else` or `select/case/default`
calculator opcodes cause unbounded recursion (200+ frames) that exhausts
the stack.  ASAN: `stack-overflow` at `IccMpeCalc.cpp:4083`.
Reproducer: `crash-e130055931f00b2bdff2ec6151d7bdbe88ef1ac9` (v5 RGB
monitor profile with MPE calc element containing nested if/else chains).
Fix: add `nRecurseDepth` parameter (default 0) with a 100-level cap.
All 5 recursive call sites pass `nRecurseDepth + 1`; returns `-1` when
exceeded, which propagates as `icFuncParseStackUnderflow`.

Patch 049 fixes memory leak in `CIccProfileXml::ParseTag()`
(IccProfileXml.cpp:756). When XML tag content parses successfully but
no valid `<TagSignature>` child element is found, the allocated `CIccTag`
is never attached to the profile and never freed.  Over thousands of
fuzzer iterations this leak accumulates → OOM.  LSAN: 192 byte(s) leaked
per invocation (32 direct + 160 indirect via CIccLocalizedUnicode).
Reproducer: `oom-442f59c9478c618234a29a3c3e7dbeaa91c0d235` (fuzzed XML
with corrupted TagSignature element).
Fix: track `bAttached` flag; `delete pTag` and `return false` if no
`AttachTag()` was called after the TagSignature scan loop.

Patch 050 fixes UBSAN float→int overflow in `ApplySequence()` select op
(IccMpeCalc.cpp:3754).  The `icSigSelectOp` handler rounds `a1` via
`(icInt32Number)(a1+0.5f)` but only guards against `isinf`, not huge
finite values like `-1.12984e+37`.  UBSAN: "is outside the range of
representable values of type 'int'".
Fix: clamp `rounded` to `INT32_MIN..INT32_MAX` range before casting.

Patch 051 fixes UBSAN NaN→unsigned short cast in
`CIccMatrixMath::SetRange()` (IccMatrixMath.cpp:385).
`(icUInt16Number)((w - srcStart) / srcScale)` produces NaN when
`srcScale` is zero or when arithmetic yields NaN.  UBSAN: "-nan is
outside the range of representable values of type 'unsigned short'".
Fix: compute intermediate `fIdx`, guard against NaN and clamp to
`0..65535` before casting to `icUInt16Number`.  Adds `#include <cmath>`.

Patch 052 fixes null-pointer dereference (SEGV) in
`CIccXformNDLut::Apply()` (IccCmm.cpp:6553).  Both CLUT switch blocks
in `Apply()` only dispatch dimensions 5 and 6 to dedicated `Interp5d`/
`Interp6d`; dimensions 1–4 fall through to the `default` case which
calls `InterpND()` with `pNDApply->m_pApply`.  But `GetNewApply()` only
allocates `CIccApplyCLUT` when `m_nNumInput > 6`, so `m_pApply` is NULL
for dimensions ≤ 6.  ASAN: SEGV at `IccTagLut.cpp:3157` dereferencing
NULL `CIccApplyCLUT*`.
Reproducer: `crash-889703d7e209eb6ffc143fc802ef1f7f8e78e539` (crafted
mft2 profile with 2-channel input CLUT via `RG s` colorspace).
Fix: add `case 1`–`case 4` dispatching to `Interp1d`–`Interp4d`, and
add NULL guard on `pNDApply->m_pApply` in the `default` fallback.

Patch 053 fixes heap-buffer-overflow in `CIccToneMapFunc::Describe()`
(IccMpeBasic.cpp:3984).  `Describe()` unconditionally accesses
`m_params[0]`, `m_params[1]`, `m_params[2]` when `m_nFunctionType == 0`,
but `Read()` allocates `m_params` based on the file's declared size
without validating it matches `NumArgs()` (which returns 3 for type 0).
A crafted profile can declare fewer parameters (e.g. 1), causing READ
past the 4-byte heap allocation.  Also fixes `Apply()` which had the
same unchecked access pattern.
ASAN: READ of size 4 at 0 bytes after 4-byte region in
`CIccToneMapFunc::Describe()`.
Reproducer: `crash-e2bf6aa3825f575b3fe6bb62c5c597e81d6c118c` (HLG
narrow-range RGB profile with truncated ToneMapFunction parameters).
Fix: guard `case 0x0000` in `Describe()` with `m_nParameters >= 3 &&
m_params`; guard `Apply()` with `m_nParameters >= 3`.

Patch 054 fixes UBSAN `invalid-enum-load` in `CIccFuncTokenizer::GetEnvSig()`
(IccMpeCalc.cpp:2813,2827,2831).  `GetEnvSig()` parses arbitrary 4-byte
signatures from calculator expression text and casts the raw `icUInt32Number`
directly to `icSigCmmEnvVar` — an enum with only two valid members
(`icSigTrueVar = 0x74727565`, `icSigNotDefVar = 0x6e646566`).  Any other
value (observed: 2254504802 = 0x865E2362) is undefined behavior per C++.
Three cast sites: line 2813 (hex path), line 2827 (text path), and
line 2831 (error path with `(icSigCmmEnvVar)0`).
Fix: use `memcpy(&envSig, &sig, sizeof(envSig))` at all three sites to
transfer the raw bit pattern without going through an enum load.  This
preserves the value semantics while avoiding UBSAN.  Same bug class as
patches 008, 013, and 024.

Patch 055 fixes a **stack buffer overflow** in `CIccTagNamedColor2::Read()`
(IccTagBasic.cpp).  The `m_szPrefix[32]` and `m_szSufix[32]` fields are
read from the ICC file via `Read8()` without null-termination.  When
`ToXml()` passes these unterminated strings through `icFixXml(char *szDest,
const char *szStr)`, XML-special characters (e.g. `0x27` = `'`) expand to
6-byte entities (`&apos;`).  With 64+ bytes of `'` read past the buffer
boundary, the expansion produces 384+ bytes into a 256-byte stack buffer
`fix[256]`, smashing the stack canary.  Crash signature:
`*** stack smashing detected ***: terminated` (SIGABRT, exit 134).
Fix: null-terminate both `m_szPrefix` and `m_szSufix` immediately after
`Read8()`, consistent with the existing `rootName` null-termination at
line 2998.

## Application

Patches are applied automatically by `build.sh`:

```bash
for p in "$SCRIPT_DIR"/patches/*.patch; do
  patch -p1 -d "$ICCDEV_DIR" < "$p"
done
```
