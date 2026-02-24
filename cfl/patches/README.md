# CFL Library Patches — Fuzzing Security Fixes

Last Updated: 2026-02-24 23:12:00 UTC

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

Patch 023 fixes heap-buffer-overflow in `CIccCalculatorFunc::InitSelectOp()`.
The function iterates `ops[]` (a pointer into the `m_Op` array) counting
`icSigCaseOp` entries via `for (n=0; n<nOps && ops[n+1].sig==icSigCaseOp; n++)`.
When `n` reaches `nOps-1`, `ops[n+1]` is `ops[nOps]` — 1 element past the
28,488-byte heap allocation.  ASAN: READ of size 4 at 0 bytes after region.
Same OOB in the subsequent `if (ops[n+1].sig==icSigDefaultOp)` check.
Fix: change loop guard to `n+1<nOps` and add `n+1<nOps` bounds check before
the `icSigDefaultOp` test.

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

## Application

Patches are applied automatically by `build.sh`:

```bash
for p in "$SCRIPT_DIR"/patches/*.patch; do
  patch -p1 -d "$ICCDEV_DIR" < "$p"
done
```
