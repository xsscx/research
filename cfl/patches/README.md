# CFL Library Patches — Fuzzing OOM Mitigation

These patches add allocation-size caps to iccDEV library code to prevent
out-of-memory conditions during LibFuzzer and ClusterFuzzLite campaigns.

**Scope:** CFL/LibFuzzer only — NOT intended as upstream PRs.  
**Applied by:** `build.sh` after cloning iccDEV, before `cmake`.

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

## Allocation Cap

Patches 001–004 use a 128 MB per-allocation cap (`134217728` bytes).
This is conservative enough to allow legitimate ICC profiles (largest
real-world CLUT ≈ 50 MB) while preventing the 2+ GB allocations that
trigger OOM kills during fuzzing.

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

## Application

Patches are applied automatically by `build.sh`:

```bash
for p in "$SCRIPT_DIR"/patches/*.patch; do
  patch -p1 -d "$ICCDEV_DIR" < "$p"
done
```
