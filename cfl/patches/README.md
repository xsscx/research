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

## Allocation Cap

Patches 001–004 use a 128 MB per-allocation cap (`134217728` bytes).
This is conservative enough to allow legitimate ICC profiles (largest
real-world CLUT ≈ 50 MB) while preventing the 2+ GB allocations that
trigger OOM kills during fuzzing.

Patch 005 caps the hex-dump input at 256 KB (`262144` bytes).
This limits output to ~1.3 MB while still dumping the first 256 KB of
any oversized tag — sufficient for forensic analysis of crafted profiles.

## Application

Patches are applied automatically by `build.sh`:

```bash
for p in "$SCRIPT_DIR"/patches/*.patch; do
  patch -p1 -d "$ICCDEV_DIR" < "$p"
done
```
