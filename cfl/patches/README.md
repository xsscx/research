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

## Allocation Cap

All patches use a 128 MB per-allocation cap (`134217728` bytes).
This is conservative enough to allow legitimate ICC profiles (largest
real-world CLUT ≈ 50 MB) while preventing the 2+ GB allocations that
trigger OOM kills during fuzzing.

## Application

Patches are applied automatically by `build.sh`:

```bash
for p in "$SCRIPT_DIR"/patches/*.patch; do
  patch -p1 -d "$ICCDEV_DIR" < "$p"
done
```
