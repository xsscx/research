# ICC Profile Analysis Report

**Profile**: `test-profiles/ub-nan-outside-range-icDtoF-float-IccUtil_cpp-Line560.icc`
**File Size**: 2405 bytes
**Date**: 2026-02-15T22:07:30Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 1 | Finding detected |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 2 | Error |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 1**

```
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x47524159 (Gray)
ICC_DEBUG: [iccDEV/IccProfLib/IccSignatureUtils.h:288] IsValidColorSpaceSignature(): input = 0x67706365 (Unknown)
ICC_WARN: [iccDEV/IccProfLib/IccSignatureUtils.h:311] IccSignatureUtils.h: ColorSpace signature: 0x67706365 (Unknown)

=======================================================================
  ICC PROFILE COMPREHENSIVE ANALYSIS (ALL MODES)
=======================================================================

File: /home/runner/work/research/research/test-profiles/ub-nan-outside-range-icDtoF-float-IccUtil_cpp-Line560.icc

=======================================================================
PHASE 1: SECURITY HEURISTIC ANALYSIS
=======================================================================


=========================================================================
|              ICC PROFILE SECURITY HEURISTIC ANALYSIS                  |
=========================================================================

File: /home/runner/work/research/research/test-profiles/ub-nan-outside-range-icDtoF-float-IccUtil_cpp-Line560.icc

=======================================================================
HEADER VALIDATION HEURISTICS
=======================================================================

[H1] Profile Size: 4286299823 bytes (0xFF7BBEAF)  [actual file: 2405 bytes]
     [WARN]  HEURISTIC: Profile size > 1 GiB (possible memory exhaustion)
     Risk: Resource exhaustion attack
     [WARN]  HEURISTIC: Header claims 4286299823 bytes but file is 2405 bytes (1782245x inflation)
     Risk: OOM via tag-internal allocations sized from inflated header

[H2] Magic Bytes (offset 0x24): 61 63 73 70 (acsp)
     [OK] Valid ICC magic signature

[H3] Data ColorSpace: 0x47524159 (GRAY)
     [OK] Valid colorSpace: GrayData

[H4] PCS ColorSpace: 0x67706365 (gpce)
     [WARN]  HEURISTIC: Invalid PCS signature (must be Lab, XYZ, or spectral)
     Risk: Colorimetric transform failures
     Name: Unknown  Bytes: 'gpce'

[H5] Platform: 0x0900A6FB (....)
     [WARN]  HEURISTIC: Unknown platform signature
     Risk: Platform-specific code path exploitation

[H6] Rendering Intent: 4280320 (0x00415000)
     [WARN]  HEURISTIC: Invalid rendering intent (> 3)
     Risk: Out-of-bounds enum access

[H7] Profile Class: 0x4150504C (APPL)
     [OK] Known class: Unknown 'APPL' = 4150504C

[H8] Illuminant XYZ: (20556.001953, 16.000000, 0.001526)
     [WARN]  HEURISTIC: Illuminant values > 5.0 (suspicious)
     Risk: Floating-point overflow in transforms

[H15] Date Validation: 14403-19538-29299 00:00:00
      [WARN]  HEURISTIC: Invalid month: 19538
      [WARN]  HEURISTIC: Invalid day: 29299
      [WARN]  HEURISTIC: Suspicious year: 14403 (expected 1900-2100)
      Risk: Malformed date may indicate crafted/corrupted profile

[H16] Signature Pattern Analysis
      [OK] No suspicious signature patterns detected

[H17] Spectral Range Validation
      Spectral: start=0.00nm end=-65504.00nm steps=20560
      [WARN]  HEURISTIC: Excessive spectral steps: 20560
      [WARN]  HEURISTIC: Spectral end < start (-65504.00 < 0.00)
      BiSpectral: start=17.56nm end=0.00nm steps=132

=======================================================================
TAG-LEVEL HEURISTICS
=======================================================================

[H9] Critical Text Tags:
     Description: Missing
     Copyright: Missing
     Manufacturer: Missing
     Device Model: Missing
     [WARN]  HEURISTIC: Multiple required text tags missing
       Risk: Incomplete/malformed profile

[H10] Tag Count: 50
      [OK] Tag count within normal range

[H11] CLUT Entry Limit Check
      Max safe CLUT entries per tag: 16777216 (16M)
      INFO: Profile has 50 tags
      Theoretical max CLUT: 838860800 entries (16777216 per tag)

[H12] MPE Chain Depth Limit
      Max MPE elements per chain: 1024
      Note: Full MPE analysis requires tag-level parsing
      [OK] Limit defined (1024 elements max)

[H13] Per-Tag Size Limit
      Max tag size: 64 MB (67108864 bytes)
      [WARN]  WARNING: Theoretical max (3355443200 bytes) > profile limit (1073741824)
       Tag count: 50, Max per tag: 67108864 bytes

[H14] TagArrayType Detection (UAF Risk)
      Checking for TagArrayType (0x74617279 = 'tary')
      Note: Tag signature â‰  tag type - must check tag DATA
      [OK] No TagArrayType tags detected

[H18] Technology Signature Validation
      INFO: No technology tag present

[H19] Tag Offset/Size Overlap Detection
      [WARN]  Tags 'Rrs.' and '...P' overlap: [3359056+1347183616] vs [1347183616+33842]
      [WARN]  Tags 'Rrs.' and 'acsp' overlap: [3359056+1347183616] vs [151037691+4294967295]
      [WARN]  Tags 'Rrs.' and 'KKKK' overlap: [3359056+1347183616] vs [1259864064+0]
      [WARN]  Tags 'Rrs.' and '.%ac' overlap: [3359056+1347183616] vs [0+2795939494]
      [WARN]  Tags 'Rrs.' and 'KKKK' overlap: [3359056+1347183616] vs [1263225675+1263225675]
      [WARN]  Tags 'Rrs.' and 'KCLR' overlap: [3359056+1347183616] vs [1263225675+1263225675]
      [WARN]  Tags 'Rrs.' and 'KKKK' overlap: [3359056+1347183616] vs [1259864064+0]
      [WARN]  Tags 'Rrs.' and '....' overlap: [3359056+1347183616] vs [10878976+16777126]
      [WARN]  Tags 'Rrs.' and 'KKKC' overlap: [3359056+1347183616] vs [1263225675+1263225675]
      [WARN]  Tags 'Rrs.' and 'KKK.' overlap: [3359056+1347183616] vs [738197504+5010034]
      [WARN]  Tags 'Rrs.' and 'izk3' overlap: [3359056+1347183616] vs [1129075314+4294967294]
      [WARN]  Tags 'Rrs.' and '....' overlap: [3359056+1347183616] vs [0+1633907568]
      [WARN]  Tags 'Rrs.' and 'PPLd' overlap: [3359056+1347183616] vs [132+843141200]
      [WARN]  Tags 'Rrs.' and 'Ld..' overlap: [3359056+1347183616] vs [16777216+50]
      [WARN]  Tags 'Rrs.' and 'Rrs.' overlap: [3359056+1347183616] vs [0+6382451]
      [WARN]  Tags 'Rrs.' and 'svcn' overlap: [3359056+1347183616] vs [255+4294967295]
      [WARN]  Tags 'Rrs.' and 'KKKK' overlap: [3359056+1347183616] vs [1263225675+4226678783]
      [WARN]  Tags 'Rrs.' and '....' overlap: [3359056+1347183616] vs [1263225624+738197504]
      [WARN]  Tags '..#i' and '..2R' overlap: [1852520515+1280471667] vs [1920139264+0]
      [WARN]  Tags '..#i' and 'acsp' overlap: [1852520515+1280471667] vs [151037691+4294967295]
      [WARN]  Tags '..#i' and 'rrrr' overlap: [1852520515+1280471667] vs [1920103026+1920093003]
      [WARN]  Tags '..#i' and '...s' overlap: [1852520515+1280471667] vs [1986227942+122]
      [WARN]  Tags '..#i' and '.%ac' overlap: [1852520515+1280471667] vs [0+2795939494]
      [WARN]  Tags '..#i' and 't..9' overlap: [1852520515+1280471667] vs [2795939494+2326134841]
      [WARN]  Tags '..#i' and '....' overlap: [1852520515+1280471667] vs [2795939418+1505012299]
      [WARN]  Tags '..#i' and 'KKKK' overlap: [1852520515+1280471667] vs [1263225675+1263225675]
      [WARN]  Tags '..#i' and 'KCLR' overlap: [1852520515+1280471667] vs [1263225675+1263225675]
      [WARN]  Tags '..#i' and 'KKKC' overlap: [1852520515+1280471667] vs [1263225675+1263225675]
      [WARN]  Tags '..#i' and 'r.L.' overlap: [1852520515+1280471667] vs [1350848577+1537671167]
      [WARN]  Tags '..#i' and 'izk3' overlap: [1852520515+1280471667] vs [1129075314+4294967294]
      [WARN]  Tags '..#i' and '..Lr' overlap: [1852520515+1280471667] vs [1920103026+1920103026]
      [WARN]  Tags '..#i' and 'rrrr' overlap: [1852520515+1280471667] vs [1920102987+1263225675]
      [WARN]  Tags '..#i' and '..Lr' overlap: [1852520515+1280471667] vs [1920103026+1920103026]
      [WARN]  Tags '..#i' and 'rrrr' overlap: [1852520515+1280471667] vs [1920103019+1263225675]
      [WARN]  Tags '..#i' and 'svcn' overlap: [1852520515+1280471667] vs [255+4294967295]
      [WARN]  Tags '..#i' and '....' overlap: [1852520515+1280471667] vs [2998055602+2998055602]
      [WARN]  Tags '..#i' and '....' overlap: [1852520515+1280471667] vs [2795939583+4294944422]
      [WARN]  Tags '..#i' and 'KKKK' overlap: [1852520515+1280471667] vs [1263225675+4226678783]
      [WARN]  Tags '..#i' and '....' overlap: [1852520515+1280471667] vs [1263225624+738197504]
      [WARN]  Tags '#...' and 'acsp' overlap: [4278083939+1987053824] vs [151037691+4294967295]
      [WARN]  Tags '#...' and '....' overlap: [4278083939+1987053824] vs [4283200114+1920103026]
      [WARN]  Tags '#...' and 't..9' overlap: [4278083939+1987053824] vs [2795939494+2326134841]
      [WARN]  Tags '#...' and '....' overlap: [4278083939+1987053824] vs [2795939418+1505012299]
      [WARN]  Tags '#...' and '....' overlap: [4278083939+1987053824] vs [4294967206+2795916107]
      [WARN]  Tags '#...' and 'KKKK' overlap: [4278083939+1987053824] vs [4227858431+4294967295]
      [WARN]  Tags '#...' and '....' overlap: [4278083939+1987053824] vs [4286644224+35]
      [WARN]  Tags '#...' and 'izk3' overlap: [4278083939+1987053824] vs [1129075314+4294967294]
      [WARN]  Tags '#...' and '....' overlap: [4278083939+1987053824] vs [4294967295+4294967295]
      [WARN]  Tags '#...' and 'sv..' overlap: [4278083939+1987053824] vs [4227858431+4294967295]
      [WARN]  Tags '#...' and 'svcn' overlap: [4278083939+1987053824] vs [255+4294967295]
      [WARN]  Tags '#...' and '....' overlap: [4278083939+1987053824] vs [4294967295+4294967295]
      [WARN]  Tags '#...' and '....' overlap: [4278083939+1987053824] vs [2998055602+2998055602]
      [WARN]  Tags '#...' and '....' overlap: [4278083939+1987053824] vs [2795939583+4294944422]
      [WARN]  Tags '#...' and '.KKK' overlap: [4278083939+1987053824] vs [3511372611+1263225675]
      [WARN]  Tags '#...' and 'KKKK' overlap: [4278083939+1987053824] vs [1263225675+4226678783]
      [WARN]  Tags '#...' and '.Lr.' overlap: [4278083939+1987053824] vs [4294967115+1263212588]
      [WARN]  Tags '...P' and 'acsp' overlap: [1347183616+33842] vs [151037691+4294967295]
      [WARN]  Tags '...P' and '.%ac' overlap: [1347183616+33842] vs [0+2795939494]
      [WARN]  Tags '...P' and 'KKKK' overlap: [1347183616+33842] vs [1263225675+1263225675]
      [WARN]  Tags '...P' and 'KCLR' overlap: [1347183616+33842] vs [1263225675+1263225675]
      [WARN]  Tags '...P' and 'KKKC' overlap: [1347183616+33842] vs [1263225675+1263225675]
      [WARN]  Tags '...P' and 'izk3' overlap: [1347183616+33842] vs [1129075314+4294967294]
      [WARN]  Tags '...P' and '....' overlap: [1347183616+33842] vs [0+1633907568]
      [WARN]  Tags '...P' and 'svcn' overlap: [1347183616+33842] vs [255+4294967295]
      [WARN]  Tags '...P' and 'KKKK' overlap: [1347183616+33842] vs [1263225675+4226678783]
      [WARN]  Tags '...P' and '....' overlap: [1347183616+33842] vs [1263225624+738197504]
      [WARN]  Tags 'APPL' and 'acsp' overlap: [1677728513+0] vs [151037691+4294967295]
      [WARN]  Tags 'APPL' and '.%ac' overlap: [1677728513+0] vs [0+2795939494]
      [WARN]  Tags 'APPL' and 'KKKK' overlap: [1677728513+0] vs [1263225675+1263225675]
      [WARN]  Tags 'APPL' and 'KCLR' overlap: [1677728513+0] vs [1263225675+1263225675]
      [WARN]  Tags 'APPL' and 'KKKC' overlap: [1677728513+0] vs [1263225675+1263225675]
      [WARN]  Tags 'APPL' and 'r.L.' overlap: [1677728513+0] vs [1350848577+1537671167]
      [WARN]  Tags 'APPL' and 'izk3' overlap: [1677728513+0] vs [1129075314+4294967294]
      [WARN]  Tags 'APPL' and '....' overlap: [1677728513+0] vs [1668706313+10943487]
      [WARN]  Tags 'APPL' and 'svcn' overlap: [1677728513+0] vs [255+4294967295]
      [WARN]  Tags 'APPL' and 'KKKK' overlap: [1677728513+0] vs [1263225675+4226678783]
      [WARN]  Tags 'APPL' and '....' overlap: [1677728513+0] vs [1263225624+738197504]
      [WARN]  Tags '..2R' and 'acsp' overlap: [1920139264+0] vs [151037691+4294967295]
      [WARN]  Tags '..2R' and 'rrrr' overlap: [1920139264+0] vs [1920103026+1920093003]
      [WARN]  Tags '..2R' and '.%ac' overlap: [1920139264+0] vs [0+2795939494]
      [WARN]  Tags '..2R' and 'KKKK' overlap: [1920139264+0] vs [1263225675+1263225675]
      [WARN]  Tags '..2R' and 'KCLR' overlap: [1920139264+0] vs [1263225675+1263225675]
      [WARN]  Tags '..2R' and 'KKKC' overlap: [1920139264+0] vs [1263225675+1263225675]
      [WARN]  Tags '..2R' and 'r.L.' overlap: [1920139264+0] vs [1350848577+1537671167]
      [WARN]  Tags '..2R' and 'izk3' overlap: [1920139264+0] vs [1129075314+4294967294]
      [WARN]  Tags '..2R' and '..Lr' overlap: [1920139264+0] vs [1920103026+1920103026]
      [WARN]  Tags '..2R' and 'rrrr' overlap: [1920139264+0] vs [1920102987+1263225675]
      [WARN]  Tags '..2R' and '..Lr' overlap: [1920139264+0] vs [1920103026+1920103026]
      [WARN]  Tags '..2R' and 'rrrr' overlap: [1920139264+0] vs [1920103019+1263225675]
      [WARN]  Tags '..2R' and 'svcn' overlap: [1920139264+0] vs [255+4294967295]
      [WARN]  Tags '..2R' and 'KKKK' overlap: [1920139264+0] vs [1263225675+4226678783]
      [WARN]  Tags '..2R' and '....' overlap: [1920139264+0] vs [1263225624+738197504]
      [WARN]  Tags 'acsp' and '....' overlap: [151037691+4294967295] vs [4283200114+1920103026]
      [WARN]  Tags 'acsp' and 'rrrr' overlap: [151037691+4294967295] vs [1920103026+1920093003]
      [WARN]  Tags 'acsp' and 'KKKK' overlap: [151037691+4294967295] vs [1259864064+0]
      [WARN]  Tags 'acsp' and '...s' overlap: [151037691+4294967295] vs [1986227942+122]
      [WARN]  Tags 'acsp' and '.%ac' overlap: [151037691+4294967295] vs [0+2795939494]
      [WARN]  Tags 'acsp' and 't..9' overlap: [151037691+4294967295] vs [2795939494+2326134841]
      [WARN]  Tags 'acsp' and '....' overlap: [151037691+4294967295] vs [2795939418+1505012299]
      [WARN]  Tags 'acsp' and 'KKKK' overlap: [151037691+4294967295] vs [1263225675+1263225675]
      [WARN]  Tags 'acsp' and 'KCLR' overlap: [151037691+4294967295] vs [1263225675+1263225675]
      [WARN]  Tags 'acsp' and 'KKKK' overlap: [151037691+4294967295] vs [1259864064+0]
      [WARN]  Tags 'acsp' and '....' overlap: [151037691+4294967295] vs [4294967206+2795916107]
      [WARN]  Tags 'acsp' and 'KKKC' overlap: [151037691+4294967295] vs [1263225675+1263225675]
      [WARN]  Tags 'acsp' and 'KKKK' overlap: [151037691+4294967295] vs [4227858431+4294967295]
      [WARN]  Tags 'acsp' and 'KKK.' overlap: [151037691+4294967295] vs [738197504+5010034]
      [WARN]  Tags 'acsp' and 'r.L.' overlap: [151037691+4294967295] vs [1350848577+1537671167]
      [WARN]  Tags 'acsp' and '....' overlap: [151037691+4294967295] vs [4286644224+35]
      [WARN]  Tags 'acsp' and 'izk3' overlap: [151037691+4294967295] vs [1129075314+4294967294]
      [WARN]  Tags 'acsp' and '....' overlap: [151037691+4294967295] vs [4294967295+4294967295]
      [WARN]  Tags 'acsp' and '....' overlap: [151037691+4294967295] vs [0+1633907568]
      [WARN]  Tags 'acsp' and '....' overlap: [151037691+4294967295] vs [1668706313+10943487]
      [WARN]  Tags 'acsp' and 'PPLd' overlap: [151037691+4294967295] vs [132+843141200]
      [WARN]  Tags 'acsp' and 'p...' overlap: [151037691+4294967295] vs [4227858178+255]
      [WARN]  Tags 'acsp' and '..Lr' overlap: [151037691+4294967295] vs [1920103026+1920103026]
      [WARN]  Tags 'acsp' and 'rrrr' overlap: [151037691+4294967295] vs [1920102987+1263225675]
      [WARN]  Tags 'acsp' and 'sv..' overlap: [151037691+4294967295] vs [4227858431+4294967295]
      [WARN]  Tags 'acsp' and '..Lr' overlap: [151037691+4294967295] vs [1920103026+1920103026]
      [WARN]  Tags 'acsp' and 'rrrr' overlap: [151037691+4294967295] vs [1920103019+1263225675]
      [WARN]  Tags 'acsp' and 'svcn' overlap: [151037691+4294967295] vs [255+4294967295]
      [WARN]  Tags 'acsp' and '....' overlap: [151037691+4294967295] vs [4294967295+4294967295]
      [WARN]  Tags 'acsp' and '....' overlap: [151037691+4294967295] vs [2998055602+2998055602]
      [WARN]  Tags 'acsp' and '....' overlap: [151037691+4294967295] vs [2795939583+4294944422]
      [WARN]  Tags 'acsp' and '.KKK' overlap: [151037691+4294967295] vs [3511372611+1263225675]
      [WARN]  Tags 'acsp' and 'KKKK' overlap: [151037691+4294967295] vs [1263225675+4226678783]
      [WARN]  Tags 'acsp' and '....' overlap: [151037691+4294967295] vs [1263225624+738197504]
      [WARN]  Tags 'acsp' and '.Lr.' overlap: [151037691+4294967295] vs [4294967115+1263212588]
      [WARN]  Tags '....' and 't..9' overlap: [4283200114+1920103026] vs [2795939494+2326134841]
      [WARN]  Tags '....' and '....' overlap: [4283200114+1920103026] vs [2795939418+1505012299]
      [WARN]  Tags '....' and '....' overlap: [4283200114+1920103026] vs [4294967206+2795916107]
      [WARN]  Tags '....' and 'KKKK' overlap: [4283200114+1920103026] vs [4227858431+4294967295]
      [WARN]  Tags '....' and '....' overlap: [4283200114+1920103026] vs [4286644224+35]
      [WARN]  Tags '....' and 'izk3' overlap: [4283200114+1920103026] vs [1129075314+4294967294]
      [WARN]  Tags '....' and '....' overlap: [4283200114+1920103026] vs [4294967295+4294967295]
      [WARN]  Tags '....' and 'sv..' overlap: [4283200114+1920103026] vs [4227858431+4294967295]
      [WARN]  Tags '....' and 'svcn' overlap: [4283200114+1920103026] vs [255+4294967295]
      [WARN]  Tags '....' and '....' overlap: [4283200114+1920103026] vs [4294967295+4294967295]
      [WARN]  Tags '....' and '....' overlap: [4283200114+1920103026] vs [2998055602+2998055602]
      [WARN]  Tags '....' and '....' overlap: [4283200114+1920103026] vs [2795939583+4294944422]
      [WARN]  Tags '....' and '.KKK' overlap: [4283200114+1920103026] vs [3511372611+1263225675]
      [WARN]  Tags '....' and 'KKKK' overlap: [4283200114+1920103026] vs [1263225675+4226678783]
      [WARN]  Tags '....' and '.Lr.' overlap: [4283200114+1920103026] vs [4294967115+1263212588]
      [WARN]  Tags 'rrrr' and '...s' overlap: [1920103026+1920093003] vs [1986227942+122]
      [WARN]  Tags 'rrrr' and '.%ac' overlap: [1920103026+1920093003] vs [0+2795939494]
      [WARN]  Tags 'rrrr' and 't..9' overlap: [1920103026+1920093003] vs [2795939494+2326134841]
      [WARN]  Tags 'rrrr' and '....' overlap: [1920103026+1920093003] vs [2795939418+1505012299]
      [WARN]  Tags 'rrrr' and 'KKKK' overlap: [1920103026+1920093003] vs [1263225675+1263225675]
      [WARN]  Tags 'rrrr' and 'KCLR' overlap: [1920103026+1920093003] vs [1263225675+1263225675]
      [WARN]  Tags 'rrrr' and 'KKKC' overlap: [1920103026+1920093003] vs [1263225675+1263225675]
      [WARN]  Tags 'rrrr' and 'r.L.' overlap: [1920103026+1920093003] vs [1350848577+1537671167]
      [WARN]  Tags 'rrrr' and 'izk3' overlap: [1920103026+1920093003] vs [1129075314+4294967294]
      [WARN]  Tags 'rrrr' and 'rrrr' overlap: [1920103026+1920093003] vs [1920102987+1263225675]
      [WARN]  Tags 'rrrr' and 'rrrr' overlap: [1920103026+1920093003] vs [1920103019+1263225675]
      [WARN]  Tags 'rrrr' and 'svcn' overlap: [1920103026+1920093003] vs [255+4294967295]
      [WARN]  Tags 'rrrr' and '....' overlap: [1920103026+1920093003] vs [2998055602+2998055602]
      [WARN]  Tags 'rrrr' and '....' overlap: [1920103026+1920093003] vs [2795939583+4294944422]
      [WARN]  Tags 'rrrr' and '.KKK' overlap: [1920103026+1920093003] vs [3511372611+1263225675]
      [WARN]  Tags 'rrrr' and 'KKKK' overlap: [1920103026+1920093003] vs [1263225675+4226678783]
      [WARN]  Tags 'rrrr' and '....' overlap: [1920103026+1920093003] vs [1263225624+738197504]
      [WARN]  Tags 'KKKK' and '.%ac' overlap: [1259864064+0] vs [0+2795939494]
      [WARN]  Tags 'KKKK' and 'izk3' overlap: [1259864064+0] vs [1129075314+4294967294]
      [WARN]  Tags 'KKKK' and '....' overlap: [1259864064+0] vs [0+1633907568]
      [WARN]  Tags 'KKKK' and 'svcn' overlap: [1259864064+0] vs [255+4294967295]
      [WARN]  Tags '...s' and '.%ac' overlap: [1986227942+122] vs [0+2795939494]
      [WARN]  Tags '...s' and 'KKKK' overlap: [1986227942+122] vs [1263225675+1263225675]
      [WARN]  Tags '...s' and 'KCLR' overlap: [1986227942+122] vs [1263225675+1263225675]
      [WARN]  Tags '...s' and 'KKKC' overlap: [1986227942+122] vs [1263225675+1263225675]
      [WARN]  Tags '...s' and 'r.L.' overlap: [1986227942+122] vs [1350848577+1537671167]
      [WARN]  Tags '...s' and 'izk3' overlap: [1986227942+122] vs [1129075314+4294967294]
      [WARN]  Tags '...s' and '..Lr' overlap: [1986227942+122] vs [1920103026+1920103026]
      [WARN]  Tags '...s' and 'rrrr' overlap: [1986227942+122] vs [1920102987+1263225675]
      [WARN]  Tags '...s' and '..Lr' overlap: [1986227942+122] vs [1920103026+1920103026]
      [WARN]  Tags '...s' and 'rrrr' overlap: [1986227942+122] vs [1920103019+1263225675]
      [WARN]  Tags '...s' and 'svcn' overlap: [1986227942+122] vs [255+4294967295]
      [WARN]  Tags '...s' and 'KKKK' overlap: [1986227942+122] vs [1263225675+4226678783]
      [WARN]  Tags '...s' and '....' overlap: [1986227942+122] vs [1263225624+738197504]
      [WARN]  Tags '.%ac' and '....' overlap: [0+2795939494] vs [2795939418+1505012299]
      [WARN]  Tags '.%ac' and 'KKKK' overlap: [0+2795939494] vs [1263225675+1263225675]
      [WARN]  Tags '.%ac' and 'KCLR' overlap: [0+2795939494] vs [1263225675+1263225675]
      [WARN]  Tags '.%ac' and 'KKKK' overlap: [0+2795939494] vs [1259864064+0]
      [WARN]  Tags '.%ac' and '....' overlap: [0+2795939494] vs [10878976+16777126]
      [WARN]  Tags '.%ac' and 'KKKC' overlap: [0+2795939494] vs [1263225675+1263225675]
      [WARN]  Tags '.%ac' and 'KKK.' overlap: [0+2795939494] vs [738197504+5010034]
      [WARN]  Tags '.%ac' and 'r.L.' overlap: [0+2795939494] vs [1350848577+1537671167]
      [WARN]  Tags '.%ac' and 'izk3' overlap: [0+2795939494] vs [1129075314+4294967294]
      [WARN]  Tags '.%ac' and '....' overlap: [0+2795939494] vs [1668706313+10943487]
      [WARN]  Tags '.%ac' and 'PPLd' overlap: [0+2795939494] vs [132+843141200]
      [WARN]  Tags '.%ac' and 'Ld..' overlap: [0+2795939494] vs [16777216+50]
      [WARN]  Tags '.%ac' and '..Lr' overlap: [0+2795939494] vs [1920103026+1920103026]
      [WARN]  Tags '.%ac' and 'rrrr' overlap: [0+2795939494] vs [1920102987+1263225675]
      [WARN]  Tags '.%ac' and '..Lr' overlap: [0+2795939494] vs [1920103026+1920103026]
      [WARN]  Tags '.%ac' and 'rrrr' overlap: [0+2795939494] vs [1920103019+1263225675]
      [WARN]  Tags '.%ac' and 'svcn' overlap: [0+2795939494] vs [255+4294967295]
      [WARN]  Tags '.%ac' and 'KKKK' overlap: [0+2795939494] vs [1263225675+4226678783]
      [WARN]  Tags '.%ac' and '....' overlap: [0+2795939494] vs [1263225624+738197504]
      [WARN]  Tags 't..9' and '....' overlap: [2795939494+2326134841] vs [2795939418+1505012299]
      [WARN]  Tags 't..9' and '....' overlap: [2795939494+2326134841] vs [4294967206+2795916107]
      [WARN]  Tags 't..9' and 'KKKK' overlap: [2795939494+2326134841] vs [4227858431+4294967295]
      [WARN]  Tags 't..9' and 'r.L.' overlap: [2795939494+2326134841] vs [1350848577+1537671167]
      [WARN]  Tags 't..9' and '....' overlap: [2795939494+2326134841] vs [4286644224+35]
      [WARN]  Tags 't..9' and 'izk3' overlap: [2795939494+2326134841] vs [1129075314+4294967294]
      [WARN]  Tags 't..9' and '....' overlap: [2795939494+2326134841] vs [4294967295+4294967295]
      [WARN]  Tags 't..9' and 'p...' overlap: [2795939494+2326134841] vs [4227858178+255]
      [WARN]  Tags 't..9' and '..Lr' overlap: [2795939494+2326134841] vs [1920103026+1920103026]
      [WARN]  Tags 't..9' and 'rrrr' overlap: [2795939494+2326134841] vs [1920102987+1263225675]
      [WARN]  Tags 't..9' and 'sv..' overlap: [2795939494+2326134841] vs [4227858431+4294967295]
      [WARN]  Tags 't..9' and '..Lr' overlap: [2795939494+2326134841] vs [1920103026+1920103026]
      [WARN]  Tags 't..9' and 'rrrr' overlap: [2795939494+2326134841] vs [1920103019+1263225675]
      [WARN]  Tags 't..9' and 'svcn' overlap: [2795939494+2326134841] vs [255+4294967295]
      [WARN]  Tags 't..9' and '....' overlap: [2795939494+2326134841] vs [4294967295+4294967295]
      [WARN]  Tags 't..9' and '....' overlap: [2795939494+2326134841] vs [2998055602+2998055602]
      [WARN]  Tags 't..9' and '....' overlap: [2795939494+2326134841] vs [2795939583+4294944422]
      [WARN]  Tags 't..9' and '.KKK' overlap: [2795939494+2326134841] vs [3511372611+1263225675]
      [WARN]  Tags 't..9' and 'KKKK' overlap: [2795939494+2326134841] vs [1263225675+4226678783]
      [WARN]  Tags 't..9' and '.Lr.' overlap: [2795939494+2326134841] vs [4294967115+1263212588]
      [WARN]  Tags '....' and '....' overlap: [2795939418+1505012299] vs [4294967206+2795916107]
      [WARN]  Tags '....' and 'KKKK' overlap: [2795939418+1505012299] vs [4227858431+4294967295]
      [WARN]  Tags '....' and 'r.L.' overlap: [2795939418+1505012299] vs [1350848577+1537671167]
      [WARN]  Tags '....' and '....' overlap: [2795939418+1505012299] vs [4286644224+35]
      [WARN]  Tags '....' and 'izk3' overlap: [2795939418+1505012299] vs [1129075314+4294967294]
      [WARN]  Tags '....' and '....' overlap: [2795939418+1505012299] vs [4294967295+4294967295]
      [WARN]  Tags '....' and 'p...' overlap: [2795939418+1505012299] vs [4227858178+255]
      [WARN]  Tags '....' and '..Lr' overlap: [2795939418+1505012299] vs [1920103026+1920103026]
      [WARN]  Tags '....' and 'rrrr' overlap: [2795939418+1505012299] vs [1920102987+1263225675]
      [WARN]  Tags '....' and 'sv..' overlap: [2795939418+1505012299] vs [4227858431+4294967295]
      [WARN]  Tags '....' and '..Lr' overlap: [2795939418+1505012299] vs [1920103026+1920103026]
      [WARN]  Tags '....' and 'rrrr' overlap: [2795939418+1505012299] vs [1920103019+1263225675]
      [WARN]  Tags '....' and 'svcn' overlap: [2795939418+1505012299] vs [255+4294967295]
      [WARN]  Tags '....' and '....' overlap: [2795939418+1505012299] vs [4294967295+4294967295]
      [WARN]  Tags '....' and '....' overlap: [2795939418+1505012299] vs [2998055602+2998055602]
      [WARN]  Tags '....' and '....' overlap: [2795939418+1505012299] vs [2795939583+4294944422]
      [WARN]  Tags '....' and '.KKK' overlap: [2795939418+1505012299] vs [3511372611+1263225675]
      [WARN]  Tags '....' and 'KKKK' overlap: [2795939418+1505012299] vs [1263225675+4226678783]
      [WARN]  Tags '....' and '.Lr.' overlap: [2795939418+1505012299] vs [4294967115+1263212588]
      [WARN]  Tags 'KKKK' and 'r.L.' overlap: [1263225675+1263225675] vs [1350848577+1537671167]
      [WARN]  Tags 'KKKK' and 'izk3' overlap: [1263225675+1263225675] vs [1129075314+4294967294]
      [WARN]  Tags 'KKKK' and '....' overlap: [1263225675+1263225675] vs [0+1633907568]
      [WARN]  Tags 'KKKK' and '....' overlap: [1263225675+1263225675] vs [1668706313+10943487]
      [WARN]  Tags 'KKKK' and '..Lr' overlap: [1263225675+1263225675] vs [1920103026+1920103026]
      [WARN]  Tags 'KKKK' and 'rrrr' overlap: [1263225675+1263225675] vs [1920102987+1263225675]
      [WARN]  Tags 'KKKK' and '..Lr' overlap: [1263225675+1263225675] vs [1920103026+1920103026]
      [WARN]  Tags 'KKKK' and 'rrrr' overlap: [1263225675+1263225675] vs [1920103019+1263225675]
      [WARN]  Tags 'KKKK' and 'svcn' overlap: [1263225675+1263225675] vs [255+4294967295]
      [WARN]  Tags 'KKKK' and '....' overlap: [1263225675+1263225675] vs [1263225624+738197504]
      [WARN]  Tags 'KCLR' and 'r.L.' overlap: [1263225675+1263225675] vs [1350848577+1537671167]
      [WARN]  Tags 'KCLR' and 'izk3' overlap: [1263225675+1263225675] vs [1129075314+4294967294]
      [WARN]  Tags 'KCLR' and '....' overlap: [1263225675+1263225675] vs [0+1633907568]
      [WARN]  Tags 'KCLR' and '....' overlap: [1263225675+1263225675] vs [1668706313+10943487]
      [WARN]  Tags 'KCLR' and '..Lr' overlap: [1263225675+1263225675] vs [1920103026+1920103026]
      [WARN]  Tags 'KCLR' and 'rrrr' overlap: [1263225675+1263225675] vs [1920102987+1263225675]
      [WARN]  Tags 'KCLR' and '..Lr' overlap: [1263225675+1263225675] vs [1920103026+1920103026]
      [WARN]  Tags 'KCLR' and 'rrrr' overlap: [1263225675+1263225675] vs [1920103019+1263225675]
      [WARN]  Tags 'KCLR' and 'svcn' overlap: [1263225675+1263225675] vs [255+4294967295]
      [WARN]  Tags 'KCLR' and '....' overlap: [1263225675+1263225675] vs [1263225624+738197504]
      [WARN]  Tags 'KKKK' and 'izk3' overlap: [1259864064+0] vs [1129075314+4294967294]
      [WARN]  Tags 'KKKK' and '....' overlap: [1259864064+0] vs [0+1633907568]
      [WARN]  Tags 'KKKK' and 'svcn' overlap: [1259864064+0] vs [255+4294967295]
      [WARN]  Tags '....' and '....' overlap: [10878976+16777126] vs [0+1633907568]
      [WARN]  Tags '....' and 'PPLd' overlap: [10878976+16777126] vs [132+843141200]
      [WARN]  Tags '....' and 'Ld..' overlap: [10878976+16777126] vs [16777216+50]
      [WARN]  Tags '....' and 'svcn' overlap: [10878976+16777126] vs [255+4294967295]
      [WARN]  Tags '....' and 'KKKK' overlap: [4294967206+2795916107] vs [4227858431+4294967295]
      [WARN]  Tags '....' and 'izk3' overlap: [4294967206+2795916107] vs [1129075314+4294967294]
      [WARN]  Tags '....' and '....' overlap: [4294967206+2795916107] vs [4294967295+4294967295]
      [WARN]  Tags '....' and 'sv..' overlap: [4294967206+2795916107] vs [4227858431+4294967295]
      [WARN]  Tags '....' and 'svcn' overlap: [4294967206+2795916107] vs [255+4294967295]
      [WARN]  Tags '....' and '....' overlap: [4294967206+2795916107] vs [4294967295+4294967295]
      [WARN]  Tags '....' and '....' overlap: [4294967206+2795916107] vs [2998055602+2998055602]
      [WARN]  Tags '....' and '....' overlap: [4294967206+2795916107] vs [2795939583+4294944422]
      [WARN]  Tags '....' and '.KKK' overlap: [4294967206+2795916107] vs [3511372611+1263225675]
      [WARN]  Tags '....' and 'KKKK' overlap: [4294967206+2795916107] vs [1263225675+4226678783]
      [WARN]  Tags '....' and '.Lr.' overlap: [4294967206+2795916107] vs [4294967115+1263212588]
      [WARN]  Tags 'KKKC' and 'r.L.' overlap: [1263225675+1263225675] vs [1350848577+1537671167]
      [WARN]  Tags 'KKKC' and 'izk3' overlap: [1263225675+1263225675] vs [1129075314+4294967294]
      [WARN]  Tags 'KKKC' and '....' overlap: [1263225675+1263225675] vs [0+1633907568]
      [WARN]  Tags 'KKKC' and '....' overlap: [1263225675+1263225675] vs [1668706313+10943487]
      [WARN]  Tags 'KKKC' and '..Lr' overlap: [1263225675+1263225675] vs [1920103026+1920103026]
      [WARN]  Tags 'KKKC' and 'rrrr' overlap: [1263225675+1263225675] vs [1920102987+1263225675]
      [WARN]  Tags 'KKKC' and '..Lr' overlap: [1263225675+1263225675] vs [1920103026+1920103026]
      [WARN]  Tags 'KKKC' and 'rrrr' overlap: [1263225675+1263225675] vs [1920103019+1263225675]
      [WARN]  Tags 'KKKC' and 'svcn' overlap: [1263225675+1263225675] vs [255+4294967295]
      [WARN]  Tags 'KKKC' and '....' overlap: [1263225675+1263225675] vs [1263225624+738197504]
      [WARN]  Tags 'KKKK' and '....' overlap: [4227858431+4294967295] vs [4286644224+35]
      [WARN]  Tags 'KKKK' and 'izk3' overlap: [4227858431+4294967295] vs [1129075314+4294967294]
      [WARN]  Tags 'KKKK' and '....' overlap: [4227858431+4294967295] vs [4294967295+4294967295]
      [WARN]  Tags 'KKKK' and 'p...' overlap: [4227858431+4294967295] vs [4227858178+255]
      [WARN]  Tags 'KKKK' and 'svcn' overlap: [4227858431+4294967295] vs [255+4294967295]
      [WARN]  Tags 'KKKK' and '....' overlap: [4227858431+4294967295] vs [4294967295+4294967295]
      [WARN]  Tags 'KKKK' and '....' overlap: [4227858431+4294967295] vs [2998055602+2998055602]
      [WARN]  Tags 'KKKK' and '....' overlap: [4227858431+4294967295] vs [2795939583+4294944422]
      [WARN]  Tags 'KKKK' and '.KKK' overlap: [4227858431+4294967295] vs [3511372611+1263225675]
      [WARN]  Tags 'KKKK' and 'KKKK' overlap: [4227858431+4294967295] vs [1263225675+4226678783]
      [WARN]  Tags 'KKKK' and '.Lr.' overlap: [4227858431+4294967295] vs [4294967115+1263212588]
      [WARN]  Tags 'KKK.' and '....' overlap: [738197504+5010034] vs [0+1633907568]
      [WARN]  Tags 'KKK.' and 'PPLd' overlap: [738197504+5010034] vs [132+843141200]
      [WARN]  Tags 'KKK.' and 'svcn' overlap: [738197504+5010034] vs [255+4294967295]
      [WARN]  Tags 'r.L.' and 'izk3' overlap: [1350848577+1537671167] vs [1129075314+4294967294]
      [WARN]  Tags 'r.L.' and '....' overlap: [1350848577+1537671167] vs [0+1633907568]
      [WARN]  Tags 'r.L.' and '....' overlap: [1350848577+1537671167] vs [1668706313+10943487]
      [WARN]  Tags 'r.L.' and '..Lr' overlap: [1350848577+1537671167] vs [1920103026+1920103026]
      [WARN]  Tags 'r.L.' and 'rrrr' overlap: [1350848577+1537671167] vs [1920102987+1263225675]
      [WARN]  Tags 'r.L.' and '..Lr' overlap: [1350848577+1537671167] vs [1920103026+1920103026]
      [WARN]  Tags 'r.L.' and 'rrrr' overlap: [1350848577+1537671167] vs [1920103019+1263225675]
      [WARN]  Tags 'r.L.' and 'svcn' overlap: [1350848577+1537671167] vs [255+4294967295]
      [WARN]  Tags 'r.L.' and '....' overlap: [1350848577+1537671167] vs [2795939583+4294944422]
      [WARN]  Tags 'r.L.' and 'KKKK' overlap: [1350848577+1537671167] vs [1263225675+4226678783]
      [WARN]  Tags 'r.L.' and '....' overlap: [1350848577+1537671167] vs [1263225624+738197504]
      [WARN]  Tags '....' and 'izk3' overlap: [4286644224+35] vs [1129075314+4294967294]
      [WARN]  Tags '....' and 'sv..' overlap: [4286644224+35] vs [4227858431+4294967295]
      [WARN]  Tags '....' and 'svcn' overlap: [4286644224+35] vs [255+4294967295]
      [WARN]  Tags '....' and '....' overlap: [4286644224+35] vs [2998055602+2998055602]
      [WARN]  Tags '....' and '....' overlap: [4286644224+35] vs [2795939583+4294944422]
      [WARN]  Tags '....' and '.KKK' overlap: [4286644224+35] vs [3511372611+1263225675]
      [WARN]  Tags '....' and 'KKKK' overlap: [4286644224+35] vs [1263225675+4226678783]
      [WARN]  Tags 'izk3' and '....' overlap: [1129075314+4294967294] vs [4294967295+4294967295]
      [WARN]  Tags 'izk3' and '....' overlap: [1129075314+4294967294] vs [0+1633907568]
      [WARN]  Tags 'izk3' and '....' overlap: [1129075314+4294967294] vs [1668706313+10943487]
      [WARN]  Tags 'izk3' and 'p...' overlap: [1129075314+4294967294] vs [4227858178+255]
      [WARN]  Tags 'izk3' and '..Lr' overlap: [1129075314+4294967294] vs [1920103026+1920103026]
      [WARN]  Tags 'izk3' and 'rrrr' overlap: [1129075314+4294967294] vs [1920102987+1263225675]
      [WARN]  Tags 'izk3' and 'sv..' overlap: [1129075314+4294967294] vs [4227858431+4294967295]
      [WARN]  Tags 'izk3' and '..Lr' overlap: [1129075314+4294967294] vs [1920103026+1920103026]
      [WARN]  Tags 'izk3' and 'rrrr' overlap: [1129075314+4294967294] vs [1920103019+1263225675]
      [WARN]  Tags 'izk3' and 'svcn' overlap: [1129075314+4294967294] vs [255+4294967295]
      [WARN]  Tags 'izk3' and '....' overlap: [1129075314+4294967294] vs [4294967295+4294967295]
      [WARN]  Tags 'izk3' and '....' overlap: [1129075314+4294967294] vs [2998055602+2998055602]
      [WARN]  Tags 'izk3' and '....' overlap: [1129075314+4294967294] vs [2795939583+4294944422]
      [WARN]  Tags 'izk3' and '.KKK' overlap: [1129075314+4294967294] vs [3511372611+1263225675]
      [WARN]  Tags 'izk3' and 'KKKK' overlap: [1129075314+4294967294] vs [1263225675+4226678783]
      [WARN]  Tags 'izk3' and '....' overlap: [1129075314+4294967294] vs [1263225624+738197504]
      [WARN]  Tags 'izk3' and '.Lr.' overlap: [1129075314+4294967294] vs [4294967115+1263212588]
      [WARN]  Tags '....' and 'sv..' overlap: [4294967295+4294967295] vs [4227858431+4294967295]
      [WARN]  Tags '....' and 'svcn' overlap: [4294967295+4294967295] vs [255+4294967295]
      [WARN]  Tags '....' and '....' overlap: [4294967295+4294967295] vs [2998055602+2998055602]
      [WARN]  Tags '....' and '....' overlap: [4294967295+4294967295] vs [2795939583+4294944422]
      [WARN]  Tags '....' and '.KKK' overlap: [4294967295+4294967295] vs [3511372611+1263225675]
      [WARN]  Tags '....' and 'KKKK' overlap: [4294967295+4294967295] vs [1263225675+4226678783]
      [WARN]  Tags '....' and '.Lr.' overlap: [4294967295+4294967295] vs [4294967115+1263212588]
      [WARN]  Tags '....' and 'PPLd' overlap: [0+1633907568] vs [132+843141200]
      [WARN]  Tags '....' and 'Ld..' overlap: [0+1633907568] vs [16777216+50]
      [WARN]  Tags '....' and 'svcn' overlap: [0+1633907568] vs [255+4294967295]
      [WARN]  Tags '....' and 'KKKK' overlap: [0+1633907568] vs [1263225675+4226678783]
      [WARN]  Tags '....' and '....' overlap: [0+1633907568] vs [1263225624+738197504]
      [WARN]  Tags '....' and 'svcn' overlap: [1668706313+10943487] vs [255+4294967295]
      [WARN]  Tags '....' and 'KKKK' overlap: [1668706313+10943487] vs [1263225675+4226678783]
      [WARN]  Tags '....' and '....' overlap: [1668706313+10943487] vs [1263225624+738197504]
      [WARN]  Tags 'PPLd' and 'Ld..' overlap: [132+843141200] vs [16777216+50]
      [WARN]  Tags 'PPLd' and 'Rrs.' overlap: [132+843141200] vs [0+6382451]
      [WARN]  Tags 'PPLd' and 'svcn' overlap: [132+843141200] vs [255+4294967295]
      [WARN]  Tags 'Ld..' and 'svcn' overlap: [16777216+50] vs [255+4294967295]
      [WARN]  Tags 'Rrs.' and 'svcn' overlap: [0+6382451] vs [255+4294967295]
      [WARN]  Tags 'p...' and 'sv..' overlap: [4227858178+255] vs [4227858431+4294967295]
      [WARN]  Tags 'p...' and 'svcn' overlap: [4227858178+255] vs [255+4294967295]
      [WARN]  Tags 'p...' and '....' overlap: [4227858178+255] vs [2998055602+2998055602]
      [WARN]  Tags 'p...' and '....' overlap: [4227858178+255] vs [2795939583+4294944422]
      [WARN]  Tags 'p...' and '.KKK' overlap: [4227858178+255] vs [3511372611+1263225675]
      [WARN]  Tags 'p...' and 'KKKK' overlap: [4227858178+255] vs [1263225675+4226678783]
      [WARN]  Tags '..Lr' and 'rrrr' overlap: [1920103026+1920103026] vs [1920102987+1263225675]
      [WARN]  Tags '..Lr' and 'rrrr' overlap: [1920103026+1920103026] vs [1920103019+1263225675]
      [WARN]  Tags '..Lr' and 'svcn' overlap: [1920103026+1920103026] vs [255+4294967295]
      [WARN]  Tags '..Lr' and '....' overlap: [1920103026+1920103026] vs [2998055602+2998055602]
      [WARN]  Tags '..Lr' and '....' overlap: [1920103026+1920103026] vs [2795939583+4294944422]
      [WARN]  Tags '..Lr' and '.KKK' overlap: [1920103026+1920103026] vs [3511372611+1263225675]
      [WARN]  Tags '..Lr' and 'KKKK' overlap: [1920103026+1920103026] vs [1263225675+4226678783]
      [WARN]  Tags '..Lr' and '....' overlap: [1920103026+1920103026] vs [1263225624+738197504]
      [WARN]  Tags 'rrrr' and '..Lr' overlap: [1920102987+1263225675] vs [1920103026+1920103026]
      [WARN]  Tags 'rrrr' and 'rrrr' overlap: [1920102987+1263225675] vs [1920103019+1263225675]
      [WARN]  Tags 'rrrr' and 'svcn' overlap: [1920102987+1263225675] vs [255+4294967295]
      [WARN]  Tags 'rrrr' and '....' overlap: [1920102987+1263225675] vs [2998055602+2998055602]
      [WARN]  Tags 'rrrr' and '....' overlap: [1920102987+1263225675] vs [2795939583+4294944422]
      [WARN]  Tags 'rrrr' and 'KKKK' overlap: [1920102987+1263225675] vs [1263225675+4226678783]
      [WARN]  Tags 'rrrr' and '....' overlap: [1920102987+1263225675] vs [1263225624+738197504]
      [WARN]  Tags 'sv..' and 'svcn' overlap: [4227858431+4294967295] vs [255+4294967295]
      [WARN]  Tags 'sv..' and '....' overlap: [4227858431+4294967295] vs [4294967295+4294967295]
      [WARN]  Tags 'sv..' and '....' overlap: [4227858431+4294967295] vs [2998055602+2998055602]
      [WARN]  Tags 'sv..' and '....' overlap: [4227858431+4294967295] vs [2795939583+4294944422]
      [WARN]  Tags 'sv..' and '.KKK' overlap: [4227858431+4294967295] vs [3511372611+1263225675]
      [WARN]  Tags 'sv..' and 'KKKK' overlap: [4227858431+4294967295] vs [1263225675+4226678783]
      [WARN]  Tags 'sv..' and '.Lr.' overlap: [4227858431+4294967295] vs [4294967115+1263212588]
      [WARN]  Tags '..Lr' and 'rrrr' overlap: [1920103026+1920103026] vs [1920103019+1263225675]
      [WARN]  Tags '..Lr' and 'svcn' overlap: [1920103026+1920103026] vs [255+4294967295]
      [WARN]  Tags '..Lr' and '....' overlap: [1920103026+1920103026] vs [2998055602+2998055602]
      [WARN]  Tags '..Lr' and '....' overlap: [1920103026+1920103026] vs [2795939583+4294944422]
      [WARN]  Tags '..Lr' and '.KKK' overlap: [1920103026+1920103026] vs [3511372611+1263225675]
      [WARN]  Tags '..Lr' and 'KKKK' overlap: [1920103026+1920103026] vs [1263225675+4226678783]
      [WARN]  Tags '..Lr' and '....' overlap: [1920103026+1920103026] vs [1263225624+738197504]
      [WARN]  Tags 'rrrr' and 'svcn' overlap: [1920103019+1263225675] vs [255+4294967295]
      [WARN]  Tags 'rrrr' and '....' overlap: [1920103019+1263225675] vs [2998055602+2998055602]
      [WARN]  Tags 'rrrr' and '....' overlap: [1920103019+1263225675] vs [2795939583+4294944422]
      [WARN]  Tags 'rrrr' and 'KKKK' overlap: [1920103019+1263225675] vs [1263225675+4226678783]
      [WARN]  Tags 'rrrr' and '....' overlap: [1920103019+1263225675] vs [1263225624+738197504]
      [WARN]  Tags 'svcn' and '....' overlap: [255+4294967295] vs [4294967295+4294967295]
      [WARN]  Tags 'svcn' and '....' overlap: [255+4294967295] vs [2998055602+2998055602]
      [WARN]  Tags 'svcn' and '....' overlap: [255+4294967295] vs [2795939583+4294944422]
      [WARN]  Tags 'svcn' and '.KKK' overlap: [255+4294967295] vs [3511372611+1263225675]
      [WARN]  Tags 'svcn' and 'KKKK' overlap: [255+4294967295] vs [1263225675+4226678783]
      [WARN]  Tags 'svcn' and '....' overlap: [255+4294967295] vs [1263225624+738197504]
      [WARN]  Tags 'svcn' and '.Lr.' overlap: [255+4294967295] vs [4294967115+1263212588]
      [WARN]  Tags '....' and '....' overlap: [4294967295+4294967295] vs [2998055602+2998055602]
      [WARN]  Tags '....' and '....' overlap: [4294967295+4294967295] vs [2795939583+4294944422]
      [WARN]  Tags '....' and '.KKK' overlap: [4294967295+4294967295] vs [3511372611+1263225675]
      [WARN]  Tags '....' and 'KKKK' overlap: [4294967295+4294967295] vs [1263225675+4226678783]
      [WARN]  Tags '....' and '.Lr.' overlap: [4294967295+4294967295] vs [4294967115+1263212588]
      [WARN]  Tags '....' and '....' overlap: [2998055602+2998055602] vs [2795939583+4294944422]
      [WARN]  Tags '....' and '.KKK' overlap: [2998055602+2998055602] vs [3511372611+1263225675]
      [WARN]  Tags '....' and 'KKKK' overlap: [2998055602+2998055602] vs [1263225675+4226678783]
      [WARN]  Tags '....' and '.Lr.' overlap: [2998055602+2998055602] vs [4294967115+1263212588]
      [WARN]  Tags '....' and '.KKK' overlap: [2795939583+4294944422] vs [3511372611+1263225675]
      [WARN]  Tags '....' and 'KKKK' overlap: [2795939583+4294944422] vs [1263225675+4226678783]
      [WARN]  Tags '....' and '.Lr.' overlap: [2795939583+4294944422] vs [4294967115+1263212588]
      [WARN]  Tags '.KKK' and 'KKKK' overlap: [3511372611+1263225675] vs [1263225675+4226678783]
      [WARN]  Tags '.KKK' and '.Lr.' overlap: [3511372611+1263225675] vs [4294967115+1263212588]
      [WARN]  Tags 'KKKK' and '....' overlap: [1263225675+4226678783] vs [1263225624+738197504]
      [WARN]  Tags 'KKKK' and '.Lr.' overlap: [1263225675+4226678783] vs [4294967115+1263212588]
      Risk: 414 tag overlap(s) â€” possible data corruption or exploitation

=======================================================================
HEURISTIC SUMMARY
=======================================================================

[WARN]  12 HEURISTIC WARNING(S) DETECTED

  This profile exhibits patterns associated with:
  - Malformed/corrupted data
  - Resource exhaustion attempts
  - Enum confusion vulnerabilities
  - Parser exploitation attempts

  Recommendations:
  â€¢ Validate profile with official ICC tools
  â€¢ Use -n (ninja mode) for detailed byte-level analysis
  â€¢ Do NOT use in production color workflows
  â€¢ Consider as potential security test case


=======================================================================
PHASE 2: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/ub-nan-outside-range-icDtoF-float-IccUtil_cpp-Line560.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/ub-nan-outside-range-icDtoF-float-IccUtil_cpp-Line560.icc
Result: NOT round-trip capable

=======================================================================
PHASE 3: SIGNATURE ANALYSIS
=======================================================================

[ERROR] Profile failed to load - skipping signature analysis
        Use -n (ninja mode) for raw analysis of malformed profiles

=======================================================================
PHASE 4: PROFILE STRUCTURE DUMP
=======================================================================

[ERROR] Profile failed to load for structure dump

=======================================================================
COMPREHENSIVE ANALYSIS SUMMARY
=======================================================================

File: /home/runner/work/research/research/test-profiles/ub-nan-outside-range-icDtoF-float-IccUtil_cpp-Line560.icc
Total Issues Detected: 13

[WARN] ANALYSIS COMPLETE - 13 issue(s) detected
  Review detailed output above for security concerns.
```

---

## Command 2: Ninja Full Dump (`-nf`)

**Exit Code: 0**

```

=========================================================================
|                   *** REDUCED SECURITY MODE ***                       |
|                                                                       |
|             Copyright (c) 2021-2026 David H Hoyt LLC                 |
|                          hoyt.net                                     |
=========================================================================

WARNING: Analyzing malformed/corrupted ICC profile without validation.
         This mode bypasses all safety checks and may expose parser bugs.
         Use only for security research, fuzzing, or forensic analysis.

File: /home/runner/work/research/research/test-profiles/ub-nan-outside-range-icDtoF-float-IccUtil_cpp-Line560.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 2405 bytes (0x965)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: FF 7B BE AF AF B3 64 00  01 00 84 32 41 50 50 4C  |.{....d....2APPL|
0x0010: 47 52 41 59 67 70 63 65  38 43 4C 52 72 73 00 00  |GRAYgpce8CLRrs..|
0x0020: 00 00 00 00 61 63 73 70  09 00 A6 FB FF 45 FF FF  |....acsp.....E..|
0x0030: FF FF FF A6 A6 A6 A6 A6  A6 A6 A6 00 84 00 74 00  |..............t.|
0x0040: 00 41 50 00 50 4C 00 64  00 10 00 00 00 00 00 64  |.AP.PL.d.......d|
0x0050: 00 03 00 23 69 6E 6B 38  43 4C 52 72 73 23 00 FD  |...#ink8CLRrs#..|
0x0060: FE FE FE 61 63 76 70 09  00 A6 FB FF 50 50 4C 64  |...acvp.....PPLd|
0x0070: 00 00 00 84 32 41 50 50  4C 64 00 1B 01 00 00 00  |....2APPLd......|

Header Fields (RAW - no validation):
  Profile Size:    0xFF7BBEAF (4286299823 bytes) MISMATCH
  CMM:             0xAFB36400  '..d.'
  Version:         0x01008432
  Device Class:    0x4150504C  'APPL'
  Color Space:     0x47524159  'GRAY'
  PCS:             0x67706365  'gpce'

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 50 (0x00000032)

Tag Table Raw Data:
0x0080: 00 00 00 32 52 72 73 00  00 33 41 50 50 4C 64 00  |...2Rrs..3APPLd.|
0x0090: 03 00 23 69 6E 6B 38 43  4C 52 72 73 23 00 FD FE  |..#ink8CLRrs#...|
0x00A0: FE FE 61 63 76 70 09 00  A6 FB FF 50 50 4C 64 00  |..acvp.....PPLd.|
0x00B0: 00 00 84 32 41 50 50 4C  64 00 1B 01 00 00 00 00  |...2APPLd.......|
0x00C0: 00 00 32 52 72 73 00 00  00 00 00 00 61 63 73 70  |..2Rrs......acsp|
0x00D0: 09 00 A6 FB FF FF FF FF  FF FF FF FF FF 4C 72 72  |.............Lrr|
0x00E0: 72 72 72 72 72 72 72 72  72 72 72 72 72 72 4B 4B  |rrrrrrrrrrrrrrKK|
0x00F0: 4B 4B 4B 4B 4B 18 00 00  00 00 00 00 00 00 00 73  |KKKKK..........s|
0x0100: 76 63 6E E6 00 00 00 7A  00 25 61 63 00 00 00 00  |vcn....z.%ac....|
0x0110: A6 A6 A6 A6 74 00 00 39  A6 A6 A6 A6 8A A6 00 39  |....t..9.......9|
0x0120: A6 E6 A6 A6 A6 A6 A6 5A  59 B4 AA 4B 4B 4B 4B 4B  |.......ZY..KKKKK|
0x0130: 4B 4B 4B 4B 4B 4B 4B 4B  4B 43 4C 52 4B 4B 4B 4B  |KKKKKKKKKCLRKKKK|
0x0140: 4B 4B 4B 4B 4B 4B 4B 4B  4B 18 00 00 00 00 00 00  |KKKKKKKKK.......|
0x0150: 00 00 00 00 00 A6 00 00  00 FF FF A6 A6 A6 A6 A6  |................|
0x0160: FF FF FF A6 A6 A6 4B 4B  4B 4B 4B 43 4B 4B 4B 4B  |......KKKKKCKKKK|
0x0170: 4B 4B 4B 4B 4B 4B 4B 4B  FB FF FF FF FF FF FF FF  |KKKKKKKK........|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0x52727300   'Rrs '        0x00334150   0x504C6400   '----'        OOB offset
1    0x03002369   '   '        0x6E6B3843   0x4C527273   '----'        OOB offset
2    0x2300FDFE   '#   '        0xFEFE6163   0x76700900   '----'        OOB offset
3    0xA6FBFF50   '¦ûÿP'        0x504C6400   0x00008432   '----'        OOB offset
4    0x4150504C   'APPL'        0x64001B01   0x00000000   '----'        OOB offset
5    0x00003252   '    '        0x72730000   0x00000000   '----'        OOB offset
6    0x61637370   'acsp'        0x0900A6FB   0xFFFFFFFF   '----'        OOB offset
7    0xFFFFFFFF   'ÿÿÿÿ'        0xFF4C7272   0x72727272   '----'        OOB offset
8    0x72727272   'rrrr'        0x72727272   0x72724B4B   '----'        OOB offset
9    0x4B4B4B4B   'KKKK'        0x4B180000   0x00000000   '----'        OOB offset
10   0x00000073   '    '        0x76636EE6   0x0000007A   '----'        OOB offset
11   0x00256163   '    '        0x00000000   0xA6A6A6A6   'ÿ{¾¯'        OOB size
12   0x74000039   't   '        0xA6A6A6A6   0x8AA60039   '----'        OOB offset
13   0xA6E6A6A6   '¦æ¦¦'        0xA6A6A65A   0x59B4AA4B   '----'        OOB offset
14   0x4B4B4B4B   'KKKK'        0x4B4B4B4B   0x4B4B4B4B   '----'        OOB offset
15   0x4B434C52   'KCLR'        0x4B4B4B4B   0x4B4B4B4B   '----'        OOB offset
16   0x4B4B4B4B   'KKKK'        0x4B180000   0x00000000   '----'        OOB offset
17   0x00000000   '    '        0x00A60000   0x00FFFFA6   '----'        OOB offset
18   0xA6A6A6A6   '¦¦¦¦'        0xFFFFFFA6   0xA6A64B4B   '----'        OOB offset
19   0x4B4B4B43   'KKKC'        0x4B4B4B4B   0x4B4B4B4B   '----'        OOB offset
20   0x4B4B4B4B   'KKKK'        0xFBFFFFFF   0xFFFFFFFF   '----'        OOB offset
21   0x4B4B4B18   'KKK'        0x2C000000   0x004C7272   '----'        OOB offset
22   0x72FB4CFF   'rûLÿ'        0x50845041   0x5BA6FFFF   '----'        OOB offset
23   0xFFFFFFFF   'ÿÿÿÿ'        0xFF810000   0x00000023   '----'        OOB offset
24   0x697A6B33   'izk3'        0x434C5272   0xFFFFFFFE   '----'        OOB offset
25   0xFFFFFFFF   'ÿÿÿÿ'        0xFFFFFFFF   0xFFFFFFFF   '----'        OOB offset
26   0xFFFFFFFF   'ÿÿÿÿ'        0x00000000   0x61637370   'ÿ{¾¯'        OOB size
27   0x0900A6FB   '	   '        0x63767009   0x00A6FBFF   '----'        OOB offset
28   0x50504C64   'PPLd'        0x00000084   0x32415050   'Rrs '        OOB size
29   0x4C64001B   'Ld  '        0x01000000   0x00000032   '----'        OOB offset
30   0x52727300   'Rrs '        0x00000000   0x00616373   'ÿ{¾¯'        OOB size
31   0x700900A6   'p	  '        0xFBFFFF02   0x000000FF   '----'        OOB offset
32   0xFFFF4C72   'ÿÿLr'        0x72727272   0x72727272   '----'        OOB offset
33   0x72727272   'rrrr'        0x7272724B   0x4B4B4B4B   '----'        OOB offset
34   0x4B4B1800   'KK '        0x00000000   0x00000000   'ÿ{¾¯'        overlap
35   0x737600A6   'sv  '        0xFBFFFFFF   0xFFFFFFFF   '----'        OOB offset
36   0xFFFF4C72   'ÿÿLr'        0x72727272   0x72727272   '----'        OOB offset
37   0x72727272   'rrrr'        0x7272726B   0x4B4B4B4B   '----'        OOB offset
38   0x4B4B1800   'KK '        0x00000000   0x00000000   'ÿ{¾¯'        overlap
39   0x7376636E   'svcn'        0x000000FF   0xFFFFFFFF   'svcn'        OOB size
40   0xFFFFFFFF   'ÿÿÿÿ'        0xFFFFFFFF   0xFFFFFFFF   '----'        OOB offset
41   0xFFFFB2B2   'ÿÿ²²'        0xB2B2B2B2   0xB2B2B2B2   '----'        OOB offset
42   0xB2630000   '²c  '        0x00000000   0x00000000   'ÿ{¾¯'        overlap
43   0x00000000   '    '        0x00000000   0x00000000   'ÿ{¾¯'        overlap
44   0xA6A60000   '¦¦  '        0x00000000   0x00000000   'ÿ{¾¯'        overlap
45   0x00000000   '    '        0xA6A6A6FF   0xFFFFA6A6   '----'        OOB offset
46   0xA64B4B4B   '¦KKK'        0xD14B4B43   0x4B4B4B4B   '----'        OOB offset
47   0x4B4B4B4B   'KKKK'        0x4B4B4B4B   0xFBEDFFFF   '----'        OOB offset
48   0xFFFFFFFF   'ÿÿÿÿ'        0x4B4B4B18   0x2C000000   '----'        OOB offset
49   0x004C72FF   '    '        0xFFFFFF4B   0x4B4B182C   '----'        OOB offset

[WARN] SIZE INFLATION: Header claims 4286299823 bytes, file is 2405 bytes (1782245x)
   Risk: OOM via tag-internal allocations based on inflated header size

[WARN] TAG OVERLAP: 414 overlapping tag pair(s) detected
   Risk: Data corruption, possible exploit crafting

=== FULL FILE HEX DUMP (all 2405 bytes) ===
0x0000: FF 7B BE AF AF B3 64 00  01 00 84 32 41 50 50 4C  |.{....d....2APPL|
0x0010: 47 52 41 59 67 70 63 65  38 43 4C 52 72 73 00 00  |GRAYgpce8CLRrs..|
0x0020: 00 00 00 00 61 63 73 70  09 00 A6 FB FF 45 FF FF  |....acsp.....E..|
0x0030: FF FF FF A6 A6 A6 A6 A6  A6 A6 A6 00 84 00 74 00  |..............t.|
0x0040: 00 41 50 00 50 4C 00 64  00 10 00 00 00 00 00 64  |.AP.PL.d.......d|
0x0050: 00 03 00 23 69 6E 6B 38  43 4C 52 72 73 23 00 FD  |...#ink8CLRrs#..|
0x0060: FE FE FE 61 63 76 70 09  00 A6 FB FF 50 50 4C 64  |...acvp.....PPLd|
0x0070: 00 00 00 84 32 41 50 50  4C 64 00 1B 01 00 00 00  |....2APPLd......|
0x0080: 00 00 00 32 52 72 73 00  00 33 41 50 50 4C 64 00  |...2Rrs..3APPLd.|
0x0090: 03 00 23 69 6E 6B 38 43  4C 52 72 73 23 00 FD FE  |..#ink8CLRrs#...|
0x00A0: FE FE 61 63 76 70 09 00  A6 FB FF 50 50 4C 64 00  |..acvp.....PPLd.|
0x00B0: 00 00 84 32 41 50 50 4C  64 00 1B 01 00 00 00 00  |...2APPLd.......|
0x00C0: 00 00 32 52 72 73 00 00  00 00 00 00 61 63 73 70  |..2Rrs......acsp|
0x00D0: 09 00 A6 FB FF FF FF FF  FF FF FF FF FF 4C 72 72  |.............Lrr|
0x00E0: 72 72 72 72 72 72 72 72  72 72 72 72 72 72 4B 4B  |rrrrrrrrrrrrrrKK|
0x00F0: 4B 4B 4B 4B 4B 18 00 00  00 00 00 00 00 00 00 73  |KKKKK..........s|
0x0100: 76 63 6E E6 00 00 00 7A  00 25 61 63 00 00 00 00  |vcn....z.%ac....|
0x0110: A6 A6 A6 A6 74 00 00 39  A6 A6 A6 A6 8A A6 00 39  |....t..9.......9|
0x0120: A6 E6 A6 A6 A6 A6 A6 5A  59 B4 AA 4B 4B 4B 4B 4B  |.......ZY..KKKKK|
0x0130: 4B 4B 4B 4B 4B 4B 4B 4B  4B 43 4C 52 4B 4B 4B 4B  |KKKKKKKKKCLRKKKK|
0x0140: 4B 4B 4B 4B 4B 4B 4B 4B  4B 18 00 00 00 00 00 00  |KKKKKKKKK.......|
0x0150: 00 00 00 00 00 A6 00 00  00 FF FF A6 A6 A6 A6 A6  |................|
0x0160: FF FF FF A6 A6 A6 4B 4B  4B 4B 4B 43 4B 4B 4B 4B  |......KKKKKCKKKK|
0x0170: 4B 4B 4B 4B 4B 4B 4B 4B  FB FF FF FF FF FF FF FF  |KKKKKKKK........|
0x0180: 4B 4B 4B 18 2C 00 00 00  00 4C 72 72 72 FB 4C FF  |KKK.,....Lrrr.L.|
0x0190: 50 84 50 41 5B A6 FF FF  FF FF FF FF FF 81 00 00  |P.PA[...........|
0x01A0: 00 00 00 23 69 7A 6B 33  43 4C 52 72 FF FF FF FE  |...#izk3CLRr....|
0x01B0: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x01C0: 00 00 00 00 61 63 73 70  09 00 A6 FB 63 76 70 09  |....acsp....cvp.|
0x01D0: 00 A6 FB FF 50 50 4C 64  00 00 00 84 32 41 50 50  |....PPLd....2APP|
0x01E0: 4C 64 00 1B 01 00 00 00  00 00 00 32 52 72 73 00  |Ld.........2Rrs.|
0x01F0: 00 00 00 00 00 61 63 73  70 09 00 A6 FB FF FF 02  |.....acsp.......|
0x0200: 00 00 00 FF FF FF 4C 72  72 72 72 72 72 72 72 72  |......Lrrrrrrrrr|
0x0210: 72 72 72 72 72 72 72 4B  4B 4B 4B 4B 4B 4B 18 00  |rrrrrrrKKKKKKK..|
0x0220: 00 00 00 00 00 00 00 00  73 76 00 A6 FB FF FF FF  |........sv......|
0x0230: FF FF FF FF FF FF 4C 72  72 72 72 72 72 72 72 72  |......Lrrrrrrrrr|
0x0240: 72 72 72 72 72 72 72 6B  4B 4B 4B 4B 4B 4B 18 00  |rrrrrrrkKKKKKK..|
0x0250: 00 00 00 00 00 00 00 00  73 76 63 6E 00 00 00 FF  |........svcn....|
0x0260: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x0270: FF FF B2 B2 B2 B2 B2 B2  B2 B2 B2 B2 B2 63 00 00  |.............c..|
0x0280: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0290: 00 00 00 00 A6 A6 00 00  00 00 00 00 00 00 00 00  |................|
0x02A0: 00 00 00 00 A6 A6 A6 FF  FF FF A6 A6 A6 4B 4B 4B  |.............KKK|
0x02B0: D1 4B 4B 43 4B 4B 4B 4B  4B 4B 4B 4B 4B 4B 4B 4B  |.KKCKKKKKKKKKKKK|
0x02C0: FB ED FF FF FF FF FF FF  4B 4B 4B 18 2C 00 00 00  |........KKK.,...|
0x02D0: 00 4C 72 FF FF FF FF 4B  4B 4B 18 2C 00 00 00 00  |.Lr....KKK.,....|
0x02E0: 4C 72 72 72 FB 4C FF 50  84 50 41 5B F3 01 00 00  |Lrrr.L.P.PA[....|
0x02F0: 00 00 00 00 A6 FF FF FF  FF 00 00 00 00 00 00 00  |................|
0x0300: 00 FF FF FF FF A6 A6 A6  A6 A6 A6 A6 A6 3F A6 74  |.............?.t|
0x0310: 00 FF FF FF 00 00 00 01  41 32 42 31 50 84 52 41  |........A2B1P.RA|
0x0320: F4 64 00 00 01 20 00 84  32 6C 76 00 69 00 00 00  |.d... ..2lv.i...|
0x0330: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x0340: 01 00 00 00 F8 4D 43 48  6E 6D 63 6C 37 00 00 00  |.....MCHnmcl7...|
0x0350: 00 00 00 00 2D 00 00 00  00 00 31 09 30 33 00 00  |....-.....1.03..|
0x0360: 00 64 00 00 00 00 72 72  72 72 72 72 84 72 72 72  |.d....rrrrrr.rrr|
0x0370: 72 72 72 72 4B 4B 4B 4B  6B 4B 4B 18 00 00 00 00  |rrrrKKKKkKK.....|
0x0380: 00 00 00 00 00 00 05 5A  F9 E6 00 B2 B2 B2 B2 B2  |.......Z........|
0x0390: B2 B2 B2 B2 B2 B2 B2 B2  B2 B2 B2 B2 B2 B2 B2 B2  |................|
0x03A0: B2 B2 B2 B2 B2 B2 B2 B2  B2 B2 B2 B2 B2 B2 B2 B2  |................|
0x03B0: B2 B2 B2 B2 B2 B2 B2 B2  B2 A1 A1 A1 A1 A1 A1 A1  |................|
0x03C0: A1 A1 A1 A1 A1 A1 A1 A1  A1 A1 A1 A1 A1 A1 A1 A1  |................|
0x03D0: A1 A1 A1 A1 A1 A1 A1 A1  A1 A1 A1 A1 A1 A1 52 72  |..............Rr|
0x03E0: 73 23 00 FD FE FE FE 61  63 76 70 09 00 A6 FB 00  |s#.....acvp.....|
0x03F0: A6 06 19 00 00 00 7A 00  25 61 63 80 70 00 00 00  |......z.%ac.p...|
0x0400: 41 50 50 4C 64 00 03 00  23 69 6E 6B 39 43 4C 52  |APPLd...#ink9CLR|
0x0410: 72 73 00 00 00 00 FF FE  FF FF FF FF FF FF FF FF  |rs..............|
0x0420: FF FF FF FF FF FF FF FF  00 39 A6 A6 A6 A6 8A A6  |.........9......|
0x0430: 00 39 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |.9..............|
0x0440: FF FF FF FF A6 A6 A6 A6  A6 A6 A6 A6 3F A6 74 00  |............?.t.|
0x0450: FF FF FF 00 00 00 01 41  32 42 31 50 84 52 41 F4  |.......A2B1P.RA.|
0x0460: 64 00 00 00 84 32 6C 76  69 73 47 52 41 59 23 69  |d....2lvisGRAY#i|
0x0470: 6E 6B 37 43 4C 52 72 73  00 00 00 00 00 00 61 63  |nk7CLRrs......ac|
0x0480: 73 70 7A 00 A6 FB FF FF  FF FF FF FF FF A6 A6 33  |spz............3|
0x0490: 32 2E A6 A6 A6 A6 14 00  68 01 00 00 00 00 00 00  |2.......h.......|
0x04A0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x04B0: 00 00 00 00 00 00 01 00  00 00 F8 4D 43 48 6E 6D  |...........MCHnm|
0x04C0: 63 6C 37 00 00 00 00 00  00 00 2D 00 00 00 00 00  |cl7.......-.....|
0x04D0: 00 00 00 00 00 61 63 73  70 7A 00 A6 FB FF FF FF  |.....acspz......|
0x04E0: FF FF FF FF A6 A6 33 32  2E A6 A6 A6 A6 14 00 68  |......32.......h|
0x04F0: 01 00 40 32 42 31 00 00  00 61 63 73 70 09 00 A6  |..@2B1...acsp...|
0x0500: FB FF FF FF FF FF A6 A6  A6 A6 A6 A6 74 00 00 39  |............t..9|
0x0510: A6 A6 A6 A6 8A A6 00 39  A6 E6 A6 A6 A6 A6 A6 A6  |.......9........|
0x0520: A6 4B 4B 6B 39 43 4C 52  72 73 00 00 00 00 00 00  |.KKk9CLRrs......|
0x0530: 61 63 73 70 09 00 A6 FB  FF FF FF 00 00 00 84 41  |acsp...........A|
0x0540: 50 50 4C 64 00 00 00 84  32 41 50 50 4C 64 00 03  |PPLd....2APPLd..|
0x0550: 00 23 69 6E 6B 38 43 4C  52 72 83 00 00 00 00 00  |.#ink8CLRr......|
0x0560: 00 61 63 73 70 09 00 A6  FB FF 50 50 4C 64 00 00  |.acsp.....PPLd..|
0x0570: 00 84 32 41 50 50 4C 64  00 1B 01 00 00 00 00 00  |..2APPLd........|
0x0580: 00 4C 52 72 73 00 00 00  00 FF 7B BE AF AF B3 64  |.LRrs.....{....d|
0x0590: 00 01 00 84 32 41 50 50  4C 47 52 41 59 67 70 63  |....2APPLGRAYgpc|
0x05A0: 65 38 43 4C 52 72 73 00  00 00 00 00 00 61 63 73  |e8CLRrs......acs|
0x05B0: 70 09 00 A6 FB FF 45 FF  FF FF FF FF A6 A6 A6 A6  |p.....E.........|
0x05C0: A6 A6 A6 A6 74 00 00 00  00 84 41 50 50 4C 64 00  |....t.....APPLd.|
0x05D0: 00 00 84 33 41 50 50 4C  64 00 03 00 23 69 6E 6B  |...3APPLd...#ink|
0x05E0: 38 43 4C 52 72 73 23 00  FD FE FE FE 61 63 76 70  |8CLRrs#.....acvp|
0x05F0: 09 00 A6 FB FF 50 50 4C  64 00 00 00 84 32 41 50  |.....PPLd....2AP|
0x0600: 50 4C 64 00 1B 01 00 00  00 00 00 00 32 52 72 73  |PLd.........2Rrs|
0x0610: 00 00 00 00 00 00 61 63  73 70 09 00 A6 FB FF FF  |......acsp......|
0x0620: FF FF FF FF FF FF FF 4C  72 72 72 72 72 72 72 72  |.......Lrrrrrrrr|
0x0630: 72 72 72 72 72 72 72 72  4B 4B 4B 4B 4B 4B 4B 18  |rrrrrrrrKKKKKKK.|
0x0640: 00 00 00 00 00 00 00 00  00 73 76 00 A6 FB FF FF  |.........sv.....|
0x0650: FF FF FF FF FF FF FF 4C  72 72 72 72 72 72 72 72  |.......Lrrrrrrrr|
0x0660: 72 72 72 72 72 72 72 72  4B 4B 4B 4B 4B 4B 4B 18  |rrrrrrrrKKKKKKK.|
0x0670: 00 00 00 00 00 00 00 00  00 73 76 63 6E 00 00 00  |.........svcn...|
0x0680: A6 00 00 00 FF FF A6 A6  A6 A6 A6 FF FF FF A6 A6  |................|
0x0690: A6 4B 4B 4B 4B 4B 43 4B  4B 4B 4B 4B 4B 4B 4B 4B  |.KKKKKCKKKKKKKKK|
0x06A0: 4B 4B 4B FB FF FF FF FF  FF FF FF 4B 4B 4B 18 2C  |KKK........KKK.,|
0x06B0: 00 00 00 00 4C 72 72 72  FB 4C FF 50 84 50 41 5B  |....Lrrr.L.P.PA[|
0x06C0: A6 FF FF FF FF FF FF FF  81 00 00 00 00 00 23 69  |..............#i|
0x06D0: 7A 6B 33 43 4C 52 72 FF  FF FF FE FF FF FF FF FF  |zk3CLRr.........|
0x06E0: FF FF FF FF FF FF FF FF  FF FF FF 00 39 A6 A6 A6  |............9...|
0x06F0: A6 8A A6 00 39 00 FF FF  FF FF 4B 4B 4B 18 2C 00  |....9.....KKK.,.|
0x0700: 00 00 00 4C 72 72 72 FB  4C FF 28 50 84 50 41 5B  |...Lrrr.L.(P.PA[|
0x0710: A6 FF FF FF FF FF FF FF  81 00 00 00 00 00 23 69  |..............#i|
0x0720: 7A 6B 33 43 4C 52 72 FF  FF FF FE FF FF FF FF FF  |zk3CLRr.........|
0x0730: FF FF FF FF FF FF FF FF  FF FF FF 00 39 A6 A6 A6  |............9...|
0x0740: A6 8A A6 00 39 00 00 00  00 00 00 00 00 00 00 00  |....9...........|
0x0750: 00 00 00 FF FF FF FF A6  A6 A6 A6 A6 A6 A6 A6 3F  |...............?|
0x0760: A6 74 00 FF FF FF 00 00  00 01 41 32 42 31 50 84  |.t........A2B1P.|
0x0770: 52 41 F4 64 00 00 00 84  32 6C 76 69 73 47 52 41  |RA.d....2lvisGRA|
0x0780: 59 23 69 6E 6B 37 43 4C  52 72 73 00 00 00 00 00  |Y#ink7CLRrs.....|
0x0790: 00 61 63 73 70 7A 00 A6  FB FF FF FF FF FF FF FF  |.acspz..........|
0x07A0: A6 A6 33 32 2E A6 A6 A6  A6 14 00 68 01 00 00 00  |..32.......h....|
0x07B0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x07C0: 00 00 00 00 00 00 00 00  00 01 00 00 00 F8 4D 43  |..............MC|
0x07D0: 48 6E 6D 63 6C 37 00 00  00 00 00 00 00 2D 00 00  |Hnmcl7.......-..|
0x07E0: 00 00 00 31 09 30 33 00  00 00 64 00 00 00 00 72  |...1.03...d....r|
0x07F0: 72 72 6A 54 52 43 72 72  72 72 72 72 4B 4B 4B 4B  |rrjTRCrrrrrrKKKK|
0x0800: 63 6E E6 00 00 00 7A 00  25 61 63 00 00 00 00 A6  |cn....z.%ac.....|
0x0810: A6 A6 A6 74 00 00 39 A6  A6 A6 A6 8A 01 00 00 00  |...t..9.........|
0x0820: 00 00 00 82 39 A6 00 A6  E6 A6 A6 A6 A6 A6 5A E6  |....9.........Z.|
0x0830: 02 00 00 00 00 00 00 59  B4 AA 4B 4B 4B 4B 4B 4B  |.......Y..KKKKKK|
0x0840: 4B 4B 4B 4B 4B 4B 4B 4B  43 4C 52 4B 4B 4B 4B 4B  |KKKKKKKKCLRKKKKK|
0x0850: 4B 4B 4B 4B 4B 4B 4B 4B  18 00 00 00 00 00 00 00  |KKKKKKKK........|
0x0860: 00 00 00 00 A6 00 FF FF  FF FF FF 00 39 A6 A6 A6  |............9...|
0x0870: A6 8A A6 00 39 00 00 00  00 00 00 00 00 00 00 00  |....9...........|
0x0880: 00 00 00 FF FF FF FF A6  A6 A6 A6 A6 A6 A6 A6 3F  |...............?|
0x0890: A6 74 00 FF FF FF 00 00  00 01 41 32 42 31 50 84  |.t........A2B1P.|
0x08A0: 52 41 F4 64 00 00 00 84  32 6C 59 52 73 47 69 41  |RA.d....2lYRsGiA|
0x08B0: 76 23 69 6E 6B 37 43 4C  52 72 73 00 00 00 00 00  |v#ink7CLRrs.....|
0x08C0: 00 61 63 73 70 7A 00 A6  FB FF FF FF FF FF FF FF  |.acspz..........|
0x08D0: A6 A6 33 32 2E A6 A6 A6  00 68 01 00 00 00 00 00  |..32.....h......|
0x08E0: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0x08F0: 00 00 00 00 00 00 00 01  00 00 00 F8 4D 43 48 6E  |............MCHn|
0x0900: 6D 63 6C 37 00 00 00 00  00 00 00 2D 00 00 00 00  |mcl7.......-....|
0x0910: 00 31 09 30 33 00 00 00  64 00 00 00 00 72 72 72  |.1.03...d....rrr|
0x0920: 72 72 72 72 72 72 72 72  72 72 4B 4B 4B 4B 4B 4B  |rrrrrrrrrrKKKKKK|
0x0930: 4B 18 00 00 00 00 00 00  00 00 00 00 05 5A F9 E6  |K............Z..|
0x0940: 00 00 00 7A 00 25 61 63  00 00 00 00 00 00 00 00  |...z.%ac........|
0x0950: 00 A6 06 19 00 00 00 7A  00 25 61 63 80 70 00 00  |.......z.%ac.p..|
0x0960: 00 03 00 03 00                                    |.....|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/runner/work/research/research/test-profiles/ub-nan-outside-range-icDtoF-float-IccUtil_cpp-Line560.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/runner/work/research/research/test-profiles/ub-nan-outside-range-icDtoF-float-IccUtil_cpp-Line560.icc
```
