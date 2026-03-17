# MultiInk NCLR Profile Security Analysis

## Profile Set

15 Named Color (NCLR) ICC v4.2 output profiles (class `prtr`, PCS=Lab, creator `ccox`/Macintosh).
Device channels span 1CLR through FCLR (1-15 inks). Total: 20.2 MB.

## Tool Compatibility Matrix

| nCLR | ColorSpace | Size | iccDumpProfile | iccToXml | iccRoundTrip (unpatched) |
|------|-----------|------|----------------|----------|--------------------------|
| 1 | 1CLR | 22 KB | OK | OK | **SEGV** (CWE-476) |
| 2 | 2CLR | 35 KB | OK | OK | **SEGV** (CWE-476) |
| 3 | 3CLR | 131 KB | OK | OK | OK |
| 4 | 4CLR | 2.8 MB | OK | OK | TIMEOUT (CWE-400) |
| 5 | 5CLR | 3.2 MB | OK | OK | TIMEOUT |
| 6 | 6CLR | 3.1 MB | OK | OK | TIMEOUT |
| 7 | 7CLR | 2.6 MB | OK | OK | TIMEOUT |
| 8 | 8CLR | 1.3 MB | OK | OK | TIMEOUT |
| 9 | 9CLR | 887 KB | OK | OK | TIMEOUT |
| 10 | ACLR | 3.3 MB | OK | OK | TIMEOUT |
| 11 | BCLR | 652 KB | OK | OK | TIMEOUT |
| 12 | CCLR | 1.7 MB | OK | OK | TIMEOUT |
| 13 | DCLR | 165 KB | OK | OK | OK |
| 14 | ECLR | 199 KB | OK | OK | OK |
| 15 | FCLR | 258 KB | OK | OK | OK |

## Findings

### 1. SEGV in CIccCLUT::InterpND — Null CIccApplyCLUT (CWE-476)

**Severity**: CRITICAL
**Affected profiles**: 1CLR, 2CLR (MCH1, MCH2)
**Reproducibility**: 3/3 with upstream `iccRoundTrip`

**Root cause**: `CIccXformNDLut::Apply()` at IccCmm.cpp:6570 dispatches CLUT
interpolation via `switch(nInput)` with cases for 5 and 6 only. Inputs 1-4 fall
through to `default:` which calls `InterpND(pApply)`, but `GetNewApply()` at
L6515 only allocates `pApply` when `m_nNumInput > 6`. Result: null dereference
at IccTagLut.cpp:3181 (`pApply->m_df`).

**Fix**: CFL-044 — Add cases 1-4 dispatching to Interp1d/2d/3d/4d (both switch blocks).
Also a **performance fix**: Interp4d is O(16n) vs InterpND which is O(2^d * n).

**Note**: CFL-025 already guards InterpND entry against null pApply, but CFL-044
is the proper fix (dispatch to the correct interpolation function).

### 2. CWE-400 Timeout in EvaluateProfile (4-12 channel profiles)

**Severity**: HIGH (DoS)
**Affected profiles**: 4CLR through CCLR (MCH4-MCH12)

`EvaluateProfile()` in IccEval.cpp iterates 33^ndim grid points. For 4-12 channels:
- 33^4 = 1.2M iterations (borderline)
- 33^6 = 1.3B iterations
- 33^10 = 1.5×10^15 iterations (heat death)

Profiles with 13-15 channels complete because LUT grid sizes shrink (21^3 input side
remains constant, but BToA CLUT uses smaller grids for high channel counts).

iccanalyzer-lite H137 correctly detects this pattern for 6+ channel profiles.

### 3. H3 Unknown ColorSpace Signatures (9CLR-FCLR)

**Severity**: LOW (informational)
**Affected profiles**: 9CLR through FCLR (9-15 channels)

ICC.1-2022-05 §7.2.6 defines colorSpace signatures up to 8CLR (0x38434C52).
Channels 9-15 use ACLR-FCLR which are valid in ICC.2-2023 (iccMAX) but flagged
by H3 as unknown in the v4 context. These are well-formed NCLR output profiles
that simply use extended channel counts.

### 4. iccanalyzer-lite H119 SIGSEGV (FIXED)

**Severity**: CRITICAL (was)
**Status**: Fixed in commit 8aa995e1

`RunHeuristic_H119_RoundTripDeltaE()` called `CIccCLUT::Interp3d()` without
prior `Begin()` initialization. CLUT metadata (m_MaxGridPoint, m_nNodes, m_nPower)
contained ASAN redzone fill bytes (0xBE). Fixed by adding `clutB->Begin()` call
and dimension-aware interpolation dispatch.

Post-fix: all 15 profiles produce valid round-trip ΔE measurements (avg 0.43-0.82,
max 1.17-1.36).

## Profile Structure Analysis

All 15 profiles share consistent structure:
- **Tags**: desc, cprt, wtpt, clrt, A2B0, B2A0, gamt, A2B1/A2B2, B2A1/B2A2
- **Tag sharing**: A2B1/A2B2 share offset with A2B0; B2A1/B2A2 share offset with B2A0
- **AToB LUTs**: 3-channel input side (Lab PCS), grid 31×31×31
- **BToA LUTs**: N-channel output side, grid varies by ink count
- **Colorant table**: Maps ink names to Lab coordinates

## Patch Status

| Patch | Bug | Status |
|-------|-----|--------|
| CFL-025 | InterpND null guard (defense-in-depth) | Applied (existing) |
| CFL-044 | NDLut Apply missing Interp1d/2d/3d/4d dispatch | **NEW** — fixes root cause |
| H119 fix | iccanalyzer-lite Begin() before interp | Applied (commit 8aa995e1) |

## Recommendations

1. **File upstream issue** for CFL-044 (InterpND null CIccApplyCLUT) with Turquoise_output.icc PoC
2. **CFL fuzzer seeding**: 15 NCLR profiles already seeded into 6 fuzzer corpora
3. **Test coverage**: Add 1CLR and 2CLR profiles to JSON test suites (iccRoundTrip regression)
4. **H137 upstream**: Consider proposing an EvaluateProfile grid cap to prevent CWE-400 timeouts
