# iccAnalyzer-lite / IccTest CFL Patch Coverage Matrix

## Purpose

This matrix is the normalized source of truth for reviewing `iccanalyzer-lite`
(V1) and `icctest` (V2) against the active `cfl/patches` inventory while
preserving the analyzer policy:

- V1/V2 link **unpatched** upstream `iccDEV`
- `cfl/patches` remain **CFL-only**
- analyzer hardening must come from analyzer-owned preflight scans, safe helpers,
  symbol overrides, quarantine logic, and H/CF reporting

## Scope

- Inventory source: active `.patch` files in `cfl/patches/`
- Current active patch files on disk: **44**
- Matrix file: [ICCANALYZER_CFL_PATCH_COVERAGE_MATRIX.csv](ICCANALYZER_CFL_PATCH_COVERAGE_MATRIX.csv)

Current reachability split from the CSV:

- `profile-runtime`: 32
- `cmm-runtime`: 9
- `xml-runtime`: 5
- `tool-only`: 14

Current priority split from the CSV:

- `P0`: 17
- `P1`: 10
- `P2`: 10
- `P3`: 9
- `OOS`: 14

This matrix separates:

- `profile-runtime`: reachable from ICC profile content during analyzer runtime
- `cmm-runtime`: reachable when analyzers exercise CMM / round-trip / transform
  paths
- `xml-runtime`: reachable through XML serialization / XML helper paths used by
  the analyzers
- `tool-only`: CLI/config/tool bugs outside ICC profile analyzer runtime

## Status Fields

- `covered`: analyzer-owned defense or reporting was verified directly in source
- `partial`: some coverage exists, but it is incomplete, narrow, or only present
  in one lane (defense vs reporting)
- `todo`: no sufficient current analyzer mapping was identified
- `oos`: out of scope for analyzer runtime parity

`review_state` indicates how strong the current row is:

- `verified`: traced directly to current V1/V2 source
- `inferred`: classified from patch target + nearby analyzer coverage, but still
  needs a deeper one-to-one confirmation pass

## Current Findings

### Strongly covered in both V1 and V2

- helper/UB hardening with analyzer-owned overrides:
  - CFL-058 `CIccEmbedIO`
  - CFL-060 `icGetSigStr`
  - CFL-061 `icF16toF`
  - CFL-062 `icGetSig`
  - CFL-066 `icGetHeaderFlagsName`
- explicit raw/reporting families in both engines:
  - CFL-004 tone-map parameter safety
  - CFL-002 / CFL-007 allocation-overflow families via `H168`
  - CFL-025 null-CLUT Apply path reporting via `H167`
  - CFL-023 sampled-curve NaN/Inf cast family
  - CFL-030 fixed-number `GetValues` stack-buffer-overflow family

### Highest-priority analyzer gaps

- **V2 TODO breadth remains the main limiter**:
  - the remaining TODO surface is now outside the H157/H159/H161 ownership family
    that has been ported; the next limiter is the unported exploit-gap/data-validation
    tail rather than the CodeQL ownership checks
- **Defense exists but reporting parity still lags**:
  - CFL-063 broader offset+size overflow family
  - CFL-067 fixed-point illuminant overflow reporting on V2

### Recently closed fixture-specific gap

- The named spectral PoC
  `heap-buffer-overflow-CIccMpeSpectralMatrix-Describe-IccMpeSpectral_cpp-Line352.icc`
  is now intentionally treated as:
  - **V1**: safe structural gap-out before `H98`
  - **V2**: raw `H98` coverage with spectral preflight quarantine and findings for
    the CFL-006 / CFL-056 family
  - parity: normalized as `coverageImprovement`, not a regression

### Correctly out of analyzer runtime scope

- tool/config patches such as CFL-031, CFL-032, CFL-033, CFL-036, CFL-038,
  CFL-040 through CFL-043, CFL-052, CFL-055, CFL-057, and CFL-075

## Recommended Execution Order

1. Burn down the `P0` rows in the CSV where V2 is `todo` or `partial`.
2. Expand narrow preflight defenses only for runtime-reachable classes that can
   still hit upstream UB before analyzer-owned reporting runs.
3. After each port/hardening change, update the corresponding matrix row and
   keep V1/V2 parity green.

## Related

- [ICCANALYZER_UPSTREAM_UB_HARDENING.md](ICCANALYZER_UPSTREAM_UB_HARDENING.md)
- [../icc-format/ICC-Binary-Format-Reference.md](../icc-format/ICC-Binary-Format-Reference.md)
