# CFL Patches -- Active Security Fixes

Last Updated: 2026-07-05

This directory contains the active CFL patch stack for current
`InternationalColorConsortium/iccDEV:master`.

This file is the source of truth for active patch inventory. Higher-level docs
should link here instead of duplicating the full patch table.

Current upstream baseline:

- Branch: `origin/master`
- Commit: `4155c6f`
- Active patches: 32

## Build Modes

```bash
# Apply all active patches and build all fuzzers.
./cfl/build.sh --patches --refresh-iccdev

# Build current upstream master without CFL patches.
./cfl/build.sh --no-patches --refresh-iccdev

# Apply one or more selected patches for on-the-fly testing.
./cfl/build.sh --refresh-iccdev --patch-file 053-formulacurve-describe-format-specifiers.patch
./cfl/build.sh --refresh-iccdev --patch-file 053-formulacurve-describe-format-specifiers.patch --patch-file 054-parametriccurve-describe-format-specifiers.patch
```

Patch application failures are fatal in patched mode.

## Active Patch Files

| Patch | Area |
|-------|------|
| `005-calculatorfunc-read-enum-ubsan.patch` | Calculator op enum read |
| `009-envvar-exec-enum-ubsan.patch` | Env var op enum execution |
| `014-sequenceneedtempreset-recursion-depth.patch` | Calculator recursion depth |
| `017-envvar-getEnvSig-parse-enum-ubsan.patch` | Env var signature parsing |
| `019-pcc-getReflectanceObserver-null-guard.patch` | PCC observer null guard |
| `021-singlesampled-curve-oom-size-validation.patch` | Sampled curve allocation size |
| `025-clut-interpnd-null-apply-guard.patch` | CLUT interpolation null guard |
| `041-fromit8-lab-xyz-val4-oob.patch` | IT8 LAB/XYZ indexing |
| `043-tool-tojson-is-object-vs-is-array.patch` | JSON type checks |
| `044-ndlut-apply-missing-interp-dispatch.patch` | NDLut interpolation dispatch |
| `050-formulacurve-describe-param-bounds.patch` | Formula curve Describe bounds |
| `051-parametriccurve-describe-param-bounds.patch` | Parametric curve Describe bounds |
| `052-fromit8-wrong-index-variable.patch` | IT8 index variable |
| `053-formulacurve-describe-format-specifiers.patch` | Formula curve format specifiers |
| `054-parametriccurve-describe-format-specifiers.patch` | Parametric curve format specifiers |
| `056-spectral-describe-null-pointer-guards.patch` | Spectral Describe null guards |
| `064-segmented-curve-subtraction-underflow-ubsan.patch` | Segmented curve underflow guard |
| `068-MpeCurveSet-operator-eq-self-assignment.patch` | Curve set self-assignment |
| `069-operator-eq-self-assignment-guards.patch` | Additional self-assignment guards |
| `070-missing-member-copies-operator-eq-copyctor.patch` | Missing member copies |
| `072-json-curve-setsize-guards.patch` | JSON curve allocation guards |
| `073-cam-divzero-guards.patch` | CAM division-by-zero guards |
| `074-calculator-describe-window-underflow.patch` | Calculator report window underflow |
| `075-xml-curve-setsize-guards.patch` | XML curve allocation guards |
| `077-cmm-dest-space-sample-guard.patch` | CMM destination sample consistency |
| `079-ndlut-channel-count-validation.patch` | NDLUT channel/color-space consistency |
| `086-sparsematrix-array-oom-budget.patch` | Sparse matrix array allocation budget |
| `088-applyprofiles-row-buffer-slack.patch` | Row Apply buffer guard slack |
| `089-spectral-data-info-null-profile.patch` | Spectral data validation null profile guard |
| `097-applyprofiles-observer-range.patch` | ApplyProfiles spectral observer allocation range |
| `098-cmm-xform-sample-link-guard.patch` | CMM adjacent xform sample-count validation |
| `099-fromcube-checked-cube-parsing.patch` | FromCube checked numeric parsing and exact 3D table length |

## Drift Review

The 2026-05-18 review moved these previously active patches to
`../patches-retired/` because current upstream master already contains the
fix, contains a stronger related hardening change, or made the patch obsolete:

`006`, `007`, `008`, `023`, `028`, `029`, `040`, `042`, `046`, `055`,
`057`, `059`, `062`, `063`, `072`, `075`, `079`, `080`.

The `017`, `053`, and `054` patches were refreshed against current source and
verified for both individual dry-run application and ordered-stack application.

The 2026-05-21 review moved `022`, `067`, `084`, and `085` to
`../patches-retired/` because current upstream master contains equivalent or
stronger fixes. Patches `047` and `069` were refreshed against the current
source after nearby upstream context drift.

The 2026-05-24 review moved `078` to `../patches-retired/` because upstream
commit `6889cb6` contains the search-cost weight validation and regression
coverage.

The 2026-05-24 OOM review added `086` to strengthen the upstream sparse matrix
array cap for long-running CFL sessions.

The 2026-05-24 crash review added `087`, `088`, and `089` for cenc AddXform
borrowed-IO ownership, row Apply guard slack, and SpectralDataInfo validation
without profile context.

The 2026-05-24 SpecSep OOM review added `090` to reject compressed TIFF output
bit depths unsupported by libtiff predictor setup and to stop on write failure.

The 2026-05-25 FromCube review added `091` to avoid signed EOF truncation in
line reads, guard empty-line indexing, and reject incomplete 3D LUT rows.

The 2026-05-26 CAM and TiffDump review added `092` to require fixed 3-channel
CAM MPE inputs/outputs before converter allocation and `093` to escape
attacker-controlled profile descriptions and input/output paths in console
output and to avoid double-writing extracted ICC profiles.

The 2026-05-26 FromCube write review added `094` to avoid signed-byte Unicode
conversion UB for first and continuation UTF-8 bytes and to reject non-monotonic
profile writer positions before offset/size backfill arithmetic.

The 2026-05-26 XML spectral review added `095` to parse SpectralDataInfo
wavelength bounds as floats before half-float conversion.

The 2026-05-26 CMM intent review added `096` to reject invalid rendering
intents before deriving transform tag signatures.

## Session Handoff -- 2026-07-04 WSL-2 Baseline

Baseline was reset on the GCC 15.2 / clang 21 WSL-2 VM to iccDEV commit
`4155c6f`. Patches `009` and `014` were refreshed against the current
calculator source. Patches `047`, `071`, `076`, `087`, `090`, `091`, `092`,
`093`, `094`, `095`, and `096` were moved to `../patches-retired/` because
the current upstream source already contains equivalent or stronger hardening,
or the original context is superseded by upstream restructuring.

Default patched build status for this baseline:

```bash
cd cfl && ./build.sh --patches
```

The active stack should apply cleanly from a clean nested `cfl/iccDEV`
checkout at `4155c6f`.

The 2026-07-04 ApplyProfiles review added `097` to allocate reflectance observer
matrices with the illuminant range passed to `getEmissiveObserver()`, covering
the AFL `applyprofiles-fast` ReflectanceCLUT and ReflectanceObserver HBO PoCs.

The 2026-07-05 ApplyProfiles review added `098` to reject CMM xform chains whose
adjacent output/input sample counts disagree after PCS conversion insertion,
covering the AFL `applyprofiles-hybrid-embedded` matrix Apply HBO PoC.

The 2026-07-05 FromCube QA review added `099` to reject malformed `.cube`
numeric fields, non-finite LUT values, incomplete tables, and trailing 3D LUT
rows before `iccFromCube` serializes a DeviceLink profile.
