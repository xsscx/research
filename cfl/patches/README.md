# CFL Patches -- Active Security Fixes

Last Updated: 2026-05-24

This directory contains the active CFL patch stack for current
`InternationalColorConsortium/iccDEV:master`.

This file is the source of truth for active patch inventory. Higher-level docs
should link here instead of duplicating the full patch table.

Current upstream baseline:

- Branch: `origin/master`
- Commit: `6889cb6`
- Active patches: 29

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
| `047-pushXYZNormalize-null-pcc-guard.patch` | PCC normalization null guard |
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
| `071-json-language-code-unsigned-shift.patch` | JSON language/country code shifts |
| `072-json-curve-setsize-guards.patch` | JSON curve allocation guards |
| `073-cam-divzero-guards.patch` | CAM division-by-zero guards |
| `074-calculator-describe-window-underflow.patch` | Calculator report window underflow |
| `075-xml-curve-setsize-guards.patch` | XML curve allocation guards |
| `076-cmm-pcs-scale-divzero.patch` | PCS scale denominator guards |
| `077-cmm-dest-space-sample-guard.patch` | CMM destination sample consistency |
| `079-ndlut-channel-count-validation.patch` | NDLUT channel/color-space consistency |

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
