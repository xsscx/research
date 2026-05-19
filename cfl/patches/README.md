# CFL Patches -- Active Security Fixes

Last Updated: 2026-05-19

This directory contains the active CFL patch stack for current
`InternationalColorConsortium/iccDEV:master`.

This file is the source of truth for active patch inventory. Higher-level docs
should link here instead of duplicating the full patch table.

Current upstream baseline:

- Branch: `origin/master`
- Commit: `6e991ae`
- Active patches: 25

## Build Modes

```bash
# Apply all active patches and build all 13 fuzzers.
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
| `022-xyzmatrix-sum-overflow.patch` | LUT XYZ matrix validation sum overflow |
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
| `067-icIsS15Fixed16NumberNear-float-overflow-ubsan.patch` | S15Fixed16 float overflow guard |
| `068-MpeCurveSet-operator-eq-self-assignment.patch` | Curve set self-assignment |
| `069-operator-eq-self-assignment-guards.patch` | Additional self-assignment guards |
| `070-missing-member-copies-operator-eq-copyctor.patch` | Missing member copies |
| `084-tagcurve-setgamma-range-ubsan.patch` | JSON gamma curve range validation |
| `085-json-numeric-narrowing-ubsan.patch` | JSON numeric narrowing validation |

## Drift Review

The 2026-05-18 review moved these previously active patches to
`../patches-retired/` because current upstream master already contains the
fix, contains a stronger related hardening change, or made the patch obsolete:

`006`, `007`, `008`, `023`, `028`, `029`, `040`, `042`, `046`, `055`,
`057`, `059`, `062`, `063`, `072`, `075`, `079`, `080`.

The `017`, `053`, and `054` patches were refreshed against current source and
verified for both individual dry-run application and ordered-stack application.

Patch `022` was restored to the active stack after
`iccDumpProfile -v 100 ... ALL` reproduced a signed integer overflow in
`CIccTagLut8::Validate()`.
