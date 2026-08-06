# CFL Patches -- Active Local Build Fixes

Last Updated: 2026-08-06

This directory contains the optional CFL patch stack for the nested
`InternationalColorConsortium/iccDEV` checkout used by `cfl/build.sh`.

This file is the source of truth for active patch inventory. Higher-level docs
should link here instead of duplicating the full patch table.

## Build Modes

```bash
# Build current upstream master without CFL patches. This is the CFL default.
./cfl/build.sh --refresh-iccdev

# Apply all active CFL patches and build all fuzzers.
./cfl/build.sh --patches --refresh-iccdev

# Apply one or more selected patches for isolated testing.
./cfl/build.sh --refresh-iccdev --patch-file 002-jpegdump-segment-bounds.patch
./cfl/build.sh --refresh-iccdev --patch-file 004-applyprofiles-tiff-sample-count-bounds.patch
./cfl/build.sh --refresh-iccdev --patch-file 005-applyprofiles-float-encoding-usage.patch
```

Patch application failures are warnings in patched mode. Non-applicable patches
are skipped so stale local patch stacks do not block AFL/CFL builds.

Before committing patch edits, run:

```bash
.github/scripts/check-afl-cfl-patches.sh
```

The checker uses fresh temporary clones of `afl/iccDEV` and `cfl/iccDEV` for
`git apply --check`, catching malformed patch hunks and patch drift without
depending on the current dirty nested checkouts.

## Active Patch Files

| Patch | Area |
|-------|------|
| `002-jpegdump-segment-bounds.patch` | Use subtraction-based JPEG segment bounds checks and one-past-safe payload pointers before reading marker segment data. |
| `004-applyprofiles-tiff-sample-count-bounds.patch` | Reject malformed TIFF sample counts before `iccApplyProfiles` strip de-planarization can copy past the strip buffer. |
| `005-applyprofiles-float-encoding-usage.patch` | Correct the `iccApplyProfiles` usage text so positional encoding `3` is documented as `icEncodeFloat`; the parser treats unsupported `4` as the default 8-bit encoding. |

## Drift Review

The 2026-07-24 review retired the previous 32-patch active stack to
`../retired-patches/` with `retired-20260724-` filename prefixes. Current
upstream and the AFL/CFL triage focus no longer need those patches active for
default patched CFL builds.

The 2026-07-25 review refreshed the remaining active patches as context diffs
validated by `.github/scripts/check-afl-cfl-patches.sh`. The prior
`005-applytolink-bpc-degenerate-lrange.patch` is no longer active because the
nested `ci-afl-cfl` baseline already rejects degenerate BPC destination L*
ranges.

The 2026-08-06 review retired
`005-fromxml-formula-functiontype-bounds.patch` because upstream commit
`1065ec1` includes the broader strict-width XML attribute parsing fix. Shared
patches `002` and `004` still apply cleanly to upstream master `a7abbee`.
