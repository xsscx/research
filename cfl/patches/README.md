# CFL Patches -- Active Local Build Fixes

Last Updated: 2026-07-24

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
./cfl/build.sh --refresh-iccdev --patch-file 001-json-config-parser-no-sanitize.patch
./cfl/build.sh --refresh-iccdev --patch-file 002-jpegdump-segment-bounds.patch
```

Patch application failures are fatal in patched mode.

## Active Patch Files

| Patch | Area |
|-------|------|
| `001-json-config-parser-no-sanitize.patch` | Reject structurally unbalanced JSON config inputs before dependency parsing and keep parser inputs from turning dependency-internal integer sanitizer reports into CFL crashes. |
| `002-jpegdump-segment-bounds.patch` | Use subtraction-based JPEG segment bounds checks and one-past-safe payload pointers before reading marker segment data. |

## Drift Review

The 2026-07-24 review retired the previous 32-patch active stack to
`../retired-patches/` with `retired-20260724-` filename prefixes. Current
upstream and the AFL/CFL triage focus no longer need those patches active for
default patched CFL builds.
