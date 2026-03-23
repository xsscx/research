# iccAnalyzer-lite / IccTest Upstream UB Hardening Policy

## Summary

`iccanalyzer-lite` (V1) and `icctest` (V2) must remain hardened against
user-controlled input even when the reachable undefined behavior lives in the
vendored upstream `iccDEV` library.

The analyzer/runtime policy is:

- keep `iccDEV` **unpatched** for V1/V2 parity work
- keep `cfl/patches` **CFL-only**
- harden V1/V2 with analyzer-owned guards, preflight scans, safe helpers, and
  symbol overrides where needed
- preserve the corresponding H/CF reporting so the triggering byte pattern is
  still surfaced to the user

## Why

There are two separate requirements:

1. **Runtime defense**
   The analyzers must not let hostile input reach known-unsafe upstream paths if
   they can reasonably defend the call site themselves.

2. **Security reporting**
   The same hostile input still needs to trip the relevant H-series heuristic or
   CF-series conformance finding so the defect class is visible in reports and
   parity runs.

Hardening without reporting hides the issue. Reporting without hardening leaves
the analyzer fragile. Both are required.

## Current Reference Cases

The current analyzer-owned override set lives in:

- `iccanalyzer-lite/IccDevSafeOverrides.cpp`

That file shadows selected upstream `IccUtil.cpp` helpers from the static
`iccDEV` libraries without modifying the vendored source tree:

- `icF16toF`
- `icGetSig`
- `icGetSigStr`
- `icGetColorSig`
- `icGetColorSigStr`

These address the two known recurring UBSan classes:

- half-float exponent rebias / unsigned-wrap (`H174` family)
- signature-formatting left-shift overflow (`H173` family)

## Maintenance Rule

When a new user-controlled upstream UB path is found:

1. fingerprint the raw trigger pattern into the appropriate `H-*` heuristic
   first
2. decide whether a preflight skip is sufficient or whether analyzer-owned safe
   code is required
3. if the unsafe path is in a shared upstream helper used broadly across V1/V2,
   prefer an analyzer-owned wrapper or symbol override rather than a growing set
   of narrow call-site skips
4. do **not** move the analyzer runtime onto `cfl/patches`
5. keep V1/V2 parity checks green after the hardening change

## Linking Rule

Because V1 and V2 link upstream `iccDEV` static libraries, analyzer-owned symbol
overrides are acceptable when they are intentionally used to harden runtime
behavior against malformed input.

If a future override is added:

- wire it into both V1 and V2 build graphs
- ensure the V2 library build actually pulls the object into downstream
  executables
- keep duplicate-definition handling explicit in the linker configuration

## Reporting Rule

Do not retire the reporting heuristic just because the runtime path became safe.

The correct outcome is:

- the analyzer survives the input
- the report still identifies the byte pattern and defect class
- parity tooling still compares the resulting `H-*` / `CF-*` outputs

## Workflow Lesson

The `iccDEV Tool Tests` workflow previously reported:

- `Built 0 tool binaries`

That was a workflow counting bug, not a build failure. Tool binaries cannot be
counted by assuming the executable name equals the directory name. The correct
workflow check is to count actual executable files under `Tools/*/*`.

This matters because several downstream artifact and smoke steps depend on the
same tool-location assumptions.
