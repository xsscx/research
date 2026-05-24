# CFL Patches - Retired Archive

Last updated: 2026-05-24

This directory archives CFL patch files that are not part of the active
`cfl/build.sh --patches` stack. The active stack is documented in
`../patches/README.md`.

Patch files stay here for audit history when they are:

- accepted upstream in `iccDEV`
- superseded by newer upstream hardening
- replaced by LibFuzzer runtime limits
- preserved from older recovery snapshots

Some patch numbers appear more than once because the archive keeps historical
recovery names verbatim.

## Drift Cleanup Note

The 2026-05-18 drift review moved obsolete or superseded patches from
`../patches/` into this archive after comparing against current iccDEV master.
Patch `022-xyzmatrix-sum-overflow.patch` was later restored to the active stack
after the signed-overflow validation path reproduced again.

The 2026-05-21 drift review moved `022`, `067`, `084`, and `085` out of the
active stack because current iccDEV master contains equivalent or stronger
fixes. Patches `047` and `069` remained active after context refreshes.

The 2026-05-24 drift review moved `078` out of the active stack because
current iccDEV master commit `6889cb6` contains the search-cost weight
validation and regression coverage.

Do not use this README as an active patch inventory. Use
`../patches/README.md` for current A/B builds.
