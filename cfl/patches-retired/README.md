# CFL Patches -- Retired Archive

Last Updated: 2026-05-18

This directory is the archive for CFL patch files that should not be applied by
the active `cfl/build.sh` patch stack.

Retirement reasons include:

- Accepted upstream in `iccDEV`
- Superseded by newer upstream hardening
- Superseded by LibFuzzer runtime limits
- Preserved from older recovery snapshots for reference

The archive currently contains 119 patch files. Some patch numbers appear more
than once with different names because historical recovery snapshots are kept
verbatim.

## 2026-05-18 Current-Master Drift Cleanup

These patches were moved out of `../patches/` after review against
`InternationalColorConsortium/iccDEV:master` at commit `793bce9`:

`006`, `007`, `008`, `022`, `023`, `028`, `029`, `040`, `042`, `046`, `055`,
`057`, `059`, `062`, `063`, `072`, `075`, `079`, `080`.

The active patch stack is documented in `../patches/README.md`.
