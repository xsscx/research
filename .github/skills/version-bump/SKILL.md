---
name: version-bump
description: >
  Synchronize version numbers after an iccDEV upstream version bump and verify
  current PAWG, MCP, CFL, and AFL consumers without relying on stale file counts.
allowed-tools:
  - bash
  - read
  - write
  - grep
  - glob
  - shell(git:*)
---

# Version Bump Workflow

## Overview

When iccDEV upstream bumps its version, update all version locations in
both the upstream repo and the research repo. Version format: MAJOR.MINOR.MICRO.PATCH.

## Upstream Locations

Start with the four version components in `Build/Cmake/CMakeLists.txt`. Search
the current checkout for the complete old version and update active package
manifests such as root, CMake, port, and example `vcpkg.json` files when they
still carry that release. Review every match; do not assume a fixed location
count.

Generated version headers and packaging files use CMake substitution. Do not
replace their `@VAR@` placeholders with literal versions.

## Research Repo Locations

| # | File | What to Update |
|---|------|----------------|
Search the active research instructions for the old upstream revision or
version. Update only live contracts; leave clearly dated historical reports
unchanged and label them as snapshots if they could be mistaken for current
guidance.

## Workflow

### 1. Update iccDEV Clone

```bash
cd iccDEV && git status --short --branch
git fetch origin
git merge --ff-only origin/master
```

Stop if the checkout is dirty or the fast-forward cannot be completed. Never
discard local work during a version synchronization.

### 2. Rebuild Everything

```bash
cd cfl && ./build.sh --with-patches --refresh-iccdev
cd ../afl && ./build.sh --with-patches --refresh-iccdev
```

### 3. Verify CFL Patches

Check `build.sh` output for "Applied:" vs "FAIL". Any FAIL requires
patch rework (see `upstream-sync` skill).

### 4. Run Tests

```bash
iccDEV/Build/Tools/IccPawgReport/iccPawgReport --json \
  iccDEV/Testing/sRGB_v4_ICC_preference.icc
pytest -q iccDEV/iccdev-mcp/tests
```

### 5. Update Version References

```bash
# Verify no old version strings remain
grep -rn 'OLD_VERSION' --include='*.cpp' --include='*.h' --include='*.md' \
  --include='*.txt' --include='*.cmake' | grep -v '.git/'
```

### 6. Commit

```bash
git add -A && git commit -m "chore: sync iccDEV upstream to vX.Y.Z.W"
```

## References

- `.github/skills/upstream-sync/SKILL.md` -- Patch reconciliation
- `.github/instructions/cfl.instructions.md` -- CFL patch system
