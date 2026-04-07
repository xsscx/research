---
name: version-bump
description: >
  Synchronize version numbers after iccDEV upstream version bump.
  Updates 6 locations across 5 files in upstream, plus 2 locations in
  the research repo.
---

# Version Bump Workflow

## Overview

When iccDEV upstream bumps its version, update all version locations in
both the upstream repo and the research repo. Version format: MAJOR.MINOR.MICRO.PATCH.

## Upstream Locations (6 locations, 5 files)

| # | File | Symbol |
|---|------|--------|
| 1 | `IccProfLib/IccProfLibVer.h` | `ICCPROFLIBVER` |
| 2 | `IccXML/IccLibXML/IccLibXMLVer.h` | `ICCLIBXMLVER` |
| 3 | `IccXML/IccLibXML/IccLibXMLVer.h` | `ICCPROFLIBLIBXMLVER` |
| 4 | `Build/Cmake/CMakeLists.txt` | `PATCH_VERSION` + comment |
| 5 | `.github/copilot-instructions.md` | Version in header |
| 6 | `.github/instructions/build-system.instructions.md` | Version string |

Files that do NOT need updating (`.in` templates use CMake `@VAR@` substitution):
`IccProfLibVer.h.in`, `IccLibXMLVer.h.in`, `RefIccMAXConfig.cmake.in`

## Research Repo Locations (2 locations)

| # | File | What to Update |
|---|------|----------------|
| 1 | `.github/copilot-instructions.md` | Upstream commit hash + version |
| 2 | `.github/instructions/cfl.instructions.md` | Upstream commit hash + version |

## Workflow

### 1. Update iccDEV Clone

```bash
cd iccDEV && git fetch origin && git reset --hard origin/master && git clean -fd
```

### 2. Rebuild Everything

```bash
cd iccanalyzer-lite && ./build.sh          # links unpatched upstream
cd ../cfl && rm -rf iccDEV/Build && ./build.sh  # re-applies patches
```

### 3. Verify CFL Patches

Check `build.sh` output for "Applied:" vs "FAIL". Any FAIL requires
patch rework (see `upstream-sync` skill).

### 4. Run Tests

```bash
python3 iccanalyzer-lite/tests/run_tests.py
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
