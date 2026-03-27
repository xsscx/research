# Version Bump Workflow -- iccDEV Upstream

## When to Use

Use this prompt when the iccDEV upstream repository bumps its version number
and the research repo needs to sync, OR when performing the upstream bump itself.

## Upstream Version Bump (iccDEV)

### Version Location Map (6 locations, 5 files)

| # | File | Symbol | Type |
|---|------|--------|------|
| 1 | `IccProfLib/IccProfLibVer.h` | `ICCPROFLIBVER` | Hardcoded string |
| 2 | `IccXML/IccLibXML/IccLibXMLVer.h` | `ICCLIBXMLVER` | Hardcoded string |
| 3 | `IccXML/IccLibXML/IccLibXMLVer.h` | `ICCPROFLIBLIBXMLVER` | Hardcoded string |
| 4 | `Build/Cmake/CMakeLists.txt` | `PATCH_VERSION` + comment | CMake variable |
| 5 | `.github/copilot-instructions.md` | Version string in header | Documentation |
| 6 | `.github/instructions/build-system.instructions.md` | Version string | Documentation |

### Files That Do NOT Need Updating

`.in` template files use CMake `@VAR@` substitution -- they inherit version
from `CMakeLists.txt` at configure time:

- `IccProfLib/IccProfLibVer.h.in`
- `IccXML/IccLibXML/IccLibXMLVer.h.in`
- `Build/Cmake/RefIccMAXConfig.cmake.in`
- `Build/Cmake/RefIccMAXUninstall.cmake.in`

### Verification Command

```bash
# Must return 0 hits after bump
grep -rn 'OLD_VERSION' \
  --include='*.cpp' --include='*.h' --include='*.txt' \
  --include='*.cmake' --include='*.md' --include='*.xml' \
  --include='*.json' --include='*.yml' --include='*.yaml' \
  | grep -v '.git/'
```

## Research Repo Sync After Upstream Bump

### Locations to Update in Research Repo

| # | File | What to Update |
|---|------|----------------|
| 1 | `.github/copilot-instructions.md` | `Current upstream: commit HASH / vX.Y.Z.W` |
| 2 | `.github/instructions/cfl.instructions.md` | `Current upstream: commit HASH / vX.Y.Z.W` |

### Sync Procedure

```bash
# 1. Update iccDEV clone
cd iccDEV && git fetch origin && git reset --hard origin/master && git clean -fd

# 2. Rebuild iccanalyzer-lite (links unpatched upstream)
cd ../iccanalyzer-lite && ./build.sh

# 3. Rebuild CFL fuzzers (re-applies patches to new upstream)
cd ../cfl && rm -rf iccDEV/Build && ./build.sh

# 4. Verify CFL patches still apply
# build.sh output shows "Applied: NNN-name.patch" or "FAIL"
# Any FAIL requires patch rework (see upstream-sync.prompt.md)

# 5. Run tests
python3 iccanalyzer-lite/tests/run_tests.py

# 6. Update version references in research repo docs
# grep for OLD version string and update

# 7. Commit
git add -A
git commit -m "chore: sync iccDEV upstream to vX.Y.Z.W"
```

## Version Numbering Convention

iccDEV uses 4-part versioning: `MAJOR.MINOR.MICRO.PATCH`

- **MAJOR** (2): ICC specification generation
- **MINOR** (3): Significant feature additions
- **MICRO** (1): Minor feature or structural changes
- **PATCH** (N): Bug fixes, security patches, maintenance

## Related Prompts

- `upstream-sync.prompt.md` -- CFL patch reconciliation after upstream changes
- `cooperative-development.prompt.md` -- Multi-agent task coordination
