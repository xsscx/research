---
name: upstream-sync
description: >
  Sync CFL iccDEV checkout to upstream HEAD and reconcile all security
  patches. Handles patch dry-run, categorization, regeneration, rebuild,
  and verification.
---

# Upstream Sync -- CFL Patch Reconciliation

## Overview

Reconcile CFL security patches after upstream iccDEV changes. Patches in
`cfl/patches/` must be re-validated whenever upstream moves forward.

## Workflow

### 1. Pre-flight

```bash
echo "Upstream: $(cd iccDEV && git rev-parse --short HEAD)"
echo "CFL:     $(cd cfl/iccDEV && git rev-parse --short HEAD)"
cd iccDEV && git log --oneline $(cd ../cfl/iccDEV && git rev-parse HEAD)..HEAD
```

### 2. Update CFL Checkout

```bash
cd cfl/iccDEV && git fetch origin && git reset --hard origin/master
```

### 3. Dry-Run All Patches

```bash
cd cfl
for p in patches/*.patch; do
  if patch -p1 -d iccDEV --forward --batch --silent --dry-run < "$p" 2>/dev/null; then
    echo "[OK]   $(basename $p)"
  else
    echo "[FAIL] $(basename $p)"
  fi
done
```

### 4. Categorize Failures

- NO-OP (drop): Fix merged upstream. Delete the patch file.
- Context shift (regenerate): Same fix needed, line numbers moved.
- Conflict (rework): Upstream changed the logic. Review and rework.

### 5. Regenerate Patches

For each patch needing regeneration:
1. Save pre-patch state: `cp file.cpp /tmp/file.pre`
2. Apply fix manually
3. Generate diff with `a/`/`b/` prefix headers
4. Reset: `cd cfl/iccDEV && git checkout -- .`

### 6. Rebuild and Verify

```bash
cd cfl/iccDEV && git reset --hard origin/master
cd .. && ./build.sh
nm cfl/bin/icc_dump_fuzzer | grep -c __asan  # must be > 0
```

MANDATORY: Delete `Build/` dir before rebuild to avoid stale CMakeCache
retaining wrong sanitizer flags.

### 7. Rebuild Upstream ASAN Tools

```bash
cd iccDEV/Build && rm -rf CMakeCache.txt CMakeFiles/
CC=clang CXX=clang++ \
  CXXFLAGS="-fsanitize=address,undefined,integer -fno-omit-frame-pointer -g -O1" \
  LDFLAGS="-fsanitize=address,undefined,integer" \
  cmake Cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_TOOLS=ON
make -j$(nproc)
```

### 8. Update Documentation

- `cfl/patches/README.md` -- patch count, dropped list
- `.github/instructions/cfl.instructions.md` -- upstream commit hash
- `README.md` -- patch count in overview table

## Key Rules

- `build.sh` does NOT auto-update cfl/iccDEV -- drift happens silently
- Patches with `/tmp/` paths in headers fail -- must use `a/`/`b/` prefix
- `-fsanitize=integer` is required for unsigned overflow detection
- Always verify ASAN instrumentation after rebuild: `nm | grep __asan`
- NEVER declare patches applied without ground-truth verification

## References

- `.github/instructions/cfl.instructions.md` -- Patch system details
- `.github/skills/version-bump/SKILL.md` -- Version sync after upstream bump
