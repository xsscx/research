# Upstream Sync — CFL iccDEV Patch Reconciliation

Sync `cfl/iccDEV/` to upstream `iccDEV/` HEAD and reconcile all patches.

## Pre-flight

```bash
echo "Upstream: $(cd iccDEV && git rev-parse --short HEAD)"
echo "CFL:     $(cd cfl/iccDEV && git rev-parse --short HEAD)"
cd iccDEV && git log --oneline $(cd ../cfl/iccDEV && git rev-parse HEAD)..HEAD
```

## Workflow

### Step 1 — Update CFL checkout
```bash
cd cfl/iccDEV && git fetch origin && git reset --hard origin/master
```

### Step 2 — Dry-run all patches
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

### Step 3 — Categorize failures
- **NO-OP (drop)**: Fix is now in upstream — delete the patch file
- **Context shift (regenerate)**: Same fix needed but line numbers moved — manually apply changes, generate new diff
- **Conflict (rework)**: Upstream changed the logic — review and rework

### Step 4 — Regenerate patches
For each patch needing regeneration:
1. Save pre-patch state: `cp file.cpp /tmp/file.pre`
2. Apply the fix manually
3. Generate diff: `diff -u /tmp/file.pre file.cpp | sed 's|--- /tmp/...|--- a/path|; s|+++ .*/|+++ b/path|' > patches/NNN-name.patch`
4. **Critical**: Patch headers must use `--- a/path` / `+++ b/path` format for `patch -p1`

### Step 5 — Verify full set
```bash
cd cfl/iccDEV && git reset --hard origin/master
cd .. && for p in patches/*.patch; do patch -p1 -d iccDEV --forward --batch --silent < "$p" 2>/dev/null || echo "[FAIL] $(basename $p)"; done
```

### Step 6 — Rebuild and verify
```bash
cd cfl && ./build.sh
./verify-patches.sh --ssd /mnt/g/fuzz-ssd   # MANDATORY ground-truth check
cp bin/icc_*_fuzzer /mnt/g/fuzz-ssd/bin/     # or ramdisk
```

**CRITICAL**: Do NOT skip `verify-patches.sh`. `build.sh` patch summary uses
`--forward` which masks context-shifted failures. The verification script provides
3-phase ground truth (source grep + binary nm + runtime test). See Anti-Pattern #13.

### Step 6b — Rebuild ASAN upstream tools
```bash
cd iccDEV/Build-ASAN && cmake ../Build/Cmake \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON -DENABLE_COVERAGE=ON
make -j32
```
This keeps the ASAN-instrumented upstream tools in sync for fidelity comparison.

### Step 7 — Update documentation
- `cfl/patches/README.md` — patch count, dropped list
- `cfl/README.md` — patch count
- `.github/copilot-instructions.md` — patch count, NO-OP list
- `README.md` — patch count in overview table
- Store updated memories for patch count and upstream commit

## Key lessons (2026-03-05 sync)
- `build.sh` does NOT auto-update cfl/iccDEV — drift happens silently
- Always verify CFL and upstream commits match before triaging findings
- 14 patches dropped as NO-OPs when syncing from `186bba0` → `5f7e03a` → `b5ade94` (PR #648)
- Patches with `/tmp/` paths in headers fail with `patch -p1` — must use `a/`/`b/` prefix
- After sync, rebuild both `cfl/` (fuzzers) and `iccDEV/Build-ASAN/` (upstream ASAN tools)
- iccDEV upstream cmake has `ENABLE_SANITIZERS` and `ENABLE_COVERAGE` options built-in
- Fidelity measurement: use `llvm-cov-18 export -format=lcov` + `FNDA` extraction to diff covered functions

## See Also
- [cooperative-development.prompt.md](cooperative-development.prompt.md) — Multi-agent coordination
- [cve-enrichment.prompt.md](cve-enrichment.prompt.md) — CVE-to-heuristic mapping
- [triage-fuzzer-crash.prompt.md](triage-fuzzer-crash.prompt.md) — Fuzzer crash triage
- [corpus-management.prompt.md](corpus-management.prompt.md) — Corpus storage operations
