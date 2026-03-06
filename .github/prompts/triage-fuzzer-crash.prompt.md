# Triage Fuzzer Crash

Use this prompt when a fuzzer reports ASAN (heap-buffer-overflow, heap-use-after-free, stack-buffer-overflow, stack-overflow, SEGV) or UBSAN (runtime error) findings.

## Step 1 — Classify the finding

From the fuzzer output, determine:
- **Fuzzer name** (e.g., `icc_link_fuzzer`)
- **Error type**: ASAN class (heap-use-after-free, heap-buffer-overflow, stack-overflow, SEGV) or UBSAN (runtime error description)
- **Source location**: file:line from the stack trace
- **CWE mapping**: e.g., CWE-122 (heap BOF), CWE-416 (UAF), CWE-787 (OOB write), CWE-758 (undefined behavior)

## Step 2 — Determine if it's fuzzer code or upstream

- If the crash is in `cfl/icc_*_fuzzer.cpp` → fix the fuzzer harness
- If the crash is in `iccDEV/IccProfLib/` or `iccDEV/Tools/` → create a CFL patch

**CRITICAL**: Before triaging, verify CFL and upstream iccDEV are at the same commit:
```bash
echo "CFL: $(cd cfl/iccDEV && git rev-parse --short HEAD)"
echo "Upstream: $(cd iccDEV && git rev-parse --short HEAD)"
```

## Step 3 — Common patterns and fixes

### Heap-use-after-free (CWE-416)
- **AddXform ownership**: `CIccCmm::AddXform(CIccProfile*)` transfers ownership. On `icCmmStatBadXform`, the profile is already freed — do NOT delete. See copilot-instructions.md AddXform ownership semantics section.
- **Iterator invalidation**: Check if containers are modified during iteration.

### NaN bypass in clamp functions (CWE-758)
- IEEE 754 NaN fails all ordered comparisons. Clamp patterns like `if(v<0)...if(v>1)...` pass NaN through to integer casts.
- Fix: Add `if (v != v) return 0.0;` as the FIRST check (NaN self-inequality idiom).
- Upstream affected: UnitClip in iccApplyProfiles.cpp, SetRange in IccMatrixMath.cpp.

### SEGV in CIccCLUT::Interp functions (CWE-125)
- Array index computed from grid points can exceed allocated buffer.
- Fix: Add `maxDataOffset` bounds check before array access. See patch 069.

### OOM / excessive allocation
- See `triage-fuzzer-oom.prompt.yml` for the full OOM workflow.

### Stack-buffer-overflow / integer overflow (CWE-121, CWE-190)
- Check for unchecked `tagCount` or `numChannels` values read from profile header.
- Fix: Validate against reasonable maximums before allocating arrays.

## Step 4 — Severity assessment

Use ASAN SCARINESS scoring for automated severity:
```bash
ASAN_OPTIONS=print_scariness=1:halt_on_error=0:detect_leaks=0 cfl/bin/<fuzzer> <crash-file> 2>&1
```

Check if the bug also affects upstream tools:
```bash
ASAN_OPTIONS=detect_leaks=0 timeout 5 iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles \
  /tmp/test_rgb.tif /tmp/out.tif 1 0 0 0 0 <crash-file> 0 2>&1 | grep "runtime error"
```

Map to CVE CWE distribution: CWE-20 (49), CWE-122 (17), CWE-476 (16), CWE-125 (11), CWE-758 (11), CWE-787 (10).

## Step 5 — Fix workflow

1. **Reproduce**: `ASAN_OPTIONS=detect_leaks=0 timeout 10 cfl/bin/<fuzzer> <crash-file> 2>&1`
2. **Fix**: Either patch the fuzzer (.cpp) or create a CFL patch (cfl/patches/NNN-*.patch)
3. **Rebuild**: `cd cfl && ./build.sh`
4. **Verify**: Re-run the crash file — must exit 0 with no ASAN/UBSAN output
5. **Deploy**: `cp cfl/bin/icc_*_fuzzer /mnt/g/fuzz-ssd/bin/` (stop running fuzzers first if Text file busy)
6. **Document**: Update cfl/patches/README.md, copilot-instructions.md patch counts, commit reproducer file

## Step 6 — Naming conventions for reproducers

Reproducer files committed to repo root use descriptive prefixes:
- `segv-<Function>-<File>-Line<N>.icc` — SEGV/SIGSEGV crashes
- `ub-<description>-<File>-Line<N>.icc` — UBSAN undefined behavior
- `hbo-<Function>-<File>-Line<N>.icc` — Heap buffer overflow (needs `git add -f`, gitignored pattern)
- `crash-<sha256hash>` — Raw LibFuzzer crash artifacts (auto-named)
- `oom-<sha256hash>` — Raw LibFuzzer OOM artifacts (auto-named)

### BPC Stack-buffer-overflow in pixelXfm (CWE-121)
- **Root cause**: `CIccApplyBPC::CalcFactors()` creates `XYZbp[3]` (12 bytes), passes as DstPixel to `pixelXfm()` → `cmm.Apply(DstPixel, SrcPixel)`. If malformed profile's LUT has `m_nOutput > 3`, the CMM writes past the buffer.
- **Key insight**: Malformed profiles LIE about color space — `cmm.GetDestSpace()` returns declared space (RGB=3 channels) but the LUT `m_nOutput` can be 9+. Never trust `icGetSpaceSamples()` for buffer sizing.
- **Fix pattern**: Always use `icFloatNumber tmpPixel[16] = {}` as destination for `cmm.Apply()`, copy back only needed values. The `[16]` matches the library's internal Apply buffer size.
- **Trigger**: BPC rendering intents only — intent 40 (Perceptual+BPC), 41 (Relative+BPC), 42 (Saturation+BPC).
- **Reproduction**: `ASAN_OPTIONS=print_scariness=1:detect_leaks=0 iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles /tmp/test_rgb.tif /tmp/out.tif 0 0 0 0 1 <profile.icc> 40`
- **SCARINESS**: 51 (4-byte-write-stack-buffer-overflow). See patch 071.
