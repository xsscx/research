# Upstream Bug Hunting -- UIO Pattern

Find and fix unsigned integer overflow (UIO) bugs in iccDEV offset+size bounds checks.

## Prerequisites

- iccDEV built with `-fsanitize=address,undefined,integer`
- CRITICAL: `-fsanitize=undefined` alone does NOT catch unsigned overflow
- PoC synthesis script: `.github/scripts/synthesize_uio_poc.py`

## Workflow

### 1. Find candidate sites

```bash
cd iccDEV
grep -rn 'offset.*+.*size.*>' IccProfLib/ Tools/ --include='*.cpp' | \
  grep -v '//' | grep -v 'size_t\|uint64\|icUInt64' | head -40
```

### 2. Classify each site

- VULNERABLE: `if (offset + size > limit)` with uint32 operands
- SAFE: operands widened to size_t or uint64 before addition
- ALREADY FIXED: uses subtraction pattern `size > limit || offset > limit - size`

### 3. Synthesize PoC profiles

```bash
python3 .github/scripts/synthesize_uio_poc.py --output-dir /tmp/uio-poc
```

Or craft manually: minimal 128-byte ICC header + tag table with
offset=0x80, size=0xFFFFFF80 so offset+size wraps to 0x00.

### 4. Test against unpatched build

```bash
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=0,print_stacktrace=1 \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <poc>.icc ALL \
  2>&1 | grep "runtime error.*unsigned integer overflow"
```

### 5. Apply fix pattern

```cpp
// Library code (uint32 operands)
// BEFORE:
if (offset + size > limit)
// AFTER:
if (size > limit || offset > limit - size)

// Tool code (uint32 to int cast)
// BEFORE:
int profileSize = (int)pHdr->size;
// AFTER:
int safeProfileSize = (pHdr->size <= (icUInt32Number)INT_MAX)
                    ? (int)pHdr->size : INT_MAX;
```

### 6. Verify fix

```bash
# Must show 0 "runtime error" lines
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=0,print_stacktrace=1 \
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
  iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile <poc>.icc ALL \
  2>&1 | grep -c "runtime error"
```

## Issue #769 Reference

- 21 UIO sites fixed across IccProfLib/ and Tools/
- Bisect: latent since initial commit 1f0a9dd (2015-09-29)
- Branch: issue-769
- PoC files: test-profiles/poc-769-*.icc (research repo)
- CI regression: .github/ci/regression/poc-769-*.icc (iccDEV repo)

## Key Insight

Unsigned integer overflow is well-defined wrapping per C/C++ standard.
UBSAN's `undefined` group intentionally excludes it. The `integer` group
adds: unsigned-integer-overflow, implicit-unsigned-integer-truncation,
implicit-signed-integer-truncation, implicit-integer-sign-change.
