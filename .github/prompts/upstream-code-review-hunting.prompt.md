---
mode: agent
description: Find semantic bugs in iccDEV that fuzzers miss via targeted code review
---

# Upstream Code-Review Bug Hunting

Find semantic bugs in iccDEV that fuzzers miss: logic errors, data corruption,
dead code, serialization asymmetries, and division-by-zero in float paths.

## Prerequisites

- iccDEV built with ASAN+UBSAN+float-divide-by-zero (see sanitizer note below)
- PoC profiles in `xsscx/fuzz/graphics/icc/` (not inline generators)
- `~/bisect/` directory for drafts and patches

## Sanitizer Note

`-fsanitize=undefined` does NOT catch float division by zero (IEEE 754 defined).
Add `-fsanitize=float-divide-by-zero,float-cast-overflow` explicitly.
iccDEV's `ENABLE_SANITIZERS=ON` gives `address,undefined,integer` only.

## Bug Categories

### Category 1: Division by Zero in Apply() Paths

Float div-by-zero produces NaN (not crash). NaN propagates silently through
color transforms, causing all-black or corrupted output with no error message.

Search pattern:
```bash
grep -rn 'a\s*=.*Param\|/.*dParam\|/.*a\b' IccProfLib/ --include='*.cpp' | grep -v '//' | grep Apply
```

Verify: `iccRoundTrip <poc>.icc` shows `DeltaE: 0.00` (all-black) or `-nan`.
With `-fsanitize=float-divide-by-zero`: shows `runtime error: division by zero`.

### Category 2: Serialization Asymmetries (fromJson != toJson)

PR #738 fixed toJsonInit but missed fromJsonInit (#700 residual pattern).
Search for all read/write pairs:

```bash
grep -n 'fromJson\|toJson\|Read\|Write' IccProfLib/*.cpp Tools/**/*.cpp --include='*.cpp' | \
  grep -c 'fromJson\|toJson'
```

Compare field names: `j["fieldName"]` in fromJson vs toJson for same class.

### Category 3: Format String Mismatches

`%d` with unsigned types, missing format args, wrong width specifiers.

```bash
grep -rn 'sprintf\|printf' IccProfLib/ --include='*.cpp' | grep -E '%[0-9]*d.*icUInt|%x.*icUInt|%d.*size\(\)'
```

### Category 4: Dead Code with Latent Bugs

Operator overloads, copy constructors, or methods that exist but are never called.
Real bugs but zero impact until API consumer invokes them.

**CRITICAL**: Before labeling severity, verify reachability:
```bash
# For operator=
grep -rn 'operator=' IccProfLib/ Tools/ --include='*.cpp' --include='*.h' | grep -v 'delete\|private'
# Then grep for actual call sites (assignments of that type)
grep -rn 'CIccTagArray.*=' IccProfLib/ Tools/ --include='*.cpp' | grep -v 'operator='
```

Dead code findings are LOW/informational, not CRITICAL.

### Category 5: Unchecked Return Values

```bash
grep -rn '\.Read\|\.Write\|\.Invert\|\.Begin\|\.SetSize' IccProfLib/ --include='*.cpp' | \
  grep -v 'if.*Read\|if.*Write\|if.*Invert\|rv.*=\|result.*=\|bRv.*='
```

Focus on Read()/Write() calls that ignore the return value -- can leave
objects in partially-initialized state.

## Workflow

### 1. Parallel Exploration

Launch 4+ explore agents, one per category. Each scans the full codebase.
Collect raw findings with file:line citations.

### 2. Reachability Gate

For each finding, trace from CLI tool entry point:
- Is the function called by any tool? (grep call sites)
- Can a PoC profile reach the buggy code path?
- What sanitizer output does it produce?

### 3. PoC Synthesis

Minimal ICC profile requirements for iccRoundTrip (v2 RGB/XYZ-mntr):
- 9 tags: desc, cprt, rTRC, gTRC, bTRC, rXYZ, gXYZ, bXYZ, wtpt
- Profile version 2.0.4 (not 4.0.3)
- Minimum 576 bytes
- Missing matrix tags (rXYZ/gXYZ/bXYZ) causes "Unable to perform round trip"

### 4. Verify End-to-End

Run the EXACT 1-liner that will appear in the issue. Capture output.
Never write the issue draft before the verification step succeeds.

VERIFY -> CITE -> CLAIM. Never reverse this order.

### 5. File Per Gold Standard

See `.github/prompts/upstream-issue-filing.prompt.md` for the format.
Gold standard: #795 (enriched golfed with Bug section + Spec ref).

## Quality Checklist

Before filing any finding:

- [ ] Is the code reachable from a CLI tool entry point?
- [ ] Does a PoC file exist in `xsscx/fuzz/graphics/icc/`?
- [ ] Does `wget <url> && <tool> <poc>` produce sanitizer output?
- [ ] Is severity justified by reachability (not just code inspection)?
- [ ] Is the draft zero-prose with only code blocks?
- [ ] Has the EXACT deliverable been tested end-to-end?

## Anti-Patterns

| Pattern | Problem | Fix |
|---------|---------|-----|
| Inline Python PoC generator | Maintainer won't run it | Commit .icc to fuzz repo |
| Claiming UBSAN without output | Build may lack float-divide-by-zero | Add -fsanitize=float-divide-by-zero |
| Labeling dead code CRITICAL | Wastes maintainer time | Grep call sites first |
| Multiple PoC file versions | Confusion about which works | One file, one name, verified |
| Writing draft before testing | CJF-12 pattern | Test first, write second |
| 504-byte PoC for iccRoundTrip | Missing matrix tags | Need 9 tags, 576+ bytes |

## References

- `.github/prompts/upstream-issue-filing.prompt.md` -- Issue format (#795 gold standard)
- `.github/prompts/iccdev-bisect-reproduction.prompt.md` -- Bisect workflow
- `.github/prompts/upstream-uio-hunting.prompt.md` -- UIO-specific hunting
- `docs/pocs/iccdev-poc-techniques.md` -- PoC synthesis techniques
- `docs/pocs/iccdev-upstream-bug-hunting.md` -- Findings catalog
