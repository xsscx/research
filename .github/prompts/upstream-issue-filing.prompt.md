# Upstream iccDEV Bug Filing -- Golfed Issue Format

Minimal-prose upstream issue format derived from #753, #755, #794.
This is the gold standard for filing bugs against
[InternationalColorConsortium/iccDEV](https://github.com/InternationalColorConsortium/iccDEV).

## Template

```markdown
## Maintainer Repro

YYYY-MM-DD HH:MM:SS UTC

## Bisect
Bad: <commit-sha> <date>

## Build
\```
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV/Build
git checkout <commit>
CC=clang CXX=clang++ cmake Cmake && make -j32
cd ../Testing/
echo "=== Updating PATH ==="
 for d in ../Build/Tools/*; do
  [ -d "$d" ] && export PATH="$(realpath "$d"):$PATH"
 done
wget <fuzz-corpus-url>
<tool-command> <poc-file>
\```

## Bad

\```
<sanitizer-output>
\```

## Patch

\```
<unified-diff>
\```

## Good

\```
<tool-command> <poc-file> | grep runtime
\```

## References
- #<related-issue>
```

## Anatomy

### Title
```
Bisect: <commit-sha-prefix> <bug-type-abbreviation>
```
Bug type abbreviations: `dbz` (division by zero), `hbo` (heap buffer overflow),
`sbo` (stack buffer overflow), `npd` (null pointer deref), `ub` (undefined behavior),
`uio` (unsigned integer overflow), `oom` (out of memory), `so` (stack overflow),
`uaf` (use after free), `fmt` (format string).

### Labels
`Triaged`, `Bisect`, `ML`, `SCAP`

### Sections

| Section | Content | Rules |
|---------|---------|-------|
| Maintainer Repro | UTC timestamp | Date of verification |
| Bisect | Commit SHA + date | Oldest bad commit |
| Build | Clone + build + wget + test | Single code block, copy-paste ready |
| Bad | Sanitizer output only | 2-3 lines max, just the error |
| Patch | Unified diff | Minimal fix |
| Good | Verification command | `grep runtime` returns empty = fixed |
| References | Related issues | `#NNN` links only |

### Rules

1. **Zero prose.** No sentences, no explanations, no background.
2. **One bug per issue.** Never bundle multiple findings.
3. **PoC from fuzz corpus.** wget from `xsscx/fuzz/graphics/icc/` -- never inline scripts.
4. **Single code block for Build.** Clone + build + wget + test in one block.
5. **Bad = sanitizer output.** Not tool output, not analysis -- just the error lines.
6. **Good = verification.** `| grep runtime` on patched build returns empty.
7. **Cut shadow byte legend** unless UAF or double-free.

## PoC Naming Convention

```
{type}-{Class}-{Method}-{File}_cpp-Line{N}.icc
```

| Field | Source |
|-------|--------|
| type | ASAN/UBSAN crash type abbreviation |
| Class | C++ class from stack frame #2-#3 |
| Method | Method name from stack frame |
| File | Source file (no path, underscores for dots) |
| Line | Source line number |

Examples:
- `dbz-CIccTagParametricCurveApply-IccTagLut_cpp-Line1049.icc`
- `hbo-CIccCLUT-Interp3d-IccTagLut_cpp-Line1234.icc`
- `npd-CIccMpeCalculator-Apply-IccMpeCalc_cpp-Line5678.icc`

## PoC Delivery Pipeline

1. Synthesize or find PoC that triggers sanitizer output
2. Name per convention above
3. Commit to `xsscx/fuzz` repo: `fuzz/graphics/icc/<name>.icc`
4. Use raw GitHub URL in issue: `wget https://github.com/xsscx/fuzz/raw/refs/heads/master/graphics/icc/<name>.icc`
5. Verify wget + tool command produces the Bad output before filing

## Sanitizer Build Requirements

iccDEV's `ENABLE_SANITIZERS=ON` gives `address,undefined,integer`.
This does NOT include:
- `float-divide-by-zero` -- IEEE 754 defined, not in `undefined` group
- `float-cast-overflow` -- also not in `undefined` group

To catch float div-by-zero (like #794), build with explicit flags:
```bash
CC=clang CXX=clang++ cmake Cmake -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON
```
Or with manual flags:
```bash
CC=clang CXX=clang++ CXXFLAGS="-fsanitize=address,undefined,integer,float-divide-by-zero,float-cast-overflow -fno-omit-frame-pointer -g" LDFLAGS="-fsanitize=address,undefined,integer,float-divide-by-zero,float-cast-overflow" cmake Cmake
```

## Comparison: Verbose vs Golfed

### Verbose (anti-pattern)
```markdown
## Description
The `CIccTagParametricCurve::Apply()` function in `IccTagLut.cpp` divides
by parameter `a` at line 1049 without checking for zero. When a malformed
ICC profile contains a parametric curve with `a=0`, this causes...
[30 more lines of prose]
```

### Golfed (gold standard -- #794)
```markdown
## Bad
\```
IccTagLut.cpp:1049:18: runtime error: division by zero
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior IccTagLut.cpp:1049:18
\```
```

The sanitizer output IS the description. The line number IS the location.
The CWE maps from the error type. No prose needed.

## Real Examples

| Issue | Title | Type | Lines |
|-------|-------|------|-------|
| #753 | Bisect: 1f0a9dd dbz | Division by zero | ~30 |
| #755 | .bat errorlevel | Script bug | ~20 |
| #794 | Bisect: 1f0a9dd dbz | Float div-by-zero | ~35 |
| #793 | printf %d with unsigned | Format string | ~25 |

## References

- `docs/pocs/iccdev-issue-reproductions.md` -- 64 closed issue reproductions
- `docs/pocs/iccdev-poc-techniques.md` -- PoC synthesis techniques
- `.github/prompts/iccdev-bisect-reproduction.prompt.md` -- Bisect workflow
- `.github/prompts/upstream-uio-hunting.prompt.md` -- UIO hunting pattern
