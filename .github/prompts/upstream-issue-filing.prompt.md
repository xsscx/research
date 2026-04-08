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

## Vuln
CWE-<NNN> | <TOOL>:<finding-type> | <File.cpp>:<line> | <Class::Method()>
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:<c>/I:<i>/A:<a> = <score>
CPE: cpe:2.3:a:icc:reficcmax:*:*:*:*:*:*:*:*
Introduced: <sha7> (<YYYY-MM-DD>) | Affected: <=<version>
Vector: <1-line attack narrative>

## Build
\```
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV/Build
git checkout <commit>
CC=clang CXX=clang++ cmake Cmake && make -j32
cd ../Testing/
for d in ../Build/Tools/*; do [ -d "$d" ] && export PATH="$(realpath "$d"):$PATH"; done
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
| Vuln | CWE, CVSS, CPE, range, vector | 5 lines, ~323 chars, machine-parseable |
| Build | Clone + build + wget + test | Single code block, copy-paste ready |
| Bad | Sanitizer output only | 2-3 lines max, just the error |
| Patch | Unified diff | Minimal fix |
| Good | Verification command | `grep runtime` returns empty = fixed |
| References | Related issues | `#NNN` links only |

### Vuln Block Fields

| Line | Content | Audience |
|------|---------|----------|
| 1 | CWE \| sanitizer:type \| file:line \| function | NVD, SCAP, devs, LLMs |
| 2 | CVSS:3.1 vector = score | NVD, SCAP, severity triage |
| 3 | CPE string | NVD, vulnerability scanners |
| 4 | Introduced SHA + affected range | Bisect, version queries |
| 5 | Attack vector narrative (1 line) | Exploit devs, NVD description |

### CVSS Quick Reference (iccDEV)

All share: AV:L/AC:L/PR:N/UI:R/S:U (local lib, no auth, user opens file).

| Bug Type | C/I/A | Score |
|----------|-------|-------|
| div-by-zero (NaN) | N/L/N | 3.3 |
| HBO read | L/N/H | 6.1 |
| UIO (bounds bypass) | L/N/H | 6.1 |
| HBO write | N/H/H | 7.1 |
| UAF / double-free | H/H/H | 7.8 |
| Stack overflow / null deref / OOM | N/N/H | 5.5 |

### Rules

1. **Zero prose.** No sentences, no explanations, no background.
2. **One bug per issue.** Never bundle multiple findings (bug chains are the exception).
3. **PoC from fuzz corpus.** wget from `xsscx/fuzz/graphics/icc/` -- never inline scripts.
4. **Single code block for Build.** Clone + build + wget + test in one block.
5. **Bad = sanitizer output.** Not tool output, not analysis -- just the error lines.
6. **Good = verification.** `| grep runtime` on patched build returns empty.
7. **Cut shadow byte legend** unless UAF or double-free.
8. **Vuln block required.** CWE, CVSS, CPE, range, vector -- all 5 lines.
9. **ASAN trim.** Keep SCARINESS + frames #0-#4 max. Cut libc, `_start`, shadow bytes.

### Bug Chain Format

For bug chains (like #700), add one `## Vuln` block per prerequisite:
```markdown
## Vuln (prerequisite 1)
CWE-843 | code-review:type-confusion | File.cpp:line | Function()
...

## Vuln (primary)
CWE-122 | ASAN:heap-buffer-overflow | File.cpp:line | Function()
SCARINESS: 23 (8-byte-read-heap-buffer-overflow)
...
```

Include SCARINESS score on line 2 when ASAN provides it (replaces CVSS line for
that Vuln block, or add as line 6).

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

| Issue | Title | Type | Format |
|-------|-------|------|--------|
| #700 | HBO in CIccApplyCmmSearch::costFunc() | Bug chain (3 prereqs + HBO) | Verbose gold |
| #753 | Bisect: 1f0a9dd dbz | Division by zero | Verbose |
| #769 | Bisect: 1f0a9dd uio | Unsigned integer overflow | Multi-file patch |
| #794 | Bisect: 1f0a9dd dbz | Float div-by-zero | Golfed gold |

### Character Budgets

| Format | Chars | Coverage |
|--------|-------|----------|
| Golfed (#794) | ~1,200 | Repro + patch |
| Enriched golfed | ~1,523 | + CWE, CVSS, CPE, range, vector |
| Verbose (#753) | ~2,500 | Same as enriched at 40% more chars |
| Multi-file (#769) | ~3,500 | Multi-file patch justified |
| Bug chain (#700) | ~3,000 | 3 prereqs + trimmed ASAN justified |

See `~/gold-issues.md` for full analysis of enrichment ROI per audience.

## References

- `docs/pocs/iccdev-issue-reproductions.md` -- 64 closed issue reproductions
- `docs/pocs/iccdev-poc-techniques.md` -- PoC synthesis techniques
- `.github/prompts/iccdev-bisect-reproduction.prompt.md` -- Bisect workflow
- `.github/prompts/upstream-uio-hunting.prompt.md` -- UIO hunting pattern
