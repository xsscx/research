---
mode: agent
description: File upstream iccDEV bug reports in gold standard golfed format (#753/#794/#795)
---

# Upstream iccDEV Bug Filing -- Issue Format

Gold standard for filing bugs against
[InternationalColorConsortium/iccDEV](https://github.com/InternationalColorConsortium/iccDEV).
Derived from #753, #794, #795.

## Template

```markdown
## Copilot Summary

YYYY-MM-DD HH:MM:SS UTC
Verified: @<maintainer>

## Bisect

Bad: <sha7> (<YYYY-MM-DD>, "<commit-message>")

## Vuln

CWE-<NNN> | <TOOL>:<finding-type> | <File.cpp>:<line> | <Class::Method()>
CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:<c>/I:<i>/A:<a> = <score>
CPE: cpe:2.3:a:icc:reficcmax:<version>:*:*:*:*:*:*:*
Introduced: <sha7> | Affected: <=<version>
Spec: <spec-ref> (<section>)
Vector: <1-line attack narrative>

## Bug (optional -- for math-heavy findings)

<brief technical analysis explaining the zero condition>

## Build

\```
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV/Build
CC=clang CXX=clang++ cmake -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="-g -fsanitize=address,undefined,float-divide-by-zero,float-cast-overflow -fno-sanitize-recover=float-divide-by-zero -fno-omit-frame-pointer" -DENABLE_TOOLS=ON Cmake
make -j32
cd ../Testing
wget <fuzz-corpus-url>
\```

## Repro

\```
ASAN_OPTIONS=detect_leaks=0,halt_on_error=0 UBSAN_OPTIONS=print_stacktrace=1,halt_on_error=0 \
  LD_LIBRARY_PATH=../Build/IccProfLib:../Build/IccXML \
  ../Build/Tools/<ToolDir>/<tool> <poc-file>
\```

## Bad

\```
<sanitizer-output>
\```

## Good

\```
<tool> <poc-file> | grep runtime
\```

## Patch

\```diff
<unified-diff>
\```

## Patch Status

Applied on branch `<branch>` at commit <sha>.

## References

- #<related-issue>
```

## Format Reference

### Title
```
Bisect: <sha7> <type>
```
Types: `dbz` `hbo` `sbo` `npd` `ub` `uio` `oom` `so` `uaf` `fmt`

### Labels
`Triaged`, `Bisect`, `ML`, `SCAP`

### Vuln Block (6 lines)

| Line | Content | Audience |
|------|---------|----------|
| 1 | CWE \| sanitizer:type \| file:line \| function | NVD, SCAP, devs |
| 2 | CVSS:3.1 vector = score | Severity triage |
| 3 | CPE string | Vulnerability scanners |
| 4 | Introduced SHA \| affected range | Bisect, version queries |
| 5 | Spec reference (section) | ICC maintainers |
| 6 | Attack vector (1 line) | NVD description |

### CVSS Quick Reference

All share: AV:L/AC:L/PR:N/UI:R/S:U (local lib, no auth, user opens file).

| Bug Type | C/I/A | Score |
|----------|-------|-------|
| div-by-zero (NaN) | N/L/L | 4.4 |
| div-by-zero (NaN, no A) | N/L/N | 3.3 |
| HBO read | L/N/H | 6.1 |
| UIO (bounds bypass) | L/N/H | 6.1 |
| HBO write | N/H/H | 7.1 |
| UAF / double-free | H/H/H | 7.8 |
| Stack overflow / null deref / OOM | N/N/H | 5.5 |

### Rules

1. **Zero prose** in Build/Repro/Bad/Good/Patch sections.
2. **One bug per issue.** Bug chains use multiple Vuln blocks.
3. **PoC from fuzz corpus.** `wget` from `xsscx/fuzz/graphics/icc/`.
4. **Build + Repro separate.** Build clones and compiles. Repro runs the tool.
5. **Bad = sanitizer output.** Cut shadow byte legend unless UAF/double-free.
6. **Good = verification.** `| grep runtime` returns empty = fixed.
7. **Full unified diff.** No abbreviated patches with `...`.
8. **Bug section optional.** Use for math-heavy findings (formula analysis).
9. **ASAN trim.** SCARINESS + frames #0-#4 max.

### Bug Chain Format

For bug chains, add one `## Vuln` block per prerequisite:
```markdown
## Vuln (prerequisite 1)
CWE-843 | code-review:type-confusion | File.cpp:line | Function()
...

## Vuln (primary)
CWE-122 | ASAN:heap-buffer-overflow | File.cpp:line | Function()
SCARINESS: 23 (8-byte-read-heap-buffer-overflow)
...
```

## PoC Convention

### Naming
```
{type}-{Class}-{Method}-{File}_cpp-Line{N}.icc
```

### Pipeline
1. Synthesize PoC that triggers sanitizer output
2. Name per convention, commit to `xsscx/fuzz/graphics/icc/`
3. `wget` raw GitHub URL in issue Build section
4. Verify `wget + tool` produces Bad output before filing

## Gold Standards

| Issue | Type | Format |
|-------|------|--------|
| #795 | Float div-by-zero (FT5/6/7) | Enriched golfed + Bug section + Spec ref |
| #794 | Float div-by-zero (parametric) | Minimal golfed |
| #700 | HBO bug chain (3 prereqs) | Multi-Vuln chain |

#795 is the current gold standard. Use #700 format only for bug chains.

## References

- `.github/prompts/iccdev-bisect-reproduction.prompt.md` -- Bisect workflow
- `.github/prompts/upstream-code-review-hunting.prompt.md` -- Bug hunting
- `.github/prompts/upstream-uio-hunting.prompt.md` -- UIO hunting
