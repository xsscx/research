# iccDEV Upstream Bug Hunting -- Findings Catalog

Findings from systematic code-review and CodeQL-pattern hunting against
iccDEV v2.3.1.7 (ca3334c). Session: April 2026.

## Method

Parallel exploration agents scanning 5 bug categories:
1. Division-by-zero in float Apply() paths
2. Serialization asymmetries (fromJson != toJson)
3. Format string mismatches
4. Dead code with latent bugs
5. Unchecked return values

All findings verified against ASAN+UBSAN-instrumented build.
PoC-verified findings tested with `iccRoundTrip` or `iccDumpProfile`.

## Filed Issues

| # | Finding | Issue | Status |
|---|---------|-------|--------|
| 003 | Parametric curve Apply() div-by-zero | [#794](https://github.com/InternationalColorConsortium/iccDEV/issues/794) | Open |

## Findings Summary (19 Live, 1 Retracted)

| # | Title | File:Line | CWE | Severity | Evidence |
|---|-------|-----------|-----|----------|----------|
| 001 | Malformed hex format strings (10 instances) | IccTagBasic.cpp:5938-6020 | CWE-134 | HIGH | PoC verified |
| 002 | CalcTest .bat ERRORLEVEL always-true (79) | CalcTest.bat | CWE-670 | MEDIUM | Code review |
| 003 | Parametric curve Apply() div-by-zero | IccTagLut.cpp:1049,1060 | CWE-369 | HIGH | Filed as #794 |
| 005 | GBD signed integer type | IccTagLut.cpp:5729 | CWE-190 | LOW | Code review |
| 006 | %d with unsigned types (14 instances) | 4 files | CWE-686 | LOW | Code review |
| 007 | Formula FT=5 div-by-zero (a=0) | IccMpeBasic.cpp:660 | CWE-369 | HIGH | PoC verified |
| 008 | Missing closing quotes (4 instances) | IccUtil.cpp | CWE-134 | LOW | PoC verified |
| 009 | Unchecked Read32 tag signature | IccTagComposite.cpp:1300 | CWE-252 | MEDIUM | Code review |
| 010 | Formula FT=6 param count (6 vs 7) | IccMpeBasic.cpp:806 | CWE-754 | HIGH | PoC verified |
| 011 | fromJsonInit reads wrong key (#700 residual) | IccCmmConfig.cpp:1156 | CWE-345 | HIGH | Code review |
| 012 | linkGridSize not serialized in toJson | IccCmmConfig.cpp:521-544 | CWE-345 | MEDIUM | Code review |
| 013 | Formula FT6/FT7 denominator div-by-zero | IccMpeBasic.cpp:667-679 | CWE-369 | HIGH | PoC verified |
| 014 | Spectral white point XYZ div-by-zero | IccMpeSpectral.cpp:1631,2164 | CWE-369 | HIGH | Code review |
| 015 | Calculator div/sdiv no zero check | IccMpeCalc.cpp:927,1053 | CWE-369 | MEDIUM | Code review |
| 016 | ToneMap copy ctor uninit m_pLumCurve | IccMpeBasic.cpp:4225 | CWE-908 | MEDIUM | Reachability TBD |
| 017 | Matrix Invert ignores singular failure | IccMatrixMath.cpp:280 | CWE-252 | HIGH | Code review |
| 018 | TagArray operator= loop runs 0 times | IccTagComposite.cpp:1081 | CWE-665 | LOW | Dead code |
| 019 | TagArray Write copies offset into size | IccTagComposite.cpp:1380 | CWE-682 | HIGH | Code review |
| 020 | SetRange steps==1 div-by-zero | IccMatrixMath.cpp:369 | CWE-369 | HIGH | Code review |

### Retracted

| # | Title | Reason |
|---|-------|--------|
| 004 | CIccTagCurve::Describe nSize=1 div | nSize==1 takes gamma shortcut; division unreachable |

## CWE Distribution

| CWE | Count | Category |
|-----|-------|----------|
| CWE-369 | 7 | Division by zero |
| CWE-134 | 2 | Format string |
| CWE-345 | 2 | Insufficient verification |
| CWE-252 | 2 | Unchecked return value |
| CWE-190 | 1 | Integer overflow |
| CWE-665 | 1 | Improper initialization |
| CWE-670 | 1 | Always-incorrect control flow |
| CWE-682 | 1 | Incorrect calculation |
| CWE-686 | 1 | Wrong argument type |
| CWE-754 | 1 | Improper check for exceptional conditions |
| CWE-908 | 1 | Uninitialized resource |

## Bug Chain: #700 Residual

PR #738 (commit f629654) fixed 3 of 4 bugs in the `CIccApplyCmmSearch`
chain reported in #700. The 4th was missed:

- Finding 011: `fromJsonInit()` at line 1156 reads `j["transform"]`
  instead of `j["interpolation"]` -- toJsonInit was fixed but fromJsonInit
  was not. Data written by toJsonInit cannot be read back correctly.

- Finding 012: `linkGridSize` is read by fromJsonInit (line 511) but
  never written by toJsonInit (lines 521-544). Round-trip always loses
  this field.

## Bisect Results

| Finding | Oldest Bad Commit | Date |
|---------|------------------|------|
| 003 | 1f0a9dd | 2015-09-29 (initial commit) |
| 001 | TBD | Likely initial commit |
| 007 | TBD | Likely initial commit |

## Lessons Learned

### 1. Sanitizer Coverage Gap
`-fsanitize=undefined` does NOT include `float-divide-by-zero`.
Float div-by-zero is IEEE 754 defined behavior (produces NaN).
Must add `-fsanitize=float-divide-by-zero` explicitly.
iccDEV CMakeLists.txt `ENABLE_SANITIZERS=ON` should be updated.

### 2. PoC Quality Bar
- PoCs belong in `xsscx/fuzz/graphics/icc/` with descriptive names
- Never use inline Python generators in issue filings
- Naming convention: `{type}-{Class}-{Method}-{File}_cpp-Line{N}.icc`
- Minimal v2 RGB profile needs 9 tags (not 6) for iccRoundTrip

### 3. Reachability Before Severity
- Grep call sites before labeling anything CRITICAL
- Dead code findings (like 018) are LOW/informational
- Finding 018's `operator=` is never called; all copy paths use `NewCopy()`

### 4. Gold Standard Issue Format
- Zero prose. Sections: Bisect, Build, Bad, Patch, Good, References
- Single code block: clone + build + wget + test
- Bad = sanitizer output only (2-3 lines)
- Good = `| grep runtime` returns empty
- See `.github/prompts/upstream-issue-filing.prompt.md`

## Detailed Drafts

Individual finding drafts with patches and PoC files are in `~/bisect/`:
- `001-hex-format-strings.md` through `020-setrange-steps1-divzero.md`
- `003-parametric-curve-divzero.patch`
- `poc-*.icc` and `poc-*.xml` files
- `SUMMARY.md` (master reference)
- `VERIFICATION.log` (full verification output)

## References

- [#794](https://github.com/InternationalColorConsortium/iccDEV/issues/794) -- Filed finding 003
- [#793](https://github.com/InternationalColorConsortium/iccDEV/issues/793) -- Format string (user filed)
- [#753](https://github.com/InternationalColorConsortium/iccDEV/issues/753) -- Gold standard dbz issue
- [#755](https://github.com/InternationalColorConsortium/iccDEV/issues/755) -- .bat script bugs
- [#700](https://github.com/InternationalColorConsortium/iccDEV/issues/700) -- Bug chain (3/4 fixed)
- [#769](https://github.com/InternationalColorConsortium/iccDEV/issues/769) -- UIO bounds checks
