# iccanalyzer-lite Modernization Plan

## Status: PLAN — Awaiting Approval

## Problem Statement

Three-agent deep review of iccanalyzer-lite (22,925 LOC, 30 C++ modules) identified
48 improvement opportunities across 7 categories. Prioritized by impact and risk.

## Review Summary

| Category | Issues | Severity |
|----------|--------|----------|
| Crash recovery gaps | 2 unwrapped modes | HIGH |
| malloc/free → std::vector | 11 sites across 4 files | HIGH |
| NULL → nullptr | 33 uses across 10 files | MEDIUM |
| Manual sig[5] → SigToChars() | 4 remaining sites (3 files) | MEDIUM |
| Output format inconsistencies | 5 issues (indentation, labels, CWE format) | LOW |
| H121 return value semantics | 1 function with wrong contract | MEDIUM |
| main() dispatch refactor | 182-line main, ad-hoc if/else | LOW |

## Phase 1: Safety & Correctness (HIGH priority)

### 1a. Wrap -cg and -xml modes in RecoverableRun
- **File**: `iccAnalyzer-lite.cpp` lines 305, 352
- **Issue**: `RunCallGraphMode()` and `RunWithXMLOutput()` are NOT wrapped in crash
  recovery. A SIGSEGV in these paths will crash the process instead of recovering.
- **Fix**: Wrap both in `RecoverableRun()` like all other analysis modes

### 1b. Replace malloc/free with std::vector (11 sites)
- **Files**: IccHeuristicsRawPost.cpp (4), IccHeuristicsDataValidation.cpp (2),
  IccAnalyzerNinja.cpp (3), IccHeuristicsProfileCompliance.cpp (2)
- **Issue**: C-style memory management risks use-after-free and double-free;
  exception-unsafe; no automatic cleanup on early return
- **Fix**: Replace `(type*)malloc(N)` + `free(ptr)` with `std::vector<type>(N)`
- **Note**: Must use `.data()` to pass to C APIs; `std::vector::resize()` zero-inits

### 1c. Fix H121 return value semantics
- **File**: IccHeuristicsIntegrity.cpp lines 44, 52
- **Issue**: Returns hardcoded 0/1 instead of using `heuristicCount` variable,
  breaking the contract that all heuristics return finding count
- **Fix**: Use `heuristicCount` consistently, increment on findings

## Phase 2: Type Safety & Consistency (MEDIUM priority)

### 2a. NULL → nullptr migration (33 uses)
- **Files**: 10 .cpp files with NULL instead of nullptr
- **Issue**: `NULL` is a macro that can cause type confusion in overload resolution;
  `nullptr` is type-safe (std::nullptr_t)
- **Fix**: Global sed replacement `NULL` → `nullptr` in analyzer code only
  (NOT in iccDEV library headers)
- **Verification**: Build + full test suite

### 2b. Remaining SigToChars migration (4 sites)
- **Files**: IccAnalyzerNinja.cpp:229-232, IccHeuristicsXmlSafety.cpp:467-470,
  IccHeuristicsIntegrity.cpp:299-302 (inline printf args)
- **Issue**: Manual 4-line `static_cast<char>(static_cast<unsigned char>(...))` blocks
  when `SigToChars()` helper exists in IccHeuristicsHelpers.h
- **Fix**: Replace with `char buf[5]; SigToChars(val, buf);` before the printf

### 2c. Fix output format inconsistencies
- **IccHeuristicsTagValidation.cpp:64**: 5-space indent → 6-space (match all others)
- **IccHeuristicsTagValidation.cpp:285**: `[CRITICAL]` label → `[WARN]` with ColorCritical()
- **IccHeuristicsTagValidation.cpp:583**: `[HIGH]` label → `[WARN]` with ColorWarning()
- **IccHeuristicsHeader.cpp:215**: CWE en-dash `—` → colon `:` format
- **IccHeuristicsHeader.cpp:36**: Verify ColorCritical() is intentional for zero-size

## Phase 3: Code Quality (LOW priority — future session)

### 3a. Extract mode dispatch table from main()
- Refactor 12+ sequential if/strcmp chains into a dispatch table
- Reduces main() from 182 → ~50 lines
- Improves extensibility for adding new modes

### 3b. Add RAII wrappers for iccDEV objects
- `std::unique_ptr<CIccProfile>` with custom deleter
- `std::unique_ptr<CIccMatrixMath>` in ProfileCompliance.cpp:311
- Reduces manual delete patterns

### 3c. Consolidate error reporting
- Unify printf/fprintf patterns into LOG_WARN/LOG_ERROR helpers
- Capture structured output for JSON mode consistency

## Verification (run after EACH phase)

```bash
cd iccanalyzer-lite && ./build.sh
python3 tests/run_tests.py               # 230/230
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 ./iccanalyzer-lite -a ../test-profiles/sRGB_D65_MAT.icc
.github/scripts/pre-push-gate.sh          # Full gate
```

## Risk Assessment

- **Phase 1**: Low risk — safety improvements, additive changes
- **Phase 2**: Medium risk — mechanical refactoring across many files, need careful
  testing. NULL→nullptr is safe. SigToChars is well-tested. Format changes affect
  test output matching.
- **Phase 3**: Higher risk — structural refactoring. Defer to future session.
