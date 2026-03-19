# CodeQL Query Catalog — iccDEV Security Research

42 queries targeting vulnerability patterns in the iccDEV ICC profile library.
Organized by discovery method: static analysis patterns, CFL fuzzer findings, and
built-in CodeQL rules.

## Maintainer Queries (CFL-048 through CFL-057)

These 7 queries detect the exact bug patterns discovered by CFL fuzzing in March 2026.

### iccdev-describe-param-bounds.ql
- **CFL Patch**: CFL-050 (FormulaCurveSegment), CFL-051 (ParametricCurve)
- **CWE**: CWE-125 (Out-of-bounds Read), CWE-122 (Heap-based Buffer Overflow)
- **Heuristic**: H171 (curve param count validation)
- **Pattern**: `Describe()` methods access `m_params[N]` without verifying
  `m_nParameters >= N+1`. Malformed profiles set `m_nFunctionType` to a value
  requiring more params than provided.
- **Files affected**: `IccMpeBasic.cpp` (FormulaCurveSegment, 8 switch cases),
  `IccTagLut.cpp` (ParametricCurve, 5 switch cases)
- **ICC Spec**: ICC.2-2023 §10.23 (FormulaCurve), ICC.1-2022-05 §10.15 (Parametric)

### iccdev-describe-null-array.ql
- **CFL Patch**: CFL-056 (SpectralMatrix, SpectralObserver)
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **Heuristic**: H98 (expanded — null m_pWhite/m_pOffset check)
- **Pattern**: `Describe()` dereferences member pointers (`m_pWhite`, `m_pOffset`,
  `m_pMatrix`) without null check. `Read()` may partially fail, leaving pointers null.
- **Files affected**: `IccMpeSpectral.cpp` (3 locations: white matrix, offset, observer)

### iccdev-format-specifier.ql
- **CFL Patch**: CFL-053 (FormulaCurve `%8f`→`%.8f`), CFL-054 (ParametricCurve `%lf`→`%.4lf`)
- **CWE**: CWE-134 (Use of Externally-Controlled Format String)
- **Heuristic**: — (output quality, not exploitable)
- **Pattern**: Printf-family calls with wrong format specifiers:
  - `%8f` (width specifier instead of precision — `%.8f`)
  - `%lf` without explicit precision (defaults to 6 digits)
  - `%8.f` (width 8, precision 0 — truncates to integer)
- **Files affected**: `IccMpeBasic.cpp:278,286`, `IccTagLut.cpp:891,903`

### iccdev-signed-unsigned-format.ql
- **CFL Patch**: CFL-055 (fromIt8 `%u` with signed `nColor`)
- **CWE**: CWE-681 (Incorrect Conversion between Numeric Types)
- **Heuristic**: — (output quality, not exploitable)
- **Pattern**: `%u` format specifier with `int` argument — negative values print as
  large positive numbers. `%d` with `unsigned` — large unsigned values print as negative.
- **Files affected**: `IccCmmConfig.cpp:1553,1556`

### iccdev-uninitialized-constructor.ql
- **CFL Patch**: CFL-057 (CIccCfgSearchApply empty constructor)
- **CWE**: CWE-908 (Use of Uninitialized Resource), CWE-457 (Use of Uninitialized Variable)
- **Heuristic**: — (design flaw, triggers UBSAN via `toJson()`)
- **Pattern**: `CIcc*` class constructors with empty body that don't initialize scalar
  members (bool, int, enum, double). `toJson()` serializes the uninitialized values,
  producing UBSAN "load of value N, which is not a valid value for type 'bool'".
- **Files affected**: `IccCmmConfig.cpp` (CIccCfgSearchApply constructor)

### iccdev-wrong-variable-index.ql
- **CFL Patch**: CFL-052 (fromIt8 `nValueIdx` instead of `nSrcIndex`)
- **CWE**: CWE-787 (Out-of-bounds Write), CWE-125 (Out-of-bounds Read)
- **Heuristic**: — (data corruption, hard to detect at runtime)
- **Pattern**: Nested loop uses outer-scope index variable for array subscript
  instead of inner loop variable. Causes wrong data access, potential OOB.
- **Files affected**: `IccCmmConfig.cpp:1651,1656,1670`

### iccdev-dumplut-missing-arg.ql
- **CFL Patch**: CFL-048 (Iterate bUseLegacy as bufSize), CFL-049 (BToA missing bUseLegacy)
- **CWE**: CWE-131 (Incorrect Calculation of Buffer Size), CWE-688 (Function Call With Incorrect Variable or Reference as Argument)
- **Heuristic**: — (output quality)
- **Pattern**: `DumpLut()` or `Iterate()` called with fewer arguments than declared,
  specifically missing the `bUseLegacy` boolean. Compiler implicitly converts or
  misaligns arguments, silently corrupting CLUT grid output.
- **Files affected**: `IccTagLut.cpp:2063` (Iterate), `IccTagLut.cpp:3644` (BToA DumpLut)

---

## Library Pattern Queries (H154-H159 Counterparts)

These 6 queries target patterns identified through CodeQL static analysis of IccProfLib.

### iccdev-read-allocation-overflow.ql
- **CWE**: CWE-789 (Memory Allocation with Excessive Size Value)
- **Heuristic**: H154 (Uncontrolled Tag Allocation Size)
- **Pattern**: `Read()` method uses file-controlled size value for `new[]`/`calloc()`
  without upper bound validation.

### iccdev-clut-dimension-overflow.ql
- **CWE**: CWE-190 (Integer Overflow)
- **Heuristic**: H155 (Integer Overflow in Tag Dimensions)
- **Pattern**: Dimension multiplication overflow in LUT/CLUT/NamedColor tags.

### iccdev-unchecked-alloc-read.ql
- **CWE**: CWE-252 (Unchecked Return Value)
- **Heuristic**: H156 (Allocation Failure Path Profiles)
- **Pattern**: `new`/`calloc()` return value used without null check.

### iccdev-tag-alloc-dealloc-mismatch.ql
- **CWE**: CWE-762 (Mismatched Memory Management Routines)
- **Heuristic**: H157 (Alloc-Dealloc Mismatch)
- **Pattern**: `new[]` allocated memory freed with `free()` or vice versa.
- **CFL Patch**: CFL-003 (CIccTagArray)

### iccdev-file-controlled-enum-cast.ql
- **CWE**: CWE-681 (Incorrect Conversion between Numeric Types)
- **Heuristic**: H158 (Enum Range Violation Detection)
- **Pattern**: File-controlled integer cast to enum type without range validation.
- **CFL Patches**: CFL-005, CFL-009, CFL-017

### iccdev-tag-ownership-uaf.ql
- **CWE**: CWE-416 (Use After Free)
- **Heuristic**: H159 (UAF Tag Ownership Chain)
- **Pattern**: `AddXform(CIccProfile*)` transfers ownership — caller must not use
  profile after call returns.

---

## Memory Safety Queries

### buffer-overflow.ql
- **CWE**: CWE-119 (Buffer Overflow)
- General buffer overflow detection in ICC code.

### icc-buffer-overflow.ql
- **CWE**: CWE-119
- ICC-specific buffer overflow patterns in tag parsing.

### icc-heap-buffer-overflow.ql
- **CWE**: CWE-122 (Heap Buffer Overflow)
- Heap-specific overflow in dynamic allocations.

### icc-stack-buffer-overflow.ql
- **CWE**: CWE-121 (Stack Buffer Overflow)
- Stack buffer overflow in fixed-size arrays.

### cross-container-oob.ql
- **CWE**: CWE-119
- Cross-container size mismatch (CFL-035 pattern).

---

## Type Safety Queries

### iccdev-nan-float-cast.ql
- **CWE**: CWE-681
- NaN/Inf float-to-integer cast (CFL-008/CFL-022/CFL-023 pattern).
- **Heuristic**: H153 (Sampled Curve NaN-to-Unsigned)

### icc-tag-cstyle-cast.ql
- **CWE**: CWE-843 (Type Confusion)
- C-style casts on ICC tag pointers.

---

## Null Safety Queries

### null-pointer-deref.ql
- **CWE**: CWE-476
- NULL pointer dereference patterns.

---

## Code Quality Queries

### uninitialized-read.ql
- **CWE**: CWE-457
- Uninitialized variable reads.

### unsafe-array-new.ql
- **CWE**: CWE-789
- Unbounded `new[]` allocations.

### unsafe-scalar-new.ql
- **CWE**: CWE-789
- Scalar allocations without error checking.

### unaligned-pointer-cast.ql
- **CWE**: CWE-704
- Unaligned pointer casts.

### signed-shift-overflow.ql
- **CWE**: CWE-190
- Signed integer shift overflow.

---

## Tool-Specific Queries

### iccdumpprofile-enum-reachability.ql
- Enum reachability in iccDumpProfile (tool-specific code paths).

### all-tools-enum-reachability.ql
- Enum reachability across all 14 iccDEV CLI tools.

### argv-output-path.ql
- **CWE**: CWE-22 (Path Traversal)
- Output path validation in CLI tools.

---

## Summary Statistics

| Metric | Value |
|--------|-------|
| Total queries | 42 |
| CWE categories covered | 18+ |
| CFL patches cross-referenced | 16 |
| Runtime heuristic counterparts | 10 |
| ICC spec sections referenced | 5 |
