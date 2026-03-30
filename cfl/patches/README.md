# CFL Library Patches — Active Security Fixes

Last Updated: 2026-03-29

45 active patch files are currently present in this directory.

For analyzer/runtime review against the unpatched-library policy, the normalized
source of truth is:

- `docs/analysis/ICCANALYZER_CFL_PATCH_COVERAGE_MATRIX.csv`
- `docs/analysis/ICCANALYZER_CFL_PATCH_COVERAGE_MATRIX.md`

**Architecture**: Post-retirement minimal patch set. Retired/upstreamed patches
still exist in project history, but this directory now carries only the current
active patch files used by CFL.

**Build**: `cd cfl && ./build.sh` applies all patches from this directory automatically.

## Active Patches

The table below is preserved as a patch-family quick reference. For current
counts and analyzer coverage status, prefer the matrix files above.

| # | Patch File | Bug | CWE | Files Modified |
|---|-----------|-----|-----|----------------|
| 001 | `001-icAnsiToUtf8-null-termination.patch` | HBO via strlen on unterminated 32-byte name | CWE-125/CWE-170 | IccTagBasic.cpp, IccUtilXml.cpp |
| 002 | `002-gamutboundary-triangles-signed-overflow.patch` | Signed int overflow: m_NumberOfTriangles*3 | CWE-190 | IccTagLut.cpp |
| 004 | `004-ToneMapFunc-Read-parameter-count-validation.patch` | HBO via Describe() accessing m_params[0..2] with only 1 allocated | CWE-122 | IccMpeBasic.cpp |
| 005 | `005-calculatorfunc-read-enum-ubsan.patch` | Enum out-of-range in calculator op read | CWE-681 | IccMpeCalc.cpp |
| 006 | `006-SpectralMatrix-Describe-iteration-bounds.patch` | HBO via Describe() iterating m_nOutputChannels rows | CWE-122 | IccMpeSpectral.cpp |
| 007 | `007-TagArray-Read-overflow-guard.patch` | Integer overflow in TagArray element count | CWE-190 | IccTagComposite.cpp |
| 008 | `008-TagCurve-Apply-NaN-to-unsigned-UBSAN.patch` | NaN bypasses [0,1] clamp, cast to unsigned is UB | CWE-681 | IccTagLut.cpp |
| 009 | `009-envvar-exec-enum-ubsan.patch` | Enum out-of-range in CIccOpDefEnvVar::Exec() | CWE-681 | IccMpeCalc.cpp |
| 014 | `014-sequenceneedtempreset-recursion-depth.patch` | SequenceNeedTempReset recursion depth limit | CWE-674 | IccMpeCalc.cpp |
| 017 | `017-envvar-getEnvSig-parse-enum-ubsan.patch` | Enum out-of-range in GetEnvSig() XML parse path | CWE-681 | IccMpeCalc.cpp, IccMpeCalc.h |
| 019 | `019-pcc-getReflectanceObserver-null-guard.patch` | NPD when PCC profile lacks spectralViewingConditionsTag | CWE-476 | IccPcc.cpp |
| 021 | `021-singlesampled-curve-oom-size-validation.patch` | SingleSampledCurve::Read OOM via unchecked nCount before SetSize() | CWE-770 | IccMpeBasic.cpp |
| 022 | `022-calc-trunc-floor-ceil-round-mod-int-overflow.patch` | Large float-to-int cast in 5 calculator ops | CWE-681 | IccMpeCalc.cpp |
| 023 | `023-sampled-curve-nan-to-unsigned-cast.patch` | 3 Apply() NaN-to-unsigned casts | CWE-681 | IccMpeBasic.cpp |
| 025 | `025-clut-interpnd-null-apply-guard.patch` | NULL CIccApplyCLUT deref in InterpNd path | CWE-476 | IccTagLut.cpp |
| 028 | `028-matrixmath-setrange-nan-guard.patch` | NaN-to-unsigned-short in SetRange() | CWE-681 | IccMatrixMath.cpp |
| 029 | `029-tagarray-operator-eq-loop-var.patch` | Loop variable modified inside body | CWE-824 | IccTagComposite.cpp |
| 030 | `030-fixednum-getvalues-sbo.patch` | GetValues loop uses m_nSize instead of nVectorSize | CWE-121 | IccTagBasic.cpp |
| 031 | `031-loadjsonfrom-ftell-overflow.patch` | ftell() unchecked return on non-seekable fd → pointer overflow | CWE-190/CWE-252 | IccJsonUtil.cpp |
| 032 | `032-icxforminterp-enum-range.patch` | icXformInterp enum out-of-range from unchecked CLI atoi() | CWE-20/CWE-681 | IccCmmConfig.cpp, iccApplyToLink.cpp |

### CFL-019 Detail — Cross-Tool Validation

**Bug**: `getPccViewingConditions()` returns NULL when PCC profile lacks `svcn` tag.
NPD in `getReflectanceObserver()` (line 294). Lines 164, 200, 233 already had NULL checks.

### CFL-030 Detail — FixedNum GetValues Stack Buffer Overflow

**Bug**: `CIccTagFixedNum::GetValues()` loop iterates `m_nSize` (total elements in tag)
instead of `nVectorSize` (caller-requested count). When `GetElemNumberValue()` calls
`GetValues(&rv, 0, 1)` with a single `icFloatNumber rv` on the stack, and the tag has
`m_nSize > 1`, the loop writes past the stack variable — stack-buffer-overflow.

**ASAN trace**: `WRITE of size 4` at `IccTagBasic.cpp:5525` →
`CIccTagFixedNum<unsigned int, 1969632050>::GetValues(float*, unsigned int, unsigned int)`

**Root cause**: Guard check `nVectorSize+nStart > m_nSize` passes, but the loop
condition `i < m_nSize` should be `i < nVectorSize`. Sibling functions
`CIccTagNum::GetValues()` and `CIccTagFloatNum::GetValues()` already use `nVectorSize`
correctly — this was a copy-paste inconsistency in `CIccTagFixedNum` only.

**Fix**: Change `for (i=0; i<m_nSize; i++)` to `for (i=0; i<nVectorSize; i++)` in both
S15Fixed16 and U16Fixed16 branches (2 sites).

**Trigger path**: v5 `cenc` profile with `cept` struct tag → `icConvertEncodingProfile()` →
`ConvertFromParams()` → `GetElemNumberValue()` → `GetValues(&rv, 0, 1)` with `m_nSize > 1`.

**PoC (fuzzer)**: `extended-test-profiles/sbo-GetValues-FixedNum-IccTagBasic_cpp-Line5519.icc`
(5410-byte link fuzzer input — unbundle with `unbundle-fuzzer-input.sh link`)

**PoC (crafted)**: `extended-test-profiles/sbo-GetValues-FixedNum-crafted-cenc.icc`
(704-byte v5 cenc profile — based on ISO22028-Encoded-sRGB.icc with `ceptWhitePointLuminanceMbr`
changed from `float32ArrayType` (1 element) to `s15Fixed16ArrayType` (4 elements))

**Upstream tools**: Confirmed reproducible in 3 upstream CLI tools:

```bash
# iccApplyToLink — SBO at IccTagBasic.cpp:5520 (exit 1/SIGABRT)
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
ASAN_OPTIONS=halt_on_error=1,detect_leaks=0 \
  iccDEV/Build/Tools/IccApplyToLink/iccApplyToLink \
  /tmp/out.icc 0 33 0 test 0.0 1.0 0 0 \
  extended-test-profiles/sbo-GetValues-FixedNum-crafted-cenc.icc 1 \
  source-of-truth/Testing/Display/sRGB_D65_MAT.icc 1

# iccApplyNamedCmm — SBO at IccTagBasic.cpp:5520 (exit 141/SIGABRT)
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
ASAN_OPTIONS=halt_on_error=1,detect_leaks=0 \
  iccDEV/Build/Tools/IccApplyNamedCmm/iccApplyNamedCmm \
  -cfg <(echo '{"dataFiles":{"srcType":"colorData"},"profileSequence":[{"iccFile":"extended-test-profiles/sbo-GetValues-FixedNum-crafted-cenc.icc","intent":1},{"iccFile":"source-of-truth/Testing/Display/sRGB_D65_MAT.icc","intent":1}],"colorData":{"space":"RGB ","encoding":"float","data":[{"values":[0.5,0.5,0.5]}]}}')

# iccApplyProfiles — SBO at IccTagBasic.cpp:5520 (exit 141/SIGABRT)
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
ASAN_OPTIONS=halt_on_error=1,detect_leaks=0 \
  iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles \
  source-of-truth/Testing/mcs/CMYKSS-Numbered-Overprint.tif /tmp/out.tif 1 0 0 0 0 \
  extended-test-profiles/sbo-GetValues-FixedNum-crafted-cenc.icc 1 \
  source-of-truth/Testing/Display/sRGB_D65_MAT.icc 1
```

**iccanalyzer-lite**: H22 (NumArray Scalar Expectation) detects this pattern.

### CFL-031 Detail — loadJsonFrom ftell() Integer Overflow

**Bug**: `loadJsonFrom()` in `IccJsonUtil.cpp:439` calls `ftell(f)` after `fseek(SEEK_END)`
and assigns the result directly to `unsigned long flen` without checking for error.
`ftell()` returns `-1` on non-seekable file descriptors (pipes, process substitutions,
FIFOs). Cast to `unsigned long`, `-1` becomes `0xFFFFFFFFFFFFFFFF`. Then:

1. `malloc(flen+1)` → `malloc(0)` (integer wrap, CWE-190) → tiny allocation
2. `buf[flen] = 0` → pointer arithmetic overflow (UBSAN: "addition of unsigned offset overflowed")

**UBSAN trace**: `IccJsonUtil.cpp:444:7: runtime error: addition of unsigned offset to 0x502000000070 overflowed to 0x50200000006f`

**Root cause**: `ftell()` return value is **unchecked** — CWE-252 (Unchecked Return Value)
combined with CWE-190 (Integer Overflow). The function was written assuming regular files
only, but process substitutions (`<(echo '...')`) and named pipes produce non-seekable fds.

**Fix**: Check `ftell()` return before use: `long pos = ftell(f); if (pos <= 0) { fclose(f); return false; }`

**Affected tools**: `iccApplyNamedCmm`, `iccApplyProfiles`, `iccApplySearch` — any tool
using `-cfg <file>` with a non-seekable file descriptor.

**Note**: This is a **CLI tool infrastructure bug**, not a library/profile bug.
`IccJsonUtil.cpp` is compiled into CLI tools only — NOT into IccProfLib or CFL fuzzer
binaries. iccanalyzer-lite cannot detect this from ICC profile content.

**Reproduction**:
```bash
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
UBSAN_OPTIONS=halt_on_error=0,print_stacktrace=1 \
  iccDEV/Build/Tools/IccApplyNamedCmm/iccApplyNamedCmm \
  -cfg <(echo '{"dataFiles":{"srcType":"colorData"},"profileSequence":[{"iccFile":"source-of-truth/Testing/Display/sRGB_D65_MAT.icc","intent":1}],"colorData":{"space":"RGB ","encoding":"float","data":[{"values":[0.5,0.5,0.5]}]}}')
```

## Retired Patches (accepted upstream via PRs #680-#695)

| # | Patch | Upstream PR |
|---|-------|-------------|
| 003 | TagArray alloc-dealloc mismatch | #680, #693 |
| 010 | CheckUnderflowOverflow recursion | #684 |
| 011 | SpecSepToTiff unique_ptr array | pre-v2.3.1.5 |
| 012 | NDLut InterpND null ApplyCLUT | pre-v2.3.1.5 |
| 013 | TagArray Cleanup uninit guard | pre-v2.3.1.5 |
| 015 | SpecSepToTiff strip geometry HBO | pre-v2.3.1.5 |
| 016 | NaN guard unsigned cast UBSAN | pre-v2.3.1.5 |
| 018 | TagUnknown Describe HBO underflow | #689 |
| 019-old | PCC null spectral viewing (both sites) | #691 (partial) |
| 020 | SampledCalculatorCurve Begin channel | #694 |
| 024 | TagArray Cleanup UAF guard | #683 |
| 026 | TagArray copy/assign UAF guard | #680, #693 |
| 027 | JSON toJson() key typos | #692 |

### CFL-021 Detail — SingleSampledCurve OOM Size Validation

**Bug**: `CIccSingleSampledCurve::Read()` calls `SetSize(m_nCount)` →
`malloc(nCount * sizeof(icFloatNumber))` BEFORE validating nCount against
remaining stream size. Crafted profiles with `nCount = 0xEB001000` (14.7 GB)
or `nCount = 0xDA000002` (13.6 GB) trigger OOM abort (SIGABRT).

**Fix**: Reorder — check `m_nCount > size - headerSize` BEFORE `SetSize()`.

**Files Modified**: `IccProfLib/IccMpeBasic.cpp`

### CFL-032 Detail — icXformInterp Enum Out-of-Range

**Bug**: `atoi()` on CLI interpolation argument cast directly to `icXformInterp` enum
without range validation. The enum only defines 2 values: `icInterpLinear=0` and
`icInterpTetrahedral=1`. Any other integer (e.g., 33) is undefined behavior per C++.

**UBSAN trace**: `IccCmmConfig.cpp:778: runtime error: load of value 33, which is not
a valid value for type 'icXformInterp'`

**Reproduction (upstream)**:
```bash
UBSAN_OPTIONS=halt_on_error=0,print_stacktrace=1 \
LD_LIBRARY_PATH=source-of-truth/IccProfLib:source-of-truth/IccXML \
  source-of-truth/Tools/CmdLine/IccApplyNamedCmm/iccApplyNamedCmm \
  /tmp/out.icc 0 33 0 test 0.0 1.0 0 0 \
  extended-test-profiles/sbo-GetValues-FixedNum-crafted-cenc.icc 1 \
  source-of-truth/Testing/Display/sRGB_D65_MAT.icc 1
```

**Fix**: Parse `atoi()` into `int`, then map: `0 → icInterpLinear`, else `icInterpTetrahedral`.
Applied at 3 sites: IccCmmConfig.cpp (2 sites) and iccApplyToLink.cpp (1 site).

**Files Modified**: `Tools/CmdLine/IccCommon/IccCmmConfig.cpp`, `Tools/CmdLine/IccApplyToLink/iccApplyToLink.cpp`

## CWE Distribution

| CWE | Count | Category |
|-----|-------|----------|
| CWE-681 | 7 | Incorrect Type Conversion (UBSAN enum, NaN, int overflow) |
| CWE-20  | 1 | Improper Input Validation |
| CWE-125 | 1 | Out-of-bounds Read |
| CWE-121 | 1 | Stack Buffer Overflow |
| CWE-122 | 2 | Heap Buffer Overflow |
| CWE-190 | 3 | Integer Overflow |
| CWE-252 | 1 | Unchecked Return Value |
| CWE-674 | 1 | Uncontrolled Recursion |
| CWE-476 | 2 | Null Pointer Dereference |
| CWE-170 | 1 | Missing Null Termination |
| CWE-770 | 1 | Allocation without Limits (OOM) |
| CWE-824 | 1 | Uninitialized Pointer Access |

## Patch Lifecycle

1. **Discover** — Fuzzer finds crash/UB via ASAN+UBSAN
2. **Reproduce** — Confirm with upstream `iccDEV/Build/Tools/` (unpatched, ASAN)
3. **Fix** — Minimal targeted patch in `cfl/iccDEV/`
4. **Generate** — `cd cfl/iccDEV && git diff > ../patches/NNN-name.patch`
5. **Verify** — Rebuild fuzzer, confirm PoC exits clean
6. **Report** — File upstream issue at InternationalColorConsortium/iccDEV
7. **Retire** — When upstream adopts fix, move patch to retired-patches/

## Related Files

- `../seeds/icc/` — Seed corpus for CFL fuzzers (206 ICC profiles)
- `../seeds/tiff/` — TIFF test images (5 Catalyst-generated)
- `../seeds/images/` — PNG/JPG CVE PoCs for image parser testing
- `../../CreateAllProfiles.sh` — Generates ICC profiles from XML sources
