# Triage Fuzzer Crash

Use this prompt when a fuzzer reports ASAN (heap-buffer-overflow, heap-use-after-free, stack-buffer-overflow, stack-overflow, SEGV) or UBSAN (runtime error) findings.

## Step 1 — Classify the finding

**STOP — Exit Code Gate (CJF-13)**

Before classifying ANY finding, determine the exit code:
- **Exit 1-127**: The tool rejected the input gracefully. This is NOT a crash.
  Do NOT document as a security finding. Do NOT proceed to Step 2.
- **Exit 128+**: Signal termination — proceed to classification below.
- **Exit 0 with ASAN/UBSAN stderr**: Memory safety bug — proceed to classification below.

The **tool's** exit code is reality. The **fuzzer's** DEADLYSIGNAL is a test artifact.
When they disagree, the tool is authoritative. Always verify with the upstream tool:
```bash
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  timeout 30 iccDEV/Build/Tools/<ToolDir>/<tool> <crash-file>; echo "EXIT: $?"
```

**If tool exits 0 or 1-127 but fuzzer shows DEADLYSIGNAL**: This is a fuzzer fidelity
issue, not an upstream bug. Do NOT document as a crash.

Origin: [xsscx/governance CJF-13](https://github.com/xsscx/governance) — exit code
confusion is the #1 crash documentation error pattern.

From the fuzzer output, determine:
- **Fuzzer name** (e.g., `icc_link_fuzzer`)
- **Error type**: ASAN class (heap-use-after-free, heap-buffer-overflow, stack-overflow, SEGV) or UBSAN (runtime error description)
- **Source location**: file:line from the stack trace
- **CWE mapping**: e.g., CWE-122 (heap BOF), CWE-416 (UAF), CWE-787 (OOB write), CWE-758 (undefined behavior)

## Step 2 — Attribute by file path, NOT by filename

**MANDATORY — CJF Envelope Rule (added 2026-03-10)**:

Read ASAN/UBSAN stack frame #2-#3 and classify by the **source file path**:

| Path contains | Classification | Action |
|---------------|---------------|--------|
| `iccanalyzer-lite/` | **OUR CODE** | Fix immediately in analyzer |
| `colorbleed_tools/` | **OUR CODE** | Fix immediately in colorbleed |
| `cfl/icc_*_fuzzer.cpp` | **OUR CODE** | Fix the fuzzer harness |
| `iccDEV/IccProfLib/` | **UPSTREAM** | Create CFL patch + report upstream |
| `iccDEV/Tools/` | **UPSTREAM** | Create CFL patch + report upstream |
| `libtiff.so` / `libpng` / etc. | **SYSTEM LIB** | Triggered by our usage — fix our call site |

**NEVER classify by profile filename**. A profile named `ub-runtime-error-*` does NOT
mean the bug is in upstream iccDEV — it means the profile was originally found via UB,
but the ASAN trace determines WHERE the bug actually lives.

**Incident reference**: Session 2026-03-10 — HUAF at `IccImageAnalyzer.cpp:962`
(our code) was misclassified as "upstream iccDEV" for an entire session because the
profile was named `ub-runtime-error-type-confusion-CIccTagEmbeddedProfile`. The ASAN
frames clearly showed our file. Fix was 10 lines (copy libtiff interior pointers to
`std::string` before directory-walking heuristics).

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

### NULL deref after unchecked Begin() (CWE-476)
- `CIccTagMultiProcessElement::Begin()` and `CIccMpeCurveSet::Begin()` return false
  when sub-curves have invalid state (e.g., `CIccSingleSampledCurve` with `m_nCount < 2`).
- If caller doesn't check, `Apply()` dereferences NULL `m_pSamples` → SEGV.
- Upstream tools with this gap: `IccV5DspObsToV4Dsp.cpp:164`. Fix: patch 072.
- **Pattern**: Always check `if (!pTag->Begin(...)) { /* bail */ }` before calling `Apply()`.

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
# For single-profile fuzzers:
ASAN_OPTIONS=detect_leaks=0 timeout 5 iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles \
  /tmp/test_rgb.tif /tmp/out.tif 1 0 0 0 0 <crash-file> 0 2>&1 | grep "runtime error"

# For multi-profile fuzzers (v5dspobs, link, applyprofiles):
.github/scripts/unbundle-fuzzer-input.sh <fuzzer_name> <crash-file>
# This extracts profiles to ./tmp/icc_<fuzzer_name>/ and runs the tool automatically
```

**IMPORTANT**: For multi-profile fuzzers, do NOT pass the raw crash file directly
to the tool — it will fail with "Unable to parse" because the fuzzer's concatenated
format (e.g., 4-byte size prefix) is not a valid ICC file. Always unbundle first.

**CRITICAL**: Always use `iccDEV/Build/Tools/` (UNPATCHED upstream) for fidelity
testing — NEVER `cfl/iccDEV/` (which has 60+ CFL patches applied).

### Timeout-specific triage (CWE-400)

For `timeout-*` artifacts, the workflow differs from crash triage:

1. **Check upstream**: Run PoC through the matching upstream tool with `timeout 30`:
   ```bash
   LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
     timeout 30 iccDEV/Build/Tools/<ToolDir>/<tool> <timeout-file>
   ```
2. **If upstream also hangs** → Legitimate algorithmic bug. Create CFL patch.
3. **If upstream handles it quickly** → Fuzzer-specific issue (e.g., different code path or excessive looping in harness).
4. **Common timeout patterns**:
   - Exponential recursion: `CheckUnderflowOverflow` → fix with global ops budget (CFL-074)
   - Grid explosion: `EvaluateProfile` nGran^ndim → fix with iteration cap (CFL-075)
   - XML parsing loops: Large `mluc`/`ProfileSeqDesc` → fix with element count cap

Map to CVE CWE distribution: CWE-20 (49), CWE-122 (17), CWE-476 (16), CWE-125 (11), CWE-758 (11), CWE-787 (10).

### TIFF-specific triage (CTiffImg patterns)

For crashes in `CTiffImg::ReadLine()` or `CTiffImg::Open()`:
1. The crash file is a raw TIFF, not an ICC profile — use `tiffinfo` to inspect headers
2. Check strip geometry: `tiffinfo <crash-file>` — look for StripByteCounts vs Image Width/Height/RowsPerStrip
3. **Upstream repro**: Pass TIFF to `iccApplyProfiles` with a known-good ICC profile:
   ```bash
   LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
     iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles \
     <crash.tiff> /tmp/out.tif 0 0 0 0 1 test-profiles/Rec2020rgbSpectral.icc 1
   ```
4. **Common pattern**: Strip buffer sized by TIFFStripSize() < RowsPerStrip × BytesPerLine
   → heap-buffer-overflow in ReadLine() memcpy. Fix: CFL-082 (bounds check in Open()).
5. **iccTiffDump is NOT affected** by ReadLine() bugs — it only reads TIFF metadata.
6. For TIFF crash files, `iccanalyzer-lite -a <file.tif>` runs H139-H141 TIFF security heuristics (strip geometry CWE-122/190, dimension validation CWE-400/131, IFD offset bounds CWE-125) before ICC extraction.

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

## See Also
- [triage-fuzzer-oom.prompt.yml](triage-fuzzer-oom.prompt.yml) — OOM triage workflow
- [triage-cve-poc.prompt.yml](triage-cve-poc.prompt.yml) — CVE PoC analysis workflow
- [fuzzer-optimization.prompt.md](fuzzer-optimization.prompt.md) — Coverage improvement after fix
- [upstream-sync.prompt.md](upstream-sync.prompt.md) — Patch reconciliation workflow
- [docs/pocs/iccdev-issue-reproductions.md](../../docs/pocs/iccdev-issue-reproductions.md) — 63 PoC reproduction steps for closed iccDEV issues
