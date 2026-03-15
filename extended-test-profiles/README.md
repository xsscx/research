# extended-test-profiles/

Security-focused ICC profiles: CVE proof-of-concepts, crash artifacts from CFL/AFL fuzzing,
malformed profiles, and edge-case inputs. All files trigger iccanalyzer-lite findings (exit 1)
or exercise specific bug patterns in iccDEV.

## Inventory (116 profiles)

| Category | Count | Description |
|----------|-------|-------------|
| AFL-generated (`id-*`) | 24 | AFL++ crash/queue samples with auto-generated names |
| Undefined behavior (`ub-*`) | 14 | UBSAN triggers: type confusion, enum OOB, NaN casts, integer overflow |
| Out-of-memory (`oom-*`) | 11 | OOM via uncapped allocations (SetSize, Read, GamutBoundaryDesc) |
| CVE PoCs (`cve-*`) | 10 | CVE-2022-26730, CVE-2023-32443, CVE-2023-46602, CVE-2024-38427 |
| Heap overflows (`heap-*`, `hbo-*`) | 7 | Heap-buffer-overflow in Read, ApplySequence, icAnsiToUtf8 |
| Malformed (`malformed-*`) | 5 | Truncated headers, invalid class, extra bytes |
| Stack overflows (`sbo-*`, `stack-*`) | 4 | Stack-buffer-overflow in GetElemNumberValue, icFixXml, ToXml |
| Known-good reference | 8 | Cat8Lab, PSSwop, Tek350, SC_paper_eci, sample.icc |
| Timeout (`timeout-*`) | 1 | CIccProfile::Describe hang (CWE-400) |
| Slow-unit (`slow-*`) | 2 | Fuzzer-classified slow inputs |
| Other (poc, segv, memcpy, etc.) | 30 | Misc crash types, vendor-specific, fidelity tests |

## OOM Artifacts — Code Path Coverage

Five distinct OOM allocation sites are represented:

| File | Allocation Site | Entry Point |
|------|----------------|-------------|
| `oom-CIccSampledCurveSegment-SetSize-IccMpeBasic_cpp-Line986.icc` (+2 variants) | `IccMpeBasic.cpp:986` | `CIccSegmentedCurve::Read` |
| `oom-CIccSampledCurveSegment-SetSize-IccTagLut_cpp-Line4121.icc` | `IccMpeBasic.cpp:986` | `CIccTagLutAtoB::Read` (different call chain) |
| `oom-CIccSingleSampledCurve-SetSize-IccMpeBasic_cpp-Line1501.icc` | `IccMpeBasic.cpp:1501` | `CIccMpeCurveSet::Read` (different class) |
| `oom-120Gb-CIccTagDict-Read-IccTagDict_cpp-Line580.icc` | `IccTagDict.cpp:580` | Dictionary tag 120GB alloc |
| `oom-CIccTagGamutBoundaryDesc-Read-1024G-IccTagLut_cpp-Line5631.icc` | `IccTagLut.cpp:5631` | GamutBoundary 1TB alloc |

## CVE Coverage

| CVE | Files | Component |
|-----|-------|-----------|
| CVE-2022-26730 | 6 variants | Apple ColorSync heap overflow |
| CVE-2023-32443 | 2 variants | Apple ColorSync |
| CVE-2023-46602 | 1 | iccDEV stack overflow |
| CVE-2023-46867 | 1 (Argyll) | Argyll CMS null byte read |
| CVE-2024-38427 | 1 | iccDEV |

## Naming Convention

```
{crash_type}-{Class}-{Method}-{File}_cpp-Line{N}.icc
cve-{YYYY}-{NNNNN}-{description}-variant-{NNN}.icc
```

Crash types: `hbo` (heap overflow), `sbo` (stack overflow), `segv` (SIGSEGV),
`oom` (out-of-memory), `ub` (undefined behavior), `npd` (null deref),
`so` (stack overflow), `malformed` (structural), `timeout`, `slow-unit`

## Usage

```bash
# Analyze a CVE PoC
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  ./iccanalyzer-lite/iccanalyzer-lite -a extended-test-profiles/cve-2023-46602.icc

# JSON analysis for structured output
./iccanalyzer-lite/iccanalyzer-lite --json extended-test-profiles/oom-CIccSampledCurveSegment-SetSize-IccMpeBasic_cpp-Line986.icc

# Test upstream tool behavior (should reject gracefully)
LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML \
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile extended-test-profiles/cve-2023-46602.icc ALL
```

## Relationship to Other Directories

| Directory | Relationship |
|-----------|-------------|
| `test-profiles/` | Standard profiles (329 v2/v4/v5 across all classes) |
| `test-profiles/cwe-400/` | CWE-400 timeout profiles (491 calculator/recursion) |
| `fuzz/graphics/icc/` | Raw CVE PoC corpus (separate git repo) |
| `cfl/corpus-*` | Fuzzer corpora (include copies of these as seeds) |
