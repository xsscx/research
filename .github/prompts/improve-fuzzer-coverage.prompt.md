# Improve Fuzzer Code Coverage

## Goal
Analyze LLVM coverage reports and create targeted seed ICC profiles and dictionary entries to increase code coverage for the 18 LibFuzzer harnesses.

## Prerequisites
- Fuzzers built: `ls cfl/bin/icc_*_fuzzer | wc -l` should return 18
- Coverage data exists: profraw files in `/mnt/g/fuzz-ssd/profraw/` or `/tmp/fuzz-ramdisk/profraw/`
- LLVM tools: `llvm-profdata-18`, `llvm-cov-18`
- ASAN-instrumented upstream tools: `iccDEV/Build-ASAN/Tools/` (see below)

## Workflow

### 1. Generate Coverage Report
```bash
# Merge all profraw files
llvm-profdata-18 merge -sparse /mnt/g/fuzz-ssd/profraw/*.profraw -o /mnt/g/fuzz-ssd/merged.profdata

# Summary report
OBJS=$(printf ' -object %s' cfl/bin/icc_*_fuzzer)
llvm-cov-18 report $OBJS -instr-profile=/mnt/g/fuzz-ssd/merged.profdata

# HTML report
llvm-cov-18 show $OBJS -instr-profile=/mnt/g/fuzz-ssd/merged.profdata \
  --format=html --output-dir=/mnt/g/fuzz-ssd/coverage-report/html
```

### 2. Identify Coverage Gaps
Rank source files by uncovered lines:
```bash
llvm-cov-18 report $OBJS -instr-profile=/mnt/g/fuzz-ssd/merged.profdata 2>/dev/null | \
  awk 'NR>2 && $0 !~ /TOTAL|---/' | sort -t'%' -k1 -n | head -20
```

For a specific file, find uncovered functions:
```bash
llvm-cov-18 show $OBJS -instr-profile=/mnt/g/fuzz-ssd/merged.profdata --format=text 2>/dev/null | \
  awk '/TargetFile\.cpp:$/{found=1;next} found && /^[^ ].*\.cpp:$/{found=0} found && /\|      0\|/' | head -30
```

### 3. Create Seed Profiles
Two approaches:

**A. Harvest from test-profiles/** — Find profiles with tag types not already in seed corpora:
```python
# Compare tag types in test-profiles/ vs existing seed corpus
# Copy missing profiles with doOpenPath bit set: data[-2] |= 0x08
```

**B. Patch existing valid profiles** — For specific tag types:
```python
# Start with a valid profile (e.g., sample.icc, sRgbEncodingOverrides.icc)
# Add tag: increment tag_count, insert 12-byte entry in tag table, shift offsets, append tag data
# Tag data format: type_sig(4) + reserved(4) + type-specific payload
# MUST pad to 4-byte boundaries
# Set doOpenPath: data[-2] |= 0x08 (uses non-validating Read() path)
```

**Critical**: Minimal hand-crafted ICC profiles FAIL `ValidateIccProfile()` — always patch existing valid profiles.

### 4. Add Dictionary Entries
Add tokens for uncovered code paths to fuzzer `.dict` files:
```
# Format: token_name="value" or token_name="\xHH\xHH\xHH\xHH"
tag_type="mft1"
tag_sig="\x41\x32\x42\x30"
```

Target dicts: `cfl/icc_deep_dump_fuzzer.dict`, `cfl/icc_profile_fuzzer.dict`, `cfl/icc_dump_fuzzer.dict`

### 5. Smoke Test
Run fuzzers for 60s each with new seeds and dicts:
```bash
for fuzzer in deep_dump profile dump; do
  BIN="/mnt/g/fuzz-ssd/bin/icc_${fuzzer}_fuzzer"
  CORPUS="/mnt/g/fuzz-ssd/corpus-icc_${fuzzer}_fuzzer"
  ASAN_OPTIONS=detect_leaks=0 \
  LLVM_PROFILE_FILE="/mnt/g/fuzz-ssd/profraw/icc_${fuzzer}_fuzzer_%m_%p.profraw" \
    "$BIN" -max_total_time=60 -detect_leaks=0 -timeout=30 -rss_limit_mb=4096 \
    -use_value_profile=1 -max_len=5242880 \
    -dict="cfl/icc_${fuzzer}_fuzzer.dict" \
    "$CORPUS/" > /tmp/fuzz_${fuzzer}.log 2>&1 &
done
wait
```

### 6. Measure and Commit
```bash
# Re-merge and compare
llvm-profdata-18 merge -sparse /mnt/g/fuzz-ssd/profraw/*.profraw -o /mnt/g/fuzz-ssd/merged.profdata
llvm-cov-18 report $OBJS -instr-profile=/mnt/g/fuzz-ssd/merged.profdata

# Commit seeds and dicts (need -f for gitignored dirs)
git add -f cfl/icc_*_seed_corpus/*.icc
git add cfl/icc_*.dict
git add -f coverage-report/
git commit -m "coverage: <description of improvements>"
```

## Fuzzer-Coverage Mapping
| Fuzzer | Key source files covered |
|--------|--------------------------|
| deep_dump, profile, dump | IccTagBasic, IccProfile, IccMpeBasic, IccTagLut |
| apply, applyprofiles, link | IccCmm, IccApplyBPC, IccPcc |
| toxml, fromxml | IccTagXml, IccProfileXml, IccXmlLib |
| specsep, tiffdump | TiffImg |
| calculator | IccMpeCalc |
| io | IccIO |
| spectral, v5dspobs | IccMpeSpectral |

## Profile Class Coverage Audit

**ALWAYS** verify all 7 ICC classes are seeded before extended fuzzing. Printer
profiles are the most LUT-dense class and exercise critical parser paths:

| Class | Example Seeds | Key Code Paths |
|-------|---------------|----------------|
| `mntr` (Display) | sRGB, Display P3 | Matrix+TRC, para curves, chad |
| `prtr` (Printer) | Tek350Monaco2, SC_paper_eci | AToB/BToA LUT pairs, gamt, CMYK |
| `scnr` (Scanner) | — | Input transforms, calibration |
| `link` (DeviceLink) | — | Direct device-to-device transforms |
| `spac` (ColorSpace) | — | Non-device color spaces |
| `abst` (Abstract) | — | Abstract transforms |
| `nmcl` (NamedColor) | — | Named color lookup |

### Printer Profile Anatomy (Tek350Monaco2 — 405KB)
- **7 LUT tags** = 77% of profile is dense numerical data
- AToB0/1/2: 17³ = 4,913 CLUT entries each (mft1 type, 16KB)
- BToA0/1/2: 33³ = 35,937 CLUT entries each (mft1 type, 109KB)
- gamt: 3→1 channel reduction (33³ grid, 37KB)
- Monaco CMM (`mnco`), v2.0, RGB→Lab PCS

## Coverage Baseline (March 2026, extended run)
| Metric | Value |
|--------|-------|
| Lines | 61.15% |
| Branches | 58.47% |
| Functions | 63.23% |
| Instantiations | 62.99% |

## Upstream Tool vs Fuzzer Fidelity

Build upstream tools with ASAN+Coverage for comparison:
```bash
cd iccDEV && mkdir -p Build-ASAN && cd Build-ASAN
cmake ../Build/Cmake -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_BUILD_TYPE=Debug -DENABLE_SANITIZERS=ON -DENABLE_COVERAGE=ON
make -j32
```

Run tool against corpus, then compare:
```bash
# Collect upstream tool coverage
for f in test-profiles/*.icc fuzz/graphics/icc/*.icc; do
  LLVM_PROFILE_FILE=/tmp/tool-cov/dump_%m.profraw \
  LD_LIBRARY_PATH=iccDEV/Build-ASAN/IccProfLib:iccDEV/Build-ASAN/IccXML \
    timeout 5 iccDEV/Build-ASAN/Tools/IccDumpProfile/iccDumpProfile "$f" >/dev/null 2>&1
done

# Collect fuzzer coverage
LLVM_PROFILE_FILE=/tmp/tool-cov/fuzz_%m.profraw ASAN_OPTIONS=detect_leaks=0 \
  cfl/bin/icc_dump_fuzzer -runs=0 cfl/corpus-icc_dump_fuzzer/

# Compare function-level fidelity
llvm-cov-18 export <tool_binary> -instr-profile=<tool.profdata> -format=lcov | \
  grep 'FNDA:[1-9]' | sed 's/FNDA:[0-9]*,//' | sort > tool-funcs.txt
llvm-cov-18 export <fuzzer_binary> -instr-profile=<fuzzer.profdata> -format=lcov | \
  grep 'FNDA:[1-9]' | sed 's/FNDA:[0-9]*,//' | sort > fuzzer-funcs.txt
comm -23 tool-funcs.txt fuzzer-funcs.txt  # Functions in tool but not fuzzer
```

**Measured fidelity** (March 2026):

| Tool / Fuzzer | Functions | Lines | Fidelity |
|---------------|-----------|-------|----------|
| iccFromCube (upstream) | 3.62% | 3.96% | — |
| icc_fromcube_fuzzer | 3.75% | 4.07% | **100%** (only `main` missing) |
| iccDumpProfile (upstream) | 1.56% | 1.88% | — |
| icc_dump_fuzzer | 29.99% | 27.65% | **>100%** (custom icRealloc) |
| iccToXml (upstream) | 13.47% | 20.30% | — |
| iccRoundTrip (upstream) | 22.58% | 28.65% | — |

## Corpus State (March 2026, post-SSD migration)
| Fuzzer | Files | Priority |
|--------|-------|----------|
| tiffdump | 47,158 | — |
| applynamedcmm | 32,214 | — |
| specsep | 30,764 | — |
| applyprofiles | 28,582 | — |
| fromxml | 27,648 | — |
| v5dspobs | 24,882 | — |
| toxml | 23,848 | — |
| apply | 21,303 | — |
| deep_dump | 19,209 | — |
| calculator | 18,038 | — |
| profile | 14,416 | — |
| dump | 14,173 | — |
| multitag | 12,333 | — |
| roundtrip | 7,269 | SLOW (Read→Write→Read per input) |
| link | 1,859 | NEEDS quarantine_size_mb=256 |
| io | 1,103 | SMALL — needs more seeds |
| spectral | 1,009 | SMALL — needs more seeds |
| fromcube | 381 | OPTIMIZED (was 1,993/199MB → 381/2.2MB, +77% exec/s) |

## Top Coverage Gaps (by missed lines)
| File | Missed | Coverage | Priority | Target Fuzzers |
|------|--------|----------|----------|----------------|
| IccCmm.cpp | 4,063 | 36.6% | CRITICAL | apply, applyprofiles, link (needs profile PAIRS) |
| IccTagBasic.cpp | 2,327 | 60.8% | HIGH | deep_dump, profile, dump |
| IccTagXml.cpp | 2,185 | 46.5% | HIGH | toxml, fromxml |
| IccMpeSpectral.cpp | 828 | 31.8% | HIGH | spectral, v5dspobs |
| IccPcc.cpp | 359 | 16.5% | HIGH | spectral, v5dspobs (needs differing viewing conditions) |
| IccSparseMatrix.cpp | 314 | 26.8% | HIGH | deep_dump, profile (needs sparse matrix tags) |
| IccCmmSearch.cpp | 275 | 0.0% | LOW | NONE — no fuzzer exercises this API |
| IccEval.cpp | 95 | 0.0% | LOW | NONE — needs new fuzzer |

### Key Insight: IccCmm.cpp
IccCmm.cpp has the most missed lines but requires profile PAIRS (not single profiles) to
trigger the CMM pipeline (AddXform→Begin→Apply). Seed corpora need matched pairs:
- sRGB + CMYK (3DLut/4DLut paths)
- Lab + Lab with different whitepoints (PCS step chain)
- v5 MPE profile pairs (CIccXformMpe)
- NamedColor + device profile (CIccNamedColorCmm)

### CMM Fuzzer Input Formats (CRITICAL for seed creation)
| Fuzzer | Format | Min Size |
|--------|--------|----------|
| `icc_link_fuzzer` | profile1 + profile2 + 4 ctrl bytes | 258 |
| `icc_applyprofiles_fuzzer` | 75% profile + 25% control [intent, interp, unused, flags] | 200 |
| `icc_applynamedcmm_fuzzer` | 4-byte header [flags, intent, extra1, extra2] + profile | 132 |
| `icc_apply_fuzzer` | entire input is one ICC profile | 130 |

**Link fuzzer ctrl byte bits (size-3)**: 0x01=firstTransform, 0x02=noD2Bx, 0x04=BPC, 0x08=luminance,
0x10=subProfile, bits5-7=lutType(0-7). **ctrl2 byte (size-4)**: 0x01=saveLink, 0x02=envVars, bits2-3=gridSize.

**ApplyNamedCmm flags byte bits**: 0x01=BPC, 0x02=D2Bx, 0x04=luminance, 0x08=subProfile,
0x10=tetrahedral, 0x40=pccEnvVars, 0x80=envVars. **Intent byte**: bits0-1=intent, bits4-6=nType, bit7=HToS.

**For detailed per-fuzzer documentation** (input formats, coverage gaps, dead code, seed strategies,
tool fidelity, dict syntax), see `fuzzer-optimization.prompt.md`.

### UBSAN Fix Patterns (for iccanalyzer-lite code)
When extracting 4-byte ICC signatures into `char[5]`:
- ALWAYS use `static_cast<char>()` — values >127 trigger UBSAN implicit-conversion
- Prefer `SignatureToFourCC()` helper which handles cast + trailing space trim
- For `tOffset + tSize` additions, use `(uint64_t)` widening to prevent unsigned overflow
- 18 sites fixed across IccHeuristicsRawPost.cpp and IccHeuristicsLibrary.cpp

## CodeQL Status (March 2026)
| Metric | Value |
|--------|-------|
| Total alerts | 4 |
| In analyzer code | 0 |
| In iccDEV upstream | 4 (assignment-does-not-return-this) |
| Fixed this session | 19 (constant-comparison, complex-condition, path-injection) |

## See Also
- [fuzzer-optimization.prompt.md](fuzzer-optimization.prompt.md) — Coverage improvement strategies
- [corpus-management.prompt.md](corpus-management.prompt.md) — Corpus storage operations
- [fuzz-corpus-analysis.prompt.md](fuzz-corpus-analysis.prompt.md) — Corpus inventory and audit
- [triage-fuzzer-crash.prompt.md](triage-fuzzer-crash.prompt.md) — Fuzzer crash triage
