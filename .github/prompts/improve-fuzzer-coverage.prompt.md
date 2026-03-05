# Improve Fuzzer Code Coverage

## Goal
Analyze LLVM coverage reports and create targeted seed ICC profiles and dictionary entries to increase code coverage for the 19 LibFuzzer harnesses.

## Prerequisites
- Fuzzers built: `ls cfl/bin/icc_*_fuzzer | wc -l` should return 19
- Coverage data exists: profraw files in `/mnt/g/fuzz-ssd/profraw/` or `/tmp/fuzz-ramdisk/profraw/`
- LLVM tools: `llvm-profdata-18`, `llvm-cov-18`

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
| specsep, spectral_b, tiffdump | TiffImg |
| calculator | IccMpeCalc |
| io | IccIO |
| spectral, v5dspobs | IccMpeSpectral |

## Coverage Baseline (March 2026)
| Metric | Value |
|--------|-------|
| Lines | 58.85% |
| Branches | 56.56% |
| Functions | 59.71% |
| Regions | 60.88% |

## CodeQL Status (March 2026)
| Metric | Value |
|--------|-------|
| Total alerts | 4 |
| In analyzer code | 0 |
| In iccDEV upstream | 4 (assignment-does-not-return-this) |
| Fixed this session | 19 (constant-comparison, complex-condition, path-injection) |
