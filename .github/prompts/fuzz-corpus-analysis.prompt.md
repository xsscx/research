# Fuzz Corpus Analysis & Seed Optimization

## Purpose
Analyze the fuzz/ corpus to identify coverage gaps, optimize seed selection for
CFL fuzzers, and map PoC files to known CVEs and CWE categories.

## When to Use
- Before starting a new fuzzing campaign
- After adding new PoC files to fuzz/
- When a CFL fuzzer shows stagnant coverage
- When triaging which seeds to prioritize for a specific fuzzer

## Workflow

### Step 1 — Inventory the corpus
```bash
# Count ICC profiles by crash type
for type in hbo sbo segv oom ub npd so cve; do
  count=$(ls fuzz/graphics/icc/ | grep -ci "^${type}" 2>/dev/null || echo 0)
  echo "$type: $count files"
done

# Count XML crash samples
echo "XML named: $(ls fuzz/xml/icc/*.xml 2>/dev/null | wc -l)"
echo "XML minimized: $(ls fuzz/xml/icc/minimized/ 2>/dev/null | wc -l)"
```

### Step 2 — Map seeds to CFL fuzzers
For each CFL fuzzer, identify which fuzz/ files exercise its code path:

| Fuzzer | Primary Seeds | Secondary Seeds |
|--------|--------------|-----------------|
| icc_profile_fuzzer | `graphics/icc/*.icc` | Root `crash-*`, `oom-*` files |
| icc_fromxml_fuzzer | `xml/icc/*.xml`, `xml/icc/minimized/*` | — |
| icc_toxml_fuzzer | `graphics/icc/*.icc` | Same as profile_fuzzer |
| icc_tiff_fuzzer | `graphics/tif/*.tif` | — |
| icc_calculator_fuzzer | `graphics/icc/*Calculator*.icc`, `*CalcOp*.icc` | — |
| icc_dump_fuzzer | `graphics/icc/*.icc` | All ICC profiles |
| icc_apply_fuzzer | `graphics/icc/*.icc` | Profiles with AToB/BToA tags |
| icc_link_fuzzer | Pairs from `graphics/icc/*.icc` | Need display+output pairs |
| icc_v5dspobs_fuzzer | v5 profiles from `graphics/icc/` | Need display+observer pairs |

### Step 3 — Audit profile class distribution
**Critical**: Verify all 7 ICC classes are represented in each corpus. A class gap
means entire code paths (LUT types, gamut mapping, device transforms) go untested.

```bash
# Check class distribution across all corpora
python3 -c "
import os, struct, collections
names = {b'mntr':'Display', b'prtr':'Printer', b'scnr':'Scanner',
         b'link':'DeviceLink', b'spac':'ColorSpace', b'abst':'Abstract', b'nmcl':'NamedColor'}
for corpus in sorted(os.listdir('cfl')):
    if not corpus.startswith('corpus-'): continue
    d = os.path.join('cfl', corpus)
    if not os.path.isdir(d): continue
    classes = collections.Counter()
    for fn in os.listdir(d):
        fp = os.path.join(d, fn)
        if not os.path.isfile(fp): continue
        try:
            with open(fp,'rb') as fh:
                hdr = fh.read(16)
                if len(hdr)>=16: classes[hdr[12:16]] += 1
        except: pass
    total = sum(classes.values())
    missing = [n for c,n in names.items() if classes.get(c,0)==0]
    if missing:
        print(f'  {corpus}: MISSING {missing} ({total} total)')
"
```

**Known gap (fixed March 2026)**: Zero printer (prtr) profiles existed across all corpora.
Printer profiles exercise AToB/BToA LUT pairs (mft1), gamut tags, and CMYK handling.
Seeds added: Tek350Monaco2 (v2.0 RGB→Lab), SC_paper_eci (v2.4 CMYK→Lab),
CMYK-3DLUTs2 (v5.0 CMYK→Lab), cve-2023-46602 (malformed CMYK).

### Step 4 — Identify code coverage gaps
```bash
# Run a short fuzzing session and check coverage
LLVM_PROFILE_FILE=/tmp/profraw/${FUZZER}_%m_%p.profraw \
  cfl/bin/${FUZZER} -max_total_time=60 cfl/corpus-${FUZZER}/

# Merge and report
llvm-profdata-18 merge -sparse /tmp/profraw/*.profraw -o /tmp/merged.profdata
llvm-cov-18 report cfl/bin/${FUZZER} -instr-profile=/tmp/merged.profdata
```

### Step 5 — Create targeted seeds
For uncovered code paths, create minimal ICC profiles that exercise specific features:

1. **Tag-specific seeds**: Profiles with rare tag signatures (e.g., `gamt`, `bfd`, `ncl2`)
2. **Version-specific seeds**: v2.x, v4.x, v5.x profiles to exercise version-specific code
3. **Class-specific seeds**: `scnr`, `mntr`, `prtr`, `link`, `spac`, `abst`, `nmcl`
4. **PCS-specific seeds**: XYZ-PCS and Lab-PCS profiles
5. **MPE seeds**: Profiles with multiProcessElementsType tags for calculator fuzzer
6. **TRC diversity**: Sampled curves (curv 1024-entry), parametric (para type 3), gamma-only (curv 1-entry)

### Step 5 — Validate seed quality
```bash
# Check each seed with iccanalyzer-lite
for f in fuzz/graphics/icc/*.icc; do
  echo "=== $(basename $f) ==="
  iccanalyzer-lite/iccanalyzer-lite -a "$f" 2>&1 | grep -E '\[H[0-9]+\]|\[WARN\]|\[CRIT\]' | head -5
done
```

### Step 6 — Sync to CFL corpora
```bash
# Seed the CFL corpus directories
.github/scripts/ramdisk-seed.sh --mount

# Or manual copy for specific fuzzers
cp fuzz/graphics/icc/*.icc /tmp/fuzz-ramdisk/corpus-icc_profile_fuzzer/
cp fuzz/xml/icc/*.xml /tmp/fuzz-ramdisk/corpus-icc_fromxml_fuzzer/
```

## CVE-to-Seed Mapping

| CVE | fuzz/ Path | CWE | Affected Component |
|-----|-----------|-----|-------------------|
| CVE-2022-26730 | `graphics/icc/cve-2022-26730-*.icc` | CWE-787 | Apple ColorSync |
| CVE-2023-32443 | `graphics/icc/cve-2023-32443*.icc` | CWE-125 | Apple ColorSync |
| CVE-2023-46602 | `graphics/icc/cve-2023-46602.icc` | CWE-122 | iccDEV (formerly DemoIccMAX) |
| CVE-2023-46867 | `graphics/icc/Argyll_V302_*.icc` | CWE-126 | ArgyllCMS |
| CVE-2024-38427 | `graphics/icc/cve-2024-38427.icc` | CWE-122 | iccDEV (formerly DemoIccMAX) |

## Crash Type Classification

When analyzing files in fuzz/graphics/icc/, classify by CWE:

| Prefix | CWE | Description |
|--------|-----|-------------|
| `hbo-` | CWE-122 | Heap-based buffer overflow |
| `sbo-` | CWE-121 | Stack-based buffer overflow |
| `segv-` | CWE-476 | NULL pointer dereference |
| `oom-` | CWE-789 | Memory allocation with excessive size |
| `ub-` | CWE-190/191 | Undefined behavior (integer overflow, type confusion) |
| `npd-` | CWE-476 | NULL pointer dereference |
| `so-` | CWE-674 | Uncontrolled recursion / stack exhaustion |
| `crash-` | Various | Unclassified crash |

### Step 7 — Seed from xnuimagetools output
iOS Image Generator and xnuimagefuzzer outputs are staged in the fuzz/ corpus repo:
```bash
# Seed from iOS-generated images (collision-free filenames with SHA-256 hash)
cp fuzz/xnuimagegenerator/tiff/*.tif cfl/corpus-icc_tiff_fuzzer/ 2>/dev/null
cp fuzz/xnuimagegenerator/icc/*.icc cfl/corpus-icc_profile_fuzzer/ 2>/dev/null

# Seed from fuzzed outputs
cp fuzz/xnuimagefuzzer/tiff/*.tif cfl/corpus-icc_tiff_fuzzer/ 2>/dev/null
cp fuzz/xnuimagefuzzer/icc/*.icc cfl/corpus-icc_profile_fuzzer/ 2>/dev/null
```

### iOS-Extracted ICC Profiles (3 unique, March 2026)
| Profile | Size | Version | CMM | TRC Type | Gamut | Notes |
|---------|------|---------|-----|----------|-------|-------|
| sRGB IEC61966-2.1 | 3,144B | v2.1 | HP/Lino | curv 1024-entry | 100% | 17 tags, shared TRC offsets |
| Display P3 | 536B | v4.0 | Apple | para type 3 | 128% | Negative XYZ, chad tag |
| Adobe RGB (1998) | 560B | v2.1 | Adobe | curv γ=2.2 | 131% | Single gamma value |

## Output
Document findings in a table with:
- Seed file name
- Target fuzzer(s)
- CWE category
- Code path exercised (if known from filename)
- Priority (high/medium/low based on coverage gap)

## See Also
- [corpus-management.prompt.md](corpus-management.prompt.md) — Corpus storage operations
- [improve-fuzzer-coverage.prompt.md](improve-fuzzer-coverage.prompt.md) — Coverage gap analysis
- [fuzzer-optimization.prompt.md](fuzzer-optimization.prompt.md) — Coverage improvement strategies
