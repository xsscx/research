# COMPREHENSIVE INVENTORY: fuzz/ & cfl/

## EXECUTIVE SUMMARY

**fuzz/** (201 MB): Public fuzzing corpus and PoC collection — security signatures, CVE PoCs, and malicious inputs across 34 subdirectories.

**cfl/** (23 GB): Crash-Free LibFuzzer framework — 19 compiled fuzzer binaries + seed corpus + dictionary files for ICC profile testing (iccDEV library).

**Relationship**: fuzz/ contains INPUT DATA (corpus + PoCs); cfl/ contains FUZZER BINARIES & INFRASTRUCTURE to execute them. cfl/ includes 27 .dict files derived from ICC standards.

---

## 1. FUZZ/ DIRECTORY STRUCTURE (201 MB)

### Root Files
| File | Size | Purpose |
|------|------|---------|
| README.md | 1.6K | Main intro — David Hoyt, xss.cx/srd.cx, last update 02-MAR-2026 |
| CONTRIBUTING.md | 63B | "Setup a PR.. All Malicious Code Accepted!!!" |
| _config.yml | 26B | Jekyll theme: jekyll-theme-cayman |
| .gitignore | 11B | Simple git ignore |
| full-unicode.txt | 5.3M | Complete Unicode character table (1,111,999 lines) |
| no-experience-required-xss-signatures-only-fools-dont-use.txt | 133K | XSS payload collection |
| xml-paste-from-gist.txt | 25K | XML injection samples |

### Major Subdirectories (Ranked by Size)

#### 1. **graphics/** (124 MB) — Image format PoCs & CVE samples
- **icc/** (largest) — ICC color profile crashes
  - 140+ .icc files: CVE-2022-26730, CVE-2023-46602, CVE-2024-38427 variants
  - xml/ subdir: 400+ ICC-to-XML PoCs (minimized corpus via AFL fuzzing)
  - Examples:
    - `cve-2024-38427.icc`, `cve-2022-26730-*.icc`
    - `CIccMpeCalculatorSetElem_StackOverflow_*.icc`
    - `xsscx-recursion-CIccMpeCalculator-Read-IccMpeCalc.cpp-L5001.icc.txt`
  - **xml/icc/minimized/**: 100+ AFL-minimized crash cases (AFL metadata in filenames)

- **exr/** — OpenEXR image crashes (2 samples)
  - `asan_heap-oob_7efd9bd346a5_639_9e0b30ed499cdf9e8802dd64e16a9508.exr` (7 KB)
  - `badoutput_ncf.exr`

- **tif/** — TIFF image crashes
  - `hoyt-undefined-behavior-runtime-error-downcast-type-confusion-poc.tiff` (2 KB)
  - `crash-7f7e9fe00073245711ca7eb81cec9316f0614b8e` (2 KB)
  - OOM crash cases

- **jpg/seed/** — 8 valid JPEG base seeds (1.3 KB each)
  - StandardRGB_image.jpg, BigEndian_image.jpg, HDRFloatComponents_image.jpg, etc.
  - Used as fuzzing seeds

- **png/seed/**, **bmp/**, **eps/**, **gif/**, **heic/**, **svg/** — Empty or placeholder dirs

- **Readme.md**: "The Gifts that Keep on Giving" — last updated Fri Apr 11 15:44:54 EDT 2025

#### 2. **xml/** (36 MB) — XXE, XML injection, XSLT PoCs
- **Classic attacks**:
  - `dos/`: Billion-laughs, recursive/quadratic blowup, entity tests
  - `xxe/`: UTF-16/UTF-7 encoding tricks, groovy, netdoc examples
  - `custom/`, `C/`, `spath-poc/`, `yunusov-poc/`, `morgan-poc/` — Various XXE variants

- **ICC-specific XML**:
  - `icc/`: 80+ XML crash examples
    - Heap overflows (CIccIO, CIccCurvesFromXml)
    - Null pointer dereference (NPD) cases
    - Stack overflow via recursive structures
  - `icc/minimized/`: 150+ AFL-minimized crash files

- **README.md**: Explains XXE/XML/XSLT windows MSXML parser risks

#### 3. **meta/** (3.3 MB) — Metadata injection, metatag PoCs
- Meta character samples, metatag injection signatures
- Apple XNU OS regex patterns (`xnu-os-cli-regexp-*`, `xnu-os-cli-fw-regex-*`)
- String samples (srd-strings-sys_sw.txt: 255K, srd-strings-psi_ram2.txt: 1.9K)

#### 4. **uri/** (212K) — Data URI, protocol handler mutations
- protocol-handlers-iana.txt
- Extended/varied/combined/corrected GPU Skia mutations (JavaScript-generated)

#### 5. **rbl/** (204K) — Real-time Blacklist samples
- Ad CDN fraud detection (YouTube, Google, mobile apps)
- Readme.md: RBL-focused filtering strategies

#### 6. **random/** (184K) — Generic malicious payloads
- XSS, SVG, HTML injection, PHP, double-URL encoding
- `all-encodings-of-lt.fuzz.txt`, various-malicious-input-small.txt

#### 7. **httpheader/** (132K) — HTTP protocol injection
- Content-Type lists, user-agent XSS, JMX console fingerprinting

#### 8. **pf/** (120K) — Firewall-related? (12B Readme: blank)

#### 9. **svg/** (80K) — SVG event handlers, font/font-size XXE

#### 10. **json/** (56K) — JSON fuzzing signatures

#### 11. **javascript/** (44K) — AngularJS XSS, event handlers, polyglot XSS

#### 12-34. **Minor Dirs** (each 8-28K):
- email/, unix/, ua/ (user-agent), parameter/, custom/, callback/, calc/, ascii/
- lfi-local-file-system-harvesting/, python/, java/, css/, ssi/, sqlinjection/, soap/, referer/, angular/, applescript/, ps/

---

## 2. CFL/ DIRECTORY STRUCTURE (23 GB)

### What is CFL?
**Crash-Free LibFuzzer**: 19 LibFuzzer harnesses (4,537 LOC C/C++) + patches + corpus + dictionaries.
- **Target**: iccDEV (International Color Consortium ICC profile library)
- **Compiler**: clang++ 18 with `-fsanitize=address,undefined,fuzzer`
- **Upstream**: github.com/InternationalColorConsortium/iccDEV (commit b5ade94, 2026-03-06)

### Root Files & Config
| File | Size | Purpose |
|------|------|---------|
| README.md | 10K | CFL documentation & fuzzer table |
| CMakeLists.txt | 8.4K | Build config for 19 fuzzers + iccDEV |
| build.sh | 11K (executable) | Build orchestrator — clones iccDEV, applies patches, compiles |
| Dockerfile | 454B | Container image definition |
| codeql-config.yml | 620B | CodeQL analysis config |
| TiffImg.o | 225K | Pre-compiled TIFF object file |

### Binary Artifacts
**bin/** — 19 compiled fuzzer binaries (after `./build.sh`)
```
icc_apply_fuzzer                 (CIccCmm::Apply)
icc_applynamedcmm_fuzzer         (Named color CMM)
icc_applyprofiles_fuzzer         (Multi-profile transforms)
icc_calculator_fuzzer            (MPE calculator)
icc_deep_dump_fuzzer             (Full tag enumeration)
icc_dump_fuzzer                  (CIccProfile::Describe)
icc_fromcube_fuzzer              (.cube LUT parsing)
icc_fromxml_fuzzer               (CIccProfile::LoadXml)
icc_io_fuzzer                    (Byte-level I/O)
icc_link_fuzzer                  (Profile linking)
icc_multitag_fuzzer              (Multi-profile load)
icc_profile_fuzzer               (CIccProfile::Read)
icc_roundtrip_fuzzer             (Round-trip transforms)
icc_specsep_fuzzer               (Spectral separation)
icc_spectral_b_fuzzer            (Spectral PCS variant B)
icc_spectral_fuzzer              (Spectral PCS)
icc_tiffdump_fuzzer              (TIFF tag reading)
icc_toxml_fuzzer                 (CIccProfile::SaveXml)
icc_v5dspobs_fuzzer              (v5 display/observer profiles)
```

### Patch Directory
**patches/** — 57 active patches (001-071, with 14 NO-OP gaps):
- NO-OP patches: 023, 027-029, 032, 039-041, 045, 055-056, 058, 062, 066
- Latest: 073 (CWE-122 heap-buffer-overflow in icMBBFromXml)
- Format: `NNN-descriptive-name.patch` (unified diff)
- All patches idempotent (`build.sh` applies with `patch -p1 --forward`)

### Corpus Directories (19 corresponding to fuzzers)
**corpus/** + **corpus-icc_*_fuzzer/** (per-fuzzer)
- Total: ~13 GB across 19 corpora
- Largest:
  - corpus-icc_deep_dump_fuzzer: 3.4 MB
  - corpus-icc_applynamedcmm_fuzzer: 2.6 MB
  - corpus-icc_applyprofiles_fuzzer: 2.1 MB
  - corpus-icc_apply_fuzzer: 1.8 MB
- Seed corpus: 6 base profiles in `corpus/` (3.9K each)
- Runtime corpus: Generated during fuzzing runs

### Dictionary Files (27 total)
Located at: `cfl/*.dict`

**Master dictionaries**:
- `icc_master_curated.dict` — Comprehensive token set
- `icc_core.dict` — Core ICC structures
- `icc_profile.dict`, `icc_xml_consolidated.dict`, etc.

**Fuzzer-specific**:
- `icc_apply_fuzzer.dict`, `icc_applynamedcmm_fuzzer.dict`, etc. (one per fuzzer)

**Specialized**:
- `icc_tiff_core.dict` — TIFF-specific tokens
- `findings/latest.dict` — Latest discovered tokens

### Source Harnesses
**icc_*_fuzzer.cpp** (in iccDEV/ after patch application)
- Each file defines `extern "C" int LLVMFuzzerTestOneInput(...)`
- 4,537 LOC total (per cfl.instructions.md)

### Subdirectories
- **codeql-queries/** — Custom CodeQL security queries
- **iccDEV/** — Cloned from upstream (not in this view, created at build time)
- **findings/** — Latest.dict and discovery tracking

---

## 3. RELATIONSHIP: FUZZ/ ↔ CFL/

### fuzz/ is INPUT DATA:
- **Corpus**: Valid ICC profiles, XML test cases, images
- **PoCs**: CVE samples, crash files, known-bad inputs
- **Signatures**: XSS, XXE, injection patterns (reusable for any fuzzer)

### cfl/ is EXECUTION INFRASTRUCTURE:
- **Fuzzers**: LibFuzzer harnesses + ASAN/UBSan instrumentation
- **Corpus management**: Ramdisk workflows, corpus merging, minimization
- **Coverage tracking**: LLVM profdata, HTML reports

### Integration:
1. Seed corpora in `cfl/corpus-icc_*_fuzzer/` derived from `fuzz/graphics/icc/` & `fuzz/xml/icc/`
2. Dictionary tokens (27 .dict files) curated from ICC standard strings
3. Crash files from CFL fuzzing fed back into fuzz/ for distribution
4. Scripts in `.github/scripts/` manage both:
   - ramdisk-seed.sh (mount ramdisk, populate seed corpus)
   - unbundle-fuzzer-input.sh (extract profiles from multi-profile fuzzer crashes)

---

## 4. .GITHUB/ FUZZING-RELATED FILES

### Instructions (`.github/instructions/`)
- **cfl.instructions.md** (MAIN) — Full CFL documentation
  - Build, upstream sync, 19 fuzzer table, patch conventions
  - Multi-profile input formats, corpus management, coverage baseline (63.23% functions)
  - Adding new fuzzers (next: #20)

### Prompts (`.github/prompts/`)
- **fuzzer-optimization.prompt.md** — Per-fuzzer coverage gap analysis & seed crafting
- **improve-fuzzer-coverage.prompt.md** — LLVM coverage report generation & interpretation
- **corpus-management.prompt.md** — Ramdisk/SSD lifecycle, 19 fuzzer list
- **triage-fuzzer-crash.prompt.yml** — Crash analysis workflow
- **triage-fuzzer-oom.prompt.yml** — OOM investigation
- **triage-cve-poc.prompt.yml** — CVE PoC analysis
- **image-fuzzer-quality.prompt.md** — Seed quality metrics

### NO "fuzz/" reference in copilot-instructions.md
- The global instructions file does not mention fuzz/ directory directly
- Path-specific instructions in cfl.instructions.md take precedence for cfl/**

---

## 5. FILE INVENTORY BY TYPE

### Source Code (1 file)
```
fuzz/unix/osx/xnu-school-xss-runtargets-applesecurityresearchdevice-example-struct-001.c
  - Apple Security Research Device runtime offsets (struct definition + device targets)
```

### Dictionary Files (27 files)
All in `cfl/`:
```
icc.dict, icc_core.dict, icc_profile.dict, icc_xml_consolidated.dict
icc_master_curated.dict, icc_recommended.dict, icc_multitag.dict
+ 20 fuzzer-specific .dict files
+ findings/latest.dict
```

### Documentation (7 README files)
```
fuzz/README.md
fuzz/graphics/Readme.md
fuzz/xml/README.md
fuzz/meta/Readme.md
fuzz/rbl/Readme.md
fuzz/callback/Readme.md
fuzz/pf/Readme.md (empty)
cfl/README.md
```

### ICC Profile Files (300+)
Locations: `fuzz/graphics/icc/`, `fuzz/xml/icc/` (both .icc binaries and XML)
Types: CVE PoCs, stack overflow, heap overflow, UB, type confusion, OOM triggers

### Image Files
- JPEG (8 seeds × 1.3KB): `fuzz/graphics/jpg/seed/`
- EXR (2): `fuzz/graphics/exr/`
- TIFF (4): `fuzz/graphics/tif/`
- PNG/BMP/GIF: placeholders

### XML/Text Corpus (1000+ files)
Locations: `fuzz/xml/`, `fuzz/meta/`, `fuzz/random/`, `fuzz/javascript/`, etc.
Types: XXE payloads, XSS injections, metatag abuse, SQL injection, etc.

### Configuration Files
```
fuzz/_config.yml                      (Jekyll theme)
cfl/CMakeLists.txt                   (Build config)
cfl/Dockerfile                        (Container)
cfl/codeql-config.yml               (Static analysis)
```

### Git Artifacts
```
fuzz/.git/                            (Git repo, 112MB pack file)
fuzz/.gitignore
```

---

## 6. COVERAGE & METRICS

### CFL Coverage Baseline (March 2026)
| Metric | Value |
|--------|-------|
| Functions | 63.23% |
| Lines | 61.15% |
| Branches | 58.47% |
| Instantiations | 62.99% |

### Fuzzer-to-Tool Fidelity
| Fuzzer | iccDEV Tool | Fidelity |
|--------|-------------|----------|
| icc_link_fuzzer | IccApplyToLink | ~65% |
| icc_applynamedcmm_fuzzer | IccApplyNamedCmm | ~75% |
| icc_specsep_fuzzer | IccSpecSepToTiff | ~85% |
| icc_roundtrip_fuzzer | IccRoundTrip | ~95% |
| icc_deep_dump_fuzzer | IccDumpProfile | >100% |

### Repository Info
- **fuzz/** owner: David Hoyt (hoyt.net, xss.cx, srd.cx)
- **fuzz/** last update: 2026-03-26 (per git metadata)
- **cfl/** upstream commit: b5ade94 (2026-03-06)
- **All files**: UTF-8 or binary

---

## 7. COMPLETE DIRECTORY TREE (fuzz/)

```
fuzz/
├── .git/                                (112 MB)
├── .gitignore
├── CONTRIBUTING.md
├── README.md
├── _config.yml
├── full-unicode.txt                     (5.3 MB)
├── no-experience-required-xss-signatures-only-fools-dont-use.txt (133 KB)
├── xml-paste-from-gist.txt             (25 KB)
│
├── angular/                             (8 KB)
├── applescript/                         (8 KB)
├── ascii/                               (12 KB)
├── calc/                                (12 KB)
├── callback/                            (12 KB) + Readme.md
├── css/                                 (8 KB)
├── custom/                              (12 KB) → {prefix.txt, vector.txt}
├── email/                               (324 KB)
│
├── graphics/                            (124 MB) ← LARGEST
│   ├── Readme.md
│   ├── bmp/, eps/, gif/                (empty)
│   ├── exr/                            (2 samples, 7.7 KB)
│   ├── heic/, svg/                     (empty)
│   ├── icc/                            (140+ profiles, 11.9 KB)
│   │   ├── *.icc                       (CVE PoCs, crash samples)
│   │   ├── xml/icc/                    (80+ XML equivalents)
│   │   └── minimized/                  (150+ AFL-minimized crashes)
│   ├── jpg/seed/                       (8 valid JPEG seeds, 10.8 KB)
│   ├── png/seed/                       (empty)
│   ├── tif/                            (4 TIFF crashes, 4 KB)
│   └── txt/                            (ICC description, 1 KB)
│
├── httpheader/                          (132 KB)
├── java/                                (8 KB)
├── javascript/                          (44 KB)
├── json/                                (56 KB)
├── lfi-local-file-system-harvesting/   (40 KB) → {windows-file-system-checks.txt, ...}
├── meta/                                (3.3 MB) + Readme.md
│   └── {xnu-os-*.txt, srd-strings-*.txt, metatag-*.txt}
├── parameter/                           (24 KB)
├── pf/                                  (120 KB) + Readme.md (blank)
├── ps/                                  (8 KB)
├── python/                              (8 KB)
│
├── random/                              (184 KB)
│   └── {uri-fuzzing-list.txt, html-script-*.txt, ...}
│
├── rbl/                                 (204 KB) + Readme.md
│   └── {mobile-app-*.txt, youtube-*.txt, google-*.txt}
│
├── referer/                             (8 KB)
├── ssi/                                 (8 KB)
├── soap/                                (8 KB)
├── sqlinjection/                        (8 KB)
├── svg/                                 (80 KB)
├── ua/                                  (24 KB)
│   └── {bash-ua.txt, ie/*, protocol-handlers-*.txt}
├── unix/                                (28 KB)
│   └── {bash-bug-*.txt, osx/{i-am-root-*.txt, dyld-*.txt, xnu-*.c}}
├── uri/                                 (212 KB)
└── xml/                                 (36 MB) ← 2ND LARGEST
    ├── README.md
    ├── classic.xml
    ├── dos/                            (5 billion-laughs variants)
    ├── xxe/                            (10 XXE PoCs)
    ├── icc/                            (80+ ICC crashes + 150+ minimized/)
    ├── custom/, C/, spath-poc/, yunusov-poc/, morgan-poc/ (XXE variants)
    └── {xxe-*.txt, entity-*.txt, svg-xxe-*.txt}
```

---

## 8. KEY FINDINGS

### Purpose Alignment
- **fuzz/**: Commodity injection signatures + public PoCs (scraped 2015+)
- **cfl/**: Specialized ICC color profile security research (4,537 LOC harnesses)
- **Integration**: fuzz/ seeds CFL corpus; CFL discovers new crashes for fuzz/

### Largest Assets
| Path | Size | Type |
|------|------|------|
| fuzz/full-unicode.txt | 5.3 MB | Unicode character reference |
| cfl/ corpus combined | 13 GB | Fuzzing corpus |
| fuzz/graphics/icc | 124 MB | ICC profile PoCs & crashes |
| fuzz/xml | 36 MB | XXE/XML injection samples |

### Critical Absence
- **NO .dict files in fuzz/** — All 27 dict files are in cfl/
- **NO CMakeLists.txt in fuzz/** — fuzz/ is data-only; CFL handles compilation
- **NO fuzzer binaries in fuzz/** — All binaries in cfl/bin/ (must build with ./build.sh)

### Security Notes
- **Ownership caveat** (CFL): `CIccCmm::AddXform()` transfers profile ownership → double-free risk documented in CFL-072
- **Leak detection** (CFL): icc_link_fuzzer requires `ASAN_OPTIONS=detect_leaks=0,quarantine_size_mb=256` (2 profiles per input = 2× ASAN memory)
- **Multi-profile fuzzers**: Input format specifications in cfl.instructions.md § "Multi-Profile Fuzzer Input Formats"

