# fuzz/ — Path-Specific Instructions

## What This Is

A curated corpus of 1,139 malicious input files (201 MB) organized into 34 categories
for security testing. Contains CVE proof-of-concept files, injection signatures,
malformed media files, and AFL-minimized crash samples. Originally created as
"Commodity-Injection-Signatures" by David Hoyt (xss.cx/srd.cx), maintained since 2015.

## Purpose

1. **Seed corpus** for CFL LibFuzzer harnesses (ICC profiles + ICC XML)
2. **CVE reproduction** — known-crashing ICC profiles with provenance naming
3. **Injection testing** — XSS, XXE, SQLi, SSI, LFI, SSRF, XSLT signatures
4. **Image format fuzzing** — malformed BMP, EPS, EXR, GIF, HEIC, JPG, PNG, SVG, TIFF
5. **Manual testing** — Burp Intruder payloads, XNU/Windows/Linux input vectors

## Directory Structure

```
fuzz/
├── README.md                           # Corpus overview
├── CONTRIBUTING.md                     # Contribution guide
├── _config.yml                         # Jekyll theme (GitHub Pages)
├── graphics/                           # 832 files, 124 MB — malformed media
│   ├── icc/                            # 95 ICC profiles — CVE PoCs + crashes
│   ├── jpg/                            # 208 malformed JPEGs
│   ├── png/                            # 200 malformed PNGs
│   ├── tif/                            # 267 malformed TIFFs (test inputs for iccanalyzer-lite H139-H141 TIFF security heuristics: strip geometry, dimension validation, IFD offset bounds)
│   ├── gif/                            # 35 malformed GIFs
│   ├── bmp/                            # 10 malformed BMPs
│   ├── heic/                           # 9 malformed HEICs
│   ├── exr/                            # 4 malformed OpenEXRs
│   ├── eps/                            # 1 malformed EPS
│   └── svg/                            # 1 malformed SVG
├── xml/                                # 173 files, 36 MB — XML attack vectors
│   ├── icc/                            # 42 ICC XML PoCs + 74 AFL-minimized
│   │   └── minimized/                  # 74 AFL-minimized XML crash samples
│   ├── xxe/                            # XXE entity injection PoCs
│   ├── morgan-poc/                     # Morgan XXE PoC variants
│   ├── yunusov-poc/                     # Yunusov XML attack PoCs
│   ├── ssrf/                           # SSRF via XML
│   ├── dos/                            # XML denial-of-service (billion laughs)
│   ├── custom/                         # Custom XML injection
│   └── spath-poc/                      # XPath injection
├── angular/                            # AngularJS template injection
├── javascript/                         # 7 JS injection payloads
├── sqlinjection/                       # SQL injection signatures
├── css/                                # CSS injection
├── ssi/                                # Server-side include injection
├── lfi-local-file-system-harvesting/   # Path traversal payloads
├── uri/                                # 15 URI-based attack vectors
├── svg/                                # 15 SVG injection payloads
├── ua/                                 # User-Agent fuzzing
├── httpheader/                         # HTTP header injection
├── email/                              # Email header injection
├── json/                               # JSON injection
├── soap/                               # SOAP injection
├── callback/                           # Callback URL injection
├── parameter/                          # Parameter pollution
├── pf/                                 # Packet filter rules
├── random/                             # Random fuzzing tokens
├── rbl/                                # RBL/DNS-based payloads
├── meta/                               # HTML meta tag injection
├── unix/                               # Unix command injection
├── ascii/                              # ASCII control characters
├── calc/                               # Formula injection
├── referer/                            # Referer header injection
├── ps/                                 # PostScript injection
├── python/                             # Python code injection
├── java/                               # Java injection
├── applescript/                        # AppleScript injection
├── custom/                             # Custom payloads
├── full-unicode.txt                    # 5.3 MB Unicode fuzzing table
├── no-experience-required-xss-*        # 133 KB XSS signature collection
└── xml-paste-from-gist.txt             # XML paste injection
```

## ICC Profile Corpus (Primary Research Asset)

### Binary ICC Profiles (`graphics/icc/` — 95 files)

| Category | Count | Examples |
|----------|-------|---------|
| CVE-2022-26730 (ColorSync) | 11 | `cve-2022-26730-variant-{1..074}.icc` |
| CVE-2023-32443 | 2 | `cve-2023-32443.icc`, `cve-2023-32443-variant-020.icc` |
| CVE-2023-46602 | 1 | `cve-2023-46602.icc` |
| CVE-2023-46867 (Argyll) | 1 | `Argyll_V302_null_byte_read-*.icc` |
| CVE-2024-38427 | 1 | `cve-2024-38427.icc` |
| Heap-buffer-overflow | 5 | `hbo-*.icc`, `stack-buffer-overflow-*.icc` |
| Stack-buffer-overflow | 4 | `sbo-*.icc`, `stack-smashing-*.icc` |
| Null-pointer deref | 3 | `npd-*.icc`, `segv-*.icc` |
| Stack overflow | 3 | `so-*.icc`, `CIccTagStruct-Read-recursive-*.icc` |
| OOM | 5 | `oom-*.icc`, `xsscx-icRealloc-*.icc` |
| Undefined behavior | 10 | `ub-*.icc` |
| Double-free | 1 | `DoubleFree_IccUtil.cpp-L121.icc` |
| Type confusion | 3 | `ub-runtime-error-type-confusion-*.icc` |
| Memcpy overlap | 1 | `memcpy-param-overlap-*.icc` |
| Infinite recursion | 2 | `xsscx-infinite-recursion-*.icc`, `xsscx-recursion-*.icc` |
| Known-good profiles | 10+ | `sample.icc`, `Cat8Lab-D65_2degMeta.icc`, vendor profiles |

### ICC XML Corpus (`xml/icc/` — 116 files)

| Category | Count | Notes |
|----------|-------|-------|
| Named crash XMLs | 42 | Descriptive filenames with crash site |
| AFL-minimized (`minimized/`) | 74 | Auto-generated by AFL, SIGNAL 11 triggers |

Naming convention: `{crash_type}-{class}-{method}-{file}_cpp-Line{N}.xml`

## Integration with CFL Fuzzers

### Seeding CFL corpus from fuzz/

```bash
# Copy ICC PoCs to CFL seed corpora
cp fuzz/graphics/icc/*.icc cfl/corpus-icc_profile_fuzzer/
cp fuzz/graphics/icc/*.icc cfl/corpus-icc_toxml_fuzzer/
cp fuzz/graphics/icc/*.icc cfl/corpus-icc_dump_fuzzer/

# Copy ICC XML PoCs to fromxml fuzzer corpus
cp fuzz/xml/icc/*.xml cfl/corpus-icc_fromxml_fuzzer/
cp fuzz/xml/icc/minimized/* cfl/corpus-icc_fromxml_fuzzer/

# Copy TIFFs for TIFF fuzzer
cp fuzz/graphics/tif/*.tif cfl/corpus-icc_tiff_fuzzer/ 2>/dev/null
```

### Mapping fuzz/ categories to CFL fuzzers

| fuzz/ Path | CFL Fuzzer | Notes |
|-----------|------------|-------|
| `graphics/icc/*.icc` | `icc_profile_fuzzer` | Primary binary ICC seeds |
| `graphics/icc/*.icc` | `icc_toxml_fuzzer` | Same profiles for XML export |
| `graphics/icc/*.icc` | `icc_dump_fuzzer` | Profile description paths |
| `graphics/icc/*.icc` | `icc_deep_dump_fuzzer` | Full tag enumeration |
| `graphics/icc/*.icc` | `icc_io_fuzzer` | Byte-level I/O |
| `graphics/icc/*.icc` | `icc_apply_fuzzer` | CMM Apply paths |
| `graphics/icc/*.icc` | `icc_calculator_fuzzer` | MPE calculator |
| `xml/icc/*.xml` | `icc_fromxml_fuzzer` | XML → ICC parsing |
| `graphics/tif/*.tif` | `icc_tiff_fuzzer` | TIFF tag reading |

### Mapping fuzz/ to xnuimagetools

| fuzz/ Path | xnuimagetools Component | Notes |
|-----------|------------------------|-------|
| `graphics/jpg/*.jpg` | xnuimagefuzzer | JPEG UTI fuzzing |
| `graphics/png/*.png` | xnuimagefuzzer | PNG UTI fuzzing |
| `graphics/tif/*.tif` | xnuimagefuzzer | TIFF UTI fuzzing |
| `graphics/gif/*.gif` | xnuimagefuzzer | GIF UTI fuzzing |
| `graphics/bmp/*.bmp` | xnuimagefuzzer | BMP UTI fuzzing |
| `graphics/heic/*.heic` | xnuimagefuzzer | HEIC UTI fuzzing |
| `graphics/icc/*.icc` | FUZZ_ICC_DIR | ICC profile injection |

## File Naming Conventions

### ICC Profile PoCs
```
{crash_type}-{Class}-{Method}-{File}_cpp-Line{N}.icc
```
Components:
- **crash_type**: `hbo` (heap-buffer-overflow), `sbo` (stack-buffer-overflow),
  `segv` (SIGSEGV), `oom` (out-of-memory), `ub` (undefined behavior),
  `npd` (null-pointer deref), `so` (stack-overflow)
- **Class**: C++ class name (e.g., `CIccCLUT`, `CIccMpeCalculator`)
- **Method**: Method that crashed (e.g., `Interp3d`, `ApplySequence`)
- **File**: Source file without path (e.g., `IccTagLut`)
- **Line**: Source line number

### CVE PoCs
```
cve-{YYYY}-{NNNNN}-{description}-variant-{NNN}.icc
```

### AFL-Minimized
```
id_{NNNNNN}_sig_{NN}_src_{NNNNNN}_time_{N}_execs_{N}_op_{type}_pos_{N}
```

## Adding New PoCs

1. Name the file using the convention above
2. Place in the appropriate category directory
3. For ICC profiles: also copy to relevant `cfl/corpus-*` directories
4. Update `fuzz/README.md` if adding a new CVE category
5. Commit with message: `fuzz: add {crash_type} PoC for {component}`

## Security Considerations

- All files in this directory are **intentionally malicious**
- Do NOT open in normal applications — use sanitizer-instrumented tools only
- ICC profiles may trigger crashes in ColorSync, Skia, WebKit, Windows ICM
- XML files may trigger XXE, SSRF, or DoS in vulnerable parsers
- Image files may trigger buffer overflows in image decoders

## Relationship to Other Directories

| Directory | Relationship |
|-----------|-------------|
| `cfl/` | fuzz/ provides seed corpus → cfl/ fuzzers find new crashes → crash files land in repo root |
| `cfl/corpus-*` | Superset of fuzz/ ICC samples + LibFuzzer-generated mutations |
| `iccanalyzer-lite/` | Validates ICC profiles from fuzz/graphics/icc/ |
| `colorbleed_tools/` | Converts fuzz/ ICC profiles to/from XML |
| `xnuimagetools/` | Uses fuzz/graphics/* for UTI format fuzzing |
| Repo root `crash-*` | New crashes found by cfl/ fuzzers, NOT yet in fuzz/ |
| Repo root `oom-*` | OOM samples from cfl/ fuzzers |
| Repo root `slow-unit-*` | Timeout samples from cfl/ fuzzers |
