# test-profiles/

Curated ICC color profiles for security testing with iccanalyzer-lite, CFL fuzzers, and AFL++ targets.

## Inventory

| Directory | Count | Description |
|-----------|-------|-------------|
| Root (`*.icc`) | 329 | Primary test corpus — v2/v4/v5 profiles across all 7 ICC classes |
| `crashes/` | 4 | Known-crashing profiles (upstream iccDEV bugs) |
| `cwe-400/` | 491 | CWE-400 timeout/DoS profiles (calculator, recursion, large allocations) |
| `spectral/` | 10 | Spectral/multi-visualization v5 profiles |

**Total: 834 files**

## Profile Class Distribution

| Class | Profiles | Notes |
|-------|----------|-------|
| `spac` (ColorSpace) | ~182 | v5/iccMAX profiles |
| `mntr` (Display) | ~47 | sRGB, Display P3, AdobeRGB variants |
| `scnr` (Input/Scanner) | ~13 | Scanner profiles |
| `prtr` (Output/Printer) | ~11 | CMYK printer profiles |
| `mid` (Material ID) | ~8 | v5-specific |
| `cenc` (Color Encoding) | ~8 | v5-specific |
| `link` (DeviceLink) | ~8 | Device link transforms |
| `abst` (Abstract) | ~6 | Lab→Lab transforms |
| `nmcl` (NamedColor) | ~5 | Named color palettes |

## Usage

```bash
# Run iccanalyzer-lite against a single profile
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  ./iccanalyzer-lite/iccanalyzer-lite -a test-profiles/sRGB_D65_MAT.icc

# Run full test suite (uses synthesized corpus, not this directory)
python3 iccanalyzer-lite/tests/run_tests.py

# Seed CFL fuzzers
cp test-profiles/*.icc cfl/corpus-icc_profile_fuzzer/

# Seed AFL fuzzers (auto-sampled by start.sh)
# AFL seeds from test-profiles/ are auto-sampled to 200 files max
./afl/start.sh dump
```

## Naming Conventions

- Standard profiles: `sRGB_D65_MAT.icc`, `DisplayP3-v4.icc`
- Calculator profiles: `calc*.icc` (MPE calculator elements)
- Multi-channel: `*Chan*.icc`, `*MVIS*.icc` (high-dimensional)
- Timeout profiles (`cwe-400/`): `timeout-*` prefix

## Relationship to Other Directories

| Directory | Relationship |
|-----------|-------------|
| `extended-test-profiles/` | CVE PoCs, crash artifacts, malformed profiles |
| `fuzz/graphics/icc/` | Separate repo — raw CVE PoC files |
| `cfl/corpus-*` | Fuzzer corpora (superset of seeds from here) |
| `afl/afl-*/input/` | AFL seed directories (sampled from here) |
