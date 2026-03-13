# iccDEV Shell Helpers — Unix (Linux / macOS / WSL-2)

Reference commands for building, testing, and debugging
[iccDEV](https://github.com/InternationalColorConsortium/iccDEV) on Unix-like systems.

> **Repository**: <https://github.com/InternationalColorConsortium/iccDEV.git>
> **Research**: <https://github.com/xsscx/research>

---

## Table of Contents

- [Dependencies](#dependencies)
- [Build — Ubuntu Debug + ASAN + UBSAN + Coverage](#build--ubuntu-debug--asan--ubsan--coverage)
- [Build — Ubuntu GNU (simple)](#build--ubuntu-gnu-simple)
- [Build — macOS Clang / Xcode](#build--macos-clang--xcode)
- [Build — macOS Homebrew](#build--macos-homebrew)
- [Build — WSL-2 Ubuntu 24](#build--wsl-2-ubuntu-24)
- [Build — Linux Presets](#build--linux-presets)
- [Build — Static Libraries](#build--static-libraries)
- [Build — Dynamic with Coverage](#build--dynamic-with-coverage)
- [CMake Configuration Examples](#cmake-configuration-examples)
- [Add Tools to PATH](#add-tools-to-path)
- [Find Binaries and Checksums](#find-binaries-and-checksums)
- [Testing — Batch Loops](#testing--batch-loops)
- [Testing — 1-Liners](#testing--1-liners)
- [Testing — Recursive with Logs](#testing--recursive-with-logs)
- [xmllint Validation](#xmllint-validation)
- [Coverage Instrumentation](#coverage-instrumentation)
- [iccanalyzer-lite (Security Research)](#iccanalyzer-lite-security-research)
- [Tool Checks](#tool-checks)
- [WASM Build](#wasm-build)
- [Debugging — LLDB](#debugging--lldb)
- [Debugging — ASAN / Build IDs](#debugging--asan--build-ids)
- [Dependency Checks](#dependency-checks)
- [Git Helpers](#git-helpers)
- [Misc Utilities](#misc-utilities)

---

## Dependencies

| Dependency | Ubuntu (apt) | macOS (brew) |
|---|---|---|
| Compiler | `clang-18`, `clang++-18` (preferred) or `gcc`/`g++` | `clang` (Xcode) |
| Build | `cmake` (3.15+), `make` | `cmake` |
| ASAN/UBSAN runtime | `libclang-rt-18-dev` | Built into Xcode |
| Image libraries | `libpng-dev`, `libjpeg-dev`, `libtiff-dev` | `libpng`, `jpeg`, `libtiff` |
| XML / JSON | `libxml2-dev`, `nlohmann-json3-dev` | `libxml2`, `nlohmann-json` |
| GUI (optional) | `libwxgtk3.2-dev` + media/webview | `wxwidgets` |
| OpenSSL (for iccanalyzer-lite) | `libssl-dev` | `openssl` (Homebrew) |

### Ubuntu Full Install

```bash
sudo apt install -y clang-18 clang++-18 libclang-rt-18-dev \
  cmake make build-essential \
  libpng-dev libjpeg-dev libtiff-dev \
  libxml2-dev nlohmann-json3-dev libssl-dev \
  libwxgtk3.2-dev libwxgtk-{media,webview}3.2-dev \
  wx-common wx3.2-headers
```

### macOS Homebrew

```bash
brew install libpng nlohmann-json libxml2 wxwidgets libtiff jpeg openssl
```

---

## Build — Ubuntu Debug + ASAN + UBSAN + Coverage

**Recommended for security research.** Full instrumentation with clang source-based
coverage (NOT gcov).

```bash
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV/Build
cmake -S Cmake -B . \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
  -DCMAKE_INSTALL_PREFIX="$HOME/.local" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_TOOLS=ON -DENABLE_STATIC_LIBS=ON -DENABLE_SHARED_LIBS=ON \
  -DCMAKE_C_FLAGS="-g3 -O0 -fno-omit-frame-pointer -fsanitize=address,undefined -fprofile-instr-generate -fcoverage-mapping" \
  -DCMAKE_CXX_FLAGS="-g3 -O0 -fno-omit-frame-pointer -fsanitize=address,undefined -fprofile-instr-generate -fcoverage-mapping" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined -fprofile-instr-generate -Wl,--build-id=sha1" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined -fprofile-instr-generate -Wl,--build-id=sha1" \
  -Wno-dev
make -j$(nproc)
```

### Sanitizer-Only Variants

**UBSAN only:**
```bash
CC=clang-18 CXX=clang++-18 cmake -S Cmake -B . -DCMAKE_BUILD_TYPE=Debug -Wno-dev \
  -DCMAKE_CXX_FLAGS="-g3 -O0 -Wall -Wextra -fno-omit-frame-pointer \
  -fno-optimize-sibling-calls -fsanitize=undefined,integer,enum \
  -fno-sanitize-recover=undefined"
```

**ASAN only:**
```bash
CC=clang-18 CXX=clang++-18 cmake -S Cmake -B . -DCMAKE_BUILD_TYPE=Debug -Wno-dev \
  -DCMAKE_CXX_FLAGS="-g3 -O0 -Wall -Wextra -fno-omit-frame-pointer \
  -fno-optimize-sibling-calls -fsanitize=address -fno-sanitize-recover=address"
```

**ASAN + UBSAN (no leak sanitizer):**
```bash
cmake -S Cmake -B . -DCMAKE_EXPORT_COMPILE_COMMANDS=ON -DCMAKE_BUILD_TYPE=Debug -Wno-dev \
  -DCMAKE_CXX_FLAGS="-g3 -O0 -fsanitize=address,undefined -fno-sanitize=leak \
  -fno-omit-frame-pointer -Wall" \
  -DENABLE_TOOLS=ON -DENABLE_STATIC_LIBS=ON -DENABLE_SHARED_LIBS=ON
```

---

## Build — Ubuntu GNU (simple)

No sanitizers, no coverage — fastest build for basic testing.

```bash
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV/Build
cmake -S Cmake -B .
make -j$(nproc)
```

---

## Build — macOS Clang / Xcode

```bash
brew install libpng nlohmann-json libxml2 wxwidgets libtiff jpeg
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV
cmake -G "Xcode" Build/Cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
xcodebuild -project RefIccMAX.xcodeproj
open RefIccMAX.xcodeproj
```

---

## Build — macOS Homebrew

### Homebrew Formula

```ruby
class Iccdev < Formula
  desc "Reference implementation tools for iccMAX (ICC.2 / iccDEV)"
  homepage "https://github.com/InternationalColorConsortium/iccDEV"
  url "https://github.com/InternationalColorConsortium/iccDEV/archive/refs/heads/master.tar.gz"
  version "2.3.1"
  license "MIT"

  depends_on "cmake" => :build
  depends_on "libpng"
  depends_on "libtiff"
  depends_on "libxml2"
  depends_on "nlohmann-json"
  depends_on "wxwidgets"

  def install
    cd "Build" do
      system "cmake", "Cmake",
                      "-DCMAKE_INSTALL_PREFIX=#{prefix}",
                      "-DCMAKE_BUILD_TYPE=Release",
                      "-DENABLE_TOOLS=ON", "-DENABLE_SHARED_LIBS=ON",
                      "-DENABLE_STATIC_LIBS=ON", "-DENABLE_TESTS=ON",
                      "-DENABLE_INSTALL_RIM=ON", "-DENABLE_ICCXML=ON",
                      "-Wno-dev"
      system "make", "-j#{ENV.make_jobs}"
      system "make", "install"
    end
  end

  test do
    system "#{bin}/iccDumpProfile", "--help"
  end
end
```

### Install

```bash
mkdir -p $(brew --repo local/iccdev)/Formula
cp iccdev.rb $(brew --repo local/iccdev)/Formula/
brew install local/iccdev/iccdev
```

---

## Build — WSL-2 Ubuntu 24

With X11 Libs, ASAN + Debug Logging:

```bash
cmake -S Cmake/ -B . \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_INSTALL_PREFIX="$HOME/.local" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_TOOLS=ON -DENABLE_SHARED_LIBS=ON -DENABLE_STATIC_LIBS=ON \
  -DENABLE_TESTS=ON -DENABLE_INSTALL_RIM=ON -DENABLE_ICCXML=ON \
  -DICC_CLUT_DEBUG=ON -DICC_ENABLE_ASSERTS=ON \
  -DICC_LOG_SAFE=ON -DICC_TRACE_NAN_ENABLED=ON \
  -DCMAKE_CXX_FLAGS="-g3 -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -Wall -Wno-dev" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined -lX11"
make -j$(nproc)

# Add tools to PATH and create test profiles
cd ../Testing
for d in ../Build/Tools/*; do
  [ -d "$d" ] && export PATH="$(realpath "$d"):$PATH"
done
sh CreateAllProfiles.sh
```

---

## Build — Linux Presets

```bash
cd iccDEV/Build/Cmake
rm -rf build/linux-* && echo "Cleaned all Linux build directories."
for preset in linux-gcc linux-clang linux-gcc-asan linux-clang-asan; do
  cmake --preset "$preset" && cmake --build --preset "build-$preset"
done
find build/linux-* -type f -executable -exec file {} \; | grep -E 'ELF.*executable'
```

---

## Build — Static Libraries

```bash
rm -rf CMakeCache.txt CMakeFiles/ Makefile Tools/ IccProfLib/ IccXML/ Testing/
cmake -S Cmake -B . \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_TOOLS=ON -DENABLE_STATIC_LIBS=ON \
  -DENABLE_SHARED_LIBS=OFF -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_FIND_LIBRARY_SUFFIXES=".a"
cmake -DCMAKE_EXE_LINKER_FLAGS="-Wl,-Bstatic \
  ${PWD}/IccProfLib/libIccProfLib2-static.a \
  ${PWD}/IccXML/libIccXML2-static.a -Wl,-Bdynamic" .
cmake --build . -j$(nproc)
```

### Verify Static Linkage

```bash
find Tools -type f -perm -111 | while read f; do
  echo "→ $f"
  ldd "$f" 2>/dev/null | grep -E "Icc|not a dynamic" || echo "static ICC linkage"
done
```

---

## Build — Dynamic with Coverage

Uses clang source-based coverage (`-fprofile-instr-generate -fcoverage-mapping`).

> **Note**: Do NOT use gcov-style flags (`-fprofile-arcs -ftest-coverage`) — they
> produce `.gcda`/`.gcno` files incompatible with `llvm-profdata`/`llvm-cov`.

```bash
export CC=clang-18 CXX=clang++-18
cmake -S Cmake/ -B build/ \
  -DCMAKE_INSTALL_PREFIX="$HOME/.local" -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_TOOLS=ON -DENABLE_SHARED_LIBS=ON -DENABLE_STATIC_LIBS=ON \
  -DENABLE_TESTS=ON -DENABLE_INSTALL_RIM=ON -DENABLE_ICCXML=ON \
  -DCMAKE_C_FLAGS="-g3 -O0 -fno-omit-frame-pointer -fno-limit-debug-info \
    -fprofile-instr-generate -fcoverage-mapping -Wall" \
  -DCMAKE_CXX_FLAGS="-g3 -O0 -fno-omit-frame-pointer -fno-limit-debug-info \
    -fprofile-instr-generate -fcoverage-mapping -fsanitize=address,undefined -Wall" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined -fprofile-instr-generate" \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON
cd build && make -j$(nproc) && cd ..
```

---

## CMake Configuration Examples

### Debug Logging + X11

```bash
cmake -S Cmake/ -B . \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_INSTALL_PREFIX="$HOME/.local" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DENABLE_TOOLS=ON -DENABLE_SHARED_LIBS=ON -DENABLE_STATIC_LIBS=ON \
  -DENABLE_TESTS=ON -DENABLE_INSTALL_RIM=ON -DENABLE_ICCXML=ON \
  -DICC_TRACE_NAN_ENABLED=ON -DICC_CLUT_DEBUG=ON \
  -DCMAKE_CXX_FLAGS="-g3 -O0 -fsanitize=address,undefined -fno-omit-frame-pointer \
    -fno-inline -Wall -Wextra -DICC_TRACE_NAN_ENABLED -DICC_CLUT_DEBUG \
    -DICC_ENABLE_ASSERTS -DICC_LOG_SAFE" \
  -DCMAKE_EXE_LINKER_FLAGS="-lX11 -fsanitize=address,undefined"
make -j$(nproc)
```

### Release with Debug Defines

```bash
cmake -S Cmake/ -B . \
  -DCMAKE_INSTALL_PREFIX="$HOME/.local" \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_TOOLS=ON -DENABLE_SHARED_LIBS=ON -DENABLE_STATIC_LIBS=ON \
  -DENABLE_TESTS=ON -DENABLE_INSTALL_RIM=ON -DENABLE_ICCXML=ON \
  -DICC_TRACE_NAN_ENABLED=ON -DICC_CLUT_DEBUG=ON \
  -DCMAKE_CXX_FLAGS="-DICC_TRACE_NAN_ENABLED -DICC_CLUT_DEBUG \
    -DICC_ENABLE_ASSERTS -DICC_LOG_SAFE" \
  -DCMAKE_EXE_LINKER_FLAGS="-Wl,--as-needed -Wl,--no-as-needed -lX11"
make -j$(nproc)
```

---

## Add Tools to PATH

```bash
cd ../Testing/
for d in ../Build/Tools/*; do
  [ -d "$d" ] && export PATH="$(realpath "$d"):$PATH"
done
```

---

## Find Binaries and Checksums

### List Recently Built Binaries
```bash
find . -type f \( -perm -111 -o -name "*.a" -o -name "*.so" -o -name "*.dylib" \) \
  -mmin -1440 ! -path "*/.git/*" ! -path "*/CMakeFiles/*" ! -name "*.sh" -print
```

### Generate SHA-256 Checksums
```bash
find . -type f \( -perm -111 -o -name "*.a" -o -name "*.so" -o -name "*.dylib" \) \
  -mmin -1440 ! -path "*/.git/*" ! -path "*/CMakeFiles/*" ! -name "*.sh" -print \
  | xargs sha256sum
```

### List Executables Only
```bash
find . -type f -executable ! -name "*.a" ! -name "*.so" ! -name "*.dylib" \
  ! -path "*/obj/*" ! -path "*/.git/*" ! -path "*/CMakeFiles/*" -print
```

---

## Testing — Batch Loops

### Runtime Environment Variables

Always set these when running iccDEV tools built with ASAN/UBSAN:

```bash
export ASAN_OPTIONS=halt_on_error=0,detect_leaks=0
export UBSAN_OPTIONS=halt_on_error=0,print_stacktrace=1
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML:$LD_LIBRARY_PATH
```

- `halt_on_error=0` — catch-and-continue to see the full error chain
- `detect_leaks=0` — iccDEV has known leak patterns; skip for analysis runs

### iccDumpProfile
```bash
for f in *.icc; do iccDumpProfile -v "$f" 2>&1 | sed "s|^|[$f] |"; done > dump.log 2>&1
```

### iccToXml
```bash
for f in *.icc; do iccToXml "$f" "${f%.icc}.xml" 2>&1 | sed "s|^|[$f] |"; done > toxml.log 2>&1
```

### iccFromXml
```bash
for f in *.xml; do iccFromXml "$f" "${f%.xml}.icc" 2>&1 | sed "s|^|[$f] |"; done > fromxml.log 2>&1
```

### iccRoundTrip
```bash
for f in *.icc; do iccRoundTrip "$f" | sed "s|^|[$f] |"; done > rt.log 2>&1
```

### iccApplyProfiles (all ICC × all TIFF)
```bash
shopt -s nullglob
for t in *.tiff; do
  for i in *.icc; do
    iccApplyProfiles "$t" "/tmp/$(basename "$t" .tiff)_$(basename "$i" .icc).tiff" 0 0 0 0 0 "$i" 0
  done
done
```

### iccDumpProfile in a Specific Directory
```bash
cd Testing/
dir=../Testing/ICS
for f in "$dir"/*.{icc,icm}; do
  [ -f "$f" ] && ../Build/Tools/IccDumpProfile/iccDumpProfile -v "$f"
done
```

---

## Testing — 1-Liners

```bash
find . -type f -name '*.icc' -print0 | xargs -0 -I{} sh -c 'iccDumpProfile -v "{}" 2>&1 | sed "s|^|[{}] |"' >> iccDumpProfile.log
find . -type f -name '*.icc' -print0 | xargs -0 -I{} sh -c 'iccToXml "{}" "{}.xml" 2>&1 | sed "s|^|[{}] |"' >> iccToXml.log
find . -type f -name '*.xml' -print0 | xargs -0 -I{} sh -c 'iccFromXml "{}" "{}.icc" 2>&1 | sed "s|^|[{}] |"' >> iccFromXml.log
find . -type f -name '*.icc' -print0 | xargs -0 -I{} sh -c 'iccRoundTrip "{}" 2>&1 | sed "s|^|[{}] |"' >> iccRoundTrip.log
```

---

## Testing — Recursive with Logs

```bash
LOG_DUMP=iccDumpProfile.log
LOG_TOXML=iccToXml.log
LOG_FROMXML=iccFromXml.log
LOG_ROUND=iccRoundTrip.log
: >"$LOG_DUMP" ; : >"$LOG_TOXML" ; : >"$LOG_FROMXML" ; : >"$LOG_ROUND"

find . -type f -name '*.icc' -print0 |
while IFS= read -r -d '' f; do
  iccDumpProfile -v "$f" 2>&1 | sed "s|^|[$f] |" >>"$LOG_DUMP"
done

find . -type f -name '*.icc' -print0 |
while IFS= read -r -d '' f; do
  iccToXml "$f" "${f}.xml" 2>&1 | sed "s|^|[$f] |" >>"$LOG_TOXML"
done

find . -type f -name '*.xml' -print0 |
while IFS= read -r -d '' f; do
  iccFromXml "$f" "${f}.icc" 2>&1 | sed "s|^|[$f] |" >>"$LOG_FROMXML"
done

find . -type f -name '*.icc' -print0 |
while IFS= read -r -d '' f; do
  iccRoundTrip "$f" 2>&1 | sed "s|^|[$f] |" >>"$LOG_ROUND"
done
```

### Log Analysis Patterns

```bash
# Errors and crashes
grep -E 'ERROR|WARN|WARNING|FAIL|FATAL|ASSERT|ABORT|PANIC|EXCEPTION|CRASH' *.log
grep -E 'SIG(SEGV|ABRT|BUS|ILL)' *.log

# Data integrity
grep -E 'INVALID|CORRUPT|MALFORMED|TRUNCATED|UNSUPPORTED|UNKNOWN|UNDEFINED' *.log
grep -E 'OVERFLOW|UNDERFLOW|OUT OF RANGE' *.log

# Memory / resource
grep -E 'ALLOC|FREE|LEAK|OOM|OUT OF MEMORY|NULL' *.log
grep -E 'TIMEOUT|DEADLOCK|HANG' *.log

# ASAN / UBSAN specific
grep -E 'AddressSanitizer|runtime error:' *.log
```

---

## Testing — Automated Test Suites

### Full 14-Tool Test Suite (parallel, 843 tests)

```bash
bash .github/scripts/test-iccdev-all.sh
```

Runs all 14 tools with ASAN+UBSAN, parallel execution on all cores.
Expected baseline: 843 tests / ~30s / 0 ASAN / 0 UBSAN.

### Dedicated iccSpecSepToTiff Tests (34 tests)

```bash
bash .github/scripts/test-specseptotiff.sh
```

Covers error handling, basic merging, compression, separation modes,
ICC profile embedding, and cross-validation with iccTiffDump.
Uses pre-built spectral seed TIFFs at `iccDEV/Testing/Fuzzing/seeds/tiff/spectral/`.

### TIFF Mass Testing (all tools × large corpus)

```bash
# Mass test all TIFF-capable tools against a large corpus
# Uses 32-core parallelism, ASAN+UBSAN, coverage profiling
python3 << 'PYEOF'
import os, subprocess, random

REPO = os.path.expanduser("~/po/research")
LD_PATH = f"{REPO}/iccDEV/Build/IccProfLib:{REPO}/iccDEV/Build/IccXML"
env = os.environ.copy()
env["LD_LIBRARY_PATH"] = LD_PATH
env["ASAN_OPTIONS"] = "halt_on_error=0,detect_leaks=0"

# iccTiffDump: read-only, safe for all TIFFs
TIFFDUMP = f"{REPO}/iccDEV/Build/Tools/IccTiffDump/iccTiffDump"
for tiff in random.sample(tiff_files, 500):
    subprocess.run([TIFFDUMP, tiff], env=env, timeout=30,
                   capture_output=True)
PYEOF
```

### iccSpecSepToTiff — All Option Combinations

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML
export ASAN_OPTIONS=halt_on_error=0,detect_leaks=0
SEEDS=iccDEV/Testing/Fuzzing/seeds/tiff/spectral

# All combos: compress(0,1) × sep(0,1) × profile(none, sRGB, spectral)
for c in 0 1; do
  for s in 0 1; do
    for p in "" "test-profiles/sRGB_D65_MAT.icc" "test-profiles/Rec2020rgbSpectral.icc"; do
      out="/tmp/ss_c${c}_s${s}.tif"
      args="$out $c $s $SEEDS/spec_%03d.tif 1 10 1"
      [ -n "$p" ] && args="$args $p"
      iccSpecSepToTiff $args
    done
  done
done
```

### iccApplyProfiles — Full Option Matrix

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML
export ASAN_OPTIONS=halt_on_error=0,detect_leaks=0

# encoding(0,1,2) × compression(0,1) × planar(0,1) × embed(0,1) × interp(0,1) × intent(0,1,2,3)
for enc in 0 1 2; do
  for comp in 0 1; do
    for plan in 0 1; do
      for embed in 0 1; do
        for interp in 0 1; do
          for intent in 0 1 2 3; do
            iccApplyProfiles input.tiff /tmp/out_${enc}${comp}${plan}${embed}${interp}${intent}.tiff \
              $enc $comp $plan $embed $interp test-profiles/sRGB_D65_MAT.icc $intent
          done
        done
      done
    done
  done
done
```

---

## xmllint Validation

### Comprehensive Per-File Check
```bash
for f in *.xml; do
  echo "==> $f"
  xmllint --noout "$f" || echo "[FAIL] well-formedness $f"
  xmllint --format --noout "$f" >/dev/null || echo "[FAIL] format/trailing-content $f"
  xmllint --noout --encode UTF-8 "$f" || echo "[FAIL] encoding $f"
  xmllint --recover --noout "$f" || echo "[FAIL] unrecoverable $f"
  xmllint --noout --maxmem 104857600 "$f" || echo "[FAIL] size/huge-node $f"
  xmllint --noout --noent --nonet "$f" || echo "[FAIL] entity/safety $f"
done
```

### Individual 1-Liners
```bash
for f in *.xml; do echo "==> $f"; xmllint --noout "$f" || echo "FAIL $f"; done
for f in *.xml; do echo "==> $f"; xmllint --format --noout "$f" >/dev/null || echo "FAIL $f"; done
for f in *.xml; do echo "==> $f"; xmllint --noout --encode UTF-8 "$f" || echo "FAIL $f"; done
for f in *.xml; do echo "==> $f"; xmllint --noout --noent --nonet "$f" || echo "FAIL $f"; done
```

---

## Coverage Instrumentation

### Important: Clang Source-Based Coverage

iccDEV uses **clang source-based coverage** (NOT gcov):

| Correct (clang) | Wrong (gcov) |
|---|---|
| `-fprofile-instr-generate -fcoverage-mapping` | `-fprofile-arcs -ftest-coverage` |
| Produces `.profraw` files | Produces `.gcda`/`.gcno` files |
| Merge: `llvm-profdata merge` | Merge: `lcov` |
| Report: `llvm-cov report/show` | Report: `genhtml` |

### Run Profiled Executions

```bash
mkdir -p output_xml
for f in *.icc; do
  base="$(basename "$f" .icc)"
  LLVM_PROFILE_FILE="profraw/iccToXml_${base}_%m.profraw" \
    iccToXml "$f" "output_xml/${base}.xml"
done
```

### Merge Profiles and Generate Reports

```bash
llvm-profdata-18 merge -sparse profraw/*.profraw -o merged.profdata

# Summary report
llvm-cov-18 report ./iccToXml -instr-profile=merged.profdata

# Per-line annotated source
llvm-cov-18 show ./iccToXml -instr-profile=merged.profdata > coverage.txt

# LCOV export for HTML
llvm-cov-18 export ./iccToXml -instr-profile=merged.profdata -format=lcov > coverage.lcov
genhtml -o htmlcov coverage.lcov
```

### Verify Instrumentation in Binaries

```bash
find . -type f \( -perm -111 -o -name "*.so" -o -name "*.a" \) \
  -exec sh -c 'llvm-objdump -t "$1" 2>/dev/null | grep -q "__llvm_profile" \
    && echo "PASS llvmprof $1" || echo "FAIL llvmprof $1"' _ {} \;
```

---

## iccanalyzer-lite (Security Research)

These commands are specific to the [xsscx/research](https://github.com/xsscx/research)
repository's security analyzer.

### Build

```bash
cd iccanalyzer-lite && ./build.sh
```

### Run 145-Heuristic Security Analysis

```bash
# Full analysis (auto-detects ICC profiles and TIFF images)
./iccanalyzer-lite -a profile.icc

# JSON structured output
./iccanalyzer-lite --json profile.icc

# Professional severity-sorted report
./iccanalyzer-lite --report profile.icc

# XML with dark-themed XSLT
./iccanalyzer-lite -xml profile.icc output.xml

# TIFF image analysis (extracts embedded ICC + H139-H141 checks)
./iccanalyzer-lite -a image.tif

# Batch analysis with ASAN catch-and-continue
ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
  ./iccanalyzer-lite -a profile.icc
```

### Batch Analysis Script

```bash
# Analyze all profiles in test-profiles/
for f in test-profiles/*.icc; do
  echo "=== $(basename "$f") ==="
  ASAN_OPTIONS=halt_on_error=0,detect_leaks=0 \
    ./iccanalyzer-lite/iccanalyzer-lite -a "$f" 2>&1 | tail -5
done
```

### Test Suite

```bash
python3 iccanalyzer-lite/tests/run_tests.py   # 217 tests, ~25s
```

---

## Tool Checks

### iccJpegDump
```bash
iccDEV/Build/Tools/IccJpegDump/iccJpegDump input.jpg output.icc
```

### iccTiffDump
```bash
iccDEV/Build/Tools/IccTiffDump/iccTiffDump input.tif exported.icc
iccDEV/Build/Tools/IccToXml/iccToXml exported.icc exported.xml
xxd -l 512 exported.icc
```

### Hex Dump
```bash
xxd -l 512 profile.icc            # first 512 bytes
xxd -s 36 -l 4 profile.icc        # magic bytes at offset 36 (should be 'acsp')
xxd -s 128 -l 4 profile.icc       # tag count at offset 128
```

---

## WASM Build

### Compile Little ICC Scanner

```bash
em++ licc.cpp -o licc.js -O2 -s USE_ZLIB=1 -s ALLOW_MEMORY_GROWTH=1 \
  -s FORCE_FILESYSTEM=1 -s MODULARIZE=1 -s EXPORT_NAME=createModule \
  -s EXPORTED_RUNTIME_METHODS='["FS","callMain"]' \
  -I../../IccProfLib -I../../IccXML/IccLibXML
```

### Find WASM/JS Files

```bash
find . -type f \( -name '*.js' -o -name '*.wasm' \) -ls
```

---

## Debugging — LLDB

### Break on LUT

```
target create "iccDEV/Build/Tools/IccRoundTrip/iccRoundTrip"
settings set -- target.run-args "ICS/Rec2100HlgFull-Part2.icc"
break set -n icDtoF
run
```

### Search Memory

```
memory find -c 7 -s "/bin/sh" -- 0x0000000000000000 0x7fffffffffffffff
memory read -fx -s8 0x7ff7bfefc000 0x7ff7bfefc050
```

---

## Debugging — ASAN / Build IDs

### Read Build ID

```bash
readelf -n iccApplyNamedCmm | grep -A2 'Build ID'
```

### Key Concept

- **Git commit** identifies source state
- **Build ID** identifies binary state (changes with compiler flags, link order, LTO)
- For ASAN issues, always report **both** commit and Build ID

### SCARINESS Output

```bash
ASAN_OPTIONS=print_scariness=1:halt_on_error=0:abort_on_error=0:print_full_stacktrace=1:detect_leaks=0 \
  iccDumpProfile -v crash-file.icc
```

---

## Dependency Checks

```bash
# Linux — check dynamic dependencies
ldd iccDEV/Build/Tools/IccFromXml/iccFromXml

# macOS — check dynamic dependencies
otool -L iccDEV/Build/Tools/IccFromXml/iccFromXml

# Check for iconv
ldd iccDEV/Build/Tools/IccFromXml/iccFromXml | grep -i iconv
```

---

## Git Helpers

### Clone

```bash
git clone https://github.com/InternationalColorConsortium/iccDEV.git
```

### Clone at Specific Commit

```bash
git clone https://github.com/InternationalColorConsortium/iccDEV.git \
  && cd iccDEV && git checkout <COMMIT_SHA>
```

### Shallow Clone at Commit

```bash
git init iccDEV && cd iccDEV \
  && git remote add origin https://github.com/InternationalColorConsortium/iccDEV.git \
  && git fetch --depth 1 origin <COMMIT_SHA> && git checkout FETCH_HEAD
```

### Build at Specific Commit

```bash
git clone https://github.com/InternationalColorConsortium/iccDEV.git \
  && cd iccDEV && git checkout <COMMIT_SHA> \
  && cd Build && cmake -S Cmake -B . && make -j$(nproc)
```

### Git Diff / Log

```bash
git --no-pager diff main..feature             # Full diff
git --no-pager diff --name-only main..feature # File list
git --no-pager diff --stat main..feature      # Stats
git --no-pager log --oneline origin/main..HEAD # Unpushed commits
git log --oneline --graph -5
```

### Delete GitHub Workflow Runs

```bash
gh run list --limit 100 --json databaseId --jq '.[].databaseId' | xargs -I{} gh run delete {}
```

### Delete GitHub Actions Caches

```bash
gh cache list --json id --limit 100 --jq '.[].id' | xargs -I{} gh cache delete {}
```

---

## Misc Utilities

### Calculate Memory Allocation

```bash
printf "0x3c05fc010 = %d bytes = %d GB\n" $((0x3c05fc010)) $((0x3c05fc010 / 1024 / 1024 / 1024))
```

### Filter Build Errors

```bash
make -j$(nproc) 2>&1 | grep -i -E 'error:'
```

### PGP / SHA Signing

```bash
sha256sum artifact.zip > artifact.zip.sha256
gpg --armor --sign --detach-sign artifact.zip.sha256
gpg --verify artifact.zip.sha256.asc artifact.zip.sha256
sha256sum -c artifact.zip.sha256
```

### vcpkg — Linux

```bash
~/vcpkg/vcpkg --classic install iccdev --overlay-ports=iccDEV/ports \
  --clean-after-build --clean-downloads-after-build --clean-packages-after-build

for bin in ~/vcpkg/installed/x64-linux/bin/icc*; do
  echo "== Testing $(basename "$bin") =="
  "$bin" --help 2>&1 | sed -n '1,20p'
done
```
