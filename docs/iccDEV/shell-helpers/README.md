# iccDEV Shell Helpers

Reference commands for building, testing, and debugging iccDEV
([InternationalColorConsortium/iccDEV](https://github.com/InternationalColorConsortium/iccDEV))
across platforms.

| Document | Platform | Sections |
|----------|----------|----------|
| [unix.md](unix.md) | Linux / macOS / WSL-2 | Build (6 configs), ASAN/UBSAN, coverage, testing, AFL, WASM, LLDB, xmllint |
| [windows.md](windows.md) | Windows / PowerShell / MSVC | Build (VS2022), vcpkg, ASAN, SARIF, multi-config, ClangCL |

## Quick Start

### Unix — Debug + ASAN + UBSAN + Coverage (recommended)

```bash
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV/Build
cmake -S Cmake -B . \
  -DCMAKE_C_COMPILER=clang-18 -DCMAKE_CXX_COMPILER=clang++-18 \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-g3 -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -fprofile-instr-generate -fcoverage-mapping" \
  -DCMAKE_CXX_FLAGS="-g3 -O0 -fsanitize=address,undefined -fno-omit-frame-pointer -fprofile-instr-generate -fcoverage-mapping" \
  -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined -fprofile-instr-generate" \
  -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined -fprofile-instr-generate" \
  -DENABLE_TOOLS=ON -Wno-dev
make -j$(nproc)
```

### Windows — Quick Start (MSVC + vcpkg)

```powershell
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV
vcpkg integrate install && vcpkg install
cmake --preset vs2022-x64 -B . -S Build/Cmake
cmake --build . -- /m /maxcpucount
```

## Relationship to Research Repo

The [xsscx/research](https://github.com/xsscx/research) repository uses iccDEV in
three components:

| Component | iccDEV Usage | Build |
|-----------|-------------|-------|
| `iccanalyzer-lite/` | Links unpatched upstream IccProfLib + IccLibXML | `./build.sh` |
| `cfl/` | Clones iccDEV, applies 20 patches, builds 12 fuzzers | `./build.sh` |
| `colorbleed_tools/` | Links unpatched upstream for ICC↔XML conversion | `make setup && make` |

The iccDEV checkout at `iccDEV/Build/` provides the **unpatched reference tools** used
for crash fidelity testing. See `copilot-instructions.md` for the full build policy.
