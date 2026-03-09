# iccDEV Shell Helpers — Windows (PowerShell / MSVC / VS2022)

Reference commands for building, testing, and debugging
[iccDEV](https://github.com/InternationalColorConsortium/iccDEV) on Windows.

> **Repository**: <https://github.com/InternationalColorConsortium/iccDEV.git>
> **Research**: <https://github.com/xsscx/research>

---

## Table of Contents

- [Dependencies](#dependencies)
- [Build — Quick Start (MSVC)](#build--quick-start-msvc)
- [Build — vcpkg Setup](#build--vcpkg-setup)
- [Build — vcpkg Exported Deps](#build--vcpkg-exported-deps)
- [Build — Multi-Configuration Loop](#build--multi-configuration-loop)
- [Build — Per-Configuration One-Liners](#build--per-configuration-one-liners)
- [Build — ASAN (Enterprise Toolchain)](#build--asan-enterprise-toolchain)
- [Build — ASAN (ClangCL)](#build--asan-clangcl)
- [Build — Per-Target](#build--per-target)
- [Build — cmake via vcpkg.json](#build--cmake-via-vcpkgjson)
- [Add Tools to PATH](#add-tools-to-path)
- [Find Binaries and Checksums](#find-binaries-and-checksums)
- [Testing — Run Batch Files](#testing--run-batch-files)
- [Testing — Full Workflow](#testing--full-workflow)
- [vcpkg Management](#vcpkg-management)
- [Clean Up](#clean-up)
- [Code Analysis — SARIF / Static Analysis](#code-analysis--sarif--static-analysis)
- [Dependency Checks](#dependency-checks)
- [Visual Studio Queries](#visual-studio-queries)
- [Build Graph Visualization](#build-graph-visualization)
- [Misc Utilities](#misc-utilities)

---

## Dependencies

| Dependency | Windows (vcpkg) |
|---|---|
| Build Tool | cmake, Visual Studio 2022 (C++ Desktop workload) |
| Image Libraries | `libpng`, `libjpeg-turbo`, `tiff` |
| GUI & Config | `wxwidgets`, `nlohmann-json`, `libxml2` |

### Prerequisites

- Windows 10/11
- Visual Studio 2022 (with C++ Desktop Development workload)
- PowerShell 5.1+
- Administrator or Developer command prompt

---

## Build — Quick Start (MSVC)

```powershell
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV
vcpkg integrate install
vcpkg install
cmake --preset vs2022-x64 -B . -S Build/Cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
cmake --build . -- /m /maxcpucount
devenv RefIccMAX.sln
```

---

## Build — vcpkg Setup

### Clone and Bootstrap vcpkg

```powershell
mkdir C:\test\
cd C:\test\
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat -disableMetrics
.\vcpkg.exe integrate install
```

### Install Required Libraries (dynamic + static)

```powershell
.\vcpkg.exe install `
  libpng `
  nlohmann-json:x64-windows `
  nlohmann-json:x64-windows-static `
  libxml2:x64-windows `
  libxml2:x64-windows-static `
  tiff:x64-windows `
  tiff:x64-windows-static `
  wxwidgets:x64-windows `
  wxwidgets:x64-windows-static `
  libjpeg-turbo:x64-windows `
  libjpeg-turbo:x64-windows-static
```

---

## Build — vcpkg Exported Deps

Download pre-built dependencies from GitHub Releases:

```powershell
Write-Host "Cloning iccDEV..."
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV
Write-Host "Fetching deps from releases..."
Start-BitsTransfer -Source "https://github.com/InternationalColorConsortium/iccDEV/releases/download/v2.3.1/vcpkg-exported-deps.zip" -Destination "deps.zip"
Write-Host "Extracting dependencies..."
tar -xf deps.zip
cd Build/Cmake
Write-Host "Configuring iccDEV..."
cmake -B build -S . `
  -DCMAKE_TOOLCHAIN_FILE="..\..\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_MANIFEST_MODE=OFF -DCMAKE_BUILD_TYPE=Debug -Wno-dev
cmake --build build -- /m /maxcpucount
```

---

## Build — Multi-Configuration Loop

Builds all 4 configurations (Debug, Release, RelWithDebInfo, MinSizeRel):

```powershell
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV\Build
mkdir win; cd win

$base = Get-Location
$sourceDir = Resolve-Path "$base\..\Cmake"
$toolchain = "C:/test/vcpkg/scripts/buildsystems/vcpkg.cmake"
$vcpkgInclude = "C:/test/vcpkg/installed/x64-windows/include"
$vcpkgLib = "C:/test/vcpkg/installed/x64-windows/lib"

$configs = @{
  "Debug"          = "MultiThreadedDebugDLL"
  "Release"        = "MultiThreadedDLL"
  "RelWithDebInfo" = "MultiThreadedDLL"
  "MinSizeRel"     = "MultiThreadedDLL"
}

foreach ($cfg in $configs.Keys) {
    $outDir = "$base\build_$cfg"
    if (-Not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
    Set-Location $outDir
    Remove-Item -Recurse -Force .\CMakeCache.txt, .\CMakeFiles -ErrorAction SilentlyContinue

    cmake -S $sourceDir -B . -G "Visual Studio 17 2022" -A x64 `
      "-DCMAKE_BUILD_TYPE=$cfg" `
      "-DCMAKE_TOOLCHAIN_FILE=$toolchain" `
      "-DCMAKE_C_FLAGS=/Od /Zi /I $vcpkgInclude" `
      "-DCMAKE_CXX_FLAGS=/Od /Zi /I $vcpkgInclude" `
      "-DCMAKE_SHARED_LINKER_FLAGS=/LIBPATH:$vcpkgLib" `
      "-DCMAKE_MSVC_RUNTIME_LIBRARY=$($configs[$cfg])" `
      -DENABLE_TOOLS=ON -DENABLE_SHARED_LIBS=ON -DENABLE_STATIC_LIBS=ON `
      -DENABLE_TESTS=ON -DENABLE_INSTALL_RIM=ON -DENABLE_ICCXML=ON `
      -DENABLE_SPECTRE_MITIGATION=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON `
      "--graphviz=iccMAX-$cfg.dot"

    Write-Host "`n>>>>> Building $cfg configuration <<<<<" -ForegroundColor Green
    cmake --build . --config $cfg -- /m /maxcpucount:32
    Set-Location $base
}
```

### Clean All 4 Configurations

```powershell
foreach($cfg in "Debug","Release","RelWithDebInfo","MinSizeRel") {
  $d = "build_$cfg"
  if (Test-Path $d) { cmake --build $d --config $cfg --target clean *> $null }
}
```

---

## Build — Per-Configuration One-Liners

### Debug

```powershell
cmake -S Cmake -B a -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Debug `
  -DCMAKE_TOOLCHAIN_FILE=C:/test/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DCMAKE_C_FLAGS="/MD /O2 /Zi /GL /DEBUG /I C:/test/vcpkg/installed/x64-windows/include" `
  -DCMAKE_CXX_FLAGS="/MD /O2 /Zi /GL /DEBUG /I C:/test/vcpkg/installed/x64-windows/include" `
  -DCMAKE_SHARED_LINKER_FLAGS="/DEBUG /OPT:REF /OPT:ICF /LTCG /LIBPATH:C:/test/vcpkg/installed/x64-windows/lib" `
  -DENABLE_TOOLS=ON -DENABLE_SHARED_LIBS=ON -DENABLE_STATIC_LIBS=ON `
  -DENABLE_TESTS=ON -DENABLE_INSTALL_RIM=ON -DENABLE_ICCXML=ON `
  -DENABLE_SPECTRE_MITIGATION=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON `
  --graphviz=iccMAX-Debug.dot
cmake --build a --config Debug -- /m /maxcpucount:32
```

### Release

```powershell
cmake -S Cmake -B a -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release `
  -DCMAKE_TOOLCHAIN_FILE=C:/test/vcpkg/scripts/buildsystems/vcpkg.cmake `
  -DCMAKE_C_FLAGS="/MD /O2 /Zi /GL /I C:/test/vcpkg/installed/x64-windows/include" `
  -DCMAKE_CXX_FLAGS="/MD /O2 /Zi /GL /DEBUG /I C:/test/vcpkg/installed/x64-windows/include" `
  -DCMAKE_SHARED_LINKER_FLAGS="/DEBUG /OPT:REF /OPT:ICF /LTCG /LIBPATH:C:/test/vcpkg/installed/x64-windows/lib" `
  -DENABLE_TOOLS=ON -DENABLE_SHARED_LIBS=ON -DENABLE_STATIC_LIBS=ON `
  -DENABLE_TESTS=ON -DENABLE_INSTALL_RIM=ON -DENABLE_ICCXML=ON `
  -DENABLE_SPECTRE_MITIGATION=OFF -DCMAKE_EXPORT_COMPILE_COMMANDS=ON `
  --graphviz=iccMAX-Release.dot
cmake --build a --config Release -- /m /maxcpucount:32
```

---

## Build — ASAN (Enterprise Toolchain)

```powershell
cmake --preset vs2022-x64 -B . -S Build/Cmake `
  -DCMAKE_BUILD_TYPE=Debug `
  -DCMAKE_CXX_FLAGS_DEBUG="/Zi /Od /fsanitize=address /Oy- /MDd" `
  -DCMAKE_C_FLAGS_DEBUG="/Zi /Od /fsanitize=address /Oy- /MDd" `
  -DCMAKE_TOOLCHAIN_FILE="C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/vcpkg/scripts/buildsystems/vcpkg.cmake"
cmake --build . -- /m /maxcpucount
```

### VS2022 Enterprise (no ASAN)

```powershell
cmake --preset vs2022-x64 -B . -S Build/Cmake `
  -DCMAKE_TOOLCHAIN_FILE="C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/vcpkg/scripts/buildsystems/vcpkg.cmake"
```

---

## Build — ASAN (ClangCL)

```powershell
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV
Start-BitsTransfer -Source "https://github.com/InternationalColorConsortium/iccDEV/releases/download/v2.3.1/vcpkg-exported-deps.zip" -Destination "deps.zip"
tar -xf deps.zip
cd Build/Cmake
cmake -Wno-dev -T ClangCL -S . -B build -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="..\..\scripts\buildsystems\vcpkg.cmake" `
  -DVCPKG_MANIFEST_MODE=OFF `
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL `
  -DCMAKE_CXX_STANDARD=17 -DCMAKE_CXX_STANDARD_REQUIRED=ON `
  -DCMAKE_CXX_EXTENSIONS=OFF
cmake --build build -- /m /maxcpucount
```

---

## Build — Per-Target

```powershell
# Build individual targets
$targets = @(
  'IccProfLib2', 'IccProfLib2-static', 'IccXML2', 'IccXML2-static',
  'iccDumpProfile', 'iccToXml', 'iccFromXml', 'iccRoundTrip',
  'iccFromCube', 'iccV5DspObsToV4Dsp', 'iccPngDump', 'iccTiffDump',
  'iccSpecSepToTiff', 'iccApplyToLink', 'iccApplyProfiles',
  'iccApplyNamedCmm', 'iccDumpProfileGui'
)
foreach ($t in $targets) {
  cmake --build . --config Release --parallel 32 --target $t
}
```

---

## Build — cmake via vcpkg.json

```powershell
cmake ..\Cmake -G "Visual Studio 17 2022" -A x64 `
  -DCMAKE_TOOLCHAIN_FILE="C:/Program Files/Microsoft Visual Studio/2022/Community/VC/vcpkg/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_MANIFEST_DIR="$PWD\..\.." `
  -DCMAKE_BUILD_TYPE=Release -DENABLE_ICCXML=ON -DUSE_SYSTEM_LIBXML2=OFF
cmake --build . --config Release -- /m /maxcpucount
```

---

## Add Tools to PATH

### Auto-Discover Tool Directories

```powershell
$exeDirs = Get-ChildItem -Recurse -File -Include *.exe -Path .\Tools\ |
    Where-Object {
      $_.FullName -match 'icc' -and
      $_.FullName -notmatch '\\CMakeFiles\\' -and
      $_.Name -notmatch '^CMake(C|CXX)CompilerId\.exe$'
    } |
    ForEach-Object { Split-Path $_.FullName -Parent } |
    Sort-Object -Unique

$env:PATH = ($exeDirs -join ';') + ';' + $env:PATH
$env:PATH -split ';' | Select-String "icc"
```

### Verify Tools in PATH

```powershell
'iccFromXml','iccDumpProfile','iccRoundTrip','iccApplyProfiles' |
  ForEach-Object {
    '{0,-18} -> {1}' -f $_, (Get-Command $_ -ErrorAction SilentlyContinue |
      Select-Object -Expand Source)
  }
```

---

## Find Binaries and Checksums

### List Build Artifacts (.exe + .lib)

```powershell
Get-ChildItem -Recurse -Include *.exe,*.lib -Path . |
  Where-Object { -not $_.PSIsContainer -and $_.FullName -notmatch '\\CMakeFiles\\' } |
  Select-Object FullName, Length | Sort-Object FullName
```

### SHA-256 Checksums

```powershell
Get-ChildItem -Path ".\build" -Recurse -File |
  Where-Object {
    ($_.Extension -in '.exe','.dll','.lib','.a','.so','.dylib') -and
    ($_.LastWriteTime -gt (Get-Date).AddMinutes(-1440)) -and
    ($_.FullName -notmatch '\.git|CMakeFiles') -and
    ($_.Extension -ne '.sh')
  } | ForEach-Object {
    "$((Get-FileHash $_.FullName -Algorithm SHA256).Hash)  $($_.FullName)"
  }
```

### List DLL/LIB/EXE/PDB in Tools

```powershell
Get-ChildItem -Recurse -Include *.dll, *.lib, *.exe, *.pdb -Path .\Tools |
  Where-Object { -Not $_.PSIsContainer } |
  Select-Object FullName | Sort-Object FullName
```

---

## Testing — Run Batch Files

```powershell
cd Testing
.\CreateAllProfiles.bat
.\RunTests.bat
cd CalcTest\; .\checkInvalidProfiles.bat; .\runtests.bat
cd ..\Display; .\RunProtoTests.bat
cd ..\HDR; .\mkprofiles.bat
cd ..\mcs\; .\updateprev.bat; .\updateprevWithBkgd.bat
cd ..\Overprint; .\RunTests.bat
cd ..\hybrid; .\BuildAndTest.bat
cd ..
```

### Run All .bat Files

```powershell
Get-ChildItem -Path "." -Recurse -Filter *.bat |
  ForEach-Object { Write-Host "Running: $($_.FullName)"; & $_.FullName }
```

---

## Testing — Full Workflow

Clone, build, add PATH, create profiles, run all tests:

```powershell
git clone https://github.com/InternationalColorConsortium/iccDEV.git
cd iccDEV
vcpkg integrate install
vcpkg install
cmake --preset vs2022-x64 -B . -S Build/Cmake
cmake --build . -- /m /maxcpucount

$toolDirs = Get-ChildItem -Recurse -File -Include *.exe -Path .\Tools\ |
  ForEach-Object { Split-Path -Parent $_.FullName } | Sort-Object -Unique
$env:PATH = ($toolDirs -join ';') + ';' + $env:PATH

cd Testing
.\CreateAllProfiles.bat
.\RunTests.bat
cd CalcTest\; .\checkInvalidProfiles.bat; .\runtests.bat
cd ..\Display; .\RunProtoTests.bat
cd ..\HDR; .\mkprofiles.bat
cd ..\mcs\; .\updateprev.bat; .\updateprevWithBkgd.bat
cd ..\Overprint; .\RunTests.bat
cd ..\hybrid; .\BuildAndTest.bat
cd ..
```

---

## vcpkg Management

### Install via vcpkg

```powershell
& "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\vcpkg\vcpkg.exe" `
  install iccdev:x64-windows --recurse
```

### Find Installed Files

```powershell
Get-ChildItem -Recurse -File -Include *.exe,*.dll,*.lib,*.a -Path C:\test\vcpkg |
  Where-Object {
    $_.FullName -match 'iccdev' -and
    $_.FullName -notmatch '\\CMakeFiles\\'
  } | ForEach-Object { $_.FullName }
```

### Test Installed Tools

```powershell
Get-ChildItem -Path "C:\tmp\vcpkg\installed\x64-windows\tools\iccdev" -Filter *.exe |
  ForEach-Object {
    Write-Host "== Testing $($_.Name) =="
    & $_.FullName --help 2>&1 | Select-Object -First 20
    ""
  }
```

### Install from Overlay Ports

```powershell
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg.exe integrate install
.\vcpkg.exe --classic --overlay-ports=..\ports install iccdev[tools]:x64-windows `
  --debug --clean-after-build
.\vcpkg.exe list --triplet x64-windows
$tools = Get-ChildItem -File "..\vcpkg\packages\iccdev_x64-windows\tools\iccdev\*.exe" `
  -ErrorAction SilentlyContinue
if (-not $tools) { Write-Error "No tools found"; exit 1 }
foreach ($t in $tools) {
  Write-Host "== Testing $($t.Name) =="
  & $t.FullName --help 2>&1 | Select-Object -First 20
  Write-Host ""
}
```

---

## Clean Up

### Clean vcpkg

```powershell
Remove-Item -Recurse -Force "C:\test\vcpkg\installed"
Remove-Item -Recurse -Force "C:\test\vcpkg\buildtrees"
Remove-Item -Recurse -Force "C:\test\vcpkg\downloads"
Remove-Item -Recurse -Force "$env:LOCALAPPDATA\vcpkg\archives"

# Reset environment
[Environment]::SetEnvironmentVariable("VCPKG_ROOT", $null, "User")
Remove-Item Env:VCPKG_ROOT -ErrorAction SilentlyContinue
```

### Clean CMake Build

```powershell
cmake --build . --config Debug --target clean -- /m /maxcpucount
```

---

## Code Analysis — SARIF / Static Analysis

### Build with SARIF Output

```powershell
cmake --build . --target clean
cmake --preset vs2022-x64 -B . -S .\Build\Cmake\ `
  "-DCMAKE_TOOLCHAIN_FILE=C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/vcpkg/scripts/buildsystems/vcpkg.cmake"
cmake --build . -- /m /v:m `
  /p:RunCodeAnalysis=true `
  /p:CodeAnalysisLogFile=build.sarif `
  /p:CodeAnalysisLogFileType=SARIF `
  /p:VcpkgEnableManifest=true
```

### Full Analysis (Enterprise)

```powershell
if(-not (Test-Path out)){New-Item -ItemType Directory out *> $null}

cmake --preset vs2022-x64 -B . -S .\Build\Cmake\ `
  "-DCMAKE_TOOLCHAIN_FILE=C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/vcpkg/scripts/buildsystems/vcpkg.cmake" `
  -DCMAKE_CXX_CLANG_TIDY="clang-tidy;-format-style=file;-export-fixes=out\\clang-tidy-fixes.yaml" `
  -DCMAKE_C_FLAGS="/fsanitize=address" `
  -DCMAKE_CXX_FLAGS="/fsanitize=address"

cmake --build . --target clean

cmake --build . -- /m /v:m `
  /p:RunCodeAnalysis=true `
  /p:CodeAnalysisTreatWarningsAsErrors=true `
  /p:CodeAnalysisRuleSet="C:\Program Files\Microsoft Visual Studio\2022\Enterprise\Team Tools\Static Analysis Tools\Rule Sets\NativeRecommendedRules.ruleset" `
  /p:EnableCppCoreCheck=true `
  /p:VcpkgEnableManifest=true `
  /p:CodeAnalysisLogFile=out\codeanalysis.sarif `
  /p:CodeAnalysisLogFileType=SARIF `
  /bl:out\build.binlog `
  /fileLogger "/fileLoggerParameters:LogFile=out\msbuild.log;Append;Verbosity=diagnostic"
```

### AST Dump (clang)

```powershell
Get-ChildItem -Recurse Tools -Filter *.cpp | ForEach-Object {
  clang++ -Xclang -ast-dump -fsyntax-only `
    -IC:/test/vcpkg/installed/x64-windows/include `
    -I./IccProfLib -I./IccXML/IccLibXML `
    $_.FullName *> (Join-Path $_.Directory.FullName "$($_.BaseName)-ast.txt") 2>> warnings.log
}
```

---

## Dependency Checks

```powershell
dumpbin /dependents .\build_Debug\Tools\IccFromXml\IccFromXml.exe | findstr /i iconv
```

---

## Visual Studio Queries

### Version String

```powershell
& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
  -products * -latest -property catalog_productDisplayVersion
```

### DevEnv Path

```powershell
$devenv = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
  -products * -latest -property productPath
Write-Host "devenv.exe path: $devenv"
```

---

## Build Graph Visualization

If [Graphviz](https://graphviz.org/download/) is installed:

```powershell
dot -Tsvg iccMAX-Debug.dot -o iccMAX-Debug.svg
```

---

## Misc Utilities

### Timestamp

```powershell
Get-Date -Format "yyyy-MM-dd HH:mm:ss UTC" -AsUTC
```

### Git Commit Info

```powershell
git rev-parse HEAD; git show --no-patch --oneline
```

### Windows PATH (Session Only)

```powershell
$exeDirs = Get-ChildItem -Recurse -File -Include *.exe -Path .\build\ |
    Where-Object {
      $_.FullName -match 'icc' -and
      $_.FullName -notmatch '\\CMakeFiles\\' -and
      $_.Name -notmatch '^CMake(C|CXX)CompilerId\.exe$'
    } | ForEach-Object { Split-Path $_.FullName -Parent } | Sort-Object -Unique
$env:PATH = ($exeDirs -join ';') + ';' + $env:PATH
$env:PATH -split ';' | Select-String "icc"
```
