###############################################################
# Copyright (c) 2026 David H Hoyt LLC
#
# Intent: Build Windows ColorBleed diagnostic variants for release
#         assets used to reproduce ICC profile loading reports.
###############################################################

[CmdletBinding()]
param(
    [string]$DiagnosticProfileUrl = "https://registry.color.org/profile-registry/profiles/Coated_Fogra39L_VIGC_300.icc",
    [string]$IccDevRef = "",
    [string]$ArtifactName = "colorbleed-windows-diagnostics-x64",
    [string[]]$VariantNames = @()
)

$ErrorActionPreference = 'Stop'
$PSDefaultParameterValues['*:ErrorAction'] = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$iccDevDir = Join-Path $repoRoot 'colorbleed_tools\iccDEV'
$buildRoot = Join-Path $repoRoot 'colorbleed_tools\build-windows-diagnostics'
$artifactRoot = Join-Path $repoRoot $ArtifactName
$zipPath = Join-Path $repoRoot "$ArtifactName.zip"
$checksumPath = Join-Path $repoRoot "SHA256SUMS-$ArtifactName.txt"
$profilePath = Join-Path $buildRoot 'Coated_Fogra39L_VIGC_300.icc'
$parallelism = [Environment]::ProcessorCount

function Invoke-Native {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        [string[]]$Arguments = @()
    )

    & $FilePath @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "$FilePath exited with $LASTEXITCODE"
    }
}

function Convert-ToForwardSlash {
    param([string]$Path)
    return $Path.Replace('\', '/')
}

function Write-DumpbinReport {
    param(
        [string]$BinaryPath,
        [string]$OutputPrefix
    )

    $dumpbin = Get-Command dumpbin -ErrorAction SilentlyContinue
    if (-not $dumpbin) {
        "dumpbin not found in PATH" | Out-File -FilePath "$OutputPrefix-unavailable.txt" -Encoding ascii
        return
    }

    & $dumpbin.Source /dependents $BinaryPath |
        Out-File -FilePath "$OutputPrefix-dependents.txt" -Encoding ascii
    & $dumpbin.Source /headers $BinaryPath |
        Out-File -FilePath "$OutputPrefix-headers.txt" -Encoding ascii
}

function New-ProbeSource {
    param([string]$OutputPath)

    @'
#include "IccProfile.h"
#include "IccTag.h"

#include <cstdio>
#include <cstdlib>

#ifdef WIN32
#include <windows.h>
#endif

static void sigToStr(icUInt32Number sig, char out[5])
{
  out[0] = (char)((sig >> 24) & 0xff);
  out[1] = (char)((sig >> 16) & 0xff);
  out[2] = (char)((sig >> 8) & 0xff);
  out[3] = (char)(sig & 0xff);
  out[4] = '\0';
}

static int inspectProfile(const char *label, CIccProfile *profile)
{
  if (!profile) {
    std::printf("%s=NULL\n", label);
    return 1;
  }

  std::printf("%s=OK size=%u tags=%zu\n",
              label,
              profile->m_Header.size,
              profile->m_Tags.size());

  int badSizes = 0;
  bool sawChad = false;
  for (TagEntryList::const_iterator i = profile->m_Tags.begin(); i != profile->m_Tags.end(); ++i) {
    if (i->TagInfo.size == 0x73663332) {
      badSizes++;
    }
    if (i->TagInfo.sig == icSigChromaticAdaptationTag) {
      char type[5] = "----";
      sawChad = true;
      if (i->pTag) {
        sigToStr(i->pTag->GetType(), type);
      }
      std::printf("chad offset=%u size=%u type=%s\n",
                  i->TagInfo.offset,
                  i->TagInfo.size,
                  type);
    }
  }

  std::printf("saw_chad=%s\n", sawChad ? "yes" : "no");
  std::printf("entries_with_size_0x73663332=%d\n", badSizes);
  delete profile;
  return sawChad && badSizes == 0 ? 0 : 1;
}

#ifdef WIN32
static void printModulePath()
{
  HMODULE module = GetModuleHandleW(L"IccProfLib2.dll");
  if (!module) {
    std::printf("IccProfLib2.dll=not_loaded\n");
    return;
  }

  wchar_t path[MAX_PATH];
  DWORD len = GetModuleFileNameW(module, path, MAX_PATH);
  if (!len || len >= MAX_PATH) {
    std::printf("IccProfLib2.dll=path_unavailable\n");
    return;
  }

  std::printf("IccProfLib2.dll=");
  for (DWORD i = 0; i < len; i++) {
    std::printf("%c", path[i] < 128 ? (char)path[i] : '?');
  }
  std::printf("\n");
}
#endif

int main(int argc, char **argv)
{
  if (argc != 2) {
    std::fprintf(stderr, "usage: %s profile.icc\n", argv[0]);
    return 2;
  }

  int rc = inspectProfile("ReadIccProfile(char)", ReadIccProfile(argv[1]));

#ifdef WIN32
  wchar_t widePath[4096];
  size_t converted = 0;
  if (mbstowcs_s(&converted, widePath, argv[1], _TRUNCATE) != 0) {
    std::printf("ReadIccProfile(wchar)=conversion_failed\n");
    rc = 1;
  }
  else {
    rc |= inspectProfile("ReadIccProfile(wchar)", ReadIccProfile(widePath));
  }
  printModulePath();
#endif

  return rc;
}
'@ | Out-File -FilePath $OutputPath -Encoding ascii
}

function New-ToolsCMake {
    param(
        [string]$OutputPath,
        [string]$VariantName,
        [string]$IccBuildDir,
        [string]$IccDevPath,
        [string]$ProfLibPath,
        [string]$ProfDllPath,
        [bool]$Shared
    )

    $iccBuild = Convert-ToForwardSlash $IccBuildDir
    $iccDev = Convert-ToForwardSlash $IccDevPath
    $profLib = Convert-ToForwardSlash $ProfLibPath
    $workspace = Convert-ToForwardSlash $repoRoot
    $probe = Convert-ToForwardSlash (Join-Path $buildRoot 'issue987ReadProbe.cpp')
    $projectName = $VariantName.Replace('-', '_')

    if ($Shared) {
        $profDll = Convert-ToForwardSlash $ProfDllPath
        $importTarget = @"
add_library(IccProfLib2Runtime SHARED IMPORTED GLOBAL)
set_target_properties(IccProfLib2Runtime PROPERTIES
  IMPORTED_IMPLIB "$profLib"
  IMPORTED_LOCATION "$profDll"
  INTERFACE_INCLUDE_DIRECTORIES "$iccBuild/IccProfLib;$iccDev/IccProfLib;$iccDev"
)
"@
    }
    else {
        $importTarget = @"
add_library(IccProfLib2Runtime STATIC IMPORTED GLOBAL)
set_target_properties(IccProfLib2Runtime PROPERTIES
  IMPORTED_LOCATION "$profLib"
  INTERFACE_INCLUDE_DIRECTORIES "$iccBuild/IccProfLib;$iccDev/IccProfLib;$iccDev"
)
"@
    }

    @"
cmake_minimum_required(VERSION 3.21)
project(ColorBleedWindowsDiagnostics_$projectName LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
$importTarget
add_executable(iccDiagnosticLoad "$workspace/colorbleed_tools/IccDiagnosticLoad.cpp")
add_executable(iccDumpAll "$workspace/colorbleed_tools/IccDumpAll.cpp")
add_executable(issue987ReadProbe "$probe")
target_compile_definitions(iccDiagnosticLoad PRIVATE WIN32)
target_compile_definitions(iccDumpAll PRIVATE WIN32)
target_compile_definitions(issue987ReadProbe PRIVATE WIN32)
target_link_libraries(iccDiagnosticLoad PRIVATE IccProfLib2Runtime)
target_link_libraries(iccDumpAll PRIVATE IccProfLib2Runtime)
target_link_libraries(issue987ReadProbe PRIVATE IccProfLib2Runtime)
"@ | Out-File -FilePath $OutputPath -Encoding ascii
}

Remove-Item -Recurse -Force $buildRoot, $artifactRoot -ErrorAction SilentlyContinue
Remove-Item -Force $zipPath, $checksumPath -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $buildRoot, $artifactRoot | Out-Null

if (Test-Path $iccDevDir) {
    Remove-Item -Recurse -Force $iccDevDir
}
Invoke-Native -FilePath 'git' -Arguments @(
    'clone',
    '--depth',
    '1',
    'https://github.com/InternationalColorConsortium/iccDEV.git',
    $iccDevDir
)
if ($IccDevRef) {
    Push-Location $iccDevDir
    try {
        Invoke-Native -FilePath 'git' -Arguments @('fetch', '--depth', '1', 'origin', $IccDevRef)
        Invoke-Native -FilePath 'git' -Arguments @('checkout', '-q', 'FETCH_HEAD')
    }
    finally {
        Pop-Location
    }
}

Invoke-WebRequest -Uri $DiagnosticProfileUrl -OutFile $profilePath
$profileLength = (Get-Item $profilePath).Length
if ($profileLength -ne 8652444) {
    throw "Downloaded diagnostic profile has unexpected size: $profileLength"
}

New-ProbeSource -OutputPath (Join-Path $buildRoot 'issue987ReadProbe.cpp')

$variants = @(
    @{
        Name = 'static-mt-release'
        Config = 'Release'
        Runtime = 'MultiThreaded'
        Shared = $false
        Target = 'IccProfLib2-static'
        LibFilter = 'IccProfLib2-static.lib'
        Description = 'Static IccProfLib2, Release, MSVC static CRT (/MT)'
    },
    @{
        Name = 'static-md-release'
        Config = 'Release'
        Runtime = 'MultiThreadedDLL'
        Shared = $false
        Target = 'IccProfLib2-static'
        LibFilter = 'IccProfLib2-static.lib'
        Description = 'Static IccProfLib2, Release, MSVC DLL CRT (/MD)'
    },
    @{
        Name = 'shared-md-release'
        Config = 'Release'
        Runtime = 'MultiThreadedDLL'
        Shared = $true
        Target = 'IccProfLib2'
        LibFilter = 'IccProfLib2.lib'
        DllFilter = 'IccProfLib2.dll'
        Description = 'Shared IccProfLib2.dll, Release, MSVC DLL CRT (/MD)'
    },
    @{
        Name = 'static-mdd-debug'
        Config = 'Debug'
        Runtime = 'MultiThreadedDebugDLL'
        Shared = $false
        Target = 'IccProfLib2-static'
        LibFilter = 'IccProfLib2-staticd.lib'
        Description = 'Static IccProfLib2, Debug, MSVC debug DLL CRT (/MDd)'
    }
)

if ($VariantNames.Count -gt 0) {
    $requested = @{}
    foreach ($variantName in $VariantNames) {
        $requested[$variantName] = $true
    }

    $variants = @($variants | Where-Object { $requested.ContainsKey($_.Name) })
    if ($variants.Count -eq 0) {
        throw "No requested variants matched: $($VariantNames -join ', ')"
    }
}

$summary = @()

foreach ($variant in $variants) {
    $name = $variant.Name
    $config = $variant.Config
    $runtime = $variant.Runtime
    $shared = [bool]$variant.Shared
    $iccBuildDir = Join-Path $buildRoot "iccdev-$name"
    $toolsDir = Join-Path $buildRoot "tools-$name"
    $toolsBuildDir = Join-Path $toolsDir 'build'
    $variantArtifactDir = Join-Path $artifactRoot $name
    New-Item -ItemType Directory -Force -Path $toolsDir, $variantArtifactDir | Out-Null

    $sharedFlag = if ($shared) { 'ON' } else { 'OFF' }
    Invoke-Native -FilePath 'cmake' -Arguments @(
        '-S', (Join-Path $iccDevDir 'Build\Cmake'),
        '-B', $iccBuildDir,
        '-G', 'Visual Studio 17 2022',
        '-A', 'x64',
        "-DCMAKE_MSVC_RUNTIME_LIBRARY=$runtime",
        '-DENABLE_TOOLS=OFF',
        '-DENABLE_TESTS=OFF',
        '-DENABLE_WXWIDGETS=OFF',
        '-DENABLE_IMAGE_TOOLS=OFF',
        '-DENABLE_ICCXML=OFF',
        '-DENABLE_ICCJSON=OFF',
        '-DENABLE_CMM_TOOLS=OFF',
        '-DENABLE_IIS_TOOLS=OFF',
        "-DENABLE_SHARED_LIBS=$sharedFlag",
        '-DENABLE_STATIC_LIBS=ON'
    )
    Invoke-Native -FilePath 'cmake' -Arguments @(
        '--build', $iccBuildDir,
        '--config', $config,
        '--target', $variant.Target,
        '--parallel', "$parallelism"
    )

    $profLib = Get-ChildItem -Path (Join-Path $iccBuildDir 'IccProfLib') `
        -Recurse -Filter $variant.LibFilter |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $profLib) {
        throw "Missing $($variant.LibFilter) for $name"
    }

    $profDll = ''
    if ($shared) {
        $profDll = Get-ChildItem -Path (Join-Path $iccBuildDir 'IccProfLib') `
            -Recurse -Filter $variant.DllFilter |
            Select-Object -First 1 -ExpandProperty FullName
        if (-not $profDll) {
            throw "Missing $($variant.DllFilter) for $name"
        }
    }

    New-ToolsCMake `
        -OutputPath (Join-Path $toolsDir 'CMakeLists.txt') `
        -VariantName $name `
        -IccBuildDir $iccBuildDir `
        -IccDevPath $iccDevDir `
        -ProfLibPath $profLib `
        -ProfDllPath $profDll `
        -Shared $shared

    Invoke-Native -FilePath 'cmake' -Arguments @(
        '-S', $toolsDir,
        '-B', $toolsBuildDir,
        '-G', 'Visual Studio 17 2022',
        '-A', 'x64',
        "-DCMAKE_MSVC_RUNTIME_LIBRARY=$runtime"
    )
    Invoke-Native -FilePath 'cmake' -Arguments @(
        '--build', $toolsBuildDir,
        '--config', $config,
        '--parallel', "$parallelism"
    )

    foreach ($exe in 'iccDiagnosticLoad.exe', 'iccDumpAll.exe', 'issue987ReadProbe.exe') {
        Copy-Item (Join-Path $toolsBuildDir "$config\$exe") $variantArtifactDir
    }
    if ($shared) {
        Copy-Item $profDll $variantArtifactDir
    }

    $versionHeader = Join-Path $iccBuildDir 'IccProfLib\IccProfLibVer.h'
    if (Test-Path $versionHeader) {
        Copy-Item $versionHeader $variantArtifactDir
    }

    @(
        "Variant: $name"
        "Description: $($variant.Description)"
        "Configuration: $config"
        "MSVC runtime: $runtime"
        "IccProfLib shared: $shared"
        "IccProfLib library: $profLib"
        "IccProfLib dll: $profDll"
        "Diagnostic profile URL: $DiagnosticProfileUrl"
        "Diagnostic profile size: $profileLength"
    ) | Out-File -FilePath (Join-Path $variantArtifactDir 'variant-info.txt') -Encoding ascii

    $probeLog = Join-Path $variantArtifactDir 'issue987ReadProbe-fogra.txt'
    & (Join-Path $variantArtifactDir 'issue987ReadProbe.exe') $profilePath |
        Tee-Object -FilePath $probeLog
    if ($LASTEXITCODE -ne 0) {
        throw "issue987ReadProbe failed for $name"
    }
    $probeText = Get-Content $probeLog -Raw
    if ($probeText -notmatch 'ReadIccProfile\(char\)=OK' -or
        $probeText -notmatch 'ReadIccProfile\(wchar\)=OK' -or
        $probeText -notmatch 'chad offset=520 size=44' -or
        $probeText -notmatch 'entries_with_size_0x73663332=0') {
        throw "issue987ReadProbe output missing expected FOGRA checks for $name"
    }

    $diagLog = Join-Path $variantArtifactDir 'iccDiagnosticLoad-fogra-smoke.txt'
    & (Join-Path $variantArtifactDir 'iccDiagnosticLoad.exe') --compare $profilePath |
        Tee-Object -FilePath $diagLog
    if ($LASTEXITCODE -ne 0) {
        throw "iccDiagnosticLoad failed for $name"
    }
    $diagText = Get-Content $diagLog -Raw
    if ($diagText -notmatch 'OpenIccProfile OK' -or
        $diagText -notmatch 'ReadIccProfile OK' -or
        $diagText -notmatch 'ValidateIccProfile OK') {
        throw "iccDiagnosticLoad output missing expected OK states for $name"
    }

    & (Join-Path $variantArtifactDir 'iccDumpAll.exe') --diag --read -v 10 $profilePath ALL |
        Out-File -FilePath (Join-Path $variantArtifactDir 'iccDumpAll-fogra-smoke.txt') -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw "iccDumpAll failed for $name"
    }

    foreach ($binary in Get-ChildItem -Path $variantArtifactDir -Include '*.exe', '*.dll' -File -Recurse) {
        $prefix = Join-Path $variantArtifactDir ([IO.Path]::GetFileNameWithoutExtension($binary.Name))
        Write-DumpbinReport -BinaryPath $binary.FullName -OutputPrefix $prefix
    }

    $summary += "| $name | $config | $runtime | $shared | OK |"
}

$variantDescriptionLines = foreach ($variant in $variants) {
    "- $($variant.Name): $($variant.Description)"
}

@(
    'ColorBleed Windows x64 diagnostics'
    ''
    'Variants:'
) + $variantDescriptionLines + @(
    ''
    'Each variant includes:'
    '- iccDiagnosticLoad.exe'
    '- iccDumpAll.exe'
    '- issue987ReadProbe.exe'
    '- FOGRA probe, diagnostic, and dump logs'
    '- dumpbin dependency/header reports when dumpbin is available'
    '- IccProfLibVer.h when generated by the build'
    ''
    'The issue987ReadProbe output asserts:'
    '- ReadIccProfile(char)=OK'
    '- ReadIccProfile(wchar)=OK'
    '- chad offset=520 size=44'
    '- entries_with_size_0x73663332=0'
) | Out-File -FilePath (Join-Path $artifactRoot 'README-windows-diagnostics-x64.txt') -Encoding ascii

$summaryLines = @(
    '### Windows Diagnostic Variant Summary'
    ''
    '| Variant | Config | Runtime | Shared DLL | Result |'
    '|---|---|---|---|---|'
) + $summary
$summaryLines | Out-File -FilePath (Join-Path $artifactRoot 'windows-diagnostic-summary.md') -Encoding ascii

$hashes = Get-ChildItem -Path $artifactRoot -Include '*.exe', '*.dll', '*.txt', '*.md' -File -Recurse |
    Sort-Object FullName |
    ForEach-Object {
        $hash = Get-FileHash -Algorithm SHA256 -Path $_.FullName
        $relative = $_.FullName.Substring($artifactRoot.Length + 1).Replace('\', '/')
        "$($hash.Hash.ToLowerInvariant())  $relative"
    }
$hashes | Out-File -FilePath (Join-Path $artifactRoot "SHA256SUMS-$ArtifactName.txt") -Encoding ascii
$hashes | Out-File -FilePath $checksumPath -Encoding ascii

Compress-Archive -Path (Join-Path $artifactRoot '*') -DestinationPath $zipPath -Force

if ($env:GITHUB_STEP_SUMMARY) {
    function ConvertTo-SummaryHtml {
        param([AllowEmptyString()][string]$Value = "")
        return $Value.Replace('&', '&amp;').
            Replace('<', '&lt;').
            Replace('>', '&gt;').
            Replace('"', '&quot;').
            Replace("'", '&#39;')
    }

    $summaryLines | ForEach-Object {
        ConvertTo-SummaryHtml $_
    } | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append
}

Write-Host "Created $zipPath"
Write-Host "Created $checksumPath"
