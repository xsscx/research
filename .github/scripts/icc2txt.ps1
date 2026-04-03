###############################################################
# Copyright (c) 2024-2026 David H Hoyt LLC. All rights reserved.
###############################################################
# Last Updated: 2026-04-03 04:30:00 UTC by Codex
#
# Intent:
#   xxd-style dump of ICC color profiles with a companion metadata file.
#   Accepts either a single ICC path or a directory to scan recursively.
#
###############################################################

[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$ScanRoot = ".",

    [Parameter(Position=1)]
    [string]$OutputDir = "./icc-xxd",

    [Parameter(Position=2)]
    [string]$ReportPath = "./consolidated_icc_report.txt"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Show-Usage {
    @'
Usage: .github/scripts/icc2txt.ps1 [scan-root] [output-dir] [report-path]

Create xxd-style dumps plus selected ICC metadata files for one file or a tree.

Defaults:
  scan-root   .
  output-dir  ./icc-xxd
  report-path ./consolidated_icc_report.txt
'@
}

function Get-Timestamp {
    (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd_HH-mm-ss")
}

function Get-SafeName {
    param([Parameter(Mandatory=$true)][string]$Name)
    $safe = $Name.Replace(" ", "_")
    return [Regex]::Replace($safe, "[^A-Za-z0-9._-]", "_")
}

function Get-HexSlice {
    param(
        [Parameter(Mandatory=$true)][byte[]]$Bytes,
        [Parameter(Mandatory=$true)][int]$Offset,
        [Parameter(Mandatory=$true)][int]$Count
    )

    if ($Offset -ge $Bytes.Length) {
        return ""
    }

    $end = [Math]::Min($Bytes.Length, $Offset + $Count)
    $slice = $Bytes[$Offset..($end - 1)]
    return ($slice | ForEach-Object { "{0:X2}" -f $_ }) -join ""
}

function Format-XxdDump {
    param([Parameter(Mandatory=$true)][byte[]]$Bytes)

    $lines = New-Object System.Collections.Generic.List[string]

    for ($offset = 0; $offset -lt $Bytes.Length; $offset += 16) {
        $count = [Math]::Min(16, $Bytes.Length - $offset)
        $hexCols = New-Object System.Collections.Generic.List[string]
        $asciiChars = New-Object System.Collections.Generic.List[string]

        for ($i = 0; $i -lt 16; $i++) {
            if ($i -lt $count) {
                $value = $Bytes[$offset + $i]
                $hexCols.Add(("{0:X2}" -f $value))
                if ($value -ge 32 -and $value -le 126) {
                    $asciiChars.Add([char]$value)
                } else {
                    $asciiChars.Add(".")
                }
            } else {
                $hexCols.Add("  ")
            }
        }

        $left = ($hexCols[0..7] -join " ")
        $right = ($hexCols[8..15] -join " ")
        $ascii = (-join $asciiChars)
        $lines.Add(("{0:X8}: {1}  {2}  {3}" -f $offset, $left, $right, $ascii))
    }

    return $lines -join [Environment]::NewLine
}

function Write-Log {
    param([Parameter(Mandatory=$true)][string]$Message)

    $line = "[{0}] {1}" -f (Get-Timestamp), $Message
    Write-Host $line
    Add-Content -Path $ReportPath -Value $line -Encoding ascii
}

function Write-AsciiFile {
    param(
        [Parameter(Mandatory=$true)][string]$Path,
        [Parameter(Mandatory=$true)][string]$Content
    )

    Set-Content -Path $Path -Value $Content -Encoding ascii
}

function Process-IccFile {
    param([Parameter(Mandatory=$true)][string]$FilePath)

    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $filename = [System.IO.Path]::GetFileName($FilePath)
    $safeFilename = Get-SafeName -Name $filename
    $timestamp = Get-Timestamp
    $dumpPath = Join-Path $OutputDir ("{0}-xxd-{1}.txt" -f $safeFilename, $timestamp)
    $metaPath = Join-Path $OutputDir ("{0}-metadata-{1}.txt" -f $safeFilename, $timestamp)
    $tagCount = if ($bytes.Length -ge 132) { Get-HexSlice -Bytes $bytes -Offset 128 -Count 4 } else { "N/A" }

    $meta = @(
        "ICC Profile Metadata for: $filename",
        "----------------------------------------",
        "Actual File Size: $($bytes.Length) bytes",
        "Profile Size (0x00-0x03): $(Get-HexSlice -Bytes $bytes -Offset 0 -Count 4)",
        "Preferred CMM (0x04-0x07): $(Get-HexSlice -Bytes $bytes -Offset 4 -Count 4)",
        "Profile Version (0x08-0x0B): $(Get-HexSlice -Bytes $bytes -Offset 8 -Count 4)",
        "Device Class (0x0C-0x0F): $(Get-HexSlice -Bytes $bytes -Offset 12 -Count 4)",
        "Color Space (0x10-0x13): $(Get-HexSlice -Bytes $bytes -Offset 16 -Count 4)",
        "PCS (0x14-0x17): $(Get-HexSlice -Bytes $bytes -Offset 20 -Count 4)",
        "Magic Bytes (0x24-0x27): $(Get-HexSlice -Bytes $bytes -Offset 36 -Count 4)",
        "Profile ID (0x54-0x63): $(Get-HexSlice -Bytes $bytes -Offset 84 -Count 16)",
        "Reserved Bytes (0x64-0x7F): $(Get-HexSlice -Bytes $bytes -Offset 100 -Count 28)",
        "Tag Count (0x80-0x83): $tagCount"
    ) -join [Environment]::NewLine

    Write-AsciiFile -Path $metaPath -Content $meta
    Write-AsciiFile -Path $dumpPath -Content (Format-XxdDump -Bytes $bytes)

    Write-Log "Processed metadata: $FilePath -> $metaPath"
    Write-Log "Processed xxd dump: $FilePath -> $dumpPath"
}

if ($ScanRoot -eq "-h" -or $ScanRoot -eq "--help") {
    Show-Usage
    exit 0
}

if (-not (Test-Path -LiteralPath $ScanRoot)) {
    throw "Scan root does not exist: $ScanRoot"
}

[System.IO.Directory]::CreateDirectory($OutputDir) | Out-Null
$reportDir = Split-Path -Parent $ReportPath
if ([string]::IsNullOrWhiteSpace($reportDir)) {
    $reportDir = "."
}
[System.IO.Directory]::CreateDirectory($reportDir) | Out-Null
Write-AsciiFile -Path $ReportPath -Content ("Consolidated ICC Profile Analysis Report{0}----------------------------------------{0}" -f [Environment]::NewLine)

Write-Host "Copyright (c) 2024-2026 David H Hoyt LLC | All rights reserved."
Write-Host "PowerShell xxd-style dump of ICC color profiles"
Write-Host ("Last Updated: {0} UTC" -f (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))

Write-Log "Starting ICC profile xxd analysis"

$extensions = @(".icc", ".icm", ".iccp", ".icf", ".profile", ".icd", ".icr", ".icb", ".iic")
$targets = New-Object System.Collections.Generic.List[string]

$scanItem = Get-Item -LiteralPath $ScanRoot
if ($scanItem.PSIsContainer) {
    Get-ChildItem -LiteralPath $ScanRoot -Recurse -File | ForEach-Object {
        if ($extensions -contains $_.Extension.ToLowerInvariant()) {
            $targets.Add($_.FullName)
        }
    }
} else {
    $targets.Add($scanItem.FullName)
}

if ($targets.Count -eq 0) {
    Write-Log "No ICC files found under: $ScanRoot"
} else {
    foreach ($target in $targets) {
        Process-IccFile -FilePath $target
    }
    Write-Log ("ICC profile xxd analysis completed: {0} file(s)" -f $targets.Count)
}
