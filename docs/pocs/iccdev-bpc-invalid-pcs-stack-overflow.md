# BPC invalid-PCS stack buffer overflow

## Classification

- Owner: upstream `IccProfLib`
- CWE: CWE-121, stack-based buffer overflow
- Fault: four-float write through `CIccApplyBPC::CalcFactors()`'s three-float
  `XYZbp` buffer
- Trigger: enable BPC on a profile whose malformed class bypasses the DeviceLink
  rejection and whose declared PCS has four channels

The original `icc_connect_fuzzer` artifact is 3,115 bytes. Its ICC header
declares 2,360 bytes, so the harness reads bytes 2,360 through 2,363 as controls:
`ca cb cc cd`. Those values select a file-backed profile, the optional named
path, one thread, perceptual/linear application, BPC, and D2B/B2D tags. Bytes
after the four-byte trailer are ignored.

## Unpatched one-line reproductions

Replay the original artifact with the CFL harness:

```bash
ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1 LLVM_PROFILE_FILE=/dev/null timeout 30 cfl/bin/icc_connect_fuzzer -runs=1 /tmp/fuzz-ramdisk/connect-crash-5f51f464c7069216dfcea21a3d4bb17f2a553e14; printf 'EXIT=%s\n' "$?"
```

Replay the same artifact through the unpatched command-line tool:

```bash
ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1 LLVM_PROFILE_FILE=/dev/null timeout 30 iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles test-profiles/tiff-codecs/seed-tiff-none-rgb-8x8.tif /tmp/connect-unpatched-out.tif 3 0 0 0 0 /tmp/fuzz-ramdisk/connect-crash-5f51f464c7069216dfcea21a3d4bb17f2a553e14 40; printf 'EXIT=%s\n' "$?"
```

Generate the durable XML fixture and replay it through the unpatched tool. The
converter deliberately returns a soft failure because the profile is invalid,
but it preserves the binary output for forensic reproduction:

```bash
ASAN_OPTIONS=detect_leaks=0 LLVM_PROFILE_FILE=/dev/null iccDEV/Build/Tools/IccFromXml/iccFromXml docs/pocs/iccdev-bpc-invalid-pcs-stack-overflow.xml /tmp/iccdev-bpc-invalid-pcs.icc >/dev/null 2>&1; ASAN_OPTIONS=detect_leaks=0,halt_on_error=1,abort_on_error=1 LLVM_PROFILE_FILE=/dev/null timeout 30 iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles test-profiles/tiff-codecs/seed-tiff-none-rgb-8x8.tif /tmp/iccdev-bpc-invalid-pcs-out.tif 3 0 0 0 0 /tmp/iccdev-bpc-invalid-pcs.icc 40; printf 'EXIT=%s\n' "$?"
```

The unpatched ASAN build exits 134 and reports
`CIccXform3DLut::Apply()` at `IccCmm.cpp:6928`, with the write immediately past
`XYZbp` in `CIccApplyBPC::CalcFactors()`.

## Local CFL mitigation

`cfl/patches/009-bpc-pcs-space-guard.patch` rejects BPC factor calculation
unless the profile PCS is XYZ or Lab. This matches the three-channel BPC math
and makes `CIccXform::Begin()` fail closed with `icCmmStatCantAdjustPcs` before
the internal transform applies a four-channel result.
