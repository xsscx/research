# NamedCMM hybrid-chain MSan QA (2026-11-12)

## Scope

This review covers the remote AFL target `applynamedcmm-hybrid-chain` and the
client artifact:

```text
/mnt/f/min/cmm-hybrid-chain-id:000000,sig:06,src:000010,time:8855948,execs:9050,op:havoc,rep:5
```

The artifact is 30,355 bytes and has SHA-256
`af13ce8500b8215def8452d6ff4539591d7e6a696579fc0419e7fbaf4ccec707`.
It is not stored in this repository. No regression test or fixture was added.

## Unpatched iccDEV tooling reproduction

Build the independent, unpatched, non-AFL iccDEV MSan tools:

```bash
./afl/build-iccdev-msan.sh --jobs 32
```

Then reproduce through the hostile-input boundary from the repository root:

```bash
.github/scripts/icc-hostile-input-runner.sh --input '/mnt/f/min/cmm-hybrid-chain-id:000000,sig:06,src:000010,time:8855948,execs:9050,op:havoc,rep:5' --workdir "$PWD" -- iccDEV/Build-MSan/Tools/IccApplyNamedCmm/iccApplyNamedCmm -exportcfganddata @SCRATCH@/cmm-hybrid-chain.json afl/support/hybrid/Data/cmykGrays.txt 3 1 afl/support/hybrid/ICC/CMYK_Hybrid_Profile.icc 10103 @INPUT0@ 10
```

The local build recorded source commit
`93eb27922619e826e13a049ce9d8a9440582909a`, source state `unpatched`,
and the empty-diff hash
`e69de29bb2d1d6434b8b29ae775ad8c2e48c5391`. The resulting
`iccApplyNamedCmm` binary had SHA-256
`ffa5cb0f39eb52b7b76b8abe6ccd8b5c6872c19634fb069d90d9cc30a182e92a`,
contained `__msan_init`, and contained no AFL symbols.

The command terminates with MSan SIGABRT and reports:

```text
MemorySanitizer: use-of-uninitialized-value
CIccXform::Begin() IccProfLib/IccCmm.cpp:1633
CIccXformMpe::Begin() IccProfLib/IccCmm.cpp:8875
CIccNamedColorCmm::Begin(bool, bool) IccProfLib/IccCmm.cpp:12577
CIccConnectCmm::CreateNamed(...) IccConnect/IccLibConnect/IccConnect.cpp:301
```

Origin tracking shows the value is created by the
`CIccCombinedConnectionConditions` heap allocation in
`CIccXformMpe::SetAppliedCC()`, copied by
`CIccCombinedConnectionConditions::getNormIlluminantXYZ()`, and consumed by
`CIccXform::Begin()`.

## Cause and local patch

`CIccProfile::calcNormIlluminantXYZ()` and
`CIccProfile::calcLumIlluminantXYZ()` return `false` when a spectral viewing
condition has no readable illuminant. Unlike their other failure paths, that
path returned without initializing the caller-provided XYZ array.
`CIccCombinedConnectionConditions` ignored the status and later exposed the
uninitialized values.

Patch `018-pcc-illuminant-fallback-initialization.patch` initializes both XYZ
outputs from the profile-header illuminant before returning `false`. The patch
is byte-identical in `afl/patches/` and `cfl/patches/`.

## Patched result

The AFL MSan build completed with patches 003, 010, and 018. Its
`iccApplyNamedCmm` binary had SHA-256
`71a137b4e26659302afffa83156dc7ee7931e13b83c827879b3adf2e37941291`.
The same contained command exited zero, emitted both expected color records,
and produced no MSan diagnostic.

An independent patched, non-AFL MSan build recorded source-diff hash
`3288fe264ef9e9591c8a479aa1f6b7abc118f2e4`. Its
`iccApplyNamedCmm` binary had SHA-256
`b5d01b923ef97e89047aa6d156cd84da2562e8bc11b68b2dc04b89ea87fc7083`;
the contained replay also exited zero with both expected records and no MSan
diagnostic.

ASan controls were also clean in both patched and unpatched AFL builds, which
is expected because the defect is an uninitialized-value read specific to MSan.
