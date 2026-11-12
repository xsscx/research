# CFL ToXML spectral CLUT OOM QA - 2026-11-11

## Outcome

The 361-byte ToXML artifact reproducibly requested a 10,104,462,720-byte
allocation in `CIccCLUT::Init()`. Optional CFL patch
`016-serialized-clut-allocation-bounds.patch` fixes the spectral reader and the
three equivalent serialized CLUT boundaries without changing the public
programmatic `Init(..., nMaxSize=0)` contract.

After the patch, the artifact exits 0 in under 2 ms with no sanitizer or OOM
output.
A real 27,280-byte spectral profile still exits 0 and serializes in under 30
ms. The full AddressSanitizer/UBSan/integer sanitizer CFL build completed
24/24 targets.

## Artifact and vulnerable path

- Original path: `/mnt/f/artifacts/toxml-oom-c847deaf1694f0038bde75b999380f8a7a76371d`
- Promoted path: `test-profiles/oom-CIccMpeSpectralCLUT-Read-IccMpeSpectral_cpp-Line1108.icc`
- Size: 361 bytes
- SHA-256: `333a347ceae34cdae73a4f4addfc038cdd85c3165395d06d0df1c936a88c1168`
- iccDEV baseline: `93eb27922619e826e13a049ce9d8a9440582909a`

`CIccMpeSpectralCLUT::Read()` accepted an element whose size exactly equaled
its 40-byte header. It passed `size - headerSize`, or zero, to
`CIccCLUT::Init()`. That API deliberately interprets a zero maximum as
unbounded programmatic construction. Grid dimensions `236 x 2 x 106 x 255 x
66`, with three outputs, therefore selected 2,526,115,680 floats and a
10,104,462,720-byte allocation before the missing payload could be rejected.

The normal unpatched `iccToXml` executable returned exit 1 with `Unable to
read`. That soft failure does not clear the defect: Linux overcommit accepted
the large virtual allocation, after which the zero-byte sample read failed.
The sanitizer fuzzer's allocation hook rejected the same request immediately
and reported the exact size and shared-library stack.

## Patch boundary

Patch 016 preserves unbounded programmatic CLUT construction and bounds only
serialized readers:

- spectral emission and reflectance CLUTs reject an exact-size header;
- standard float32 MPE CLUTs pass their remaining payload and sample width to
  `CIccCLUT::Init()`;
- Lut8 and Lut16 reject zero remaining bytes before calling `Init()`;
- `CIccCLUT::Init()` enforces a nonzero payload limit after dimension
  accumulation, including the one-input case whose loop is otherwise skipped;
- the patch-owned serialized-CLUT CTest covers malformed and complete controls
  for generic CLUT, MPE CLUT, spectral CLUT, Lut8, and Lut16 encodings, and
  confirms that zero-limit programmatic CLUT construction remains available.

This is an uncontrolled allocation/resource-consumption defect (CWE-789 under
the CWE-400 resource-consumption category). Both spectral CLUT element types
share the vulnerable base reader.

## Verification

The patched stack through patch 015 used
`cfl/bin/icc_toxml_fuzzer` SHA-256
`aae97b6ca58df780d874174b3f08917072ed5710941462bd71171fd4ef97bb41`.
The contained artifact replay exited 71 and reported
`libFuzzer: out-of-memory (malloc(10104462720))` at
`CIccMpeSpectralCLUT::Read()`.

The patched build command was:

```bash
cd cfl && ./build.sh --with-patches
```

It built 24/24 targets. The resulting ToXML fuzzer SHA-256 is
`76033cf1fdd43c8216c9128db4ed121bc4fb2d1f8856025fd9234226edd9283d`.

The decisive artifact replay was:

```bash
.github/scripts/icc-hostile-input-runner.sh --input test-profiles/oom-CIccMpeSpectralCLUT-Read-IccMpeSpectral_cpp-Line1108.icc --workdir "$PWD" -- cfl/bin/icc_toxml_fuzzer -runs=1 @INPUT0@
```

Result: exit 0, under 2 ms, no sanitizer diagnostic, no cgroup resource limit,
and no timeout.

The legitimate spectral control was
`iccDEV/Testing/Display/SpectralObserverElements.icc`, SHA-256
`1ae5b738cc4ebac7064decb4aa4589acdfffd6ef220fb689145949c84b3aa683`.
The same contained replay exited 0 in under 30 ms.

The focused regression gate was:

```bash
cmake --build cfl/iccDEV/Build --target iccSerializedClutAllocationBoundsTest -j32
ctest --test-dir cfl/iccDEV/Build -R '^iccdev\.serialized-clut-allocation-bounds$' --output-on-failure
```

Result: 1/1 passed in 0.02 seconds.

## 2026-11-12 revalidation

The CFL checkout and upstream reference remained aligned at
`93eb27922619e826e13a049ce9d8a9440582909a`. A clean
`./cfl/build.sh --with-patches --refresh-iccdev` reapplied all 13 active patches,
built 24/24 fuzzers, and reported 2,446 ASan, 381 UBSan, and 3,198 coverage
symbols in the profile library. The patch-stack applicability check passed for
every AFL and CFL patch.

The focused CTest passed 1/1 after the refresh. Its direct output also confirmed
the added positive control for public zero-limit programmatic CLUT construction.
The contained malformed replay exited 0 in 1 ms without a timeout or resource
limit, and the 27,280-byte spectral control exited 0 in 21 ms.
