---
mode: agent
description: Triage LibFuzzer OOM findings against iccDEV fuzzers
---

# Triage Fuzzer OOM

Analyze LibFuzzer out-of-memory findings. Identify unbounded allocation
vectors and guide patch creation.

## Workflow

1. **Analyze OOM file** -- `file`, `xxd | head -20`, check the ICC header
   (0-128), XML/JSON structure, or image-container directory. OOM files are
   often <1MB while declaring decoded data or element counts above 1GB.

2. **Parse stack trace** -- Key fields: `Live Heap Allocations`, top allocation
   sites with byte counts. Common iccDEV OOM patterns:
   - `CIccLocalizedUnicode` copy ctor -- unbounded mluc strings
   - `new icFloatNumber[nSize]` -- exponential CLUT grid allocation
   - serialized CLUT with zero remaining bytes -- `CIccCLUT::Init()` treats a
     zero size limit as unbounded programmatic construction; audit every
     serialized caller and pass its real payload byte count
   - `calloc(nCount, ...)` -- unbounded element counts from XML
   - `std::list::_M_create_node` -- unbounded list growth
   - `CTiffImg::Open` / `TIFFStripSize` -- compressed bytes declare a huge
     decoded strip or tile buffer

3. **Create the code patch** -- Next number:
   `ls cfl/patches/0*.patch | tail -1`. Apply all prior patches first. Patch
   the real allocation path only. Do not add a regression source, CTest target,
   synthetic fixture, test-only harness, or upstream test content to the
   research patch stack.

4. **Verify** -- replay through the mandatory hostile-input boundary, for
   example `.github/scripts/icc-hostile-input-runner.sh --input oom-file
   --workdir "$PWD" -- cfl/bin/FUZZER -runs=1 @INPUT0@`.
   Confirm that the oversized allocation disappears, the input is rejected or
   safely ignored, and representative valid corpus inputs still pass. Record
   elapsed time, exit status, resource-limit outcome, and exact artifact hashes.
   The preserved OOM artifact and real fuzzer replay are the decisive check.

5. **Cross-check product tooling** -- identify whether the CLI uses the same
   allocation path. Run it only through an approved boundary that enforces a
   virtual-memory limit. A soft CLI parse failure does not clear an allocation
   defect when Linux overcommit accepted the request before a later short read.
   Metadata-only tools may not reach a pixel-decoding allocation even when they
   accept the same file.

## Allocation Cap Guidelines

| Element type            | Cap   | Rationale              |
|-------------------------|-------|------------------------|
| Tags per profile        | 1,000 | Compatibility ceiling |
| Strings per tag         | 100   | Real profiles have <10 |
| Text content per string | 64KB  | Largest real mluc ~4KB |
| CLUT grid per dimension | 255   | 8-bit field maximum; total data stays payload-bound |
| TIFF decode buffer      | 256MB | Matches tile-band cap  |

## Usage

```
Triage the OOM finding at: <oom_file_path>
Fuzzer: <fuzzer_name>
Output: <oom_output>
```
