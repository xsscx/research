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
   - `calloc(nCount, ...)` -- unbounded element counts from XML
   - `std::list::_M_create_node` -- unbounded list growth
   - `CTiffImg::Open` / `TIFFStripSize` -- compressed bytes declare a huge
     decoded strip or tile buffer

3. **Create patch** -- Next number: `ls cfl/patches/0*.patch | tail -1`.
   Apply ALL prior patches first. Test: RSS should drop 10x+.

4. **Verify** -- `ASAN_OPTIONS=detect_leaks=0 /path/to/fuzzer -runs=1 oom-file`.
   Confirm that the oversized allocation disappears, the input is rejected or
   safely ignored, and representative valid corpus inputs still pass. Record
   elapsed time, peak RSS, exit status, and the exact artifact hashes.

5. **Cross-check product tooling** -- identify whether the CLI uses the same
   allocation path. Use a virtual-memory limit for unpatched Release replays;
   `strace -e trace=brk,mmap,mmap2` can prove the attempted size without
   allowing a multi-gigabyte allocation. Metadata-only tools may not reach a
   pixel-decoding allocation even when they accept the same file.

## Allocation Cap Guidelines

| Element type            | Cap   | Rationale              |
|-------------------------|-------|------------------------|
| Tags per profile        | 1,000 | Compatibility ceiling |
| Strings per tag         | 100   | Real profiles have <10 |
| Text content per string | 64KB  | Largest real mluc ~4KB |
| CLUT grid points        | 256   | ICC spec max per dim   |
| TIFF decode buffer      | 256MB | Matches tile-band cap  |

## Usage

```
Triage the OOM finding at: <oom_file_path>
Fuzzer: <fuzzer_name>
Output: <oom_output>
```
