---
mode: agent
description: Triage LibFuzzer OOM findings against iccDEV fuzzers
---

# Triage Fuzzer OOM

Analyze LibFuzzer out-of-memory findings. Identify unbounded allocation
vectors and guide patch creation.

## Workflow

1. **Analyze OOM file** -- `file`, `xxd | head -20`, check ICC header (0-128)
   or XML structure. OOM files are often <1MB triggering >1GB allocations.

2. **Parse stack trace** -- Key fields: `Live Heap Allocations`, top allocation
   sites with byte counts. Common iccDEV OOM patterns:
   - `CIccLocalizedUnicode` copy ctor -- unbounded mluc strings
   - `new icFloatNumber[nSize]` -- exponential CLUT grid allocation
   - `calloc(nCount, ...)` -- unbounded element counts from XML
   - `std::list::_M_create_node` -- unbounded list growth

3. **Create patch** -- Next number: `ls cfl/patches/0*.patch | tail -1`.
   Apply ALL prior patches first. Test: RSS should drop 10x+.

4. **Verify** -- `ASAN_OPTIONS=detect_leaks=0 /path/to/fuzzer oom-file`.
   Peak RSS should be <100MB (was typically >4000MB).

## Allocation Cap Guidelines

| Element type            | Cap   | Rationale              |
|-------------------------|-------|------------------------|
| Tags per profile        | 256   | ICC spec max ~128      |
| Strings per tag         | 100   | Real profiles have <10 |
| Text content per string | 64KB  | Largest real mluc ~4KB |
| CLUT grid points        | 256   | ICC spec max per dim   |

## Usage

```
Triage the OOM finding at: <oom_file_path>
Fuzzer: <fuzzer_name>
Output: <oom_output>
```
