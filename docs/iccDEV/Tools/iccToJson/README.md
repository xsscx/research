# iccToJson

Convert an ICC profile to JSON.

## Usage

```text
iccToJson src.icc dst.json {-indent=N -sort}
```

## Arguments

| Argument | Required | Notes |
|----------|----------|-------|
| `src.icc` | Yes | Input ICC profile path |
| `dst.json` | Yes | Output JSON path |
| `-indent=N` | No | Pretty-print indentation, clamped to 0..20; default is 2 |
| `-sort` | No | Sort JSON keys for deterministic output |

## APTEC Profiling Note

Local profiling for `origin/ci-qa-flags` at commit `d25bef3` used this input:

```text
/home/xss/head/iccDEV/Testing/profile-registry/APTEC_CMYKOGV_Coated_LinearCTV_2025.icc
```

Durable local artifacts are saved here:

```text
/home/xss/work/codex/iccdev-ci-qa-flags-aptec-profile-20260730
```

Observed optimized run:

| Metric | Value |
|--------|-------|
| Exit status | 0 |
| Wall time | 2.63s |
| User time | 2.11s |
| System time | 0.51s |
| Max RSS | 337,520 KB |
| Output JSON | 86 MB ASCII text |

Installed local profiling tooling for this run:

```text
linux-perf linux-tools-common linux-tools-generic valgrind strace
```

Primary report:

```text
/home/xss/work/codex/iccdev-ci-qa-flags-aptec-profile-20260730/COMPLETE_REPORT.md
```

Primary APTEC perf flamegraph:

```text
/home/xss/work/codex/iccdev-ci-qa-flags-aptec-profile-20260730/aptec-perf-fp/iccToJson-aptec-perf-fp-flamegraph.svg
```

The branch `.github/scripts/iccdev-tool-flamegraphs.sh` also produced a real
perf flamegraph for its default sRGB `iccToJson` manifest case:

```text
/home/xss/work/codex/iccdev-ci-qa-flags-aptec-profile-20260730/tool-flamegraphs-perf-fp/reports/iccToJson/flamegraph.svg
```

The default sRGB wrapper case had low samples because it is too fast. The APTEC
focused perf capture recorded 390 samples over a 2.57s wall-clock run.

Supporting local visuals and reports:

- `artifacts/iccToJson-aptec-gprof-flamegraph.svg`
- `artifacts/iccToJson-aptec-hotspots.svg`
- `artifacts/gprof.full.txt`
- `aptec-perf-fp/perf.data`
- `aptec-perf-fp/perf.script`
- `aptec-perf-fp/perf.folded`
- `callgrind/callgrind.annotate.txt`
- `strace/strace.summary.txt`

Top gprof self-time entries were nlohmann JSON lifecycle and container work:

| Self time | Function family |
|-----------|-----------------|
| 40.43% | `nlohmann::basic_json::assert_invariant` |
| 22.87% | `nlohmann::basic_json::json_value::destroy` |
| 14.89% | `std::vector<nlohmann::basic_json>::_M_realloc_append` |
| 9.57% | `nlohmann::basic_json` copy constructor |

The traced path is:

1. `IccJSON/CmdLine/IccToJson/IccToJson.cpp` reads the profile and calls `profile.ToJson(jsonStr, indent)`.
2. `IccJSON/IccLibJSON/IccProfileJson.cpp` builds the root object and iterates tags.
3. Tag JSON extensions serialize tag payloads.
4. CLUT MPEs route through `IccJSON/IccLibJSON/IccMpeJson.cpp`.
5. `IccJSON/IccLibJSON/IccUtilJson.cpp` emits CLUT sample arrays with repeated `push_back`.
6. The completed nlohmann object is dumped to a single JSON string and written.

The APTEC profile produces a large JSON document, so large CLUT array
construction, copies, and destruction are the likely runtime amplifier.

`strace -c` showed only about 0.116s in syscalls, so the APTEC conversion is
CPU-bound in JSON construction/teardown rather than I/O-bound on this host.
