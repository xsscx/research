# CFL Manual Fuzzer Command Runbook

Last updated: 2026-08-19

This runbook gives maintainers copy-paste one-liners for manually exercising
each CFL LibFuzzer harness from the repository root. Use it after rebuilding
`cfl/` with the intended baseline:

```bash
cd cfl && ./build.sh
```

The active fuzzer list comes from `cfl/fuzzers.sh`. The examples below use
checked-in corpus directories, dictionaries, and per-fuzzer option values from
the current WSL-2 baseline.

## Common Presets

Run these once per shell before using the direct `bin/<fuzzer>` commands:

```bash
export CFL_ASAN='detect_leaks=0,allocator_may_return_null=1,halt_on_error=1,abort_on_error=1'
export CFL_LINK_ASAN="${CFL_ASAN},quarantine_size_mb=256"
export CFL_ARTIFACTS="$PWD/cfl/runs/manual/artifacts/"
export CFL_PROFRAW="$PWD/cfl/runs/manual/profraw"
mkdir -p "$CFL_ARTIFACTS" "$CFL_PROFRAW"
```

Command modes:

| Mode | Purpose | Typical shape |
|------|---------|---------------|
| Smoke | Fast maintainer start check through `fuzz-local.sh` | `cd cfl && ./fuzz-local.sh -t 30 -w 1 <alias>` |
| Explore | Longer coverage-guided run with value profiling | direct fuzzer, dictionary, corpus, 10 minutes |
| Rare | Larger inputs or focused flags to shake out slow branches | representative large corpus plus `-entropic=1`, `-reduce_inputs=0` |

For ICC and JSON/XML conversion lanes, the checked-in `max_len=0` is resolved
by `fuzz-local.sh` and `start.sh` to the largest corpus-file size. Seed
representative large inputs rather than imposing a repository ceiling; RSS and
per-input timeout limits still bound resource use. For a direct binary command,
replace `-max_len=0` with the largest corpus or artifact size because LibFuzzer
itself may otherwise fall back to 1 MiB.
| Exploit repro | Deterministic sanitizer reproduction/minimization of a finding | direct fuzzer with `-runs=1` or `-minimize_crash=1 <artifact>` |

Use `LLVM_PROFILE_FILE=/dev/null` unless you are collecting coverage. For
coverage runs, set `LLVM_PROFILE_FILE="$CFL_PROFRAW/<fuzzer>_%m_%p.profraw"`.

## Per-Fuzzer One-Liners

Replace `<artifact>` with a crash, leak, OOM, timeout, or slow-unit file from
`cfl/runs/*/artifacts/` when running exploit-repro commands.

### `icc_applynamedcmm_fuzzer`

Input is one raw ICC profile. Do not prepend control bytes or modify the ICC
reserved header bytes to select behavior; the harness applies its fixed
tool-control matrix to every parseable profile. `fuzz-local.sh` installs the
tracked `cfl/seeds-applynamedcmm/` files into the mutable runtime corpus.

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 namedcmm
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applynamedcmm_fuzzer -max_total_time=600 -timeout=120 -rss_limit_mb=6144 -max_len=0 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_applynamedcmm_fuzzer.dict cfl/corpus-icc_applynamedcmm_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applynamedcmm_fuzzer -max_total_time=900 -timeout=120 -rss_limit_mb=6144 -max_len=0 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_applynamedcmm_fuzzer.dict cfl/corpus-icc_applynamedcmm_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applynamedcmm_fuzzer -runs=1 -timeout=120 -rss_limit_mb=6144 -max_len=0 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_applyprofiles_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 profiles
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applyprofiles_fuzzer -max_total_time=600 -timeout=120 -rss_limit_mb=8192 -max_len=5242880 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_applyprofiles_fuzzer.dict cfl/corpus-icc_applyprofiles_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applyprofiles_fuzzer -max_total_time=900 -timeout=120 -rss_limit_mb=8192 -max_len=5242880 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_applyprofiles_fuzzer.dict cfl/corpus-icc_applyprofiles_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applyprofiles_fuzzer -runs=1 -timeout=120 -rss_limit_mb=8192 -max_len=5242880 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_applyprofiles_row_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 profiles-row
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applyprofiles_row_fuzzer -max_total_time=600 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_applyprofiles_row_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applyprofiles_row_fuzzer -max_total_time=900 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_applyprofiles_row_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applyprofiles_row_fuzzer -runs=1 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_applysearch_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 search
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applysearch_fuzzer -max_total_time=600 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_applysearch_fuzzer.dict cfl/corpus-icc_applysearch_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applysearch_fuzzer -max_total_time=900 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_applysearch_fuzzer.dict cfl/corpus-icc_applysearch_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applysearch_fuzzer -runs=1 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_applysearch_weight_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 search-weight
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applysearch_weight_fuzzer -max_total_time=600 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_applysearch_weight_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applysearch_weight_fuzzer -max_total_time=900 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_applysearch_weight_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_applysearch_weight_fuzzer -runs=1 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_connect_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 connect
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_connect_fuzzer -max_total_time=600 -timeout=45 -rss_limit_mb=4096 -max_len=0 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_cfg.dict cfl/corpus-icc_connect_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_connect_fuzzer -max_total_time=900 -timeout=45 -rss_limit_mb=4096 -max_len=0 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_cfg.dict cfl/corpus-icc_connect_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_connect_fuzzer -runs=1 -timeout=45 -rss_limit_mb=4096 -max_len=0 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_cfg_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 cfg
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_cfg_fuzzer -max_total_time=600 -timeout=30 -rss_limit_mb=4096 -max_len=0 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_cfg_fuzzer.dict cfl/corpus-icc_cfg_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_cfg_fuzzer -max_total_time=900 -timeout=30 -rss_limit_mb=4096 -max_len=0 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_cfg_fuzzer.dict cfl/corpus-icc_cfg_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_cfg_fuzzer -runs=1 -timeout=30 -rss_limit_mb=4096 -max_len=0 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_dump_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 dump
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_dump_fuzzer -max_total_time=600 -timeout=45 -rss_limit_mb=8192 -max_len=15728640 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_dump_fuzzer.dict cfl/corpus-icc_dump_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_dump_fuzzer -max_total_time=900 -timeout=45 -rss_limit_mb=8192 -max_len=15728640 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_dump_fuzzer.dict cfl/corpus-icc_dump_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_dump_fuzzer -runs=1 -timeout=45 -rss_limit_mb=8192 -max_len=15728640 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_fromcube_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 cube
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_fromcube_fuzzer -max_total_time=600 -timeout=25 -rss_limit_mb=8192 -max_len=2097152 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_fromcube_fuzzer.dict cfl/corpus-icc_fromcube_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_fromcube_fuzzer -max_total_time=900 -timeout=25 -rss_limit_mb=8192 -max_len=2097152 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_fromcube_fuzzer.dict cfl/corpus-icc_fromcube_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_fromcube_fuzzer -runs=1 -timeout=25 -rss_limit_mb=8192 -max_len=2097152 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_fromjson_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 json
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_fromjson_fuzzer -max_total_time=600 -timeout=30 -rss_limit_mb=2048 -max_len=0 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_json.dict cfl/corpus-icc_fromjson_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_fromjson_fuzzer -max_total_time=900 -timeout=30 -rss_limit_mb=2048 -max_len=0 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_json.dict cfl/corpus-icc_fromjson_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_fromjson_fuzzer -runs=1 -timeout=30 -rss_limit_mb=2048 -max_len=0 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_fromxml_fuzzer`

The harness exercises the `iccFromXml` default import, `-noid`, and `-v=<schema>`
argv modes for each parseable XML input.

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 fromxml
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_fromxml_fuzzer -max_total_time=600 -timeout=25 -rss_limit_mb=8192 -max_len=0 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_fromxml_fuzzer.dict cfl/corpus-icc_fromxml_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_fromxml_fuzzer -max_total_time=900 -timeout=25 -rss_limit_mb=8192 -max_len=0 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_fromxml_fuzzer.dict cfl/corpus-icc_fromxml_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_fromxml_fuzzer -runs=1 -timeout=25 -rss_limit_mb=8192 -max_len=0 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_jpegdump_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 jpeg
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_jpegdump_fuzzer -max_total_time=600 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_jpegdump_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_jpegdump_fuzzer -max_total_time=900 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_jpegdump_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_jpegdump_fuzzer -runs=1 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_link_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 link
ASAN_OPTIONS="$CFL_LINK_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_link_fuzzer -max_total_time=600 -timeout=45 -rss_limit_mb=8192 -max_len=10485760 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_link_fuzzer.dict cfl/corpus-icc_link_fuzzer/
ASAN_OPTIONS="$CFL_LINK_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_link_fuzzer -max_total_time=900 -timeout=45 -rss_limit_mb=8192 -max_len=10485760 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_link_fuzzer.dict cfl/corpus-icc_link_fuzzer/
ASAN_OPTIONS="$CFL_LINK_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_link_fuzzer -runs=1 -timeout=45 -rss_limit_mb=8192 -max_len=10485760 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_pawgreport_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 pawg
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_pawgreport_fuzzer -max_total_time=600 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_pawgreport_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_pawgreport_fuzzer -max_total_time=900 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_pawgreport_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_pawgreport_fuzzer -runs=1 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_pngdump_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 png
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_pngdump_fuzzer -max_total_time=600 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_pngdump_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_pngdump_fuzzer -max_total_time=900 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_pngdump_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_pngdump_fuzzer -runs=1 -timeout=30 -rss_limit_mb=4096 -max_len=5242880 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_profilevisualize_fuzzer`

This harness is the in-memory `IccVizModel` lane for `iccProfilePlot`. The
`profileplot` and `plot` aliases select it; AFL owns CLI and raw-output replay.

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 profileplot
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_profilevisualize_fuzzer -max_total_time=600 -timeout=30 -rss_limit_mb=4096 -max_len=65536 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_profilevisualize_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_profilevisualize_fuzzer -runs=1 -timeout=30 -rss_limit_mb=4096 -max_len=65536 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

Tool-level cross-check:

```bash
ASAN_OPTIONS="$CFL_ASAN" afl/bin/iccProfilePlot <artifact> list
```

### `icc_roundtrip_fuzzer`

```bash
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_roundtrip_fuzzer -runs=1000 -timeout=45 -rss_limit_mb=8192 -max_len=10485760 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_roundtrip_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_roundtrip_fuzzer -max_total_time=600 -timeout=45 -rss_limit_mb=8192 -max_len=10485760 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_roundtrip_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_roundtrip_fuzzer -max_total_time=900 -timeout=45 -rss_limit_mb=8192 -max_len=10485760 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_roundtrip_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_roundtrip_fuzzer -runs=1 -timeout=45 -rss_limit_mb=8192 -max_len=10485760 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_specsep_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 specsep
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_specsep_fuzzer -max_total_time=600 -timeout=30 -rss_limit_mb=4096 -max_len=10485760 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_specsep_fuzzer.dict cfl/corpus-icc_specsep_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_specsep_fuzzer -max_total_time=900 -timeout=30 -rss_limit_mb=4096 -max_len=10485760 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_specsep_fuzzer.dict cfl/corpus-icc_specsep_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_specsep_fuzzer -runs=1 -timeout=30 -rss_limit_mb=4096 -max_len=10485760 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_tiffdump_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 tiffdump
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_tiffdump_fuzzer -max_total_time=600 -timeout=45 -rss_limit_mb=8192 -max_len=15728640 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_tiffdump_fuzzer.dict cfl/corpus-icc_tiffdump_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_tiffdump_fuzzer -max_total_time=900 -timeout=45 -rss_limit_mb=8192 -max_len=15728640 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_tiffdump_fuzzer.dict cfl/corpus-icc_tiffdump_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_tiffdump_fuzzer -runs=1 -timeout=45 -rss_limit_mb=8192 -max_len=15728640 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_tojson_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 tojson
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_tojson_fuzzer -max_total_time=600 -timeout=30 -rss_limit_mb=4096 -max_len=0 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_tojson_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_tojson_fuzzer -max_total_time=900 -timeout=30 -rss_limit_mb=4096 -max_len=0 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_core.dict cfl/corpus-icc_tojson_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_tojson_fuzzer -runs=1 -timeout=30 -rss_limit_mb=4096 -max_len=0 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_toxml_fuzzer`

This harness redirects upstream stdout to `/dev/null` during initialization.
Expected XML serialization diagnostics stay out of fuzzer logs; libFuzzer
progress and sanitizer reports still print on stderr.

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 toxml
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_toxml_fuzzer -max_total_time=600 -timeout=30 -rss_limit_mb=8192 -max_len=0 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_toxml_fuzzer.dict cfl/corpus-icc_toxml_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_toxml_fuzzer -max_total_time=900 -timeout=30 -rss_limit_mb=8192 -max_len=0 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_toxml_fuzzer.dict cfl/corpus-icc_toxml_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_toxml_fuzzer -runs=1 -timeout=30 -rss_limit_mb=8192 -max_len=0 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

### `icc_v5dspobs_fuzzer`

```bash
cd cfl && ./fuzz-local.sh -t 30 -w 1 v5
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_v5dspobs_fuzzer -max_total_time=600 -timeout=45 -rss_limit_mb=8192 -max_len=15728640 -use_value_profile=1 -print_final_stats=1 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_v5dspobs_fuzzer.dict cfl/corpus-icc_v5dspobs_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_v5dspobs_fuzzer -max_total_time=900 -timeout=45 -rss_limit_mb=8192 -max_len=15728640 -use_value_profile=1 -entropic=1 -reduce_inputs=0 -artifact_prefix="$CFL_ARTIFACTS" -dict=cfl/icc_v5dspobs_fuzzer.dict cfl/corpus-icc_v5dspobs_fuzzer/
ASAN_OPTIONS="$CFL_ASAN" LLVM_PROFILE_FILE=/dev/null cfl/bin/icc_v5dspobs_fuzzer -runs=1 -timeout=45 -rss_limit_mb=8192 -max_len=15728640 -artifact_prefix="$CFL_ARTIFACTS" <artifact>
```

## Manual Findings Template

Use this shape in the next session handoff or a dated report:

```text
Date:
VM/compiler:
Build mode: patched / no-patches / single patch
iccDEV baseline:
Fuzzer:
Mode: smoke / explore / rare / exploit repro
Command:
Corpus/dictionary:
Runtime:
Result: clean / crash / leak / OOM / timeout / UBSan
Artifact path:
Minimized artifact path:
Reproducer command:
Stack top:
Suspected owner: harness / iccDEV library / iccDEV tool / dependency
Next action:
```

## Session Handoff - 2026-07-04

This runbook was added after the WSL-2 GCC 15.2 / clang 21 CFL baseline reset.
The baseline had already built 22/22 fuzzers and completed a 30-second
`./fuzz-local.sh -t 30 -w 1` pass with zero artifacts. Next-session work can
start by selecting a fuzzer from this runbook, running the smoke command, then
switching to the explore or rare command while recording findings in the
template above.
