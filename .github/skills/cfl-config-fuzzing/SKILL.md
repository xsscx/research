---
name: cfl-config-fuzzing
description: Review, extend, measure, and triage the CFL icc_cfg_fuzzer and its shared AFL/CFL JSON configuration assets. Use for config-fuzzer plateaus, CIccCfg API drift, config dictionaries or seeds, and library-level JSON config findings; do not use for ICC-profile JSON import handled by icc_fromjson_fuzzer.
---

# CFL Config Fuzzing

Keep `icc_cfg_fuzzer` aligned with the current public classes and fields in
`cfl/iccDEV/IccConnect/IccLibConnect/IccCmmConfig.h` and `.cpp`. The harness
consumes one ordinary JSON document without a selector prefix and must not open
paths named by the input.

## Review

1. Record the nested iccDEV revision, fuzzer hash, loaded counter count, corpus
   file count, and largest input before comparing coverage.
2. Inventory every public `CIccCfg*` class and JSON field. Compare that inventory
   with `cfl/icc_cfg_fuzzer.cpp`, `cfl/icc_cfg.dict`, the complete config, and
   `cfl/seeds-cfg/`. Upstream API drift is a coverage defect even when a long run
   has plateaued.
3. Separate JSON-reachable gaps from `fromArgs()`, legacy/IT8 file I/O, and other
   code that shares the translation unit but belongs to tool QA.
4. Preserve reset and non-reset parsing, stable serialize/reparse coverage, and
   bounded direct traversal of nested arrays. Do not add a fixed input-size
   guard; runners derive `max_len` from the corpus.

## Corpus And Measurement

Use the `corpus-management` skill and `.github/scripts/corpus-merge.sh` for bulk
runtime corpora. Keep the merge on a native Linux scratch path and leave imported
or mounted corpora unchanged. Promote only small, named JSON inputs with durable
coverage or regression value into `cfl/seeds-cfg/`.

Always run this target with `cfl/icc_cfg.dict`. A profile-oriented dictionary can
inflate the token set while reducing useful JSON mutations. For multi-worker
source coverage use `<fuzzer>_%m_%p.profraw`; `%m` alone lets workers overwrite
one another. Compare annotated coverage for `IccCmmConfig.cpp` and
`IccJsonUtil.cpp` from the same binary instead of treating aggregate `cov:` as a
cross-build metric.

## Library Findings

A deterministic sanitizer, undefined-behavior, assertion, or stable semantic
failure from `cfl/bin/icc_cfg_fuzzer -runs=1 ARTIFACT` is sufficient evidence of
a public config-library defect. Do not require a command-line tool to reproduce
library-owned behavior. When a CLI reaches the same path, use it as additional
ownership evidence. Minimize and preserve the JSON artifact plus the exact replay
command; do not create a standalone C++ PoC.

## Validation

Run:

```bash
.github/scripts/validate-afl-cfl-config-alignment.sh
.github/scripts/validate-afl-target-configs.sh
cd cfl && ./build.sh --keep-iccdev
cd cfl && ./fuzz-local.sh -t 60 -w 1 cfg
```

Replay every curated config seed with `-runs=1`. If shared config fields or the
complete fixture changed, verify the corresponding AFL config lanes as well.
