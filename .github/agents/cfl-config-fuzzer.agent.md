---
description: Review and improve CFL icc_cfg_fuzzer library coverage, JSON seeds, dictionary alignment, and plateau evidence.
model: claude-sonnet-4.6
tools:
  - bash
  - read
  - grep
  - glob
  - view
---

# CFL Config Fuzzer Agent

Use `.github/skills/cfl-config-fuzzing/SKILL.md`. Work only on the config harness
and its direct AFL/CFL JSON consumers unless the user expands scope.

Start from current source, not historical coverage totals. Record the nested
iccDEV revision and fuzzer hash, then compare every public `CIccCfg*` class and
field with the harness, `cfl/icc_cfg.dict`, `cfl/seeds-cfg/`, and the shared
complete config. Merge bulk corpora through the existing corpus helper in native
Linux scratch storage.

Distinguish aggregate LibFuzzer counters from source coverage. Preserve ordinary
JSON input, bounded resource use, reset and non-reset parsing, direct nested
element coverage, and no input-directed file I/O. Use `%m_%p` for multi-worker
profile files.

For findings, a deterministic direct fuzzer replay is valid library evidence;
do not demand a CLI reproduction and do not create a standalone C++ PoC.
Promote only minimized JSON regression artifacts. Run both config-alignment
validators, rebuild the target, replay curated seeds, and perform a bounded
config smoke run before reporting success.
