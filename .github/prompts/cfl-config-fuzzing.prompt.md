---
mode: agent
description: Review a plateaued CFL JSON config campaign and improve measurable CIccCfg library coverage
---

# Review CFL Config Fuzzing

Use `.github/skills/cfl-config-fuzzing/SKILL.md` and the repository's
`corpus-management` skill.

Review the current `icc_cfg_fuzzer`, imported and local corpora, dictionary,
curated seeds, complete config, runner metadata, validators, and current
`IccCmmConfig` API. Identify API drift, unreachable source categories, stale or
wrong run flags, missing state transitions, and later array elements hidden by
early rejection.

Measure a same-binary baseline, make only evidence-backed harness or asset
changes, rebuild, replay curated positive and negative JSON, and report:

- binary and upstream revisions;
- corpus counts before and after merge;
- aggregate LibFuzzer counters and source coverage separately;
- changed public classes, fields, or state contracts;
- exact validation commands and sanitizer results;
- minimized JSON artifacts for any library finding.

Treat a deterministic direct harness failure as library-defect evidence even
when no command-line tool reproduces it. Do not create standalone C++ PoCs or
commit bulk corpus, logs, profraw, profdata, or generated coverage HTML.
