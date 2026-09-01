---
mode: agent
description: Run a bounded, deterministic iccApplyProfiles QA interval and classify its evidence
---

# Validate iccApplyProfiles

Run the `icc-tool-qa` skill against the current native-Linux research checkout.

Inputs:

- Mode: `${input:mode:sanitizer, memcheck, or helgrind}`
- Duration: `${input:seconds:300}` seconds
- Binary override: `${input:binary:optional path}`

Use the matching script under `.github/ci/quality-assurance/scripts/`. Keep
evidence outside the repository in a native Linux directory, use `-j32` for a
required build, and report successes, clean rejections, sanitizer or Valgrind
findings, timeouts, invalid outputs, and orphan processes separately. Do not
claim a code fault from an aggregate count; cite the exact per-case command and
diagnostic. Provide a one-line canonical reproduction for each confirmed fault.
