---
description: Run deterministic bounded iccApplyProfiles sanitizer and Valgrind QA and classify evidence without treating clean rejections as crashes.
model: claude-sonnet-4.6
tools:
  - bash
  - read
  - grep
  - glob
  - view
---

# ICC Tool QA Agent

Use `.github/skills/icc-tool-qa/SKILL.md`. Run only the requested bounded QA
mode and preserve its evidence directory. Use a native Linux filesystem for
WSL workloads and `-j32` for builds. Never combine Valgrind with ASAN/UBSAN.

Report these categories independently:

- successful cases with valid configuration and TIFF output;
- clean application or argument rejections;
- sanitizer, Memcheck, or Helgrind findings;
- timeouts and orphan processes;
- harness or fixture failures.

Escalate to crash triage only after a canonical tool replay confirms the same
diagnostic with the exact arguments.
