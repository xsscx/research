---
mode: agent
description: Verify explicit authorization and upstream PR readiness without creating the PR
---

# Upstream PR Readiness Audit

Audit `BRANCH_NAME` against `BASE_BRANCH` using
`.github/skills/upstream-pr-readiness/SKILL.md`.

## Inputs

- Repository: `OWNER/REPOSITORY`
- Branch: `BRANCH_NAME`
- Base: `BASE_BRANCH`
- Authorization quotation: `EXACT_USER_QUOTATION` or `NONE`
- Required build/test commands: `COMMANDS`

## Required Behavior

1. Do not create, reopen, edit, or request review on a PR.
2. Fail immediately when explicit authorization is absent.
3. Use a clean worktree and current remote base.
4. Verify rebase, linear history, range-diff, complete diff scope, normal and
   excluded test builds, the smallest complete CTest selection for the mapped
   contract, negative configurations, and generated artifact cleanup. Escalate
   to the full suite only when dependencies require it.
5. Before any push, reconcile the PR title, issue, and description with the
   complete diff. Map all equivalent platform entry points plus every changed
   producer-consumer path. Fixture changes must cover their platform-specific
   generators, generated outputs, baselines, and CTest dependencies. Run the
   smallest local test selection that proves this complete map.
6. Compare the proposed push commit with the commit reviewed by the latest
   completed local review. If files changed, re-review their complete scope and
   platform contract, then run and record the applicable targeted build/test
   gate before pushing. Do not rely on CI or a later Cloud review for this gate.
7. Build a configuration-contract matrix for every changed configuration,
   workflow, Dockerfile, or dependency manifest. Verify defaults, explicit
   overrides, failure paths, and compiler support boundaries with local
   evidence. Verify runtime sanitizer suppression names with the runtime.
8. For workflow, Dockerfile, or CI-summary changes, run
   `.github/scripts/preflight-safety-checks.sh --require-tools` locally before
   a PR update or review request. For Docker user/home changes, validate the
   final image as its runtime user, including a writable home and
   `git config --global`. For failure-summary changes, verify same-step
   checked-in sanitizer access or the established inline fallback and all
   `tee` pipeline statuses.
9. Inventory review summaries and review threads; suppressed comments require
   disposition even when no resolvable thread exists. Record every review's
   exact head SHA, active and suppressed findings, disposition, and post-repair
   validation.
10. For package, protocol, or subprocess-launch changes, record a
    platform-by-installation-mode matrix that separately proves source-tree and
    installed-package child-process imports.
11. If a second automated review finds any new blocker, including one in the
    repair, report `review-stop: FAIL - maintainer direction required`. Do not
    launch a local or cloud reviewer, publish another repair, resolve findings
    as closure, or claim readiness.
12. If a no-rebase request conflicts with the required base or stack-parent
   rebase, report FAIL and do not initialize or submit the stack.
13. Do not use this audit for a user-approved branch-only documentation,
    configuration, or UI-only revision unless the user explicitly requests it.
    A requested small-diff audit is limited to the named files and direct
    consumers, 25 tool calls, and 10 minutes. It must not create artifacts; a
    cancellation or timeout returns INCOMPLETE and does not block an otherwise
    authorized commit or push.
14. Report PASS, FAIL, or INCOMPLETE with command evidence and blockers.

## Output

```text
authorization:
base:
range-diff:
merge commits:
build:
tests:
negative tests:
configuration-contract matrix:
intent and parity review:
local preflight:
Docker identity/home validation:
failure-summary sanitizer:
review inventory:
platform/install matrix:
review-stop:
review-to-push diff:
suppressed findings:
scope documentation:
readiness:
```
