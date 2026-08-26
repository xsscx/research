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
   excluded test builds, complete CTest, negative configurations, generated
   artifact cleanup, and suppressed findings.
5. For workflow, Dockerfile, or CI-summary changes, run
   `.github/scripts/preflight-safety-checks.sh --require-tools` locally before
   a PR update or review request. For Docker user/home changes, validate the
   final image as its runtime user, including a writable home and
   `git config --global`. For failure-summary changes, verify same-step
   checked-in sanitizer access or the established inline fallback and all
   `tee` pipeline statuses.
6. If a no-rebase request conflicts with the required base or stack-parent
   rebase, report FAIL and do not initialize or submit the stack.
7. Report only PASS or FAIL with command evidence and blockers.

## Output

```text
authorization:
base:
range-diff:
merge commits:
build:
tests:
negative tests:
local preflight:
Docker identity/home validation:
failure-summary sanitizer:
suppressed findings:
scope documentation:
readiness:
```
