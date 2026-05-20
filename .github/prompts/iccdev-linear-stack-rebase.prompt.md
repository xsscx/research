---
mode: agent
description: Rebase an iccDEV branch on master and stack extra commits linearly with local validation
---

# iccDEV Linear Stack Rebase

Use this prompt when an iccDEV branch must be rebased on `origin/master` and one
or more commits must be stacked on top without a merge commit. The source of
truth is `.github/skills/iccdev-linear-stack/SKILL.md`; use that skill for the
full step-by-step workflow.

## Inputs

- Repository: `InternationalColorConsortium/iccDEV`
- Target branch: `BRANCH_NAME`
- Extra commit or source branch: `COMMIT_OR_BRANCH`
- Conflict preference: `PREFER_EXTRA_COMMIT` or `PREFER_TARGET_BRANCH`
- Work directory: `~/work/copilot/iccdev-linear-stack`

## Required Behavior

1. Work in a clean clone or worktree under `~/work/copilot/`.
2. Rebase onto `origin/master`, then stack extras with `git cherry-pick` only.
3. Use `git cherry-pick -X theirs <commit>` only when `PREFER_EXTRA_COMMIT` is set.
4. Review with `git range-diff`, then configure, build, and run CTest locally.
5. Push only with an exact `--force-with-lease=refs/heads/BRANCH_NAME:<lease>`.

## Report Format

Report the final stack, the conflict policy used, validation commands, and the
remote update result. If the lease changed or local tests failed, do not push;
report the blocker and the exact command output that matters.
