---
mode: agent
description: Rebase an iccDEV branch on master and stack extra commits linearly with local validation
---

# iccDEV Linear Stack Rebase

Use this prompt when an iccDEV branch must be rebased on `origin/master` and one
or more commits must be stacked on top without a merge commit.

## Inputs

- Repository: `InternationalColorConsortium/iccDEV`
- Target branch: `BRANCH_NAME`
- Extra commit or source branch: `COMMIT_OR_BRANCH`
- Conflict preference: `PREFER_EXTRA_COMMIT` or `PREFER_TARGET_BRANCH`
- Work directory: `~/work/copilot/iccdev-linear-stack`

## Required Behavior

1. Work in a clean clone or worktree under `~/work/copilot/`.
2. Do not use an existing dirty checkout.
3. Fetch `master`, the target branch, and the source commit or branch.
4. Rebase the target branch onto `origin/master`.
5. Stack the extra commit with `git cherry-pick`; do not merge.
6. If `PREFER_EXTRA_COMMIT` is set, use `git cherry-pick -X theirs <commit>`
   and then manually inspect any remaining conflict. In cherry-pick conflicts,
   `theirs` means the commit being picked.
7. Run `git range-diff origin/master origin/BRANCH_NAME HEAD`.
8. Configure, build, and test locally:

   ```bash
   rm -rf /tmp/iccdev-linear-stack-build
   cmake -S Build/Cmake -B /tmp/iccdev-linear-stack-build -DCMAKE_BUILD_TYPE=Debug -DENABLE_TOOLS=ON
   cmake --build /tmp/iccdev-linear-stack-build -j"$(nproc)"
   ctest --test-dir /tmp/iccdev-linear-stack-build --output-on-failure
   ```

9. If tests regenerate tracked ICC files, restore only generated artifacts after
   tests pass.
10. Push only with an exact `--force-with-lease`:

    ```bash
    git fetch --prune origin master BRANCH_NAME
    lease=$(git rev-parse origin/BRANCH_NAME)
    git push --force-with-lease=refs/heads/BRANCH_NAME:$lease origin BRANCH_NAME
    ```

## Report Format

Report the final stack, the conflict policy used, validation commands, and the
remote update result. If the lease changed or local tests failed, do not push;
report the blocker and the exact command output that matters.
