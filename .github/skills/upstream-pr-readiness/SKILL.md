---
name: upstream-pr-readiness
description: >
  Verify explicit authorization and complete grooming before creating,
  reopening, or requesting review on an upstream pull request.
allowed-tools:
  - bash
  - read
  - grep
  - glob
  - shell(git:*)
  - shell(gh:*)
---

# Upstream PR Readiness

## Hard Stop

Find an exact user quotation authorizing PR creation or reopening. Requests to
push, trigger CI, prepare a description, request review, or monitor checks do
not qualify.

If explicit authorization is absent, return:

```text
readiness: FAIL
reason: PR creation is not explicitly authorized
```

Do not call `gh pr create`, `gh pr reopen`, or an equivalent API.

## Rebase Conflict Hard Stop

A user request not to rebase does not waive the linear-history requirement. If
the branch is not linear with the current base or required stack parent, return:

```text
readiness: FAIL
reason: required rebase conflicts with the user's no-rebase constraint
```

Do not initialize or submit a divergent stack. Report the conflicting ancestry
and wait for the user to authorize the rebase, choose independent branches or
stacks, or defer PR publication.

## Workflow

1. Work in a clean clone or worktree.
2. Fetch the target branch and current base.
3. Rebase onto the current base before PR creation.
4. Verify linear history and review the rewrite:

   ```bash
   git diff --check origin/master..HEAD
   test -z "$(git rev-list --merges origin/master..HEAD)"
   git range-diff origin/master origin/BRANCH HEAD
   ```

5. Review every changed file and confirm the PR description covers the entire
   feature surface.
6. Build normal targets and excluded regression helpers:

   ```bash
   cmake -S Build/Cmake -B /tmp/iccdev-pr-ready \
     -DCMAKE_BUILD_TYPE=Debug -DENABLE_TOOLS=ON
   cmake --build /tmp/iccdev-pr-ready -j"$(nproc)"
   cmake --build /tmp/iccdev-pr-ready \
     --target build-test-binaries -j"$(nproc)"
   ctest --test-dir /tmp/iccdev-pr-ready --output-on-failure
   ```

7. Run task-specific Release, compiler, sanitizer, diagnostics, runtime-dispatch,
   fallback, malformed-input, and other negative tests.
8. Remove generated artifacts and verify a clean worktree.
9. Inspect all active and suppressed findings from any existing review.
10. Produce the evidence record from
    `docs/governance/UPSTREAM_PR_READINESS.md`.

## Result

Only `readiness: PASS` plus explicit authorization permits PR creation.

If a second automated review finds missed unchanged-code issues, change the
result to FAIL and return to branch-only grooming.
