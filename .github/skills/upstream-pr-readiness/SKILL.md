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

## Approved Small-Diff Handoff

Do not invoke this full readiness workflow for a branch-only documentation,
configuration, or UI-only revision that the user has reviewed and approved
locally, unless the user explicitly asks for a readiness audit.

After the user approves a small diff and authorizes commit or push:

1. Freeze scope and perform only the authorized handoff action.
2. Do not start another review, broad validation, or adjacent cleanup unless a
   command fails or the user asks.
3. A requested small-diff review inspects only the named files and direct
   consumers, uses at most 25 tool calls, and returns within 10 minutes.
4. A cancelled or timed-out review is incomplete and must not block the user's
   remaining authorization.
5. Leave no generated files, logs, or other artifacts in the reviewed worktree.

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
6. Before any push, compare the PR title, issue, and description with the
   complete diff. Map every equivalent platform entry point and each changed
   producer-consumer path. For fixture work, include every generator,
   generated artifact, baseline, and CTest dependency. Run the smallest local
   selection that proves the complete map; never treat a single-platform test
   as proof for an unreviewed counterpart.
7. Build normal targets and excluded regression helpers, then run the smallest
   complete CTest selection identified by the map. Run the entire suite only
   when the changed contract or its dependencies require it:

   ```bash
   cmake -S Build/Cmake -B /tmp/iccdev-pr-ready \
     -DCMAKE_BUILD_TYPE=Debug -DENABLE_TOOLS=ON
   cmake --build /tmp/iccdev-pr-ready -j"$(nproc)"
   cmake --build /tmp/iccdev-pr-ready \
     --target build-test-binaries -j"$(nproc)"
   ctest --test-dir /tmp/iccdev-pr-ready -R '<changed-selection>' --output-on-failure
   ```

8. Build a configuration-contract matrix for every changed configuration,
   workflow, Dockerfile, or dependency manifest. Cover defaults, explicit
   overrides, failure paths, and the exact local evidence. For compiler-specific
   settings, verify supported and unsupported compilers. Prove runtime
   suppression syntax with the runtime; do not infer it from compile-time
   ignorelist categories.
9. Run task-specific Release, compiler, sanitizer, diagnostics, runtime-dispatch,
   fallback, malformed-input, and other negative tests.
10. For workflow, Dockerfile, or CI-summary changes, run and record the local
   preflight before PR creation, update, or review:

   ```bash
   .github/scripts/preflight-safety-checks.sh --require-tools
   ```

   Do not use CI or automated review to discover local policy failures.
11. For Docker user, home, or ownership changes, validate the final image as
   its runtime user. Its declared home must be owned and writable, and
   `git config --global` must work.
12. For failure-summary changes, verify the step independently loads a
    checked-in sanitizer or defines the standard inline fallback. Verify every
    pipeline status when logs are captured with `tee`.
13. Remove generated artifacts and verify a clean worktree.
14. Inventory all review summaries and review threads. Suppressed comments may
    exist only in a review summary and still require disposition.
15. If an automated review identifies an omitted requirement or platform
    counterpart, stop treating reviews as the repair loop. Return to
    branch-only grooming and repeat the requirement, parity, and
    producer-consumer review locally before a follow-up push or review.
16. If a second automated review finds any new blocker, including one in the
    repair, stop, report the review-cycle count to the user, and return to
    branch-only grooming for a complete contract-matrix audit before another
    review.
17. Produce the evidence record from
    `docs/governance/UPSTREAM_PR_READINESS.md`.

## Result

Only `readiness: PASS` plus explicit authorization permits PR creation.

If a second automated review finds any new blocker, including one in the
repair, change the result to FAIL and return to branch-only grooming.
