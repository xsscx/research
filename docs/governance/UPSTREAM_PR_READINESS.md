# Upstream Pull Request Authorization and Readiness

Use this policy before creating, reopening, or requesting review on an
upstream pull request.

## Authorization Boundary

Only explicit user language such as "open a PR", "create the pull request", or
"reopen PR N" authorizes PR publication.

The following requests do not authorize PR creation:

- push the branch;
- trigger CI;
- run a workflow whose name contains `pr`;
- request or monitor a review;
- prepare a PR description;
- synchronize related branches.

If a requested workflow requires an open PR, report the prerequisite and ask
for authorization. Do not create the PR under the user's authenticated account.

## Readiness Gate

All items must pass before an authorized PR is opened:

1. Scope is frozen and the PR description covers every feature, ISA path,
   toolchain, workflow, and behavior change.
2. The branch is rebased on the current target branch in a clean worktree.
   A no-rebase request is not a waiver when the branch is not linear with that
   target or its required stack parent: record `readiness: FAIL`, explain the
   conflict, and wait for direction before submitting or marking a PR ready.
3. History is linear: no merge commits; `git range-diff` is reviewed.
4. `git diff --check` passes and the complete diff is manually reviewed.
5. Normal build targets and project-specific excluded test helpers are built.
6. The complete applicable test suite passes locally.
7. Positive and negative configuration cases pass, including Debug/Release,
   compiler, sanitizer, diagnostics, runtime CPU dispatch, and fallback paths.
8. For workflow, Dockerfile, or CI-summary changes, run the local preflight
   before the first PR create, update, or review request:

   ```bash
   .github/scripts/preflight-safety-checks.sh --require-tools
   ```

   Record its exit status. CI is not a substitute.
9. Docker user, home, and ownership changes preserve the runtime identity
   invariant: a user with `--home-dir` must have an owned, writable home
   (`--create-home` or an equivalent explicit directory and ownership step).
   Validate the final image as that user, including `git config --global`.
10. A failure-summary step independently loads a checked-in sanitizer available
    in that step or defines the established inline fallback there. It must not
    depend on a sanitizer copied into a temporary path by an earlier failing
    step.
11. Generated artifacts are removed or intentionally documented.
12. Active and suppressed automated-review findings are inspected.
13. Documentation and reported evidence describe actual runtime behavior, not
    only compile-time eligibility.
14. Related branches are synchronized only after the canonical branch passes.
15. The user explicitly authorizes PR creation.

Any incomplete item means the branch remains branch-only.

When rebasing is required but the user has prohibited it, the user must
explicitly choose one of these paths before PR creation: authorize the rebase,
use independent branches or stacks, or defer publication. Do not approximate
`gh stack sync` with a fetch-only update and do not submit a divergent stack.

## Review Cycle Stop Rule

Automated review is a final verification gate, not the implementation loop.

- First cycle: resolve all active and suppressed findings together.
- Second cycle: if it identifies missed issues in unchanged code, stop.
- Return to branch-only grooming and perform a complete diff/configuration
  audit.
- Do not request another review or rewrite an active PR branch without telling
  the user why and obtaining direction.

## Required Evidence

Record:

```text
authorization: exact user quotation
base: target branch and fetched SHA
range-diff: reviewed
merge commits: none
build: command and result
tests: command, pass count, skip count
negative tests: cases and results
local preflight: exact command and exit status
Docker identity/home validation: command and result, if applicable
failure-summary sanitizer: checked-in source or same-step fallback, if applicable
suppressed findings: checked
scope documentation: checked
readiness: PASS or FAIL
```

Use `.github/skills/upstream-pr-readiness/SKILL.md` for the executable workflow.
