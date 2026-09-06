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
5. Before any push, reconcile the PR title, issue, and description with the
   proposed diff. Map every equivalent platform entry point and every
   producer-consumer path affected by the change. For a generated fixture, this
   includes all platform generators, generated output, baselines, and the CTest
   fixture dependency that consumes them. Run the smallest local test selection
   that proves that complete map; a Linux-only result cannot stand in for its
   Windows counterpart.
   For package, protocol, or subprocess-launch changes, record each supported
   platform and installation mode. A child-process test must prove source-tree
   and installed-package imports separately; an editable-install result does
   not prove a no-install launch path.
6. Before every PR-branch push, compare `HEAD` with the exact commit reviewed
   by the most recent completed local review. A nonempty diff invalidates that
   review's readiness result until the new files, requirements, platform paths,
   and targeted build/test evidence are reviewed and recorded. Never push a
   repair before its applicable local build and test gate has passed.
7. Normal build targets and project-specific excluded test helpers are built.
8. The smallest complete local test selection for the mapped change passes.
   Run the full suite only when the changed contract or its dependencies require
   it; unrelated CTest coverage is not readiness evidence.
9. Positive and negative configuration cases pass, including Debug/Release,
   compiler, sanitizer, diagnostics, runtime CPU dispatch, and fallback paths.
10. For workflow, Dockerfile, or CI-summary changes, run the local preflight
   before the first PR create, update, or review request:

   ```bash
   .github/scripts/preflight-safety-checks.sh --require-tools
   ```

   Record its exit status. CI is not a substitute.
11. Docker user, home, and ownership changes preserve the runtime identity
   invariant: a user with `--home-dir` must have an owned, writable home
   (`--create-home` or an equivalent explicit directory and ownership step).
   Validate the final image as that user, including `git config --global`.
12. A failure-summary step independently loads a checked-in sanitizer available
    in that step or defines the established inline fallback there. It must not
    depend on a sanitizer copied into a temporary path by an earlier failing
    step.
13. Every changed configuration, workflow, Dockerfile, or dependency manifest
    has a written contract matrix. For each changed surface, record its default,
    explicit override, failure path, and matching local command or inspection.
    Compiler-specific flags require both a supported-compiler and an unsupported-
    compiler check. Runtime suppression syntax must be proven with the runtime,
    not inferred from compile-time special-case syntax.
14. Generated artifacts are removed or intentionally documented.
15. Active and suppressed automated-review findings are inspected. Query both
    review threads and review summaries: suppressed comments may not create
    resolvable threads.
16. Documentation and reported evidence describe actual runtime behavior, not
    only compile-time eligibility.
17. Related branches are synchronized only after the canonical branch passes.
18. The user explicitly authorizes PR creation.

Any incomplete item means the branch remains branch-only.

When rebasing is required but the user has prohibited it, the user must
explicitly choose one of these paths before PR creation: authorize the rebase,
use independent branches or stacks, or defer publication. Do not approximate
`gh stack sync` with a fetch-only update and do not submit a divergent stack.

## Approved Small-Diff Handoff

Do not apply this full readiness audit to a branch-only documentation,
configuration, or UI-only revision that the user has reviewed and approved
locally, unless the user explicitly asks for the audit.

### Small Upstream Fix Execution Contract

Before editing a small upstream fix, record in the session handoff:

```text
scope: exact files and direct consumers
worktree and branch:
decisive validation:
review budget:
stop condition:
documentation home:
```

A requirement found outside this contract is a scope failure, not the next
repair. Stop and ask the user whether to consolidate it into one repair or
defer it. Do not create process or governance documentation as a substitute
for completing the agreed code fix.

1. Freeze the approved scope. Do not reopen discovery, add adjacent cleanup, or
   start another review unless a command fails or the user asks.
2. When the user authorizes commit or push, perform only that handoff action.
   Report a credential or remote failure immediately; do not substitute
   additional validation or investigation.
3. Do not delegate a review unless the user requests one or the change needs a
   defined readiness gate. A requested small-diff review must inspect only the
   stated files and direct consumers, use at most 25 tool calls, and return
   within 10 minutes.
4. A cancelled or timed-out review is not a gate. Stop waiting, report it as
   incomplete, and proceed only with the user's remaining authorization.
5. Read-only reviewers must not create files, build outputs, logs, or other
   workspace artifacts. Remove any such artifact before handoff.

## Review Cycle Stop Rule

Automated review is a final verification gate, not the implementation loop.

- Before requesting the first review, record one complete local readiness
  review and the configuration-contract matrix. The evidence identifies every
  local review by date, reviewer, commit range, reviewed files, and outcome.
- First cycle: inventory all active and suppressed findings together. Return to
  branch-only grooming, audit the complete cumulative diff, and make one
  coherent repair for every confirmed root cause. Do not publish one repair per
  comment. Re-run the complete local matrix before any new review.
- A review finding is evidence that the local scope model was incomplete. Return
  to branch-only grooming, re-check the PR requirement against every equivalent
  platform path and producer-consumer edge, and validate that map locally before
  pushing a repair. Do not use a Cloud Agent review to discover omitted
  counterparts or acceptance criteria.
- A reviewer suggestion is a hypothesis, not evidence. Verify proposed
  compiler flags, runtime suppression names, and tool configuration semantics
  against the implementation and the actual runtime.
- Second cycle: if it identifies any new blocker, including one in the repair,
  set `review-stop: FAIL - maintainer direction required`. Do not launch a
  local or cloud reviewer, publish another repair, resolve findings as a
  completion signal, or claim readiness. Return to branch-only grooming,
  perform a complete diff/configuration audit, and report the review-cycle
  count and gap to the user before any further PR activity.

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
configuration-contract matrix: changed surface, default, override, failure path, and evidence
intent and parity review: PR requirement, equivalent platform paths, producer-consumer map, and local evidence
platform/install matrix: supported platform, installation mode, child-process path, result, and skip rationale
local preflight: exact command and exit status
Docker identity/home validation: command and result, if applicable
failure-summary sanitizer: checked-in source or same-step fallback, if applicable
review inventory: local review count; for each local review, date, reviewer,
  commit range, reviewed files, and outcome; automated review IDs and count
review-cycle ledger: exact head SHA, active findings, suppressed findings, disposition, and post-repair validation
review-stop: PASS or FAIL - maintainer direction required
review-to-push diff: reviewed commit, proposed push commit, diff status, and
  validation rerun after the most recent changed file
active findings: checked
suppressed findings: checked from review threads and review summaries
scope documentation: checked
readiness: PASS or FAIL
```

Use `.github/skills/upstream-pr-readiness/SKILL.md` for the executable workflow.
Use `.github/checklists/upstream-pr-review-evidence.md` to record the
review-cycle and configuration-contract evidence.
