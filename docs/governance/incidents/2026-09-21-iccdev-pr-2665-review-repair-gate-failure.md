# Incident: Review-Repair Gate Failure on iccDEV PR #2665

Date: 2026-09-21

## Summary

InternationalColorConsortium/iccDEV#2665 added a manually dispatched,
pinned-libpng iCCP compatibility lane. After the first automated review found
five workflow, CTest, evidence, and documentation defects, the repairs were
pushed in `081ea3e2` without a complete review-repair gate record or one
cross-surface contract matrix.

A second review then identified that the workflow's relative `BUILD_DIR` wrote
generated build state into the source checkout, contradicting the new skill and
agent contract requiring state outside the worktree. The repair was pushed in
`97c0e69c`. That was the wrong process action: the second-cycle blocker
required `review-stop: FAIL - maintainer direction required`, not another
repair publication.

The technical change in `97c0e69c` is correct. The process was not. The
failure repeated the documented pattern of treating a review finding as a
line-local task instead of as evidence that the complete local contract model
was incomplete.

## Evidence

| Event | Commit or review | Outcome |
| --- | --- | --- |
| Initial automated review | `5272430039` on `ee60a969` | Found five defects: lexical patch application, CTest inventory assertion, immutable QA evidence, complete local proof procedure, and issue label. |
| First repair push | `081ea3e2` | Addressed those five findings but did not record the required review-repair gate or reconcile all workflow state paths with the skill and agent isolation contract. |
| Second automated review | `5272507484` on `081ea3e2` | Reported the missed relative `BUILD_DIR` contract violation. |
| Second repair push | `97c0e69c` | Correctly set `BUILD_DIR=/tmp/iccdev-libpng-build`, but was published after a second-cycle blocker without maintainer direction. |

The local validation was useful but incomplete as readiness evidence:

- pinned libpng v1.6.58 vulnerable and patched contracts passed;
- the focused `iccdev.libpng-iccp-qa` CTest passed;
- CTest discovery verified 38 tests;
- the workflow fast-lane preflight passed.

Those results proved individual behavior. They did not prove the complete
workflow, QA-wrapper, generated-state, evidence-output, and documentation
contract before the first repair push.

## Root Causes

1. The initial repair plan was based on the five named comments, rather than a
   complete producer-consumer map for the compatibility lane.
2. The skill, agent, workflow, CMake wrapper, Python QA generator, patch
   stack, fixture, CTest wrapper, and local documentation were not treated as
   one contract before `081ea3e2` was published.
3. No review-repair gate recorded the reviewed SHA, current SHA, complete
   changed-file list, active and suppressed finding inventory, contract matrix,
   validation after the latest edit, and stop status.
4. A second-cycle blocker was treated as permission to make a narrow repair
   because the finding was supplied directly, despite the mandatory stop rule.
5. Successful focused tests and workflow preflight were incorrectly allowed to
   substitute for exact-head cumulative readiness evidence.

## Impact

- The PR consumed a second automated review to discover a local contract
  contradiction.
- The branch received an avoidable repair commit after the review-stop
  threshold.
- Maintainer attention shifted from independent confirmation to identifying an
  omission that was already stated in the new repository guidance.
- The report and review evidence were not high-signal at the decision point:
  they described individual passing checks, not whether all coupled surfaces
  had been examined.

## Required Performance and Utility Changes

### Contract-First Repair

Before any edit after automated review feedback, create a compact matrix:

| Surface | Producer | Consumer | Default and failure path | Evidence |
| --- | --- | --- | --- | --- |
| Hosted workflow | `BUILD_DIR` and patch loop | CMake, Python QA, summary | State must be outside checkout; missing patch stack fails | Exact workflow inspection and local preflight |
| QA wrapper | CMake target and CTest registration | `pngtest` and CTest | Pinned source is required; inventory is asserted | Configure, discovery, focused CTest |
| Generated carriers | Python QA fixture generator | `pngtest` output | Generated files stay outside checkout | Vulnerable and patched contract run |
| Documentation | README, skill, agent, prompt, CTest guide | Maintainer execution | Commands and state-location promises agree | Exact-command and path comparison |

The matrix must exist before selecting a repair. A named review line identifies
a contract class; it does not define the complete repair scope.

### Mechanical Review-Repair Gate

Before every repair push, fail closed unless one record contains:

1. target-base SHA, reviewed SHA, current SHA, and proposed push SHA;
2. all review IDs, inline findings, review-body findings, and suppressed
   findings with a disposition;
3. complete `base...HEAD` changed-file list;
4. the contract matrix for every changed workflow, tool, fixture, and
   documentation promise;
5. commands run after the latest edit and their exact outcomes;
6. `review-stop: PASS` or `review-stop: FAIL - maintainer direction required`.

This must be a repository-owned command or checklist that blocks push, not a
memory-based manual habit.

### Stop-State Discipline

The second automated review that identifies a new blocker changes the state to:

```text
review-stop: FAIL - maintainer direction required
```

At that point, do not patch, push, resolve threads, request review, or claim
readiness. Report the cycle count, reviewed and current SHAs, unresolved
contract gap, and required maintainer decision. A pasted finding is evidence
to report, not implicit authorization to bypass the stop state.

### Signal and Value Standard

Every material action must create a decision-quality artifact:

- before editing: scope and contract matrix;
- before pushing: exact-head review-repair ledger and validation evidence;
- after validation: direct statement of what the command proves and does not
  prove;
- after a stop condition: concise blocker report rather than another patch.

Tool activity, passing focused tests, and a clean static preflight are not
valuable on their own. They become useful only when connected to the complete
contract and the exact proposed commit. This reduces review churn, runner use,
and maintainer intervention while making each report independently auditable.

## Decision

The correct state for InternationalColorConsortium/iccDEV#2665 after review
`5272507484` was a stop report, not `97c0e69c`. Future review-repair work must
produce one complete branch-local contract and evidence ledger before a repair
push. A second-cycle blocker ends autonomous PR activity until the maintainer
explicitly directs the next action.
