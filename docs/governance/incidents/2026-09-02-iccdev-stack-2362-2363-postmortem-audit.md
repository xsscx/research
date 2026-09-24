# Post-Mortem Audit: iccDEV Stack #2362/#2363

Audit date: 2026-09-02

## Audit Disposition

```text
preparedness: FAIL
review-process: FAIL
closure-claim: INVALID
publication-state: open, not ready to represent as complete
```

This audit covers parent PR `InternationalColorConsortium/iccDEV#2362` and
child PR `InternationalColorConsortium/iccDEV#2363`. The child is the primary
failure surface because it combined bounded MCS profiling, threaded diagnostic
behavior, CodeQL query and pack work, workflow trust-boundary changes, CI scope
selection, Docker PR-lane retirement, and related documentation.

As audited from GitHub on 2026-09-02, PR #2363 is open on
`ci-qa-perf-analysis` at `cd70615199204e3beb44bc2a402c202b39820400`, based on
parent `ci-qa-iccconnect-threading` at
`c9bd01ba5ba7a82d5ad59bf56d59bc6c1a0fe613`. GitHub reports 25 commits in the
child PR and 20 completed Copilot review submissions.

## Scope and Evidence

| Audit item | Observed state | Evidence | Disposition |
| --- | --- | --- | --- |
| Review-cycle limit | 20 completed child-PR Copilot reviews | Review IDs `5091749242` through `5095964589` | FAIL |
| Published repair history | 25 child commits, plus 7 parent commits | GitHub PR commit inventory | FAIL |
| Exact-head readiness record | No one record binds complete diff, PR body, review inventory, matrix, and results to `cd706151` | Existing incident record and published repair sequence | FAIL |
| Review stop rule | New blockers continued to receive incremental repair pushes after the second review cycle | Repeated commits and reviews across the same child PR | FAIL |
| Closure evidence | Review threads were resolved after individual fixes, then described as zero unresolved | Thread state is administrative and proves neither complete scope nor readiness | INVALID |
| Child scope coherence | C++ behavior, query policy, CI selection, artifact handling, and documentation changed together | Current PR title/body and 42-file review scope | FAIL |
| Docker policy | Retired Docker PR lane was initially repaired/reintroduced, then removed; normal matrix coverage required a later correction | Docker fallback, removal, and container-matrix follow-up commits | FAIL |

## Failure Timeline

1. The stack began with threading and bounded profiling intent, but publication
   preceded a final, exact-head contract review.
2. Reviews discovered omissions in fixture paths, CI behavior, Docker handling,
   CodeQL query semantics, diagnostic metrics, trace encoding, and CLI parsing.
3. Each discovery generally produced a narrow commit and another external
   review, instead of stopping for a complete branch-only reconciliation.
4. A clean rebase rewrote the stack, but later commits again accumulated review
   repairs without a replacement full-diff audit.
5. Individual conditions were eventually tested, including worker-strip
   reporting, trace control-byte encoding, strict thread parsing, and CodeQL
   fixtures. Those targeted passes did not establish that the entire child
   diff, policy set, and PR narrative were coherent.
6. Statements that the work was "resolved" relied on focused test success and
   zero unresolved threads. Neither condition is a readiness result.

## Material Preparedness Failures

### 1. Automated review became the discovery mechanism

The review sequence found basic behavioral and policy defects that should have
been enumerated before publication: a literal zero asynchronous-work metric,
`atoi` accepting malformed thread counts, non-ASCII trace bytes emitted
verbatim, multiple CodeQL hard-cap bypasses, job-wide failure attribution for
MCS artifacts, and container-only matrix skipping. This is direct evidence
that the complete requirement and producer-consumer map was not established
locally before each repair was pushed.

### 2. The stop rule was not followed

Repository policy requires a return to branch-only grooming when a second
automated review identifies a new blocker. Instead, the child accumulated
successive single-finding commits through twenty review submissions. The stop
rule existed in documentation but was not used as an operational gate.

### 3. The change set was not kept coherent

The child PR title identifies bounded MCS profiling, but the cumulative diff
also changes threading diagnostics, trace-output security, CodeQL detection
semantics, dependency/query-pack behavior, CI matrix selection, artifact
policy, and Docker-lane policy. These concerns have different owners,
acceptance criteria, and validation requirements. Combining them made it
possible for a repair to be locally correct while the PR remained globally
unprepared.

### 4. Thread resolution was misused as a completion signal

Resolving a review thread means only that a conversation was marked resolved.
It does not prove the proposed change is correct, that equivalent paths were
examined, that suppressed findings were dispositioned, or that the next commit
did not invalidate prior evidence. Reporting zero unresolved threads as if it
were closure was misleading.

### 5. The evidence model was fragmented

Focused commands proved individual properties, but no final evidence record
connected the exact child head to:

- the complete `base...HEAD` diff;
- the child PR narrative and every changed acceptance criterion;
- parent-child stack ancestry and range-diff;
- CodeQL positive and negative query semantics;
- CI defaults, explicit overrides, skip behavior, and failure artifacts;
- threaded dispatch, timing, trace, CLI parsing, and fallback behavior; and
- active plus suppressed review disposition.

Without that binding, a passing targeted command cannot support a claim of
overall readiness.

## Root Cause Analysis

| Root cause | How it manifested | Required control |
| --- | --- | --- |
| Repair-first mindset | Each new finding became a new commit before cumulative scope was reviewed | Freeze publication after the second new blocker |
| Missing exact-head gate | Earlier review evidence was reused after new files changed | Require an exact SHA-bound evidence record before every push |
| Incomplete change decomposition | Independent C++, CodeQL, workflow, and governance changes shared one child PR | Split independent concerns into separately owned commits and normally separate PR layers |
| Inadequate negative testing | Fail-open parsing, false-negative query paths, and trace encoding gaps escaped initial work | Define negative and adversarial cases from each acceptance contract before editing |
| Incorrect closure metric | Zero unresolved threads was reported as success | Permit closure claims only from the full readiness record |
| Late policy decisions | Docker-lane retirement and normal-matrix replacement were clarified after review | Record intentional policy changes and replacement coverage before implementation |

## Corrective Actions

1. Freeze further review-driven repair publication on this stack. Do not request
   or treat another automated review as a readiness gate until a complete
   branch-only audit is recorded for one exact head SHA.
2. Produce an evidence record using
   `.github/checklists/upstream-pr-review-evidence.md` that maps every changed
   file to its owner, acceptance criterion, platform/toolchain paths, failure
   path, and local evidence.
3. Reconcile the child PR against its stated purpose. Move unrelated CodeQL
   policy/pack, CI governance, and Docker policy work to focused branches
   unless their combined inclusion has a documented maintainer decision and
   shared acceptance contract.
4. Treat the parent and child as a stack: verify current base ancestry,
   linearity, range-diff, and the full parent-to-child contract before any
   child publication.
5. Audit the PR body against the complete diff before claiming progress. The
   PR body must distinguish implemented behavior, deliberately retired
   behavior, selected CI paths, skipped paths, and evidence.
6. Make the review stop rule enforceable in the readiness checklist: review
   count greater than one with a new blocker sets `readiness: FAIL` until a
   new branch-only audit is completed.
7. Prohibit readiness language based solely on a focused test, CI subset, or
   review-thread count. Claims must name the exact audited SHA and evidence
   record.

## Conditions for a Future Readiness Claim

No future statement that this stack is resolved, complete, or ready is valid
until all of these are true for the same exact child SHA:

1. The cumulative diff and PR description have one approved scope decision.
2. Every changed surface has a configuration-contract and
   producer-consumer matrix covering defaults, overrides, skips, and failures.
3. The parent-child ancestry is linear and the range-diff is reviewed.
4. Targeted positive and negative tests cover each changed behavior, including
   all supported platform counterparts where applicable.
5. Active and suppressed review findings have an explicit disposition tied to
   the complete diff, not only to individual commits.
6. The evidence record reports `readiness: PASS`; otherwise the branch remains
   branch-only and must be described as incomplete.

## Conclusion

The repeated review cycle was not an unavoidable consequence of complex code.
It resulted from publishing an incompletely scoped stack, using external
review to discover requirements, and repeatedly treating local fixes and
resolved threads as evidence of whole-PR readiness. The correct audit result
is **FAIL**. The required remedy is one exact-head, branch-only preparedness
decision, not another incremental repair-and-review cycle.
