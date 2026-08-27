# Incident: Approved Handoff Delayed by Unbounded Review

Date: 2026-08-27

## Summary

After a user reviewed and approved a small Doxygen navigation revision, an
automated review continued for more than 50 minutes and made 100 read-only tool
calls without returning a result. The user had authorized only the next
handoff action, but the agent restarted validation and treated the reviewer as
a blocking gate.

## Impact

- The approved branch push was delayed by more than 12 minutes after the user
  asked for it.
- The user had to request cancellation and then request the push again.
- The review created an untracked workspace artifact despite being assigned a
  read-only role.

## Root Causes

1. The PR-readiness policy was applied to a branch-only, user-approved UI
   refinement without a request for the full audit.
2. The reviewer had no enforced small-diff scope, tool-call budget, or deadline.
3. Cancellation was treated as a message to the reviewer rather than an
   immediate removal of the review from the handoff gate.
4. No explicit policy required agents to stop after user approval and perform
   only the authorized commit or push.

## Corrective Actions

- Add an approved small-diff handoff protocol to the readiness policy, skill,
  prompt, agent, and evidence checklist.
- Limit requested small-diff reviews to named files and direct consumers, 25
  tool calls, and 10 minutes.
- Treat review cancellation or timeout as INCOMPLETE, never as a blocker for
  the user's remaining authorization.
- Prohibit reviewers from writing workspace artifacts and remove any artifact
  before handoff.

## Decision

User approval freezes a small branch-only revision. The next action is limited
to the user-authorized handoff; extra review, validation, or investigation
requires an explicit request or a demonstrated command failure.
