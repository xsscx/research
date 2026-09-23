# Incident: iccDEV Pin Refresh Validation Overrun

Date: 2026-09-23

## Summary

An agent spent nearly 50 minutes resolving a small dependency-pin failure on
the InternationalColorConsortium/iccDEV `ci-qa-pr-docker-testing` branch. The
functional result was an eight-file, one-commit update with 24 insertions and
25 deletions. Once the hosted failure was inspected, the required edits were
mechanical and could be applied in less than one minute.

The session produced valid changes and useful targeted evidence, but the
validation strategy was disproportionate. It repeated expensive container
builds, launched an unrelated 310-test CTest suite, waited more than seven
minutes inside the long hybrid pipeline test, ran both fast and full workflow
preflight paths, and repeated image vulnerability scans that did not change
the decision. The user had to identify CTest as a time sink and redirect the
session toward completion.

## Requested Scope

The requested work was to:

- use a fresh checkout of the upstream `ci-qa-pr-docker-testing` branch;
- resolve the failure in GitHub Actions run `35904139516`;
- update directly affected documentation, prompts, skills, agent files,
  artifacts, workflows, CTest, CMake, and scripts when needed;
- review other dependencies for available updates;
- update the iccDEV vcpkg port source SHA;
- preserve the intentionally Windows-only vcpkg workflow contract;
- squash the result into one commit and push the branch;
- leave CI execution to the user.

No C++, CMake behavior, test registration, fixture, or application runtime
logic changed.

## Result

The final commit was `e70f3a0c52a9dd2f9127e6fd15ee23ffe638f70e`,
`ci: refresh container and vcpkg dependency pins`.

It made four substantive changes:

1. Updated the unavailable Ubuntu 26.04 package pin from
   `linux-perf=7.0.0-31.31` to `linux-perf=7.0.0-34.34`.
2. Updated CodeQL bundle 2.27.0 to 2.27.1 and synchronized the official
   SHA-256 across the Dockerfile, three workflows, and documentation.
3. Updated the vcpkg port source reference to `dfc4ffd2`, replaced its SHA-512,
   and incremented `port-version` from 4 to 5.
4. Corrected vcpkg documentation and the portfile comment to describe the
   Windows 2022 `x64-windows` CI contract.

The commit was pushed normally to `ci-qa-pr-docker-testing`. No pull request
was created and no workflow was manually dispatched.

## Evidence Produced

Useful evidence included:

- the failed hosted log identified the unavailable `linux-perf` version;
- the replacement Ubuntu package version was verified from the pinned base;
- the old and new vcpkg source archives matched their recorded SHA-512 values;
- CodeQL 2.27.1 matched the official Linux release-asset SHA-256;
- one final no-cache Docker build completed successfully;
- the finished image reported the intended `linux-perf` and CodeQL versions;
- the real MCP and REST smoke test passed with 26 available tools;
- the Docker health check reported `healthy`;
- a local vcpkg install and installed-tool smoke passed;
- workflow preflight completed with zero failures and zero skips;
- the pushed remote SHA matched the local commit SHA.

The incomplete CTest run reached 201 of 310 tests with zero failures and one
expected skip before the user-directed stop. It is not a full-suite pass and
must not be represented as one.

## Time and Value Assessment

The user observed a nearly 50-minute interval for work whose text changes
could have been completed in less than 60 seconds after diagnosis. A bounded
amount of validation was still appropriate, but only an estimated 10 to 15
minutes of the session produced decision-relevant evidence.

| Activity | Value for this change | Assessment |
| --- | --- | --- |
| Inspect failed Actions log | High | Directly identified the broken package pin. |
| Verify replacement package and archive hashes | High | Required for reproducible dependency pins. |
| One final Docker build and smoke | High | Reproduced the failed acquisition path and validated the image. |
| CodeQL pin parity and changed-workflow lint | High | Directly covered synchronized workflow consumers. |
| vcpkg source/hash validation | High | Directly covered the port update. |
| Linux vcpkg install | Moderate | Proved general port integrity but not the Windows-only CI contract. |
| First successful Docker build before scope freeze | Low | Became redundant after later dependency edits. |
| Interrupted second Docker build | None | Resulted from discovering the CodeQL update too late. |
| Full 310-test CTest launch | Very low | Retested unchanged application source and CMake behavior. |
| Seven-minute hybrid pipeline wait | None | Did not cover a changed contract. |
| Full preflight after fast preflight | Low incremental value | Repeated broad analysis beyond the changed workflow pins. |
| Repeated Trivy image scans | Low | Findings remained 209 HIGH and 8 CRITICAL and did not alter the patch. |

CTest was a visible time sink, but not the only one. The larger failure was
sequencing: dependency discovery continued after a successful expensive build,
which forced another build cycle. Broad security and workflow analysis then
continued after the decisive pin checks had passed.

## Root Causes

1. The agent did not freeze the dependency inventory before starting the first
   full container build.
2. The phrase "review other dependencies" was interpreted as authorization
   for open-ended scanning rather than a bounded review of direct pin owners.
3. Validation was selected by repository availability instead of changed-file
   relevance.
4. The presence of CTest in the requested scope was treated as a reason to run
   the complete suite even though no CMake, CTest, source, or fixture change
   proved that it was needed.
5. An already successful fast preflight was not accepted as sufficient for a
   small set of synchronized workflow values.
6. Ongoing CPU activity in the hybrid pipeline was treated as a reason to keep
   waiting rather than evidence that the test was outside the time budget.
7. Heartbeat updates described progress but did not enforce a wall-clock or
   value budget.
8. The agent optimized for accumulating evidence instead of reaching the
   user-authorized push with the minimum decisive evidence.

## Anti-Patterns

- Start an expensive build before dependency review and scope are complete.
- Run repository-wide CTest for dependency metadata, workflow, and
  documentation-only changes.
- Treat an active long test as valuable merely because it has not failed.
- Validate a Windows-only contract primarily through a Linux installation.
- Run both fast and full versions of the same gate without a new relevant
  failure.
- Repeat vulnerability scans when the first result does not select or block a
  change.
- Continue optional validation after the user emphasizes elapsed time.
- Count partial test progress as justification for continuing a low-value
  lane.

## Required Pin-Only Workflow

Future dependency-pin-only work must use this sequence:

1. Inspect the named failure and identify the exact failed producer-consumer
   edge.
2. Inventory every directly synchronized pin, workflow, manifest, and document
   before making an edit or starting an expensive build.
3. Freeze scope and apply the complete patch once.
4. Verify checksums, manifest syntax, pin parity, changed-workflow syntax, and
   `git diff --check`.
5. Run at most one clean build of the failed artifact and one existing smoke
   test of that artifact.
6. For a Windows-only vcpkg workflow, verify the source archive, manifest, and
   port structure locally. State that the manually run Windows CI lane is the
   authoritative platform result.
7. Do not run CTest unless source code, CMake behavior, test registration, or a
   fixture changed. If a focused CTest directly covers the changed contract,
   run only that test.
8. Do not run broad CodeQL, Trivy, sanitizer, or coverage suites unless the
   change or a discovered blocker directly requires them.
9. Create one commit, review the exact diff, push, and stop.

## Time Controls

For a pin-only branch repair:

- target wall-clock time: 10 minutes;
- warning threshold: 15 minutes;
- mandatory strategy stop: 20 minutes;
- maximum unrelated test wait: 2 minutes;
- maximum clean container builds: one after scope freeze;
- maximum aggregate gates: one, only if directly required.

Crossing the warning threshold requires dropping optional tests. Crossing the
mandatory stop requires reporting the remaining blocker and asking for
direction instead of continuing broad validation.

## Decision

Dependency-pin work is an acquisition and synchronization problem, not an
application-regression matrix. The decisive evidence is a verified pin, one
successful build of the failed artifact, its focused smoke test, and syntax or
parity checks for direct consumers.

Full CTest, broad security scans, and repeated aggregate gates provide little
value when application code and test contracts are unchanged. They must not be
used to fill a validation checklist or delay an explicitly authorized push.
