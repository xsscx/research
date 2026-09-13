# Incident: Serial Local Validation Matrix

Date: 2026-09-13

## Summary

An agent executed an iccDEV local compiler and configuration validation matrix
mostly serially, despite the work consisting of independent lanes that should
have run concurrently. Repeated full-suite reruns after test-harness fixes
extended the session to nearly three hours and consumed more than 2,600 AIC.
The user assessed the duration and cost as unacceptable.

## Requested Scope

The requested validation covered:

- Windows MSVC, ClangCL, and MinGW UCRT64;
- WSL2 GCC and Clang;
- Debug, Release, RelWithDebInfo, and MinSizeRel;
- full CTest coverage;
- vcpkg overlay-port and consumer validation;
- local diagnosis and correction of failures.

The work was expected to follow the repository's parallel build guidance and
complete near the normal CI wall-clock envelope, approximately 12 minutes.

## Impact

- Independent toolchain and configuration lanes were serialized.
- Full suites were repeated after focused test-harness fixes.
- The session ran for nearly three hours.
- The user reported more than 2,600 AIC of cost.
- Hundreds of Windows default-application selection dialogs appeared during an
  early automated attempt, requiring all related work to be stopped.
- The user had to request status repeatedly and ultimately directed the final
  WSL Clang MinSizeRel CTest run to stop.
- The resulting code fixes were useful, but the execution strategy made the
  overall session disproportionately expensive.

## Completed Validation

The completed full suites were:

| Toolchain | Configurations completed | Result |
|---|---|---|
| MSVC 19.44 | Debug, Release, RelWithDebInfo, MinSizeRel | 656/656 |
| ClangCL 19.1 | Debug, Release, RelWithDebInfo, MinSizeRel | 656/656 |
| MinGW UCRT64 GCC 16.1 | Debug, Release, RelWithDebInfo, MinSizeRel | 656/656 |
| WSL2 GCC 15.2 | Debug, Release, RelWithDebInfo, MinSizeRel | 1108/1108 |
| WSL2 Clang 22.1 | Debug, Release, RelWithDebInfo | 831/831 |

The WSL2 Clang MinSizeRel build completed, but its final 277-test CTest run was
stopped at the user's direction and is not reported as complete.

The vcpkg overlay install, tool smoke, and Debug and Release consumer checks
completed successfully.

## Defects Found

The local matrix exposed five test-infrastructure defects:

1. The nested taint-configuration test forwarded an incomplete exported vcpkg
   toolchain instead of using the parent compiler identity.
2. The visualization leak test wrote TIFF and PDF output beside a source-tree
   profile and polluted `Testing/`.
3. The dict round-trip script compared CRLF fixture lines directly with LF
   writer output.
4. The installed-package consumer requested MinSizeRel from Ninja Multi-Config
   without generating that configuration.
5. Two shell regressions selected static archives before shared libraries,
   causing Clang Release LTO helper links to fail with `ld.bfd`.

These fixes were squashed into commit `99cdc33d` and pushed to
`ci-qa-pr-docker-testing` without Copilot attribution.

## Root Causes

1. The agent treated a matrix as a sequence rather than a dependency graph.
2. The execution plan optimized command simplicity instead of wall-clock time
   and resource cost.
3. The initial automation was not proven on one harmless lane before broad
   execution.
4. After each discovered defect, the agent reran complete suites rather than
   rerunning only affected tests and lanes.
5. Heartbeats reported progress but did not enforce an elapsed-time budget or
   trigger a strategy correction.
6. Background-agent results were not consistently reliable and required later
   correction.

## Anti-Patterns

- Running independent toolchains and configurations serially.
- Combining many lanes in one fail-fast command chain.
- Repeating successful suites after an unrelated harness correction.
- Using full CTest as the first diagnostic step.
- Allowing tests to share writable source fixtures.
- Continuing after runtime exceeds twice the expected budget.
- Treating ongoing activity as evidence that the execution plan remains sound.
- Reporting background-agent summaries without reconciling them against direct
  command evidence.

## Required Pattern

Future local matrices must:

1. Enumerate lanes and dependencies before execution.
2. Use isolated build, runtime, output, and log directories.
3. Run independent lanes concurrently with bounded per-lane CPU allocation.
4. Keep source-tree-writing fixtures serialized or move their output into the
   build tree.
5. Reproduce failures with the smallest command.
6. Rerun focused tests first after a fix.
7. Rerun only affected lanes, followed by at most one required aggregate gate.
8. Define an expected elapsed-time budget and stop for review at 2x that budget.
9. Report exact completed, failed, skipped, and unrun coverage.
10. Stop immediately when requested or when unexpected host-impacting behavior
    occurs.

## Documentation Review Findings

The repository documentation already establishes several correct principles:

- `docs/build.md` and `docs/ctest.md` use parallel builds.
- `docs/bisect.md` requires the smallest reproducing command before a broader
  suite.
- `docs/pre-pr-security-cycle.md` requires focused deterministic tests and
  repeating only checks affected by a fix.
- `docs/regression-workflow-governance.md` describes an 8-12 minute PR lane and
  requires bounded jobs.
- `docs/governance/UPSTREAM_PR_READINESS.md` requires complete applicable local
  evidence before publication.

The gap is that these documents do not explicitly define orchestration for a
large local cross-toolchain matrix. Parallelism is described inside individual
build commands, but concurrency across independent toolchains and
configurations, elapsed-time budgets, and rerun limits are not stated as one
coherent policy.

## Corrective Actions

- Treat a local validation matrix as parallel CI-equivalent work.
- Add an explicit lane graph, concurrency budget, and expected duration before
  execution.
- Use one coordinator and bounded independent workers.
- Preserve a result record per lane rather than repeatedly reading full logs.
- Stop and reassess at twice the expected duration.
- Never restart canceled validation without explicit authorization.
- Keep incident records for material time, cost, or host-impact failures.

## Decision

Independent validation lanes must not be serialized by default. A request for
comprehensive coverage authorizes breadth, not unlimited elapsed time, repeated
full-suite execution, or unbounded cost.
