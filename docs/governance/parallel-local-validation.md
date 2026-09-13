# Parallel Local Validation Pattern

Date: 2026-09-13

## Purpose

Run broad compiler and configuration validation in approximately the same wall
clock envelope as CI. Independent matrix lanes must execute concurrently rather
than serially.

## Required Pattern

1. Define the complete matrix before starting.
2. Give every lane its own build directory, log directory, and output directory.
3. Run independent toolchains and configurations concurrently, subject to a
   declared CPU and memory limit.
4. Use all appropriate local Windows and WSL2 resources.
5. Keep each lane as one bounded configure, build, test sequence.
6. Collect exit status and a short result record from every lane.
7. Diagnose failures from retained logs without rerunning successful lanes.
8. Reproduce a failure with the smallest relevant command.
9. After a fix, rerun the focused failing test first.
10. Rerun only affected matrix lanes. Run one final aggregate gate only when
    repository policy requires it.
11. Report elapsed time, active lanes, completed lanes, failures, and remaining
    work at each heartbeat.
12. Stop all work promptly when requested.

## Execution Model

Use a bounded fan-out model:

- Windows MSVC, Windows ClangCL, MinGW, WSL GCC, WSL Clang, and independent
  package checks are separate workers.
- Debug, Release, RelWithDebInfo, and MinSizeRel may run concurrently when they
  use isolated build and output directories.
- Do not run concurrent tests that write into the same source-tree fixture
  directory.
- Reserve CPU and memory capacity for the host. Reduce per-lane build and CTest
  parallelism when several lanes are active.
- Use one coordinator to collect results. Workers must not launch additional
  unbounded child matrices.

Example allocation on a 32-logical-CPU host:

| Concurrent lanes | Build jobs per lane | CTest jobs per lane |
|---|---:|---:|
| 2 | 12-14 | 12-14 |
| 4 | 6-7 | 6-7 |
| 6 | 4 | 4 |

Adjust for memory pressure and expensive nested tests. More jobs are not useful
when a suite contains serial package-consumer gates.

## Time and Cost Controls

- Record an expected wall-clock budget before execution.
- Treat a 2x budget overrun as a stop-and-review threshold.
- Do not silently expand a focused validation request into repeated full suites.
- Do not repeat a successful configuration after an unrelated test-driver fix.
- Do not poll large logs repeatedly. Read bounded tails or completion summaries.
- Preserve logs once and extract concise evidence from them.
- If a full matrix is expected to complete in about 12 minutes, stop and
  reassess before continuing toward an hour.

## Safe Iteration Sequence

1. Inspect repository instructions and canonical CI configuration.
2. Configure one representative lane.
3. Build required normal and excluded test targets.
4. Run focused tests covering changed behavior.
5. Fix confirmed defects.
6. Start the full matrix concurrently.
7. If one lane fails, let independent lanes finish unless the failure is unsafe.
8. Fix the root cause and rerun only that lane or test.
9. Perform one final required aggregate check.
10. Review the diff and report incomplete coverage accurately.

## Anti-Patterns

- Serializing every independent toolchain and configuration.
- Running one giant command chain where one failure prevents unrelated lanes
  from starting.
- Repeating full 277-test suites after each small test-harness correction.
- Using full CTest as the first reproduction step.
- Launching background agents without explicit ownership, build-tree isolation,
  and completion criteria.
- Allowing several workers to write into the source `Testing` directory.
- Generating shell commands with quoting or variable-expansion behavior that
  has not been validated.
- Continuing after unexpected GUI dialogs, runaway child processes, or other
  host-impacting behavior.
- Treating a build as proof that CTest executed.
- Reporting skipped or unavailable tests as passed.
- Claiming completion while a required configuration remains untested.
- Using cloud CI as an iterative development loop.
- Adding further review or validation after the user requests immediate
  commit, push, stop, or handoff.

## Stop Conditions

Stop the matrix and report immediately when any of these occurs:

- The user asks to stop or wrap up.
- Unexpected GUI prompts or file-association dialogs appear.
- A process writes generated artifacts into tracked source directories.
- A worker is operating on the wrong repository, distribution, compiler, or
  configuration.
- The elapsed time exceeds twice the agreed budget without explicit approval.
- Resource consumption prevents normal use of the machine.
- The same failure is rerun without a new hypothesis or code change.

## Incident Rule

After a material execution failure, preserve a concise local incident record:

- requested scope;
- expected and actual duration;
- resource or cost impact;
- incorrect decisions;
- completed and incomplete validation;
- corrective controls;
- repository state and any pushed commit.

The incident record is evidence for improving execution behavior, not a
substitute for fixing the repository.
