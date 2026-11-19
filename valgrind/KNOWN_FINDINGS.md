# Valgrind Known Findings

This catalog records reviewed, reproducible diagnostics from the local
Valgrind tool-family runner. A catalog entry is not a global suppression and
does not make a run clean. Use `--allow-findings` to retain these diagnostics
while completing the remaining targets.

Re-evaluate an entry when its signature, stack, affected source lines,
toolchain, or target behavior changes. Treat any unlisted diagnostic as a new
finding.

## Reference environment

The active classification below was revalidated on 2026-11-19 with:

- Valgrind 3.26.0
- Linux 6.18.33.2-microsoft-standard-WSL2 x86_64
- Clang 22.1.2 with libstdc++.so.6.0.35
- iccDEV `babb032e3d78`
- The separate non-sanitized Debug build produced by `valgrind/build.sh`

Reproduction commands:

```bash
./valgrind/run.sh --tool memcheck --allow-findings all
./valgrind/run.sh --tool helgrind --allow-findings connect-thread applyprofiles-row applysearch-row benchapply
./valgrind/run.sh --tool drd --allow-findings connect-thread applyprofiles-row applysearch-row benchapply
```

Memcheck completed all 13 registered targets with zero errors. Helgrind and
DRD completed all four threshold-crossing threaded targets with zero errors.
The former shallow workloads for `applyprofiles-row`, `applysearch-row`, and
`benchapply` reproduced only DRD-CV-002 before the registry was corrected to
execute worker threads.

## Retired: DRD-CV-001 notification without the associated mutex held

Status: no longer reproducible after upstream `7860726c` (#2595) moved the
thread-pool condition-variable notifications under the associated mutex.

Signature:

```text
Probably a race condition: condition variable ... has been signaled but the associated mutex ... is not locked by the signalling thread.
```

Historical target and count:

| Target | Errors | Contexts |
|---|---:|---:|
| `connect-thread` | 76 | 4 |

Historical stacks pointed to notifications in:

- `CIccApplyThreadedCmmPool::Apply()` at `IccCmmThread.cpp:168`
- `CIccApplyThreadedCmmPool::~CIccApplyThreadedCmmPool()` at
  `IccCmmThread.cpp:113`
- The `iccConnectThreadTest` synchronization barrier at
  `iccconnect-threaded-cmm.cpp:277` and `iccconnect-threaded-cmm.cpp:293`

Do not classify new diagnostics under this retired entry. The current
`connect-thread` target completes with zero DRD and Helgrind errors. Any future
notification diagnostic requires a fresh investigation.

## Retired from active targets: DRD-CV-002 destruction of an unobserved condition variable

Status: known DRD and libstdc++ instrumentation mismatch for the reviewed
stacks.

Signature:

```text
not a condition variable: cond ...
pthread_cond_destroy_intercept
CIccApplyThreadedCmmPool::~CIccApplyThreadedCmmPool()
```

Historical shallow targets and counts:

| Target | Errors | Contexts |
|---|---:|---:|
| `applyprofiles-row` | 1 | 1 |
| `applysearch-row` | 1 | 1 |
| `benchapply` | 2 | 1 |

libstdc++ can construct `std::condition_variable` from the static pthread
initializer without calling an initialization function that DRD intercepts.
When a condition variable remains unused, its later intercepted destruction
can therefore appear to DRD as destruction of an unknown object. The reviewed
stack is emitted during implicit member destruction at `IccCmmThread.cpp:99`
after the pool destructor has set the stop predicate and notified waiting
workers while holding the mutex, then joined every joinable worker thread.

The historical target commands supplied only 1 pixel, 6 records, and 4 pixels.
Each call remained below the threaded dispatch threshold, so no worker thread
observed either condition variable. Threshold-crossing replacements use four
active image workers, two active inverse-search workers, and repeated one-,
two-, and four-thread benchmark calls. Those replacements complete cleanly
under both Helgrind and DRD.

Classification boundary: only the pool-destructor signature above is known.
An `EBUSY` result, a waiter surviving destruction, a different owner type, a
different stack, or any conflicting memory access is not covered by this
entry.

## Reading run results

`--allow-findings` changes only the runner's final exit policy. It does not
suppress logs, reduce error counts, or classify diagnostics automatically.
Confirm that every nonzero entry in `summary.tsv` matches a cataloged signature
and its classification boundary. Preserve and investigate anything else.
