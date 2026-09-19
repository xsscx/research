# Valgrind Known Findings

This catalog records reviewed, reproducible diagnostics from the local
Valgrind tool-family runner. A catalog entry is not a global suppression and
does not make a run clean. Use `--allow-findings` to retain these diagnostics
while completing the remaining targets.

Re-evaluate an entry when its signature, stack, affected source lines,
toolchain, or target behavior changes. Treat any unlisted diagnostic as a new
finding.

## Reference environment

The initial classifications below were reproduced on 2026-09-18 with:

- Valgrind 3.26.0
- Linux 6.18.33.2-microsoft-standard-WSL2 x86_64
- Clang 18 with libstdc++.so.6.0.35
- The separate non-sanitized Debug build produced by `valgrind/build.sh`

Reproduction command:

```bash
./valgrind/run.sh --tool drd --allow-findings all
```

The reference run completed all 13 registered targets. Nine were clean. The
four targets listed below produced only the two cataloged DRD signatures.

## DRD-CV-001: notification without the associated mutex held

Status: known DRD limitation for the reviewed stacks.

Signature:

```text
Probably a race condition: condition variable ... has been signaled but the associated mutex ... is not locked by the signalling thread.
```

Observed target and count:

| Target | Errors | Contexts |
|---|---:|---:|
| `connect-thread` | 76 | 4 |

Reviewed stacks point to notifications in:

- `CIccApplyThreadedCmmPool::Apply()` at `IccCmmThread.cpp:168`
- `CIccApplyThreadedCmmPool::~CIccApplyThreadedCmmPool()` at
  `IccCmmThread.cpp:113`
- The `iccConnectThreadTest` synchronization barrier at
  `iccconnect-threaded-cmm.cpp:277` and `iccconnect-threaded-cmm.cpp:293`

In each reviewed path, the predicate is changed while its mutex is held and
the condition variable is notified after unlocking. C++ permits notification
without holding the associated mutex. The predicate-based waits prevent a
lost notification. The same `connect-thread` target completed with zero
Helgrind errors in the reference runs.

Classification boundary: only the exact notification stacks above are known.
A conflicting load/store report, a different condition variable, an unlocked
predicate update, a hang, or a changed stack is not covered by this entry.

## DRD-CV-002: destruction of an unobserved condition variable

Status: known DRD and libstdc++ instrumentation mismatch for the reviewed
stacks.

Signature:

```text
not a condition variable: cond ...
pthread_cond_destroy_intercept
CIccApplyThreadedCmmPool::~CIccApplyThreadedCmmPool()
```

Observed targets and counts:

| Target | Errors | Contexts |
|---|---:|---:|
| `applyprofiles-row` | 1 | 1 |
| `applysearch-row` | 1 | 1 |
| `benchapply` | 2 | 1 |

libstdc++ can construct `std::condition_variable` from the static pthread
initializer without calling an initialization function that DRD intercepts.
When a condition variable remains unused, its later intercepted destruction
can therefore appear to DRD as destruction of an unknown object. The reviewed
stack is emitted during implicit member destruction after the pool destructor
body has set the stop predicate, notified waiting workers, and joined every
joinable worker thread.

Classification boundary: only the pool-destructor signature above is known.
An `EBUSY` result, a waiter surviving destruction, a different owner type, a
different stack, or any conflicting memory access is not covered by this
entry.

## Reading run results

`--allow-findings` changes only the runner's final exit policy. It does not
suppress logs, reduce error counts, or classify diagnostics automatically.
Confirm that every nonzero entry in `summary.tsv` matches a cataloged signature
and its classification boundary. Preserve and investigate anything else.
