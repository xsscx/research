# iccanalyzer-lite Resource-Bomb Quarantine Policy

## Scope

Routine local and CI profile sampling must not randomly select known OOM/timeout/stack-exhaustion seeds from `test-profiles/` and `extended-test-profiles/`.

Those files are still valuable, but they belong in dedicated resource-exhaustion verification paths rather than broad sanitizer or smoke loops.

## Why

A recent WSL2 failure killed `iccanalyzer-lite` after it expanded to roughly:

- `total-vm: 21488284876kB`
- `anon-rss: 5669632kB`

That host-level OOM event corrupted journald state, broke the 9P bridge, and destabilized the session before the active profile could be recovered cleanly.

## Repo Mechanism

Routine sampling now uses:

- Quarantine list: `iccanalyzer-lite/tests/profile-resource-quarantine.txt`
- Workflow helper: `.github/scripts/icc-profile-quarantine.sh`

The quarantine list excludes obvious resource-bomb families such as:

- `oom-*`
- `seed_oom-*`
- `timeout-*`
- `*stack-overflow*`
- `*stackoverflow*`
- `test-profiles/cwe-400/*`

## Policy

Use the quarantine list by default for:

- local `run_tests.py` repo-profile sampling
- routine profile-selection workflows
- broad CLI smoke / coverage loops

Do **not** use the quarantine list for:

- dedicated CWE-400 / timeout verification
- targeted single-profile reproductions
- explicit resource-exhaustion regression work

Prefer a cgroup wrapper or dedicated resource-test workflow for those targeted runs. Avoid relying on `ulimit -v` in the routine ASan path because AddressSanitizer reserves large virtual address ranges and can false-fail under tight RLIMIT_AS caps.

## Breadcrumb Requirement

Profile-loop workflows should write the current profile path to a small text file before each run. If the host still dies, the last written breadcrumb narrows the culprit immediately.

Current workflow breadcrumbs:

- `results/current-profile.txt`
- `profile-test-results/current-profile.txt`
- `cli-test-results/current-profile.txt`
- `coverage-report/current-profile.txt`

## Local Override

To include quarantined files on purpose during a targeted local investigation:

```bash
ICCANALYZER_INCLUDE_QUARANTINED=1 python3 iccanalyzer-lite/tests/run_tests.py -k "Repo Profile Sample"
```

Use that only when the host is already constrained or the run is scoped to a small, known set of files.
