---
applyTo: "fuzztest/**"
---

# Google FuzzTest Instructions

Use these instructions for the property-based, coverage-guided ICC harnesses
under `fuzztest/`.

## Source of Truth

- Framework and iccDEV revisions: `fuzztest/versions.sh`
- Build configuration: `fuzztest/CMakeLists.txt` and `fuzztest/build.sh`
- Curated valid seed list: `fuzztest/seeds.txt`
- User workflow and tracking policy: `fuzztest/README.md`

Keep Google FuzzTest and iccDEV as ignored source checkouts. Do not commit the
upstream repositories as gitlinks, submodules, or vendored source.

## Standard Commands

```bash
./fuzztest/build.sh
./fuzztest/build.sh --mode unit
./fuzztest/test.sh --mode unit
./fuzztest/test.sh --seconds 60
./fuzztest/rebuild.sh
```

Use Clang for every FuzzTest fuzzing-mode build. Keep ASan, UBSan, and coverage
instrumentation aligned across the harness and iccDEV library; do not link an
instrumented harness to an uninstrumented iccDEV archive. Keep full integer
instrumentation in iccDEV even when documented FuzzTest template operations
require narrower harness-only exclusions.

## Harness Contracts

- Fuzz raw ICC bytes without adding, removing, or truncating bytes for harness
  controls. Generate reader modes and other controls as separate typed domain
  arguments.
- Curated seeds must be ordinary valid ICC files already tracked elsewhere in
  the repository. Do not add known crash artifacts to the default smoke list.
- Keep explicit input-size and RSS/time limits because FuzzTest's generated
  containers otherwise have no useful campaign ceiling.
- Every active C/C++ harness source requires the complete license block.
- A safety property may ignore ordinary parse rejection, but sanitizer exits,
  assertions, timeouts, and property failures are findings.
- FuzzTest corpus-database files encode typed domain values. Do not pass them
  directly to iccDEV tools or promote them as raw `.icc` fixtures.

## Tracking Policy

Track harness source, scripts, CMake configuration, version pins, seed
manifests, and documented regression fixtures. Do not commit `upstream/`,
`iccDEV/`, `build*/`, `corpus*/`, findings, logs, or coverage output.
