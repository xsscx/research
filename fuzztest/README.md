# Google FuzzTest Harnesses for iccDEV

This component adds property-based, coverage-guided testing of the unpatched
upstream iccDEV libraries with Google FuzzTest. It complements the `cfl/`
LibFuzzer callbacks and `afl/` command-line lanes; it does not replace either.

The tracked component contains harness source, configuration, scripts, and a
small manifest of known-valid ICC seeds. Local upstream source checkouts,
build output, corpus databases, and findings are ignored.

## Source Layout

| Path | Purpose |
|------|---------|
| `upstream/` | Ignored Google FuzzTest checkout pinned by `versions.sh` |
| `iccDEV/` | Ignored unpatched upstream iccDEV checkout |
| `icc_profile_fuzz_test.cpp` | In-memory profile property and safety harness |
| `seeds.txt` | Curated valid profiles used by unit checks and fuzzing |
| `build.sh` | Clone, verify, configure, and build helper |
| `test.sh` | Unit checks and bounded coverage-guided runner |

## Build

Requirements are Clang/Clang++, CMake 3.19 or newer, Ninja, Git, and the
ordinary iccDEV core-library dependencies. The default build uses 32 jobs and
enables FuzzTest coverage guidance together with ASan, UBSan, integer,
float-divide-by-zero, and float-cast-overflow instrumentation. The iccDEV
archive keeps the full checker set. The harness translation unit excludes
implicit-integer-conversion and unsigned-integer-overflow checks because
FuzzTest and standard-library templates intentionally perform those operations
while generating and reporting byte-domain values. LibFuzzer compatibility
mode also excludes the nonnull-attribute checker from the harness translation
unit because FuzzTest performs a zero-length copy while decoding an empty byte
vector.

```bash
./fuzztest/build.sh
./fuzztest/build.sh --mode unit
./fuzztest/build.sh --mode libfuzzer
```

The user's initial Google FuzzTest clone belongs at `fuzztest/upstream/`.
`build.sh` creates either ignored checkout when it is absent. The FuzzTest
revision is exact-pinned; iccDEV follows upstream `master`, matching AFL and
CFL policy. Refreshes are explicit and refuse dirty source checkouts:

```bash
./fuzztest/build.sh --refresh-fuzztest --refresh-iccdev
```

Use `ICC_FUZZTEST_FRAMEWORK_DIR` or `ICC_FUZZTEST_ICCDEV_DIR` to test an
existing clean checkout without copying it.

iccDEV is configured as its own top-level CMake project, built as an
instrumented static core library, and imported by the harness project. This
preserves iccDEV's source-root and generated-version-header assumptions while
keeping the library and harness sanitizer/coverage flags aligned.

## Test and Fuzz

Run unit-mode registration and curated-seed checks:

```bash
./fuzztest/test.sh --mode unit
```

Run a bounded coverage-guided smoke test, or extend its duration:

```bash
./fuzztest/test.sh --seconds 60
./fuzztest/test.sh --seconds 3600
```

Use `--mode libfuzzer` to smoke-test the experimental compatibility build. Its
wall-clock budget is enforced by the runner because compatibility mode does not
honor FuzzTest's native `--fuzz_for` deadline.

The default property is
`IccProfileFuzzTest.ProfileOperationsDoNotCrash`. It keeps profile bytes intact
and supplies the reader mode as a separate generated argument. Unit mode opens
every curated seed with all four readers; guided mode rotates the seed modes
and mutates both typed arguments. Successful parses exercise lazy, eager,
validating, and sub-profile readers; profile and tag validation; descriptions;
PCC accessors; copy construction; and serialization to a bounded null output.

FuzzTest stores its serialized coverage inputs below the ignored
`fuzztest/corpus/` database; LibFuzzer compatibility mode uses the separate
`fuzztest/corpus-libfuzzer/` directory. Do not treat either encoding as a raw
ICC file.
Use FuzzTest's printed reproducer command first, then promote an independently
reproduced raw ICC artifact to `test-profiles/`, `fuzz/`, or `docs/pocs/` with
the exact iccDEV replay command and sanitizer evidence.

## Tracking Policy

Track harnesses, scripts, configuration, seed manifests, and deliberately
promoted regression fixtures. Keep `upstream/`, `iccDEV/`, `build*/`,
`corpus*/`, logs, generated coverage, and transient findings local.
