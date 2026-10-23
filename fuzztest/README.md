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
| `seeds.txt` | Curated valid-profile catalog used by checks and seed providers |
| `build.sh` | Clone, verify, configure, and build helper |
| `test.sh` | Unit checks and bounded coverage-guided runner |
| `minimize-corpus.sh` | Non-destructive native corpus minimizer |

## Build

Requirements are Clang/Clang++, CMake 3.19 or newer, Ninja, Git, and the
ordinary iccDEV core-library dependencies. The default build uses 32 jobs and
enables FuzzTest coverage guidance together with ASan, UBSan, integer,
float-divide-by-zero, and float-cast-overflow instrumentation. The iccDEV
archive keeps the full checker set. The harness translation unit excludes
implicit-integer-conversion and unsigned-integer-overflow checks because
FuzzTest and standard-library templates intentionally perform those operations
while generating and reporting byte-domain values. Native fuzzing and
LibFuzzer compatibility modes also exclude the nonnull-attribute checker from
the harness translation unit because FuzzTest performs a zero-length copy while
decoding an empty byte vector.

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

The runner discovers every registered fuzz target, splits the requested total
CPU-time budget across them, and runs independent targets concurrently. Limit
parallelism with `--jobs N` or `ICC_FUZZTEST_RUN_JOBS`. Isolate one property
when reproducing or extending a campaign:

```bash
./fuzztest/test.sh --seconds 60 \
  --target IccProfileFuzzTest.ProfileSerializationDoesNotCrash
```

Each run writes ignored per-target logs, revision metadata, and a tab-separated
summary below `fuzztest/logs/`. Override the destination with `--log-dir DIR`
or `ICC_FUZZTEST_LOG_DIR`.

Use `--mode libfuzzer` to smoke-test the experimental compatibility build. Its
wall-clock budget is enforced by the runner because compatibility mode does not
honor FuzzTest's native `--fuzz_for` deadline. Compatibility corpora are kept
in target-specific directories because each property has a different typed
input encoding. The runner passes engine flags after FuzzTest's argument
separator so compatibility mode can reach the same 4 MiB profile domain.

The registered properties are:

| Target | Coverage |
|------|------|
| `IccProfileFuzzTest.ProfileOperationsDoNotCrash` | Lazy, eager, validating, and sub-profile readers with a typed selector for validation, tag inspection, PCC accessors, or copy/write operations |
| `IccProfileFuzzTest.ProfileSerializationDoesNotCrash` | All profile-ID save methods, bounded memory serialization, reparse through a different reader, and operations on the reparsed profile |
| `IccProfileFuzzTest.ProfileTagLookupDoesNotCrash` | Generated tag and type signatures across mutable/const lookup, typed lookup, tag I/O, description, and validation paths |

Every property keeps the raw profile bytes intact and supplies parser modes,
operation selectors, save methods, and signatures as separate typed arguments.
The compact fuzz seed set spans every reader and operation selector globally;
unit checks cover every curated profile with every reader and save method, plus
all readable tag/type pairs and negative lookup cases. Profile processing
has a 4 MiB hard limit, while generated byte vectors use a 64 KiB soft maximum
to bound retained corpus and comparison-dictionary memory. Larger curated and
replayed profiles remain valid domain inputs and are only shrunk during
mutation. Serializer output is capped at 16 MiB before allocation. RSS, stack,
per-input, and wall-clock limits remain explicit so malformed size fields
cannot turn a smoke run into an unbounded resource-consumption test.
Unit mode opens every curated seed with all four readers, checks each save
method by serializing and reparsing, and verifies that curated tag-lookup seeds
reach a real tag.

FuzzTest stores its serialized coverage inputs below the ignored
`fuzztest/corpus/` database; LibFuzzer compatibility mode uses the separate
`fuzztest/corpus-libfuzzer/` directory. Do not treat either encoding as a raw
ICC file. Each target uses its own subdirectory because the properties have
different typed input encodings. Override the corpus root with
`ICC_FUZZTEST_CORPUS_DIR` when a campaign uses scratch storage. Native runs
write coverage entries to FuzzTest's canonical
`<binary>/<suite.test>/coverage/` database layout. Bounded native campaigns
restore that target-specific corpus through FuzzTest's bounded Centipede input
path and write newly discovered entries back to the full target directory. To
keep startup proportional to the campaign, the runner samples one persisted
input per ten target-seconds, capped at 64 inputs. Override the cap with
`--replay-inputs N` or `ICC_FUZZTEST_REPLAY_INPUTS`; zero disables replay. The
selected hashes are recorded with the run logs. The runner intentionally leaves
`--corpus_database` empty because the pinned native runtime applies `--fuzz_for`
only after database replay, allowing a large corpus to exceed the wall-clock
envelope.

Periodically distill accumulated native entries into a separate corpus tree:

```bash
./fuzztest/minimize-corpus.sh --seconds 900
```

The minimizer runs targets concurrently, verifies that every output is
non-empty and no larger than its source, and never modifies the source corpus.
Inspect its summary before replacing a corpus. Use `--source`, `--output`, and
`--target` for controlled maintenance or scratch-storage campaigns.

Crash reproducers are written below the ignored `fuzztest/findings/` directory.
Override that root with `ICC_FUZZTEST_REPRODUCERS_DIR`. Native FuzzTest findings
use its typed reproducer encoding; LibFuzzer compatibility findings use the
compatibility input encoding.
Use FuzzTest's printed reproducer command first, then promote an independently
reproduced raw ICC artifact to `test-profiles/`, `fuzz/`, or `docs/pocs/` with
the exact iccDEV replay command and sanitizer evidence.

## Tracking Policy

Track harnesses, scripts, configuration, seed manifests, and deliberately
promoted regression fixtures. Keep `upstream/`, `iccDEV/`, `build*/`,
`corpus*/`, logs, generated coverage, and transient findings local.
