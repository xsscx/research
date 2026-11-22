# ICC Profile Custom Mutator

`icc_profile_mutator.cpp` is an AFL++ custom mutator for targets that consume
ordinary binary ICC profiles. It parses the profile header and tag table,
mutates headers, tag signatures, tag payloads, and tag ordering, then rebuilds
offsets, sizes, padding, and the declared profile length. It also includes a
small malformed-directory mode so parser error paths remain reachable.

The standard AFL tool build compiles the mutator automatically. Build only the
shared object with:

```bash
./afl/build-mutator.sh
```

Run it alongside AFL++'s native mutation stages (the recommended default):

```bash
./afl/start.sh pawgreport-fast --mutator icc --time 60
./afl/start.sh pawgreport --mode cmplog --mopt --mutator icc
```

Use `--mutator-only` only for attribution experiments. Leaving native stages
enabled preserves byte-level corruption and splice behavior that complements
structure-aware mutations.

The built-in `icc` selection is restricted to targets whose `@@` input is a
raw ICC profile. It is rejected for JSON, XML, Cube, TIFF, PNG, JPEG, HEIF, and
other carrier or control formats. `start.sh` also caps generated outputs at the
selected target's configured seed ceiling unless the caller already set
`AFL_MAX_LENGTH`.

For an A/B comparison, use the same initial corpus, runtime, target, AFL++
build, and worker count, but separate `AFL_BASE` directories. Compare new
edges per hour and source coverage, not only executions per second. Operation
names such as `icc-tag-crossover` and `icc-payload-boundary` appear in retained
queue filenames for campaign attribution.

The built shared object, AFL queues, logs, and campaign statistics are runtime
artifacts and must not be committed.
