# AFL third-party dependencies

`build.sh` fetches pinned current releases of iccDEV's non-wxWidgets
dependencies and installs static libraries under `install/`. The sources,
build trees, and install prefix are local generated state and are ignored by
Git.

The parent `afl/build.sh` runs this build with the selected AFL compiler
wrappers. Every compiled dependency uses AddressSanitizer, UndefinedBehavior
Sanitizer, IntegerSanitizer, float-divide-by-zero, and float-cast-overflow.
nlohmann-json is header-only and receives the same AFL and sanitizer flags when
iccDEV compiles it.

The libjpeg-turbo build disables hand-written SIMD assembly so JPEG processing
stays in compiler-instrumented C code. This also means NASM is not required for
the AFL build.

libheif is pinned and linked statically so ISO BMFF parsing contributes AFL
feedback. Codec backends, plugin loading, and optional compression libraries
are disabled because the HEIF lanes target carrier and ICC-property parsing,
not pixel decoding. The local empty-vector patch guards a zero-length write
that otherwise raises a deterministic `nonnull-attribute` UBSan finding on the
upstream `empty-prof.heic` QA carrier before fuzzing can begin. A matching
zero-length memory-reader guard prevents the same diagnostic when malformed
carriers request an empty libheif read. Both guards leave non-empty reads and
writes unchanged.

Run a clean dependency rebuild directly with:

```bash
./afl/third_party/build.sh --clean
```

Release tags and verified commits are recorded in `versions.sh`.
