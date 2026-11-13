# AFL Patch Stack

Temporary comparison patches can be applied to the isolated `afl/iccDEV`
checkout:

- `003-pawg-calculator-cost-estimate.patch`: adds the selector-width-aware,
  saturating calculator work estimate used by PAWG S10 and patch 010.
- `010-roundtrip-calculator-work-budget.patch`: rejects a round-trip before its
  sample grid when estimated calculator work exceeds the temporary
  100,000,000-unit comparison ceiling.
- `018-pcc-illuminant-fallback-initialization.patch`: initializes normalized
  and luminance illuminant outputs from the profile header when a malformed
  spectral viewing condition has no readable illuminant, preventing the named
  hybrid chain from consuming uninitialized connection-condition values.

These patches are for the next AFL/CFL comparison cycle. The ceiling is based
on current slow-unit and compatibility controls; it is not final upstream
policy. Patches 003, 010, and 018 are byte-identical to their `cfl/patches/`
counterparts and must remain synchronized.

The November 12 selector-width slow-unit follow-up and budget validation are
recorded in
[`docs/analysis/cfl-roundtrip-calculator-budget-qa-20261112.md`](../../docs/analysis/cfl-roundtrip-calculator-budget-qa-20261112.md).
The November 12 NamedCMM hybrid-chain MSan reproduction and patch 018
validation are recorded in
[`docs/analysis/afl-namedcmm-hybrid-chain-msan-qa-20261112.md`](../../docs/analysis/afl-namedcmm-hybrid-chain-msan-qa-20261112.md).

The build accepts a patch that is already present in the selected upstream
branch and reports it as `Already applied`. Any other patch conflict is fatal.

Build the AFL-instrumented tools against patched upstream `master`:

```bash
./afl/build.sh --with-patches --branch master --refresh-iccdev
```

The default remains an unpatched upstream comparison build.

For independent, symbolized MSan confirmation against the same patched source,
build outside the source checkout and then point triage at that build:

```bash
ICCDEV_MSAN_SOURCE_DIR="$PWD/afl/iccDEV" \
ICCDEV_MSAN_BUILD_DIR="$HOME/qa/iccDEV-patched-msan-build" \
./afl/build-iccdev-msan.sh --skip-dependencies --allow-patched-source
ICCDEV_MSAN_BUILD_DIR="$HOME/qa/iccDEV-patched-msan-build" \
./afl/triage.sh --sanitizer memory TARGET
```
