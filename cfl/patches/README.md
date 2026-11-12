# CFL Optional Patch Stack

The default CFL build uses unpatched upstream `master`. For explicit comparison
runs, `--with-patches` applies every `.patch` file present in this directory to
the isolated `cfl/iccDEV` checkout. The repository-tracked inventory is:

- `001-spectral-clut-apply-context.patch`: allocates spectral CLUT apply
  scratch from the initialized apply table, avoiding poisoned copy-state sizes
  in NamedCMM profile copies.
- `002-embedded-subprofile-attach-leak.patch`: preserves caller ownership of
  parent IO on embedded-profile attach failures and releases wrappers when
  nested header parsing fails.
- `003-pawg-calculator-cost-estimate.patch`: adds a selector-width-aware,
  saturating iccMAX calculator cost estimate and uses it for PAWG S10.
- `004-pawg-calculator-quality-budget.patch`: bounds PAWG Q1 Cartesian grids
  to 100,000 samples and rejects Q1 or Q3 before repeated calculator evaluation
  would exceed the quality-metric work budget.
- `005-pawg-report-detail-bounds.patch`: makes shared tag-region validation
  linear and bounds repeated private/compression detail examples while retaining
  exact counts. The linear layout check also covers `icc_proflib_fuzzer` slow
  unit `f9cdb738397ae9c4664ba62ed6969b7573ed772c`.
- `008-profile-tag-count-bound.patch`: rejects binary profiles with more than
  1,000 tag-directory entries before attacker-controlled counts can multiply
  profile parsing, validation, and shared-tag association work.
- `009-bpc-pcs-space-guard.patch`: rejects black-point compensation for a
  non-XYZ/Lab PCS before a profile transform can write more than three channels
  through BPC's three-float black-point buffer.
- `010-roundtrip-calculator-work-budget.patch`: combines the round-trip sample
  count with selector-width-aware calculator cost before evaluating the grid.
  The temporary 250,000,000-unit ceiling is for the next AFL/CFL comparison
  cycle and is not final upstream policy.
- `011-binary-element-allocation-bounds.patch`: rejects curve-set child ranges
  outside their enclosing binary element and refuses a header-only CLUT before
  zero payload bytes can select the unbounded programmatic-allocation path.
- `012-profile-tag-io-extent-bounds.patch`: validates deferred raw-tag extents
  against the attached profile before `GetTagIO()` allocates or seeks, while
  retaining valid raw-tag access for API consumers.
- `013-profilevisualize-descriptor-render.patch`: adds descriptor-based graph
  and raster render overloads so callers that already enumerated a profile do
  not repeat descriptor discovery and CLUT probes for every output; existing
  string-ID calls remain compatible.
- `015-prmg-fuzzer-granularity.patch`: preserves the production PRMG 101-point
  grid while exposing a source-compatible bounded-grid overload so patched CFL
  can cover the same paths without a million samples per valid input.
- `016-serialized-clut-allocation-bounds.patch`: keeps serialized spectral,
  float32 MPE, Lut8, and Lut16 CLUT allocations within their encoded payloads,
  prevents zero remaining bytes from selecting `CIccCLUT::Init()`'s unbounded
  programmatic mode, and enforces the payload bound for one-dimensional CLUTs.

The build accepts a patch that is already present in the selected upstream
branch and reports it as `Already applied`. Any other patch conflict is fatal.
Patches 003 and 010 are byte-identical to their `afl/patches/` counterparts
and must remain synchronized for comparison cycles.
Patch `001` is already present on current upstream `master`. It remains in the
stack so older comparison refs receive the same fix and current refs exercise
the `Already applied` compatibility path. Patches `006` and `007` were removed
from the active stack after upstream incorporated their fixes. Patch `014` was
retired after its TIFF strip decode-buffer guard and regression coverage merged
upstream in `305d2d5f` (#2952).

## Campaign and upstream scope

The optional stack changes the isolated iccDEV source used by CFL; it is not a
harness-only mode. Classify each result before proposing the same change to
upstream maintainers:

- A slowdown that is material only under `-O0`, sanitizers, and coverage is a
  campaign-throughput finding. Keep its work bound local unless a clean Release
  build also shows unacceptable cost.
- PAWG sample and calculator budgets (`003`, `004`) change whether a
  quality check runs. An upstream proposal therefore needs an agreed reporting
  policy and accuracy threshold, not just a faster fuzz replay.
- The tag-count bound (`008`) changes the core reader and can reject profiles
  that the specification can encode. Audit real corpus tag counts and document
  compatibility before proposing that limit upstream.
- Memory-ownership, bounds-safety, or overflow fixes such as `001`, `002`,
  `009`, `011`, `012`, and `016` are product correctness or security candidates
  when independently reproduced outside the fuzzer or through the affected
  public API. Treat their upstream status separately from campaign throughput.
- The descriptor-render overload in `013` is an additive API and tooling
  efficiency candidate. Compare the unpatched and patched Release tool as well
  as the instrumented harness before assigning severity to a slow unit.
- The PRMG overload in `015` is campaign-throughput support. Production callers
  retain the historical 101-point default; only patched CFL selects 17 points.

Record the unpatched Release control, patched sanitizer replay, patch inventory,
and any compatibility analysis in a dated report. Do not describe an
instrumentation-only slow unit as a production denial of service.

The 2026-10-31 multi-VM slow-unit A/B is recorded in
[`docs/analysis/cfl-slow-unit-qa-20261031.md`](../../docs/analysis/cfl-slow-unit-qa-20261031.md).
The October 31 OOM replay, allocation-bound fixes, and sanitizer build matrix
are recorded in
[`docs/analysis/cfl-oom-artifact-qa-20261031.md`](../../docs/analysis/cfl-oom-artifact-qa-20261031.md).
The follow-up ProfileVisualize, TIFF strip-allocation, and round-trip findings
are recorded in
[`docs/analysis/cfl-profilevisualize-slow-unit-qa-20261031.md`](../../docs/analysis/cfl-profilevisualize-slow-unit-qa-20261031.md),
[`docs/analysis/cfl-tiff-strip-oom-qa-20261031.md`](../../docs/analysis/cfl-tiff-strip-oom-qa-20261031.md),
and
[`docs/analysis/cfl-roundtrip-slow-unit-qa-20261031.md`](../../docs/analysis/cfl-roundtrip-slow-unit-qa-20261031.md).
The November 11 ToXML spectral-CLUT allocation finding and patch 016 validation
are recorded in
[`docs/analysis/cfl-toxml-spectral-clut-oom-qa-20261111.md`](../../docs/analysis/cfl-toxml-spectral-clut-oom-qa-20261111.md).

Build the LibFuzzer harnesses against patched upstream `master`:

```bash
./cfl/build.sh --with-patches --refresh-iccdev
```

Record `--with-patches` and the applied patch names with findings produced by
this mode. Omitting the option preserves the unpatched comparison baseline.
