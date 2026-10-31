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
- `006-pawg-private-tag-scan-bounds.patch`: merges overlapping in-bounds private
  tag regions before the PAWG S12 and S13 byte scans, so malformed tag tables
  cannot multiply scan work by repeatedly naming the same profile bytes.
- `007-pawg-q3-ndlut-budget.patch`: bounds PAWG Q3 n-D LUT interpolation work
  before sampling the neutral path and every device axis, preventing 14- and
  15-channel legacy LUT profiles from multiplying work through `2^N` corner
  visits per sample.
- `008-profile-tag-count-bound.patch`: rejects binary profiles with more than
  1,000 tag-directory entries before attacker-controlled counts can multiply
  profile parsing, validation, and shared-tag association work.
- `009-bpc-pcs-space-guard.patch`: rejects black-point compensation for a
  non-XYZ/Lab PCS before a profile transform can write more than three channels
  through BPC's three-float black-point buffer.
- `010-roundtrip-calculator-work-budget.patch`: combines the round-trip sample
  count with selector-width-aware calculator cost before evaluating the grid,
  preventing wide stack operations from multiplying into billions of work units.

The build accepts a patch that is already present in the selected upstream
branch and reports it as `Already applied`. Any other patch conflict is fatal.
At upstream `b6ce0cf`, patches `001` and `007` are already present. They remain
in the stack so older comparison refs receive the same fixes and current refs
exercise the `Already applied` compatibility path.

## Campaign and upstream scope

The optional stack changes the isolated iccDEV source used by CFL; it is not a
harness-only mode. Classify each result before proposing the same change to
upstream maintainers:

- A slowdown that is material only under `-O0`, sanitizers, and coverage is a
  campaign-throughput finding. Keep its work bound local unless a clean Release
  build also shows unacceptable cost.
- PAWG sample and calculator budgets (`003`, `004`, `007`) change whether a
  quality check runs. An upstream proposal therefore needs an agreed reporting
  policy and accuracy threshold, not just a faster fuzz replay.
- The tag-count bound (`008`) changes the core reader and can reject profiles
  that the specification can encode. Audit real corpus tag counts and document
  compatibility before proposing that limit upstream.
- Memory-ownership, bounds-safety, or overflow fixes such as `001`, `002`, and
  `009` are product correctness or security candidates when independently
  reproduced outside the fuzzer. Treat their upstream status separately from
  campaign throughput.

Record the unpatched Release control, patched sanitizer replay, patch inventory,
and any compatibility analysis in a dated report. Do not describe an
instrumentation-only slow unit as a production denial of service.

The 2026-10-31 multi-VM slow-unit A/B is recorded in
[`docs/analysis/cfl-slow-unit-qa-20261031.md`](../../docs/analysis/cfl-slow-unit-qa-20261031.md).

Build the LibFuzzer harnesses against patched upstream `master`:

```bash
./cfl/build.sh --with-patches --refresh-iccdev
```

Record `--with-patches` and the applied patch names with findings produced by
this mode. Omitting the option preserves the unpatched comparison baseline.
