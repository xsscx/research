# AFL Patch Stack

Active patches can be applied to the isolated `afl/iccDEV` checkout:

- `001-issue-2686-curve-gamma.patch`
- `002-issue-2688-colorant-table-pcs.patch`
- `003-issue-2699-mpe-buffer-channels.patch`
- `004-issue-2703-mpe-buffer-channels.patch`
- `005-issue-2704-pixel-buffer-initialization.patch`
- `006-issue-2705-apply-scratch-initialization.patch`
- `007-mpe-curve-position-bounds.patch`

The build accepts a patch that is already present in the selected upstream
branch and reports it as `Already applied`. Any other patch conflict is fatal.

Build the AFL-instrumented tools against the patched QA branch:

```bash
./afl/build.sh --with-patches --branch ci-qa-pr-docker-testing --refresh-iccdev
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
