# CFL Patch Stack

Active patches can be applied to the isolated `cfl/iccDEV` checkout:

- `001-issue-2686-curve-gamma.patch`
- `002-issue-2688-colorant-table-pcs.patch`
- `003-issue-2699-mpe-buffer-channels.patch`
- `004-issue-2703-mpe-buffer-channels.patch`
- `005-issue-2704-pixel-buffer-initialization.patch`
- `006-issue-2705-apply-scratch-initialization.patch`
- `007-mpe-curve-position-bounds.patch`
- `008-unknown-tag-size-initialization.patch` - initialize empty unknown tags
  before JSON serialization reads their payload size. Regression fixture:
  `docs/Testing/test-data/fromjson-unknown-tag-empty.json`.

The build accepts a patch that is already present in the selected upstream
branch and reports it as `Already applied`. Any other patch conflict is fatal.

Build the LibFuzzer harnesses against patched upstream `master`:

```bash
./cfl/build.sh --with-patches --refresh-iccdev
```

The default remains an unpatched upstream comparison build.
