# AFL Local Patch Stack

`./afl/build.sh --patches` applies every `*.patch` file in this directory to
the nested `afl/iccDEV` checkout before building AFL-instrumented tools.

These patches are local AFL build aids. They are used to suppress or harden
known tool-level crash classes while keeping upstream reference triage
separate. `./afl/build.sh` without `--patches` still builds the unpatched
iccDEV checkout.

Current patches:

- `002-jpegdump-segment-bounds.patch` uses subtraction-based JPEG segment
  bounds checks before reading marker length bytes.
- `004-applyprofiles-tiff-sample-count-bounds.patch` rejects malformed TIFF
  sample counts before `iccApplyProfiles` strip de-planarization can copy past
  the strip buffer.
- `005-applyprofiles-float-encoding-usage.patch` corrects the
  `iccApplyProfiles` usage text to identify positional encoding `3`, rather
  than unsupported value `4`, as `icEncodeFloat`.

The former `005-fromxml-formula-functiontype-bounds.patch` is no longer in the
AFL stack because upstream commit `1065ec1` includes the complete strict-width
formula-segment attribute parsing fix. The CFL stack retired its duplicate for
the same reason.

Patch failures warn and the build continues so older or newer iccDEV snapshots
can still be tested.

Before committing patch edits, run:

```bash
.github/scripts/check-afl-cfl-patches.sh
```

The checker uses fresh temporary clones of `afl/iccDEV` and `cfl/iccDEV` for
`git apply --check`, catching malformed patch hunks and patch drift without
depending on the current dirty nested checkouts.
