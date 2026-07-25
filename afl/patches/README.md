# AFL Local Patch Stack

`./afl/build.sh --patches` applies every `*.patch` file in this directory to
the nested `afl/iccDEV` checkout before building AFL-instrumented tools.

These patches are local AFL build aids. They are used to suppress or harden
known tool-level crash classes while keeping upstream reference triage
separate. `./afl/build.sh` without `--patches` still builds the unpatched
iccDEV checkout.

Current patches:

- `001-json-config-parser-no-sanitize.patch` rejects structurally unbalanced
  JSON config inputs before dependency parsing and keeps parser inputs from
  turning dependency-internal integer sanitizer reports into AFL crashes.
- `002-jpegdump-segment-bounds.patch` uses subtraction-based JPEG segment
  bounds checks before reading marker length bytes.
- `003-applyprofiles-cam-encoding-div-zero.patch` guards malformed CAM inverse
  and encoding surround-ratio denominators found by `iccApplyProfiles` AFL
  replays.
- `004-applyprofiles-tiff-sample-count-bounds.patch` rejects malformed TIFF
  sample counts before `iccApplyProfiles` strip de-planarization can copy past
  the strip buffer.
- `005-fromxml-namedcolor-devicecoords-bounds.patch` rejects malformed
  `namedColor2Type` `CountOfDeviceCoords` values before `iccFromXml` can feed
  an overflowing `atoi()` result into `SetSize()`.

Patch failures warn and the build continues so older or newer iccDEV snapshots
can still be tested.

Before committing patch edits, run:

```bash
.github/scripts/check-afl-cfl-patches.sh
```

The checker uses fresh temporary clones of `afl/iccDEV` and `cfl/iccDEV` for
`git apply --check`, catching malformed patch hunks and patch drift without
depending on the current dirty nested checkouts.
