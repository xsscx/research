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

Patch failures warn and the build continues so older or newer iccDEV snapshots
can still be tested.
