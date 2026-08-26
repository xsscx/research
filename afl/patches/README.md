# AFL Patch Stack

Active patches can be applied to the isolated `afl/iccDEV` checkout:

- `001-fromxml-channel-selector-bounds.patch` - reject malformed calculator
  channel selectors without reading past the `std::string` buffer.

Build the AFL-instrumented tools against patched upstream `master`:

```bash
./afl/build.sh --patches --refresh-iccdev
```

The default remains an unpatched upstream comparison build.
