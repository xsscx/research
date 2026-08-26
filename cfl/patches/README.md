# CFL Patch Stack

Active patches can be applied to the isolated `cfl/iccDEV` checkout:

- `001-fromxml-channel-selector-bounds.patch` - reject malformed calculator
  channel selectors without reading past the `std::string` buffer.

Build the LibFuzzer harnesses against patched upstream `master`:

```bash
./cfl/build.sh --patches --refresh-iccdev
```

The default remains an unpatched upstream comparison build.
