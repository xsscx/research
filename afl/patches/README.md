# AFL Patch Stack

Active patches can be applied to the isolated `afl/iccDEV` checkout:

- `001-fromxml-channel-selector-bounds.patch` - reject malformed calculator
  channel selectors without reading past the `std::string` buffer.
- `003-single-sampled-curve-finite-position.patch` - prevent non-finite curve
  positions from reaching the float-to-unsigned sample index conversion (#2324).

Build the AFL-instrumented tools against patched upstream `master`:

```bash
./afl/build.sh --with-patches --refresh-iccdev
```

The default remains an unpatched upstream comparison build.
