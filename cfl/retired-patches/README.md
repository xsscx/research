# Retired CFL Patches

These patches are preserved for historical comparison but are not applied by
`cfl/build.sh --with-patches`.

- `014-tiff-strip-buffer-limit.patch`: retired at upstream `305d2d5f`
  (`Fix: Bound TIFF strip decode buffers`, #2952). The upstream implementation
  retains the caller decode-buffer budget and metadata-only behavior, adds a
  strict `ICCDEV_TIFF_MAX_DECODE_MIB` opt-in for trusted large images, and
  expands the regression coverage.
