# CFL Patch Stack Retired

There are no active CFL patches. Build the LibFuzzer harnesses against upstream
`master`:

```bash
./cfl/build.sh --refresh-iccdev
```

The former JPEG bounds, TIFF sample-count, and float-encoding usage patches
are now covered by upstream iccDEV. This directory is intentionally retained
as an explicit zero-patch inventory.
