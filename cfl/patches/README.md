# CFL Patch Stack

Active patches can be applied to the isolated `cfl/iccDEV` checkout:

- `001-issue-2751-calculator-copy-owner.patch` - rebind a copied calculator
  function to its new owning calculator, preventing the issue #2751 use-after-free.

The build accepts a patch that is already present in the selected upstream
branch and reports it as `Already applied`. Any other patch conflict is fatal.

Build the LibFuzzer harnesses against patched upstream `master`:

```bash
./cfl/build.sh --with-patches --refresh-iccdev
```

The default remains an unpatched upstream comparison build.
