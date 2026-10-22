# CFL Patch Stack

Active patches can be applied to the isolated `cfl/iccDEV` checkout:

| Patch | Purpose |
| --- | --- |
| `001-spectral-clut-apply-context.patch` | Allocate spectral CLUT apply scratch from the initialized apply table, avoiding poisoned copy-state sizes in NamedCMM profile copies. |

The build accepts a patch that is already present in the selected upstream
branch and reports it as `Already applied`. Any other patch conflict is fatal.

Build the LibFuzzer harnesses against patched upstream `master`:

```bash
./cfl/build.sh --with-patches --refresh-iccdev
```

The default remains an unpatched upstream comparison build.
