# CFL Optional Patch Stack

The default CFL build uses unpatched upstream `master`. For explicit comparison
runs, `--with-patches` applies every `.patch` file present in this directory to
the isolated `cfl/iccDEV` checkout. The repository-tracked inventory is:

- `001-spectral-clut-apply-context.patch`: allocates spectral CLUT apply
  scratch from the initialized apply table, avoiding poisoned copy-state sizes
  in NamedCMM profile copies.
- `002-embedded-subprofile-attach-leak.patch`: preserves caller ownership of
  parent IO on embedded-profile attach failures and releases wrappers when
  nested header parsing fails.

The build accepts a patch that is already present in the selected upstream
branch and reports it as `Already applied`. Any other patch conflict is fatal.

Build the LibFuzzer harnesses against patched upstream `master`:

```bash
./cfl/build.sh --with-patches --refresh-iccdev
```

Record `--with-patches` and the applied patch names with findings produced by
this mode. Omitting the option preserves the unpatched comparison baseline.
