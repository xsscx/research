# iccDEV CLI and Fuzzer Alignment - 2026-09-02

## Reviewed upstream range

The previous AFL argv centralization was committed while upstream iccDEV was at
`f8c48f1b`. Both the reference checkout and `cfl/iccDEV` now resolve to
`bbb123cf`. The reviewed range was therefore `f8c48f1b..bbb123cf`.

The CLI-relevant changes in that range are:

- `9c5fdbc6` (#2356) documents that transform codes 50 through 83 carry an
  intent digit for BRDF parameter, BRDF direct, BRDF MCS parameter, and MCS
  transforms in iccApplyNamedCmm, iccApplyProfiles, and iccApplyToLink.
- `42e9a1fa` (#2357) makes iccBenchApply honor the BPC tens column and the
  luminance hundreds column, matching iccApplyToLink's decoder.
- `bbb123cf` (#2358) hardens ACS description and allocation consistency. It
  changes profile-library behavior but does not change tool argv.

The other commits in the range change organization text, V5 curve-set output,
or CMM initialization and require no AFL/CFL configuration change.

## Consumer alignment

| Producer | Consumer | Alignment | Evidence |
|---|---|---|---|
| iccBenchApply intent decoder | AFL `benchapply` | Fuzz one profile with code 140, exercising BPC and luminance together | AFL target contract and seed dry run |
| iccBenchApply executable | AFL triage | Resolve canonical binary through `IccBenchApply/iccBenchApply` | Triage mapping contract |
| ApplyProfiles transform config | CFL `icc_applyprofiles_fuzzer` | Use the existing option byte's bits 3 through 5 to select color, named, preview, gamut, BRDF, or MCS families | CFL build and bounded replay |
| ApplyNamedCmm transform config | CFL `icc_applynamedcmm_fuzzer` | No change: it already iterates `icXformLutMinimum..icXformLutMaximum` | Source inspection and existing contract test |
| ApplyToLink intent decoder | CFL `icc_link_fuzzer` | No change: it already selects all documented BRDF/MCS types and independently controls BPC and luminance hints | Source inspection |

The new AFL target keeps exactly one `@@` profile argument, so existing profile
corpora remain compatible. Other running targets do not need to be restarted.
