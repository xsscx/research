# iccAnalyzer-lite / IccTest Instrumented Build and Artifact Policy

## Summary

V1 (`iccanalyzer-lite`) and V2 (`icctest`) developer-facing binaries are expected
to come from the same **Debug + ASAN + UBSAN + Clang coverage** build path used
for local validation and CI. Do **not** introduce a separate Release-only
packaging path for command-line testing or GitHub Release assets.

## Why

- Parity work is validated against instrumented builds, not a second
  uninstrumented configuration.
- The V2 parity and PAWG paths are exercised in the existing Debug workflow
  lane, so shipping those same binaries keeps developer testing aligned with CI.
- Clean-room Release rebuilds add avoidable drift in compiler flags, linker
  behavior, and runtime expectations.

## Required Runtime Environment

For harnessed V2 test execution, keep these environment rules:

```bash
ASAN_OPTIONS=detect_leaks=0
LLVM_PROFILE_FILE=/dev/null
```

LeakSanitizer can abort under harness / ptrace-like execution even when the
suite itself passes. Disable leak detection unless the run is explicitly
collecting leak data.

## GitHub Release / Artifact Expectations

When shipping V2 binaries for developers to test on the command line, the
bundle should include:

- `icctest`
- `icctest-parity`
- `README.md`
- `heuristic-remap.tsv`
- `verify-parity-summary.json`

The current GitHub Release workflow packages instrumented tarballs:

- `iccanalyzer-lite-linux-amd64-instrumented.tar.gz`
- `icctest-linux-amd64-instrumented.tar.gz`

## Workflow Coverage

Any workflow that already builds V2 should either upload or smoke `icctest`:

- `.github/workflows/iccanalyzer-cli-release.yml`
- `.github/workflows/iccanalyzer-lite-unit-tests.yml`
- `.github/workflows/iccanalyzer-lite-debug-sanitizer-coverage.yml`
- `.github/workflows/mcp-server-test.yml`
- `.github/workflows/mcp-server-docker.yml`
- `.github/workflows/copilot-setup-steps.yml`

## Maintenance Rule

If a future workflow packages or extracts command-line analyzers, add V2 in the
same pass rather than treating it as optional. V1/V2 command-line testing should
stay symmetrical wherever practical.
