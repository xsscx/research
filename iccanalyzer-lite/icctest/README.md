# IccTest (V2 Rewrite)

`icctest/` is the V2 rewrite of `iccAnalyzer-lite`.

## Build

From the repository root:

```bash
cmake -S icctest -B icctest/build
cmake --build icctest/build -j"$(nproc)"
```

Parity verification expects the V1 binary to exist at `./iccanalyzer-lite` by
default. To override that path during configure time:

```bash
cmake -S icctest -B icctest/build \
  -DICCTEST_V1_BINARY=/absolute/path/to/iccanalyzer-lite
```

## Test

Unit tests and registered CTest targets:

```bash
ctest --test-dir icctest/build --output-on-failure
```

Registered tests:

- `icctest_unit_tests`
- `icctest_verify_parity`
- `icctest_generated_image_smoke`

## Parity Verification

The parity harness compares V1 and V2 on the in-repo corpus.

One-shot verifier:

```bash
python3 icctest/tools/verifyParity.py \
  --unit-binary icctest/build/lib/tests/icctest_unit_tests \
  --v2-binary icctest/build/tools/icctest-parity \
  --heuristic-remap icctest/tools/heuristic-remap.tsv \
  --output-dir /tmp/icctest-parity-verify \
  --pretty
```

CMake target:

```bash
cmake --build icctest/build --target icctest-verify-parity
```

Build-target artifacts are written to:

- `icctest/build/parity-artifacts/verify-parity-summary.json`
- `icctest/build/parity-artifacts/raw-parity.json`
- `icctest/build/parity-artifacts/image-parity.json`
- `icctest/build/parity-artifacts/generated-image-smoke.json`
- `icctest/build/parity-artifacts/unit-tests.log`

## Current Baseline

On the current corpus and generated image smoke:

- raw ICC parity: `delta = 0`
- image outer parity: `delta = 0`
- embedded raw parity: `delta = 0`
- generated PNG/JPEG embedded-ICC smoke: pass
- unit tests: `406/406 passed`

## CI Notes

- The V1 parity adapters auto-resolve shared libraries from both supported
  layouts: `iccanalyzer-lite/iccDEV/Build/...` and repo-root `iccDEV/Build/...`.
  Current GitHub workflows use both.
- `icctest/tools/smokeGeneratedImageFormats.py` is intentionally standard-library
  only. If CI reports `ModuleNotFoundError: No module named 'PIL'`, the runner
  is executing an older checkout.
- The fastest environment-level parity repro commands are:

```bash
env -u LD_LIBRARY_PATH \
  cmake --build icctest/build --target icctest-verify-parity

env -u LD_LIBRARY_PATH \
  python3 -S icctest/tools/smokeGeneratedImageFormats.py \
    --v1-binary ../iccanalyzer-lite \
    --v2-binary build/tools/icctest-parity \
    --heuristic-remap tools/heuristic-remap.tsv
```

## Notes

- The heuristic remap used for collision and TODO quarantine lives in `icctest/tools/heuristic-remap.tsv`.
- CTest and the verifier disable LeakSanitizer leak detection with `ASAN_OPTIONS=detect_leaks=0` because LSAN aborts under the harness execution environment even when the suite itself passes.
- A zero-record multiLocalizedUnicodeType (`mluc`) placeholder is treated as a
  12-byte recommended encoding per the ICC TN PSD guidance.
- Legacy 16-byte zero-record encodings are readable in some SampleICC paths but
  should still be reported as non-minimal rather than silently normalized away.
- The corpus case `tests/corpus/cf_mluc_zero_name_placeholder.icc`
  intentionally keeps the legacy 16-byte readable form so both V1 and V2 can
  warn on the same file.
