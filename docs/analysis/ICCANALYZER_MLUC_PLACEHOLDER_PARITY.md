# ICCANALYZER-LITE MLUC PLACEHOLDER PARITY NOTES

## Scope

This note captures the `multiLocalizedUnicodeType` (`mluc`) parity work driven by
the ICC technical note in `docs/iccDEV/specifications/PSD_TechNote.pdf` and the
supporting structure diagram in `~/mluc-structure.png`.

## Approved Parity Note

- A zero-record multiLocalizedUnicodeType (`mluc`) placeholder is treated as a
  12-byte recommended encoding per the ICC TN PSD guidance.
- Legacy 16-byte zero-record encodings are readable in some SampleICC paths but
  should still be reported as non-minimal rather than silently normalized away.

## Closed Parity Bug

- V1 `CF-223` already followed that guidance.
- V2 `CF-223` was incorrectly enforcing a **16-byte** size for zero-record
  `mluc` tags.
- V2 was corrected to match V1 and the approved ICC TN PSD guidance.

Code anchors:

- V1: `IccConformanceTagTypes.cpp` `RunCF223_MlucZeroNamePlaceholder()`
- V2: `icctest/lib/src/checks/CfTagTypeChecks.cpp`

## Test Coverage Added

- Added synthesized corpus profile:
  - `iccanalyzer-lite/tests/corpus/cf_mluc_zero_name_placeholder.icc`
- Synth generator:
  - `iccanalyzer-lite/tests/synthesize_profiles.py`
- V1 conformance assertions:
  - `iccanalyzer-lite/tests/run_tests.py`
- V2 conformance assertions:
  - `iccanalyzer-lite/icctest/lib/tests/test_runner.cpp`

The synthesized profile intentionally uses a readable **16-byte** zero-record
`mluc` so both engines can load it through SampleICC and still report the
non-minimal encoding via `CF-223`.

## Verification State

- V1 conformance section: `357/357 passed`
- V2 unit tests: `406/406 passed`
- V1/V2 parity verifier: raw parity `delta = 0`

## Forward-Looking Count Note

- Do not treat the current `173` heuristic entries or `329` canonical
  conformance entries as a fixed ceiling.
- V1 and V2 are expected to grow the `H-*` and `CF-*` namespaces toward
  `1000` checks each over time.
- Any count-sensitive tooling should read the registries instead of hardcoding
  upper bounds.

## Remaining Gap

The ICC technical note is mainly about **embedded** `mluc` inside
`profileSequenceDescType` (`pseq`), including:

- zero-name placeholder encoding
- inferred `mluc` extent as `max(offset + length)`
- 4-byte padding before the next embedded structure

Current `CF-221` in both V1 and V2 still performs only shallow
`profileSequenceDescTag` validation. Raw embedded-`mluc` validation inside `pseq`
was not expanded here because SampleICC's `CIccTagMultiLocalizedUnicode::Read()`
still assumes the legacy 16-byte standalone header shape.
