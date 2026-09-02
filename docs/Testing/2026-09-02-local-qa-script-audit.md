# Local ICC QA Script Audit - 2026-09-02

## Scope and outcome

This audit covered all 44 regular files in `/home/xss/scripts`, the active
iccDEV quality-assurance scripts, and the configured iccDEV CTest suite. The
local apply QA suite now includes `iccBenchApply`, distinguishes a known clean
`iccApplySearch` incompatibility rejection from crashes, and does not report a
sanitizer finding as a passing case. No retirement candidates were deleted.

The proposed iccDEV changes are kept separately in the nested `iccDEV`
checkout. Research-repository changes only adjust the bounded sanitizer QA
wrapper, its validator, and its documentation.

## `/home/xss/scripts` disposition

`Keep and migrate` means the script is useful but should have one maintained
copy in iccDEV rather than an independent home-directory copy. `Retire` means
remove it after confirming no external caller depends on the path.

| File | Disposition | Reason |
| --- | --- | --- |
| `apply-1.sh` | Retire | Ad hoc predecessor to the bounded apply suite. |
| `apply-suite-smoke.out` | Retire | Generated log, not a test or fixture. |
| `cube-bugs.sh` | Retire | Exact duplicate of `cube.sh`; superseded by maintained tests. |
| `cube.sh` | Retire | Ad hoc issue commands with no durable assertions. |
| `get-iccdump-registry-info.sh` | Retire | One-line local corpus probe with hard-coded paths. |
| `get-registry.sh` | Retire | Local registry probe superseded by corpus and manifest tests. |
| `iccApplyNamedCmm-quick-check.sh` | Keep and migrate | Useful positive and negative CLI coverage; canonical iccDEV copy exists. |
| `iccApplyNamedCmm_QA_200.txt` | Retire | Generated command list duplicated in canonical QA data. |
| `iccApplyNamedCmm_QA_revisions_200.txt` | Archive, then retire | Historical revision commands without a maintained generator contract. |
| `iccApplyNamedCmm_ci_path_exercise.sh` | Keep canonical only | Useful generator; home copy should follow iccDEV. |
| `iccApplyProfiles-quick-check.sh` | Keep and migrate | Useful deterministic CLI coverage; canonical iccDEV copy exists. |
| `iccApplyProfiles_all_mutations.sh` | Retire | Superseded by the bounded deterministic path driver. |
| `iccApplyProfiles_ci_path_exercise.sh` | Keep canonical only | Useful generator; home copy should follow iccDEV. |
| `iccApplyProfiles_mutations_1000.txt` | Retire | Generated command output, reproducible from the driver. |
| `iccApplyProfiles_semantic_mutations_1000.sh` | Retire | Raw commands mislabeled as an executable shell script. |
| `iccApplyProfiles_semantic_mutations_1000.txt` | Archive, then retire | Historical generated commands with no unique test assertions. |
| `iccApplySearch-quick-check.sh` | Keep and migrate | Useful deterministic CLI coverage; canonical iccDEV copy exists. |
| `iccApplySearch_QA_1000_latest.txt` | Retire | Exact duplicate of `iccApplySearch_random_1000.txt`. |
| `iccApplySearch_QA_200-latest.txt` | Retire | Exact duplicate of three other 200-case files. |
| `iccApplySearch_QA_200.txt` | Retire home copy | Canonical command corpus belongs in iccDEV. |
| `iccApplySearch_QA_200_v2_aligned.txt` | Retire | Exact duplicate of the other 200-case files. |
| `iccApplySearch_ci_path_exercise.sh` | Keep wrapper if called | Thin unique wrapper, but move any caller to the generic canonical driver. |
| `iccApplySearch_random_1000.txt` | Retire | Generated command output and exact duplicate. |
| `iccApplySearch_strict_QA_200-002.txt` | Retire | Exact duplicate of the other 200-case files. |
| `iccApplyToLink-quick-check.sh` | Keep and migrate | Useful deterministic CLI coverage; canonical iccDEV copy exists. |
| `iccApplyToLink_QA_200.txt` | Retire | Generated commands reproducible from the maintained driver. |
| `iccBenchApply-quick-check.sh` | Keep and migrate | New coverage for BPC, luminance, combined flags, and clean rejection paths. |
| `iccSpecSepToTiff-corpus-matrix.sh` | Keep canonical only | Useful corpus matrix already maintained by iccDEV QA. |
| `iccSpecSepToTiff-spectral-coverage.sh` | Keep canonical only | Useful spectral coverage already maintained by iccDEV QA. |
| `icc_apply_qa_suite.sh` | Keep and migrate | Useful bounded orchestration; expanded in this audit. |
| `icc_ci_tool_path_exercise.sh` | Keep and migrate | Useful generic deterministic generator; improved rejection classification. |
| `iccapplysearch-check-1.sh` | Retire | Ad hoc command list without a shebang or assertions. |
| `iccapplysearch-check-2.sh` | Retire | Ad hoc command list; exact duplicate of check 3. |
| `iccapplysearch-check-3.sh` | Retire | Exact duplicate of check 2. |
| `iccapplysearch-check-4.sh` | Retire | Ad hoc command list without a shebang or assertions. |
| `iccdev-specsep-profile-sweep.sh` | Keep, then migrate | Useful sweep, but the home copy embeds `/home/xss/research`. |
| `namedcmm-smoke.out` | Retire | Generated log, not a test or fixture. |
| `next_qa.sh` | Retire | Superseded orchestration scratch script. |
| `qa-common.sh` | Keep and migrate | Shared bounded execution and sanitizer classification helper. |
| `qa_cli_surface.sh` | Retire | Overlaps focused quick checks and registered CLI CTests. |
| `specsep-1-liners.sh` | Retire | Ad hoc command list without a shebang or assertions. |
| `specsep-qa.sh` | Keep canonical only | Useful QA exists in iccDEV; retire the independent home copy. |
| `tolink-script-random-001.sh` | Keep canonical only | Useful deterministic driver already maintained in iccDEV. |
| `tolink-script-random-001.sh.bak-20260707-162421` | Retire | Stale CRLF backup; not a maintained test. |

## Changes made

### Local `/home/xss/scripts`

- Added `iccBenchApply-quick-check.sh` with positive BPC/luminance checks and
  negative intent, decoded-intent, and missing-profile checks.
- Expanded `icc_apply_qa_suite.sh` to run the new bench lane.
- Added opt-in clean-rejection classification to
  `icc_ci_tool_path_exercise.sh`; strict behavior remains the default.
- Updated `qa-common.sh` so sanitizer diagnostics cannot be followed by a
  misleading pass and added `allocator_may_return_null=1` to bounded ASAN
  defaults.

### Research repository

- Changed the `iccApplyProfiles` sanitizer wrapper default from an invalid
  100,000 cases to a bounded 1,000 cases. The upstream generator's effective
  maximum with safe scalar settings is 23,040.
- Added explicit `--mutations max` support for long sweeps.
- Expanded the static validator and documented the bounded default.

### Proposed iccDEV branch changes

- Added the `iccBenchApply` quick check to the canonical QA suite and README.
- Added opt-in clean Search rejection recording.
- Added the bounded ASAN allocator option to the shared QA environment.

No CMake or CTest definitions were changed: iccDEV already registers focused
bench and apply argument tests, and those focused tests pass.

## Verification evidence

- Four original home-directory quick checks: all passed with zero failures.
  Evidence: `/tmp/local-iccApply*-quick-check-baseline`.
- New home-directory bench quick check: passed with zero failures. Evidence:
  `/tmp/local-iccBenchApply-quick-check-rerun`.
- Expanded home-directory suite, 12 deterministic mutations per generated
  lane: passed all five tools and the sanitizer scan. Evidence:
  `/tmp/local-apply-suite-expanded`.
- Expanded canonical iccDEV candidate suite: passed all five tools and the
  sanitizer scan. Evidence: `/tmp/upstream-apply-suite-expanded`.
- Research wrapper validation: `.github/scripts/validate-iccapplyprofiles-qa.sh`
  passed.
- Bounded sanitizer wrapper, 30 seconds and 1,000 generated cases: 76 commands
  completed, zero sanitizer lines, and zero clean rejections. Evidence:
  `/tmp/iccapplyprofiles-sanitizer-qa-20260902-1000`.
- Focused apply and bench CTests: 29 of 29 passed, including the 30-second
  issue-1781 ApplyToLink matrix.

The complete configured CTest run passed 136 of 240 tests. Seventy-one of the
104 failed or not-run entries explicitly report missing test executables in the
partially built local tree; dependent script tests account for most remaining
failures. The 391-second hybrid pipeline passed. The profile-manifest test also
identified 39 unlisted local/generated profiles; that is corpus-state drift,
not a tool crash. This run is useful as a build-tree and corpus-state audit, but
it is not a green full-suite result.
