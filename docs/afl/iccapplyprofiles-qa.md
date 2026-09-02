# iccApplyProfiles Bounded QA

Use these checks after an AFL campaign, compiler or sanitizer update, or a
change to `iccApplyProfiles` threading and configuration replay.

## Storage and build contract

Run Linux builds and measured workloads from the WSL ext4 filesystem, such as
`/home/xss/research` and `/home/xss/qa`. Do not place the workload under
`/mnt/c` or `/mnt/e`; those paths cross the Windows filesystem boundary.

Build with 32 jobs on the research hosts. Sanitizer QA uses the canonical
ASAN/UBSAN build. Valgrind requires a separate non-sanitized Debug build:

```bash
cmake -S iccDEV/Build/Cmake -B /home/xss/qa/iccdev-valgrind-build -DCMAKE_BUILD_TYPE=Debug -DENABLE_TOOLS=ON -DENABLE_TESTS=OFF -DENABLE_SANITIZERS=OFF && cmake --build /home/xss/qa/iccdev-valgrind-build --target iccApplyProfiles --parallel 32
```

Generate the ignored hybrid ICC/TIFF fixtures with
`iccDEV/Testing/hybrid/BuildAndTest.sh` before starting a campaign. Supply a
new or empty evidence directory for each interval; runners reject nonempty
directories so earlier results cannot affect current counts.

## Bounded commands

```bash
.github/ci/quality-assurance/scripts/iccApplyProfiles_sanitizer_qa.sh --seconds 300 --jobs 8 --output-dir /home/xss/qa/iccapplyprofiles-sanitizer
.github/ci/quality-assurance/scripts/iccApplyProfiles_valgrind_qa.sh --tool memcheck --seconds 300 --binary /home/xss/qa/iccdev-valgrind-build/Tools/IccApplyProfiles/iccApplyProfiles --output-dir /home/xss/qa/iccapplyprofiles-memcheck
.github/ci/quality-assurance/scripts/iccApplyProfiles_valgrind_qa.sh --tool helgrind --seconds 300 --binary /home/xss/qa/iccdev-valgrind-build/Tools/IccApplyProfiles/iccApplyProfiles --output-dir /home/xss/qa/iccapplyprofiles-helgrind
```

The sanitizer runner reuses upstream's deterministic CI path generator and
defaults to 1,000 cases so bounded intervals spend time executing rather than
materializing the full command space. Pass `--mutations max` for a long sweep;
the wall-clock limit remains authoritative. The runner audits per-case failure
and sanitizer summaries. The Valgrind runner uses
known-valid raw-spectral and multispectral transformations, cycles thread
counts 0, 1, 2, and 4, and validates nonempty JSON and TIFF outputs.
Its 120-second per-case default accommodates the slower full-image
`-threads 0` Memcheck path while the overall interval remains hard-bounded.

## Classification

Keep these results separate:

- sanitizer or Valgrind diagnostics;
- clean tool rejection, including invalid transform or invalid arguments;
- per-case timeout;
- missing fixture or harness error;
- exit zero with missing or invalid output.

Do not count a missing file, parser rejection, or ordinary exit 1-127 as a
crash. Inspect every per-case log before reporting an aggregate.

## 2026-09-01 baseline

- ASAN/UBSAN: 492 deterministic mutations, 971 completed phases, 819 passes,
  152 clean transform rejections, and no sanitizer finding.
- Memcheck 3.26.0: 13 full-image cases, 9 validated successes, 4 clean
  transform rejections, and no memory error or leak finding.
- Helgrind 3.26.0: 15 fully corrected cases, 11 validated successes, one clean
  invalid-transform rejection, three invalid-argument rejections, and no data
  race, lock-order error, timeout, invalid output, or orphan worker.

The rejected cases informed the checked-in positive-path matrix; they are not
code faults. A preliminary Helgrind pass with bad fixture links was discarded
rather than included in the baseline.

The only confirmed AFL finding in this review was the sampled-curve
NaN-to-unsigned UBSAN abort documented in `local-reproductions.md`. Research
patch `003-single-sampled-curve-finite-position.patch` guards the non-finite
position; retain the unpatched upstream replay for attribution.
