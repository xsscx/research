# CFL OOM artifact QA - 2026-10-31

## Outcome

The October 31 `/mnt/f/artifacts/oom-*` collection contains three reproducible
allocation-bound defects and four additional target batches that replay cleanly
after the fixes. Two local iccDEV patches now reject attacker-controlled extents
before allocation:

- `011-binary-element-allocation-bounds.patch` bounds curve-set children and
  rejects a serialized CLUT that contains only its 20-byte header.
- `012-profile-tag-io-extent-bounds.patch` validates `GetTagIO()` extents against
  the attached profile before allocation or seek.

The patched AddressSanitizer build replayed all 208 copied artifacts with exit
0, no sanitizer diagnostics, and no replay at or above one second. Address,
Memory, and Thread sanitizer builds each completed 24/24 both with and without
the optional patch stack.

This work used research repository `main` initially at
`ca9cfc3f81428405f8c848b3755834b7de4e6f84` and nested iccDEV upstream
`b6ce0cf`. Raw runtime artifacts were not added to Git.

## Artifact inventory and attribution

Top-level copies lose their originating fuzzer name. Attribution below is from
the narrow copy-time batches, input shape, and the supplied logs; it should not
be inferred from the content hash alone.

| Copy time (EDT) | Count | Replayed target | Result with patches 001-012 |
|---|---:|---|---|
| 20:32:28 | 178 | `icc_dump_fuzzer` | 178 clean |
| 20:33:06 | 12 | `icc_applysearch_weight_fuzzer` | 12 clean |
| 20:33:16 | 6 | `icc_link_fuzzer` | 6 clean |
| 20:33:34 | 11 | `icc_roundtrip_fuzzer` | 11 clean |
| 20:54:38 | 1 | `icc_proflib_fuzzer` | 1 clean |

No separate `connect`, `cfg`, or plain `search` batch was identifiable in the
copied top-level October 31 set. Future runs should use a target-specific
directory or `-artifact_prefix=/mnt/f/artifacts/<target>-`.

The complete local replay ledger is
`/home/xss/qa/cfl-oom-replay-20261031/summary.tsv` (header plus 208 records).

## Reproduced defects

### Curve-set child extent

Artifact:

- path: `/mnt/f/artifacts/oom-22a4b1ceae7340741b14214f1e8e91195d55a013`
- bytes: 8,142
- SHA-256: `ca2beb0deac7c18cbf822e0324432452df64afe2df75833676d06d5621d74c10`

The unpatched `icc_applysearch_weight_fuzzer` exits 71 after requesting
2,147,605,508 bytes. A curve-set entry supplies a child size outside its
enclosing element; `CIccMpeCurveSet::Read()` entered the segmented/sampled curve
reader without validating that range.

This case also has a tested unpatched stock-tool reproduction. It is deliberately
bounded with a 30-second timeout and `allocator_may_return_null=1`:

```bash
cd /home/xss/research && /usr/bin/time -f 'elapsed=%e maxrss_kb=%M exit=%x' timeout 30s env ASAN_OPTIONS=detect_leaks=0,allocator_may_return_null=1 iccDEV/Build/Tools/IccDumpProfile/iccDumpProfile -v 100 /mnt/f/artifacts/oom-22a4b1ceae7340741b14214f1e8e91195d55a013 ALL
```

Observed against unpatched `b6ce0cf`: exit 255, elapsed 1.44 seconds, peak RSS
2,114,684 KiB. The tool ultimately reports that the profile cannot be parsed,
but only after the approximately 2 GiB resource spike.

### Header-only CLUT

Artifact:

- path: `/mnt/f/artifacts/oom-09cf5db9e1345d7194ad05c4961c297bc15c5299`
- bytes: 795
- SHA-256: `939f5570c92a0d614849044fcf0a0dcb54d9dee6beda051b9bb2d2f9f33015b1`

The unpatched `icc_roundtrip_fuzzer` exits 71 after requesting 9,828,399,360
bytes. `CIccCLUT::Read(size=20)` passed zero remaining bytes to `Init()`;
`Init()` interprets a zero maximum as its unbounded programmatic mode, so the
serialized grid dimensions became an allocation request before `ReadData()`
could reject the missing samples.

The raw compound artifact is not a stock `iccRoundTrip` reproducer. Unpatched
`iccRoundTrip` and `iccDumpProfile` reject it before reaching the CLUT path, so
this remains a CFL/library-parser reproduction unless a valid standalone ICC
fixture is derived with existing iccDEV tooling.

### Deferred raw-tag extent

Artifact:

- path: `/mnt/f/artifacts/oom-8edd2184e5ce0faed68ec2f632c0a28dc3b38e0f`
- bytes: 3,768
- SHA-256: `a1d692e52c2d097cb272a47410126176c04235893a15a40bb88527aea5c995f6`

The unpatched `icc_proflib_fuzzer` exits 71 after requesting 4,284,902,770
bytes. `CIccProfile::LoadTag()` already validates tag directory ranges, but
`CIccProfile::GetTagIO()` allocated `TagInfo.size` before performing any
equivalent range check. Patch 012 applies the same header, zero-size,
file-length, and overflow-safe extent rules before allocation or seek.

Unpatched `iccDumpProfile` rejects this artifact in 0.12 seconds at about 21 MiB
RSS. `GetTagIO()` has no command-line caller in the non-GUI tools, so this is a
public library/API defect with a focused CMake regression, not a stock CLI
reproduction.

## Patched validation

Representative final AddressSanitizer replays:

| Target | Artifact suffix | Exit | Elapsed |
|---|---|---:|---:|
| weight | `22a4b1ce...` | 0 | 67 ms |
| roundtrip | `09cf5db9...` | 0 | 45 ms |
| proflib | `8edd2184...` | 0 | 43 ms |

The two focused regression tests pass:

```bash
cmake --build cfl/iccDEV/Build --target \
  iccBinaryElementAllocationBoundsTest \
  iccProfileTagIoExtentBoundsTest -j32
ctest --test-dir cfl/iccDEV/Build \
  -R '^iccdev\.(binary-element-allocation-bounds|profile-tag-io-extent-bounds)$' \
  --output-on-failure
```

The tests include positive controls for a complete minimal CLUT and a valid
four-byte raw tag, so the bounds checks do not merely reject every input.

## Sanitizer build matrix

| Sanitizer | Unpatched | With patches 001-012 | Additional validation |
|---|---|---|---|
| Address/UBSan | 24/24 pass | 24/24 pass | 208/208 patched artifact replays clean; 2/2 focused CTests pass |
| Memory | 24/24 pass | 24/24 pass | dependency boundary gate passes in both modes; patched proflib artifact clean in 12 ms; focused CTest passes |
| Thread | 24/24 pass | 24/24 pass | five-second deterministic dump replay passes in both modes; patched proflib artifact replay completes 1,708 units without a report |

MSan now disables iccDEV shared libraries and supplies the instrumented static
libc++ runtime to CMake executable links. Before that pipeline fix, regression
executables used libc++ headers but failed to link `std::__1` symbols; attempting
to put the non-PIC instrumented libc++ archive in a shared library instead
failed on local-exec TLS relocations.

Repeated `--with-patches` builds are also idempotent. `cfl/build.sh` removes
untracked files created by a patch before applying that patch again. This fixes
the prior `already exists in working directory` failure for patches 008, 011,
and 012 without deleting unrelated files from the nested checkout.

## Remote continuation plan

Stop each active CFL process gracefully before replacing its binary and build
tree. For runs launched by the repository helpers, use `cd ~/research/cfl &&
./stop.sh all`; for foreground manual LibFuzzer commands, use Ctrl-C in their
own sessions. Then update and rebuild:

```bash
cd ~/research
git pull --ff-only
cd cfl
./build.sh --with-patches --refresh-iccdev
```

Resume the existing target-specific campaigns only after the 24/24 build
summary. Keep `FUZZ_TMPDIR` on the native WSL filesystem and preserve target
attribution in each artifact prefix. Use the unpatched stock-tool command above
when documenting the curve-set defect for a future iccDEV branch; do not report
the two raw compound artifacts as stock CLI reproductions.
