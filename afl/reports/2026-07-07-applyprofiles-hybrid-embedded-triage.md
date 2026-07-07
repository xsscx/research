# applyprofiles-hybrid-embedded triage and coverage review

Date: 2026-07-07

## Scope

Reviewed the AFL `applyprofiles-hybrid-embedded` lane after a stopped campaign
reported 3 saved crashes:

```text
run_time: 39h44m53s
cycles_done: 68
execs_done: 16777823
corpus_count: 492
corpus_found: 506
saved_crashes: 3
saved_hangs: 0
edges_found: 6120
total_edges: 152116
bitmap_cvg: 4.02%
```

## argc Alignment

The target argv shape in `targets.sh` is:

```text
@@ tmp.tif 1 1 0 1 1 -embedded 10003 -pcc Spec400_10_700-F11_2deg-Abs.icc sRGB_v4_ICC_preference.icc 1
```

This aligns with `iccApplyProfiles` alternate usage:

```text
src_tiff_file dst_tiff_file dst_sample_encoding dst_compression dst_planar dst_embed_icc interpolation {{-ENV:sig value} profile_file_path rendering_intent {-PCC connection_conditions_path}}
```

Parser review:

- `CIccCfgImageApply::fromArgs()` consumes 6 image arguments.
- `CIccCfgProfileSequence::fromArgs()` consumes interpolation first.
- The first profile may be `-embedded`, which clears `m_iccFile` and uses the
  source TIFF embedded ICC profile.
- `-PCC path` is accepted after each profile entry.
- The final `sRGB_v4_ICC_preference.icc 1` entry completes the output profile
  sequence.

No argc-shape change was needed for this lane.

## Helper Script Fix

The campaign had archived AFL finding directories:

```text
crashes.2026-07-05-09:50:14/
crashes.2026-07-05-19:57:18/
```

The previous `triage.sh`, `map.sh --crashes`, and `status.sh --detail` only
looked at the live `crashes/` and `hangs/` directories. This caused default
triage to report:

```text
--- Crashes ---
  No crashes found
```

Changes made:

- `triage.sh`: include `crashes.*` and `hangs.*` directories.
- `map.sh`: map `crashes.*` and `hangs.*` when `--crashes` or `--hangs` is used.
- `status.sh`: count and display archived finding files in status/detail output.

## Triage Results

After the helper fix:

```text
./status.sh applyprofiles-hybrid-embedded --detail
```

reported:

```text
Findings: crashes=3 hangs=0 crash_files=3 hang_files=0
```

`./triage.sh applyprofiles-hybrid-embedded` reported:

```text
crashes summary: 3 total, 1 actionable, 0 clean, 2 soft-fail, 1 sanitizer, 0 signal, 0 timeout
```

Two crash artifacts replay as graceful tool failures with exit 255. One artifact
is actionable against the canonical ASan build:

```text
id:000002,sig:06,src:000325,time:63520646,execs:5770616,op:havoc,rep:2
exit=134
AddressSanitizer: heap-buffer-overflow
WRITE of size 324 at 0x7c1ff55e01d1
```

Top stack:

```text
__asan_memcpy
CIccPcsXform::pushBiRef2Rad(CIccProfile*, IIccProfileConnectionConditions*) IccCmm.cpp:3633
CIccPcsXform::pushBiRef2Xyz(CIccProfile*, IIccProfileConnectionConditions*) IccCmm.cpp:3660
CIccPcsXform::Connect(CIccXform*, CIccXform*) IccCmm.cpp:2458
CIccCmm::CheckPCSConnections(bool) IccCmm.cpp:9149
CIccCmm::Begin(bool, bool) IccCmm.cpp:9387
CIccConnectCmm::CreateStandard(...) IccConnect.cpp:444
main iccApplyProfiles.cpp:423
```

Allocation site:

```text
CIccPcsStepSrcMatrix::CIccPcsStepSrcMatrix(unsigned short, unsigned short) IccCmm.cpp:5086
CIccPcsXform::pushBiRef2Rad(...) IccCmm.cpp:3623
```

The actionable input is a mutated TIFF:

```text
TIFF image data, little-endian, direntries=16, width=58, height=65342,
bps=44118, compression=LZW, PhotometricInterpretation=RGB
```

Repro command:

```bash
cd /home/xss/research
LD_LIBRARY_PATH="/home/xss/research/iccDEV/Build/IccProfLib:/home/xss/research/iccDEV/Build/IccXML:/home/xss/research/iccDEV/Build/IccJSON:/home/xss/research/iccDEV/Build/IccConnect" \
ASAN_OPTIONS="halt_on_error=1,abort_on_error=1,detect_leaks=0,symbolize=1,allocator_may_return_null=1" \
UBSAN_OPTIONS="halt_on_error=1,print_stacktrace=1" \
/home/xss/research/iccDEV/Build/Tools/IccApplyProfiles/iccApplyProfiles \
  /home/xss/research/afl/afl-applyprofiles-hybrid-embedded/output/default/crashes.2026-07-05-19:57:18/id:000002,sig:06,src:000325,time:63520646,execs:5770616,op:havoc,rep:2 \
  /tmp/applyprofiles-hybrid-embedded-asan-repro/out.tif \
  1 1 0 1 1 \
  -embedded 10003 \
  -pcc /home/xss/research/afl/support/hybrid/ICC/Spec400_10_700-F11_2deg-Abs.icc \
  /home/xss/research/iccDEV/Testing/sRGB_v4_ICC_preference.icc 1
```

Full replay log:

```text
/tmp/applyprofiles-hybrid-embedded-asan-repro/repro.log
```

## Coverage

Queue showmap:

```text
./map.sh applyprofiles-hybrid-embedded --queue --out /tmp/applyprofiles-hybrid-embedded-queue-showmap.txt
```

Result:

```text
Mapped 492 input(s)
Captured 6120 tuples
Coverage: 6120 edges out of 152128 existing (4.02%)
```

Crash showmap:

```text
./map.sh applyprofiles-hybrid-embedded --crashes --out /tmp/applyprofiles-hybrid-embedded-crashes-showmap.txt
```

Result:

```text
Mapped 3 input(s)
Captured 3665 tuples
Coverage: 3665 edges out of 152128 existing (2.41%)
```

LLVM source coverage:

```text
./coverage.sh applyprofiles-hybrid-embedded --no-reachability --report-root /tmp/afl-applyprofiles-hybrid-embedded-coverage-20260707T203915Z --jobs 2 --report-name applyprofiles-hybrid-embedded
```

Result:

```text
Replaying 502 queue files
TOTAL: 9.11% region, 13.07% function, 8.36% line, 6.32% branch coverage
Covered function list entries: 403
Report: /tmp/afl-applyprofiles-hybrid-embedded-coverage-20260707T203915Z/cov-applyprofiles-hybrid-embedded-static
```

Selected files:

```text
IccCmm.cpp: 80/279 functions, 1181/6831 lines, 478/3974 branches
IccConnect.cpp: 7/15 functions, 113/430 lines, 44/170 branches
IccCmmConfig.cpp: 9/93 functions, 118/1878 lines, 35/1110 branches
TiffImg.cpp: 13/14 functions, 228/417 lines, 81/220 branches
iccApplyProfiles.cpp: 5/10 functions, 237/563 lines, 79/228 branches
```

## Conclusion

The `applyprofiles-hybrid-embedded` argv is aligned with the `iccApplyProfiles`
argument parser and should remain as-is. The useful refinement was in the AFL
helper scripts: archived AFL finding directories must be included in status,
triage, and crash/hang mapping. With that fixed, the campaign yields one
actionable upstream ASan heap-buffer-overflow in `CIccPcsXform::pushBiRef2Rad()`
and broad enough queue coverage to justify keeping this lane active.
