# AFL Local Reproductions

This file records locally retained AFL findings that have an exact
copy-paste replay command but have not yet been promoted to durable fixtures.
Raw AFL output directories remain local runtime state; if an input is needed
for long-term tests, promote the minimized artifact separately.

## 2026-07-23 -- iccApplyNamedCmm JSON config UBSAN

Target: `applynamedcmm-cfg`

Current retained artifact:

```text
afl/afl-applynamedcmm-cfg/output/default.unusable-resume.20260723T133241Z/crashes/id:000005,sig:06,src:001444,time:5006818,execs:896502,op:havoc,rep:2
```

Original live AFL path, before resume cleanup archived the instance:

```text
afl/afl-applynamedcmm-cfg/output/default/crashes/id:000005,sig:06,src:001444,time:5006818,execs:896502,op:havoc,rep:2
```

Verified one-liner:

```bash
cd /home/xss/research && LD_LIBRARY_PATH=/home/xss/research/iccDEV/Build/IccProfLib:/home/xss/research/iccDEV/Build/IccXML:/home/xss/research/iccDEV/Build/IccJSON:/home/xss/research/iccDEV/Build/IccConnect ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1:allocator_may_return_null=1 UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1 timeout 60s /home/xss/research/iccDEV/Build/Tools/IccApplyNamedCmm/iccApplyNamedCmm -cfg 'afl/afl-applynamedcmm-cfg/output/default.unusable-resume.20260723T133241Z/crashes/id:000005,sig:06,src:001444,time:5006818,execs:896502,op:havoc,rep:2'
```

Expected sanitizer signature:

```text
/usr/lib/gcc/x86_64-linux-gnu/15/../../../../include/c++/15/bits/stl_bvector.h:221:20: runtime error: unsigned integer overflow: 0 - 1 cannot be represented in type 'unsigned int'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /usr/lib/gcc/x86_64-linux-gnu/15/../../../../include/c++/15/bits/stl_bvector.h:221:20
```

Observed exit from the verified replay: `134`.

Stack ownership:

```text
std::vector<bool>::pop_back()
nlohmann::detail::parser<...>::sax_parse_internal()
nlohmann::basic_json<...>::parse()
loadJsonFrom() at iccDEV/IccConnect/IccLibConnect/IccJsonUtil.cpp
main() at iccDEV/Tools/CmdLine/IccApplyNamedCmm/iccApplyNamedCmm.cpp
```

Triage note: this reproduces in JSON config parsing before CMM execution.
Treat it as `iccApplyNamedCmm -cfg` / `IccConnect` JSON input handling, not as
an ICC profile processing crash.

## 2026-07-24 -- Marked AFL iccDEV replay bundle

Generated local review bundle:

```text
~/most-recent-reply.md
```

The bundle is generated from `afl/marked/*/crashes/*.cmd` and contains 100
copy-paste one-line replays using canonical `iccDEV/Build/Tools` binaries.
It includes the JSON config, JPEG APP2, applyprofiles CAM/encoding,
applyprofiles hybrid embedded, and older timeout-only marked artifacts.

The 2026-07-24 sweep used local patches for comparison. Those patches are now
retired; current AFL and CFL builds use upstream `master` without local source
patches.

## 2026-07-24 -- live iccApplyToLink BPC L* range UBSAN

Target: `applytolink`

Current retained artifact:

```text
afl/afl-applytolink/output.backup.20260726T210318Z/default/crashes.2026-07-24-15:33:04/id:000299,sig:06,src:004287,time:558341213,execs:103328920,op:ext_UO,pos:30592
```

Current canonical iccDEV replay:

```bash
cd /home/xss/research && mkdir -p ~/work/codex/iccdev-repro && LD_LIBRARY_PATH=$PWD/iccDEV/Build/IccProfLib:$PWD/iccDEV/Build/IccXML:$PWD/iccDEV/Build/IccJSON:$PWD/iccDEV/Build/IccConnect ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1:allocator_may_return_null=1:print_scariness=1 UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1 timeout 20s ./iccDEV/Build/Tools/IccApplyToLink/iccApplyToLink ~/work/codex/iccdev-repro/applytolink-299.icc 0 2 1 AFL 0.0 1.0 0 0 'afl/afl-applytolink/output.backup.20260726T210318Z/default/crashes.2026-07-24-15:33:04/id:000299,sig:06,src:004287,time:558341213,execs:103328920,op:ext_UO,pos:30592' 40
```

Historic sanitizer signature:

```text
IccProfLib/IccApplyBPC.cpp:505:28: runtime error: division by zero
```

Current replay result on 2026-07-31: exit `255`,
`Error - Unable to begin profile application (status 8: Incorrect Apply object)`.
This entry is retained as stale historical context only; do not cite it as a
current reproducer unless a future replay restores the sanitizer signature with
canonical `iccDEV/Build/Tools` tooling.

## 2026-07-25 -- live iccApplyNamedCmm string length UBSAN

Target: `applynamedcmm`

Current retained artifact:

```text
afl/afl-applynamedcmm/output.backup.20260726T210406Z/default/crashes.2026-07-25-16:22:30/id:000023,sig:06,src:000727,time:191457324,execs:29300737,op:havoc,rep:8
```

Original live AFL path:

```text
afl/afl-applynamedcmm/output.backup.20260726T210406Z/default/crashes.2026-07-25-16:22:30/id:000023,sig:06,src:000727,time:191457324,execs:29300737,op:havoc,rep:8
```

Verified one-liner:

```bash
cd /home/xss/research && LD_LIBRARY_PATH=$PWD/iccDEV/Build/IccProfLib:$PWD/iccDEV/Build/IccXML:$PWD/iccDEV/Build/IccJSON:$PWD/iccDEV/Build/IccConnect ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1:allocator_may_return_null=1 UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1 timeout 20s ./iccDEV/Build/Tools/IccApplyNamedCmm/iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 'afl/afl-applynamedcmm/output.backup.20260726T210406Z/default/crashes.2026-07-25-16:22:30/id:000023,sig:06,src:000727,time:191457324,execs:29300737,op:havoc,rep:8' 1
```

Expected sanitizer signature:

```text
/usr/lib/gcc/x86_64-linux-gnu/15/../../../../include/c++/15/bits/basic_string.h:553:51: runtime error: unsigned integer overflow: 2 - 4 cannot be represented in type 'size_type' (aka 'unsigned long')
```

Observed exit from the verified replay: `124`. Classification is UBSAN
unsigned-overflow followed by timeout; the sanitizer finding is emitted before
the timeout terminates the replay.

Issue 1833 follow-up on 2026-07-25 verified that runtime
`UBSAN_OPTIONS=suppressions=iccDEV/Testing/silence.txt` did not suppress this
existing AFL binary, but rebuilding `iccApplyNamedCmm` with
`-DUBSAN_IGNORELIST=.github/ci/ubsan-ignorelist.txt` changed the replay to a
normal tool failure (`Profile application failed.`, exit `1`) with no
`basic_string.h` sanitizer report.

Current default-instance hang triage from the stopped AFL run:

- `pawgreport`: 7 hangs replayed, 0 actionable, 7 soft-fail.
- `applynamedcmm-cfg`: 81 hangs replayed, 0 actionable, 81 soft-fail.
- `tiffdump-extract`: 84 hangs replayed, 0 actionable, 3 clean, 81 soft-fail.
- `fromjson`: 42 hangs replayed, 0 actionable, 12 clean, 30 soft-fail.

## 2026-09-01 -- iccApplyNamedCmm sampled-curve NaN UBSAN

Target: `applynamedcmm`

Artifact:

```text
afl/afl-applynamedcmm/output/default/crashes/id:000000,sig:06,src:000049,time:451805755,execs:10506180,op:havoc,rep:3
```

SHA-256:

```text
02d1bda4b36939a692bc46d4723fe60f7475eb7dab706e010bd31f3f7ad54a5d
```

Verified canonical one-liner against the unpatched `faa6b311` build:

```bash
cd /home/xss/research && LD_LIBRARY_PATH=$PWD/iccDEV/Build/IccProfLib:$PWD/iccDEV/Build/IccXML:$PWD/iccDEV/Build/IccJSON:$PWD/iccDEV/Build/IccConnect ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1:allocator_may_return_null=1 UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1 timeout 20s ./iccDEV/Build/Tools/IccApplyNamedCmm/iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-16bit.txt 5 1 'afl/afl-applynamedcmm/output/default/crashes/id:000000,sig:06,src:000049,time:451805755,execs:10506180,op:havoc,rep:3' 1
```

Clean batch GDB stack:

```bash
cd /home/xss/research && env LD_LIBRARY_PATH=$PWD/iccDEV/Build/IccProfLib:$PWD/iccDEV/Build/IccXML:$PWD/iccDEV/Build/IccJSON:$PWD/iccDEV/Build/IccConnect ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer-21 ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1 UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1 gdb -q --batch -ex 'set pagination off' -ex 'set print frame-arguments all' -ex run -ex 'thread apply all bt 40' --args ./iccDEV/Build/Tools/IccApplyNamedCmm/iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-16bit.txt 5 1 'afl/afl-applynamedcmm/output/default/crashes/id:000000,sig:06,src:000049,time:451805755,execs:10506180,op:havoc,rep:3' 1
```

The sanitizer reports a non-finite sampled-curve position converted to an
unsigned index in `CIccSingleSampledCurve::Apply()` (`IccMpeBasic.cpp`; line
1228 in the verified build's sanitizer mapping). Research patch
`003-single-sampled-curve-finite-position.patch` restores an `std::isfinite`
guard before the conversion. This is the only confirmed upstream finding from
the 2026-09-01 fleet triage; U3, U5, and U8 candidates replayed cleanly or were
ordinary tool rejections.
