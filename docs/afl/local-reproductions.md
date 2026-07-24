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

Patch coverage after the 2026-07-24 sweep:

- `001-json-config-parser-no-sanitize.patch` covers the marked
  `applynamedcmm-cfg` JSON parser sanitizer class in patched AFL/CFL builds.
- `002-jpegdump-segment-bounds.patch` covers the marked `jpegdump` segment
  bounds assertion class in patched AFL/CFL builds.
- `003-applyprofiles-cam-encoding-div-zero.patch` covers the marked
  `applyprofiles` CAM inverse and encoding surround-ratio division-by-zero
  classes in patched AFL/CFL builds.
- `004-applyprofiles-tiff-sample-count-bounds.patch` covers the marked
  `applyprofiles-hybrid-embedded` malformed TIFF sample-count
  heap-buffer-overflow class in patched AFL/CFL builds.
- `005-applytolink-bpc-degenerate-lrange.patch` covers the live
  `applytolink` BPC destination L* range division-by-zero class in patched
  AFL/CFL builds.

## 2026-07-24 -- live iccApplyToLink BPC L* range UBSAN

Target: `applytolink`

Current retained artifact:

```text
afl/afl-applytolink/output/default/crashes/id:000299,sig:06,src:004287,time:558341213,execs:103328920,op:ext_UO,pos:30592
```

Verified one-liner:

```bash
cd /home/xss/research && LD_LIBRARY_PATH=/home/xss/research/iccDEV/Build/IccProfLib:/home/xss/research/iccDEV/Build/IccXML:/home/xss/research/iccDEV/Build/IccJSON:/home/xss/research/iccDEV/Build/IccConnect ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1:allocator_may_return_null=1:print_scariness=1 UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1 timeout 30s /home/xss/research/iccDEV/Build/Tools/IccApplyToLink/iccApplyToLink /tmp/iccdev-repro/applytolink-299.icc 0 2 1 AFL 0.0 1.0 0 0 'afl/afl-applytolink/output/default/crashes/id:000299,sig:06,src:004287,time:558341213,execs:103328920,op:ext_UO,pos:30592' 40
```

Expected sanitizer signature:

```text
IccProfLib/IccApplyBPC.cpp:505:28: runtime error: division by zero
```

Observed exit from the verified replay: `124`. Classification is UBSAN
division-by-zero followed by timeout; the sanitizer finding is emitted before
the timeout terminates the replay.
