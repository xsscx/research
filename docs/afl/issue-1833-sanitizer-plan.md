# Issue 1833 Sanitizer Config Plan

GitHub issue: https://github.com/InternationalColorConsortium/iccDEV/issues/1833

## Scope

Issue 1833 tracks noisy IntegerSanitizer findings from libstdc++ 15 container
implementation details. The immediate AFL evidence is an `iccApplyNamedCmm`
input that emits unsigned-overflow from libstdc++ `basic_string.h` before the
tool times out.

This is a CI and QA configuration task, not an iccDEV profile parser fix, unless
later replay shows project-owned frames before the STL sanitizer report.

Local verification found that runtime UBSAN suppression via
`UBSAN_OPTIONS=suppressions=iccDEV/Testing/silence.txt` did not suppress this
existing AFL binary's `basic_string.h` report. The verified path is compile-time
suppression through `.github/ci/ubsan-ignorelist.txt`, followed by rebuilding
the sanitizer target.

## Local Evidence

Current retained AFL artifact:

```text
afl/afl-applynamedcmm/output.backup.20260726T210406Z/default/crashes.2026-07-25-16:22:30/id:000023,sig:06,src:000727,time:191457324,execs:29300737,op:havoc,rep:8
```

Unsuppressed replay:

```bash
cd /home/xss/research && LD_LIBRARY_PATH=$PWD/iccDEV/Build/IccProfLib:$PWD/iccDEV/Build/IccXML:$PWD/iccDEV/Build/IccJSON:$PWD/iccDEV/Build/IccConnect ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1:allocator_may_return_null=1 UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1 timeout 20s ./iccDEV/Build/Tools/IccApplyNamedCmm/iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 'afl/afl-applynamedcmm/output.backup.20260726T210406Z/default/crashes.2026-07-25-16:22:30/id:000023,sig:06,src:000727,time:191457324,execs:29300737,op:havoc,rep:8' 1
```

Observed sanitizer signature:

```text
/usr/lib/gcc/x86_64-linux-gnu/15/../../../../include/c++/15/bits/basic_string.h:553:51: runtime error: unsigned integer overflow: 2 - 4 cannot be represented in type 'size_type' (aka 'unsigned long')
```

## Proposed Upstream Patch

Runtime suppressions:

```text
unsigned-integer-overflow:*/include/c++/*/bits/basic_string.h
unsigned-integer-overflow:*/include/c++/*/bits/basic_string.tcc
unsigned-integer-overflow:*/include/c++/*/bits/stl_bvector.h
unsigned-integer-overflow:*/include/c++/*/bits/stl_uninitialized.h
```

Compile-time ignorelist entries:

```text
[unsigned-integer-overflow]
src:*/include/c++/*/bits/basic_string.h
src:*/include/c++/*/bits/basic_string.tcc
src:*/include/c++/*/bits/stl_bvector.h
src:*/include/c++/*/bits/stl_uninitialized.h
```

Keep the scope to standard-library implementation paths. Do not suppress
`Icc*`, `Tools`, `IccConnect`, or fuzzer harness paths for this issue.

## Verification Plan

1. Confirm the unsuppressed replay still emits the `basic_string.h` sanitizer
   finding.
2. Attempt `UBSAN_OPTIONS=suppressions=iccDEV/Testing/silence.txt` on the same
   replay and record whether the current sanitizer runtime honors it.
3. Run the sanitizer config smoke checks:

```bash
cd /home/xss/research/iccDEV && bash .github/tests/test_sanitization.sh
```

4. For compile-time ignorelist coverage, configure a small sanitizer build with
   `-DUBSAN_IGNORELIST=.github/ci/ubsan-ignorelist.txt` and verify CMake emits
   the expected `-fsanitize-ignorelist=` flag.
5. Re-run the AFL marked command against the rebuilt sanitizer binary and
   confirm it no longer emits the libstdc++ `basic_string.h` sanitizer report.

## Local Verification Results

Commands run on 2026-07-25:

```bash
cd /home/xss/research && LD_LIBRARY_PATH=$PWD/iccDEV/Build/IccProfLib:$PWD/iccDEV/Build/IccXML:$PWD/iccDEV/Build/IccJSON:$PWD/iccDEV/Build/IccConnect ASAN_OPTIONS=detect_leaks=0:halt_on_error=1:abort_on_error=1:symbolize=1:allocator_may_return_null=1 UBSAN_OPTIONS=suppressions=/home/xss/research/iccDEV/Testing/silence.txt:halt_on_error=1:abort_on_error=1:print_stacktrace=1 timeout 20s ./iccDEV/Build/Tools/IccApplyNamedCmm/iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 'afl/afl-applynamedcmm/output.backup.20260726T210406Z/default/crashes.2026-07-25-16:22:30/id:000023,sig:06,src:000727,time:191457324,execs:29300737,op:havoc,rep:8' 1
```

Result: exit `124`; runtime suppression file was not sufficient for this
existing AFL binary. The same `basic_string.h:553:51` unsigned-overflow report
was still emitted.

```bash
cd /home/xss/research && cmake -S /home/xss/research/iccDEV/Build/Cmake -B ~/work/codex/iccdev-issue1833-build -DENABLE_TOOLS=ON -DENABLE_TESTS=OFF -DENABLE_INTEGER_SANITIZER=ON -DUBSAN_IGNORELIST=.github/ci/ubsan-ignorelist.txt && cmake --build ~/work/codex/iccdev-issue1833-build --target iccApplyNamedCmm -j 8
```

Result: build passed. CMake reported:

```text
>>> UBSAN ignorelist: /home/xss/research/iccDEV/.github/ci/ubsan-ignorelist.txt
>>> Final sanitizer flags: -fsanitize=integer -fno-omit-frame-pointer -fno-sanitize-recover=integer -fsanitize-ignorelist=/home/xss/research/iccDEV/.github/ci/ubsan-ignorelist.txt
```

```bash
cd /home/xss/research && UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1:print_stacktrace=1 timeout 20s ~/work/codex/iccdev-issue1833-build/Tools/IccApplyNamedCmm/iccApplyNamedCmm docs/iccDEV/Tools/test-data/test-data-rgb-8bit.txt 0 0 'afl/afl-applynamedcmm/output.backup.20260726T210406Z/default/crashes.2026-07-25-16:22:30/id:000023,sig:06,src:000727,time:191457324,execs:29300737,op:havoc,rep:8' 1
```

Result: exit `1`, output `Profile application failed.` No libstdc++
`basic_string.h` sanitizer report was emitted.

```bash
cd /home/xss/research/iccDEV && bash .github/tests/test_sanitization.sh
```

Result: `86 passed, 0 failed`.

## Issue Comment Draft

```markdown
I expanded the issue into a concrete config plan and tested the current AFL
evidence locally.

Evidence:
- Target: `iccApplyNamedCmm`
- Artifact: `afl/afl-applynamedcmm/output.backup.20260726T210406Z/default/crashes.2026-07-25-16:22:30/id:000023,sig:06,src:000727,time:191457324,execs:29300737,op:havoc,rep:8`
- Unsuppressed replay exits `124` after emitting:
  `/usr/lib/gcc/x86_64-linux-gnu/15/../../../../include/c++/15/bits/basic_string.h:553:51: runtime error: unsigned integer overflow: 2 - 4 cannot be represented in type 'size_type' (aka 'unsigned long')`

Plan:
1. Add runtime suppressions to `Testing/silence.txt` for libstdc++ implementation
   paths only: `basic_string.h`, `basic_string.tcc`, `stl_bvector.h`, and
   `stl_uninitialized.h`. Local replay showed this is not sufficient for the
   current AFL binary, but it keeps recovering UBSAN CI runs consistent.
2. Add matching compile-time ignorelist `src:` entries to
   `.github/ci/ubsan-ignorelist.txt` under `[unsigned-integer-overflow]`. This
   is the verified fix path for the AFL evidence.
3. Keep project-owned iccDEV paths unsuppressed so new sanitizer reports in
   `Icc*`, `Tools`, `IccConnect`, or fuzz harness code remain actionable.
4. Verify with the AFL `iccApplyNamedCmm` repro, sanitizer config smoke tests,
   and a CMake configure that confirms `-fsanitize-ignorelist=` is applied.

Local verification:
- Runtime `silence.txt` replay: still emitted `basic_string.h:553:51` and
  exited `124`.
- Rebuilt with `-DUBSAN_IGNORELIST=.github/ci/ubsan-ignorelist.txt`: replay
  exited `1` with `Profile application failed.` and no `basic_string.h`
  sanitizer report.
- Sanitizer helper smoke test: `86 passed, 0 failed`.

This keeps issue 1833 scoped as CI/QA sanitizer noise management rather than a
parser bug, unless later stack evidence shows project-owned UB before the STL
implementation report.
```

## Completion Reminder

After local verification is complete, commit the research-side docs and any
selected upstream patch artifacts, then push `research:main` and report the
commands and results.
