# AFL++ dev and Clang 22 update

Date: 2026-08-07

## Result

The local AFL++ source checkout used by `afl/build.sh` was updated from the
stable-based AFL++ 5.02c build to upstream `dev` commit
`98b0251411ec223335a6efb34596d86032d20776` (AFL++ 5.03a). It was rebuilt with
Clang 22.1.2 and `llvm-config-22` 22.1.2.

The ICC workflow accepts the updated wrappers. A clean build produced all 20
AFL-instrumented iccDEV tools with AddressSanitizer, UndefinedBehaviorSanitizer,
IntegerSanitizer, float-divide-by-zero, and float-cast-overflow instrumentation.
An `afl-showmap` replay of `iccDumpProfile` produced a 35,829-byte tuple map.

## Commands and evidence

```text
git fetch --no-recurse-submodules --depth=100 origin dev:refs/remotes/origin/dev
git switch -C dev refs/remotes/origin/dev
make clean
make -j32 all LLVM_CONFIG=llvm-config-22 CC=clang-22 CXX=clang++-22
```

The AFL++ build reported:

```text
We have llvm-config version 22.1.2 with a clang version 22.1.2, good.
afl-fuzz and supporting tools successfully built
LLVM mode successfully built
LLVM LTO mode successfully built
```

The optional GCC plugin did not build against GCC 15 plugin headers. The ICC
workflow uses LLVM mode and does not require that plugin.

```text
AFL_CLANG_FAST=/home/xss/work/copilot/AFLplusplus-dev-98b0251/afl-clang-fast \
AFL_CLANG_FASTXX=/home/xss/work/copilot/AFLplusplus-dev-98b0251/afl-clang-fast++ \
./afl/build.sh --clean-third-party --clean
```

The integration build reported:

```text
AFL backend: /usr/bin/clang-22 / /usr/bin/clang++-22
Sanitizer instrumentation:
  [OK] AddressSanitizer
  [OK] UndefinedBehaviorSanitizer
  [OK] IntegerSanitizer
  [OK] float-divide-by-zero
  [OK] float-cast-overflow
[OK] 20 AFL-instrumented tools deployed to /home/xss/research/afl/bin
```

Focused runtime validation:

```text
ASAN_OPTIONS=detect_leaks=0 AFL_PATH=/home/xss/work/copilot/AFLplusplus-dev-98b0251 \
  /home/xss/work/copilot/AFLplusplus-dev-98b0251/afl-showmap \
  -m none -q -o MAP -- \
  ./afl/bin/iccDumpProfile test-profiles/sRGB_D65_MAT.icc ALL
wc -c MAP
```

Result: `35829 MAP`, with non-empty tuple entries.

The JPEG seed contract also passed:

```text
.github/scripts/validate-afl-jpeg-seeds.sh
[OK] raw ICC negative fixture rejected by JPEG extension policy
[OK] /home/xss/research/afl/afl-jpegdump/input: 190 staged seed(s) checked
```

## Upstream LLVM 22 test status

The AFL++ direct `test/test-all.sh` suite completed 39 test groups but returned
1. Core compiler, instrumentation, fuzzing, LTO, CmpLog routines, minimizers,
IJON, timeout, and runtime value-profile checks passed. Failures were confined
to LLVM-IR-sensitive or host-specific checks, including C11 interference,
CmpLog non-standard integer and loop checks, x86 `long double` value-profile
IR, the AWK minimizer's host `stat` parsing, and a unit-test relative wrapper
path.

Upstream checks for this commit were green through LLVM 21; the upstream matrix
did not include LLVM 22. Therefore Clang 22 is validated for this repository's
LLVM instrumentation and ICC runtime path, but not claimed as fully green for
the complete upstream AFL++ test matrix.
