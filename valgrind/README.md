# Local Valgrind and Helgrind Tooling

This component builds a separate non-sanitized Debug iccDEV tree and runs
registered CLI and threaded-regression targets under the Valgrind tool family.
Never point it at the ASAN/UBSAN binaries in `iccDEV/Build` or `afl/bin`.

## Quick start

```bash
./valgrind/build.sh
./valgrind/run.sh --tool memcheck dump fromxml fromjson
./valgrind/run.sh --tool helgrind connect-thread applyprofiles-row benchapply
./valgrind/status.sh
```

`run.sh` also supports `drd`, `massif`, and `callgrind`. Use `all` to run the
complete registry. Each run creates an ignored evidence directory under
`valgrind/output/` containing stdout, stderr, the Valgrind log, generated
artifacts, and `summary.tsv`. A finding or timeout makes the runner fail unless
`--allow-findings` is supplied for evidence-collection work.

The build defaults to `iccDEV/` and `valgrind/build/`. Override them without
editing scripts:

```bash
VALGRIND_ICCDEV_DIR=/path/to/iccDEV VALGRIND_BUILD_DIR=/home/xss/qa/iccdev-valgrind ./valgrind/build.sh --clean
```

The build explicitly disables ASAN, UBSAN, integer/float sanitizers, TSan,
MSan, LSan, fuzzing instrumentation, and LTO. It rejects produced executables
that dynamically link a sanitizer runtime.

## Container parity

The published iccDEV image contains Valgrind and its development headers. Run
the same local component inside that image with:

```bash
./valgrind/container.sh build
./valgrind/container.sh run --tool helgrind connect-thread
```

Set `ICCDEV_VALGRIND_IMAGE` or pass `--image IMAGE` to select a local image.
The repository is mounted at `/research`; build and evidence output remain in
the ignored `valgrind/container-build/` and `valgrind/container-output/`
directories, separate from native CMake state. The image's installed iccDEV
tools are sanitizer-instrumented, so the wrapper deliberately builds and runs
the separate non-sanitized tree instead.

## Target registry

`targets.sh` is the source of truth for target commands, required fixtures,
CMake targets, and recommended analysis modes. Validate edits with:

```bash
bash -n valgrind/*.sh
shellcheck valgrind/*.sh
./valgrind/validate.sh
```
