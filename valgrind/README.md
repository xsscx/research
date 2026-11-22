# Local Valgrind Tool-Family Analysis

This component builds a separate non-sanitized Debug iccDEV tree and runs
registered CLI and threaded-regression targets under the Valgrind tool family.
Never point it at the ASAN/UBSAN binaries in `iccDEV/Build` or `afl/bin`.

## Quick start

```bash
./valgrind/build.sh
./valgrind/run.sh --tool memcheck all
./valgrind/run.sh --tool helgrind connect-thread applyprofiles-row applysearch-row benchapply
./valgrind/run.sh --tool drd connect-thread applyprofiles-row applysearch-row benchapply
./valgrind/status.sh
```

`run.sh` also supports `drd`, `massif`, and `callgrind`. Use `all` to run the
complete registry. Each run creates an ignored evidence directory under
`valgrind/output/` containing stdout, stderr, the Valgrind log, generated
artifacts, and `summary.tsv`. A finding or timeout makes the runner fail unless
`--allow-findings` is supplied for evidence-collection work.
Missing completion summaries or profiler output are classified as
`incomplete-log` and always fail the run.

`--allow-findings` applies only to completed Valgrind diagnostics. Target
failures, signals, timeouts, setup failures, incomplete logs, and output
verification failures always fail the run. The runner records Valgrind's used
default suppressions in each Memcheck, Helgrind, and DRD log.

## One-line analysis commands

Run each supported Valgrind tool across the complete target registry:

```bash
./valgrind/run.sh --tool memcheck all
./valgrind/run.sh --tool helgrind all
./valgrind/run.sh --tool drd all
./valgrind/run.sh --tool massif all
./valgrind/run.sh --tool callgrind all
```

For faster, high-signal race coverage, run Helgrind and DRD only on the four
targets that exercise threads:

```bash
./valgrind/run.sh --tool helgrind connect-thread applyprofiles-row applysearch-row benchapply
./valgrind/run.sh --tool drd connect-thread applyprofiles-row applysearch-row benchapply
```

These targets cross the threaded CMM dispatch threshold rather than merely
constructing a threaded wrapper. `applyprofiles-row` performs four 1,024-pixel
row batches with four active threads. `applysearch-row` uses 257 records, which
keeps DRD bounded while engaging two active threads. `benchapply` repeats
2,048-pixel calls at one, two, and four threads. For a broader inverse-search
Helgrind pass, use
`VALGRIND_APPLYSEARCH_LINES=746 ./valgrind/run.sh --tool helgrind applysearch-row`.
The full input is intentionally not the default DRD smoke because it can exceed
three minutes under DRD.

For one complete tool-family pass from a single shell line, run the full target
registry under every supported tool. The loop stops on the first finding or
timeout:

```bash
for tool in memcheck helgrind drd massif callgrind; do ./valgrind/run.sh --tool "$tool" all || break; done
```

For evidence collection that continues after findings, use a unique output
directory for each tool and allow recorded findings:

```bash
for tool in memcheck helgrind drd massif callgrind; do ./valgrind/run.sh --tool "$tool" --allow-findings --output-dir "valgrind/output/full-$tool" all || break; done
```

The registry includes profile parsing and representation tools, calculator and
named-CMM application, threaded apply paths, `.cube` conversion, and v5
display/observer conversion. Use `./valgrind/run.sh --list` to print the current
source-of-truth inventory. `applynamedcmm-calculator` is the short deterministic
reproduction for the process-lifetime calculator registry reported in iccDEV
issue #3095. Repeating a target on one command line runs it again and retains
each repetition in a distinct evidence subdirectory; it does not add structural
coverage by itself.

## Known findings and tool limitations

See [`KNOWN_FINDINGS.md`](KNOWN_FINDINGS.md) for reviewed false positives,
affected targets, reference counts, and the boundaries of each classification.
Known findings remain visible in logs and `summary.tsv`; they are not silently
suppressed. Use `--allow-findings` only to finish evidence collection, then
compare every reported context with the catalog. A changed or unlisted
signature requires investigation.

Memcheck reports all leak kinds in its log, but only definite, indirect, and
possible losses count as runner errors. `still reachable` process-lifetime
registries remain visible for review without being mislabeled as lost memory.

Successful targets also verify their declared outputs. The registry checks
nonempty generated artifacts and stdout where applicable; `tiffdump` pins the
SHA-256 of the extracted profile so raw extraction changes cannot pass solely
because the tool returned zero.

The build defaults to `iccDEV/` and `valgrind/build/`. Override them without
editing scripts; explicit CLI paths take precedence and work for both build and
run automation:

```bash
./valgrind/build.sh --clean --source-dir /path/to/iccDEV \
  --build-dir /home/xss/qa/iccdev-valgrind-build
./valgrind/run.sh --tool memcheck --source-dir /path/to/iccDEV \
  --build-dir /home/xss/qa/iccdev-valgrind-build all
```

The build explicitly disables ASAN, UBSAN, integer/float sanitizers, TSan,
MSan, LSan, fuzzing instrumentation, and LTO. It rejects produced executables
and build-tree libraries that dynamically or statically expose sanitizer
runtimes.

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
