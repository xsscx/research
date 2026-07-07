# applyprofiles-cfg argc and coverage review

Date: 2026-07-07

## Scope

Reviewed the AFL `applyprofiles-cfg` lane against the `iccApplyProfiles`
command-line parser in:

- `iccDEV/Tools/CmdLine/IccApplyProfiles/iccApplyProfiles.cpp`
- `afl/targets.sh`
- `afl/start.sh`
- `afl/map.sh`
- `afl/minimize.sh`
- `afl/triage.sh`
- `afl/coverage.sh`

## Findings

`iccApplyProfiles` documents and accepts:

```text
iccApplyProfiles {-threads N} -cfg config_file
```

The previous AFL lane used only:

```text
-cfg @@
```

That reached JSON config parsing, but it did not exercise the documented
`-threads N` prefix path for the config mode.

A second coverage blocker was the process working directory. The checked-in JSON
configs use repo-root relative fixture paths such as:

```text
test-profiles/tiff-codecs/seed-tiff-none-rgb-8x8.tif
docs/Testing/test-data/rgb-4x4-8bit.tif
```

Running `./start.sh applyprofiles-cfg` from `afl/` left the target process in
`/home/xss/research/afl`, so the valid config seed failed before TIFF/image
application:

```text
exit=255
TIFFOpen: test-profiles/tiff-codecs/seed-tiff-none-rgb-8x8.tif: No such file or directory.
File [test-profiles/tiff-codecs/seed-tiff-none-rgb-8x8.tif] cannot be opened.
```

Running the same binary and config from `/home/xss/research` completed:

```text
exit=0
12% 25% 37% 50% 62% 75% 87% 100%
```

## Changes Made

- `targets.sh`: changed `applyprofiles-cfg` argv to `-threads 1 -cfg @@`.
- `targets.sh`: added `SEED_INCLUDE_REGEX` and per-config-lane filters so
  applyprofiles, applynamedcmm, and applysearch config lanes do not seed mostly
  unrelated tool schemas.
- `start.sh`: applies `SEED_INCLUDE_REGEX`.
- `start.sh`: runs seed dry-runs and `afl-fuzz` from the repo root.
- `map.sh`, `minimize.sh`, `triage.sh`, `coverage.sh`: replay targets from the
  repo root so reporting, minimization, and triage match live fuzzing.

## Validation

Syntax and encoding:

```text
bash -n start.sh targets.sh map.sh minimize.sh triage.sh coverage.sh
file start.sh targets.sh map.sh minimize.sh triage.sh coverage.sh
```

All edited shell scripts are ASCII text, and `bash -n` returned success.

Seed-only validation used a temporary AFL base:

```text
AFL_BASE=/tmp/afl-applyprofiles-cfg-test.hnj90A ./start.sh applyprofiles-cfg --fresh --reseed --seed-only --seed-order sorted
```

Result:

```text
json-configs: 2 eligible files
malformed-json: 19 eligible files
dry-run rejected 0 crashing/hanging seed(s)
Seeds: 21 files
Command shape: -threads 1 -cfg @@
```

Short AFL smoke run:

```text
AFL_BASE=/tmp/afl-applyprofiles-cfg-run.TudNy6 ./start.sh applyprofiles-cfg --fresh --reseed --seed-order sorted --run-time 20 --power-schedule explore
```

Result:

```text
Loaded a total of 21 seeds.
Dry-run map size for applyprofiles-basic.json: 5580
run_time: 20
execs_done: 3427
execs_per_sec: 171.28
corpus_count: 235
corpus_found: 214
edges_found: 6397
total_edges: 152116
bitmap_cvg: 4.21%
saved_crashes: 0
saved_hangs: 0
command_line: afl-fuzz ... -- /home/xss/research/afl/bin/iccApplyProfiles -threads 1 -cfg @@
```

Showmap replay:

```text
AFL_BASE=/tmp/afl-applyprofiles-cfg-run.TudNy6 ./map.sh applyprofiles-cfg --queue --out /tmp/applyprofiles-cfg-queue-showmap.txt
```

Result:

```text
Mapped 235 input(s)
Captured 6397 tuples
Coverage: 6397 edges out of 152128 existing (4.21%)
```

LLVM source coverage smoke:

```text
AFL_BASE=/tmp/afl-applyprofiles-cfg-run.TudNy6 ./coverage.sh applyprofiles-cfg --no-reachability --report-root /tmp/afl-applyprofiles-cfg-coverage-20260707T203031Z --jobs 2 --output-dir /tmp/afl-applyprofiles-cfg-run.TudNy6/afl-applyprofiles-cfg/output --report-name applyprofiles-cfg-smoke
```

Result:

```text
Replaying 236 queue files
TOTAL: 0.17% region, 0.39% function, 0.16% line, 0.07% branch coverage
Tools/CmdLine/IccApplyProfiles/iccApplyProfiles.cpp: 7.55% region, 10.00% function, 3.73% line coverage
IccConnect/IccLibConnect/IccCmmConfig.cpp: 0.35% region, 5.38% function, 1.01% line coverage
IccConnect/IccLibConnect/IccJsonUtil.cpp: 9.13% region, 4.55% function, 8.65% line coverage
```

The LLVM source coverage smoke remains parser-heavy after only 20 seconds. The
AFL bitmap result is the better short-run signal here: the valid config now
enters a 5580-edge path instead of failing on relative file paths, and the queue
replay consistently reports 6397 edges.

## Follow-up

Run a longer fresh `applyprofiles-cfg` campaign after this change, then rerun
`coverage.sh` with reachability enabled. If source coverage remains limited to
the config parser after a longer queue, add targeted valid applyprofiles JSON
seeds for alternate `imageFiles`, `connect.threads`, embedded-profile, and
profile-sequence shapes.
