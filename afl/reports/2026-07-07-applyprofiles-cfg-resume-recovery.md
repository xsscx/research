# applyprofiles-cfg empty resume recovery

Date: 2026-07-07

## Problem

Restarting `applyprofiles-cfg` aborted with:

```text
PROGRAM ABORT : No usable test cases in '/home/xss/research/afl/afl-applyprofiles-cfg/output/default/_resume'
```

The target input corpus was valid:

```text
afl-applyprofiles-cfg/input: 21 JSON seed files
```

but the existing AFL instance state had `fuzzer_stats` plus an empty `_resume`
directory and no usable queue files:

```text
afl-applyprofiles-cfg/output/default/_resume/
afl-applyprofiles-cfg/output/default/_resume/.state/
```

Because `start.sh` saw `fuzzer_stats`, it selected `-i-`. AFL++ then treated the
empty `_resume` directory as the resume input and aborted before it could scan
the real input corpus.

## Fix

`start.sh` now checks whether an existing instance has at least one regular test
case in either:

```text
output/<instance>/_resume
output/<instance>/queue
```

If neither directory has usable test cases, `start.sh` archives the unusable
instance directory before launching AFL with the staged input corpus. This keeps
the bad state for inspection but prevents AFL_AUTORESUME from forcing an empty
`_resume` scan.

## Validation

Command:

```text
./start.sh applyprofiles-cfg --run-time 5
```

Relevant output:

```text
Removed 1 stale AFL _resume directory
Existing session has no usable queue/resume corpus - using input corpus
Archived unusable AFL instance state: /home/xss/research/afl/afl-applyprofiles-cfg/output/default.unusable-resume.20260707T204603Z
Scanning '/home/xss/research/afl/afl-applyprofiles-cfg/input'
Loaded a total of 21 seeds.
Attempting dry run with 'id:000000,time:0,execs:0,orig:applyprofiles-basic.json'
len = 447, map size = 5580
Statistics: 129 new corpus items found, 4.12% coverage achieved, 0 crashes saved, 0 timeouts saved, total runtime 0 days, 0 hrs, 0 min, 5 sec
fastresume.bin successfully written with 2259046 bytes.
```

The original AFL abort no longer reproduces.
