# AFL++ Fuzzing Pipeline — iccDEV Upstream Tools

AFL++ fuzzing infrastructure for the **upstream iccDEV tools directly** — absolute
fidelity by definition (no harness, no wrapper, the actual binary).

## Quick Start

```bash
# 1. Build AFL-instrumented iccDEV (one-time, or after upstream sync)
./afl/build.sh

# 2. Start fuzzing iccFromCube (single instance)
./afl/start.sh fromcube

# 3. Check status
./afl/status.sh

# 4. Stop fuzzing
./afl/stop.sh fromcube

# 5. Triage crashes
./afl/triage.sh fromcube
```

## Architecture

```
afl/
├── README.md          # This file
├── build.sh           # Build iccDEV with AFL++ instrumentation (ASAN+UBSAN)
├── start.sh           # Start AFL fuzzer for a target tool
├── stop.sh            # Stop AFL fuzzer gracefully
├── status.sh          # Show fuzzer stats (all or specific)
├── triage.sh          # Triage crashes/hangs against unpatched upstream
├── rebuild.sh         # Full rebuild cycle (clean + build)
└── seeds/             # Per-tool seed directories (symlinks or copies)
```

## Supported Targets

| Target | Binary | Input Format | Notes |
|--------|--------|-------------|-------|
| `fromcube` | IccFromCube | `.cube` LUT text | CVE-2026-27691 (patched) |

More targets can be added by extending the `case` blocks in `start.sh`.

## Storage Layout (SSD)

```
/mnt/g/fuzz-ssd/afl-{target}/
├── input/          # Seed corpus
├── output/         # AFL output (queue, crashes, hangs)
│   └── default/    # Single-instance output
└── {target}.dict   # Dictionary file
```

## Build Details

- Compiler: `afl-clang-fast++` (clang 17 backend)
- Sanitizers: ASAN + UBSAN (`AFL_USE_ASAN=1 AFL_USE_UBSAN=1`)
- Build dir: `iccDEV/Build-AFL/`
- Libraries: `iccDEV/Build-AFL/IccProfLib/libIccProfLib2.so`

## Adding a New Target

1. Add a `case` block in `start.sh` with binary path and argument template
2. Create seed corpus in `afl/seeds/{target}/` or point to existing seeds
3. Create/copy a dictionary file
4. Add to the targets table above
5. Test: `./afl/start.sh {target}` then `./afl/status.sh`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AFL_SSD` | `/mnt/g/fuzz-ssd` | Base path for AFL working directories |
| `AFL_TIMEOUT` | `5000` | Per-exec timeout in ms |
| `AFL_JOBS` | `1` | Number of parallel AFL instances |
| `AFL_MAP_SIZE` | `131072` | Shared memory map size (from `__afl_final_loc`) |

## CVE Coverage

| CVE | Tool | Status | Description |
|-----|------|--------|-------------|
| CVE-2026-27691 | iccFromCube | Patched (43ae18d) | SIO in parse3DTable(), CWE-190/681 |
