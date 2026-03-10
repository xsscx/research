# CFL Patches — Retired (March 2026)

## Decision

All 62 CFL library patches were retired on 2026-03-10. The patching system caused
repeated multi-hour rework cycles due to:

1. Context conflicts on upstream sync (patches depend on exact line numbers)
2. `patch --dry-run --forward` masking 3 failure modes (reversed, fuzz-offset, context-shift)
3. False success claims — patches reported as applied but not actually compiled in
4. Compounding verification debt — each rebuild requires full 3-phase ground truth check

## New Approach: Zero-Patch Fuzzing

Fuzzers now run against **unpatched upstream iccDEV**. LibFuzzer's built-in mechanisms
handle timeouts and OOM:

```bash
-timeout=30        # Kill inputs that take >30s
-rss_limit_mb=4096 # Kill on OOM >4GB
-max_len=5242880   # Cap input size at 5MB
```

Real crashes, timeouts, and OOM findings are reported upstream as issues.

## Patch History

62 patches (+ 21 upstreamed/deleted = 83 total patch numbers used) were created
between 2024-2026 to harden iccDEV for fuzzing:

- **Allocation caps** (CFL-001 through CFL-018): Cap realloc/malloc sizes
- **Enum bounds** (CFL-008, CFL-013, CFL-024, CFL-054, CFL-057): Validate enum loads
- **Float→int overflow** (CFL-034, CFL-042, CFL-046, CFL-050): Clamp conversions
- **Depth/recursion limits** (CFL-061, CFL-074, CFL-079, CFL-081): Cap recursion
- **Timeout prevention** (CFL-074, CFL-075, CFL-076): Ops budgets, iteration caps
- **Describe() output caps** (CFL-078, CFL-080): Limit string generation
- **Bounds checks** (CFL-069, CFL-071, CFL-082): Array/buffer bounds validation

## Files

- `*.patch` — The 62 retired patch files
- `verify-patches.sh` — 3-phase ground truth verification script (also retired)
