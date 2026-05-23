# iccDumpProfile

Dump ICC profile headers, tag tables, and decoded tag data in a human-readable
format.

## Usage

```text
iccDumpProfile {-v} {verbosity_int} {--diag} {--read} profile {tagId/"ALL"}
```

## Arguments

| Argument | Required | Notes |
|----------|----------|-------|
| `-v` | No | Enable validation while dumping |
| `verbosity_int` | No | Verbosity level, usually `1` to `100` |
| `--diag` | No | Emit diagnostic size checks and tag-load tracing to stderr |
| `--read` | No | Use eager `ReadIccProfile` loading instead of lazy `OpenIccProfile` |
| `profile` | Yes | Input ICC profile path |
| `tagId` or `ALL` | No | Dump one tag or every tag |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `255` | Graceful tool error or unsupported case |

## Common Examples

```bash
export LD_LIBRARY_PATH=iccDEV/Build/IccProfLib:iccDEV/Build/IccXML

# Basic dump
iccDumpProfile test-profiles/sRGB_D65_MAT.icc

# Dump with validation
iccDumpProfile -v test-profiles/sRGB_D65_MAT.icc

# Dump one tag
iccDumpProfile test-profiles/sRGB_D65_MAT.icc desc

# Dump every tag
iccDumpProfile test-profiles/sRGB_D65_MAT.icc ALL

# Diagnostic eager-load run for hostile inputs
iccDumpProfile --diag --read suspicious.icc ALL
```

## Output

Typical output includes:

1. Header fields such as class, color space, PCS, version, and profile ID.
2. The tag table with signature, offset, and size.
3. Decoded tag contents when the tag type is understood by the library.

## Notes

- NamedColor and other edge-case profiles may return `255` without crashing.
- For crash triage or hostile inputs, run the ASAN/UBSAN build from
  `docs/iccDEV/shell-helpers/README.md`.
- For XML output instead of text output, use `../iccToXml/README.md`.
