# Security Analysis: test-hoyt.icc

## Profile Metadata

| Field | Value |
|-------|-------|
| File | test-hoyt.icc |
| Size | 7460 bytes (0x1D24) |
| ICC Version | 4.0.0 |
| Device Class | mntr (Display) |
| Color Space | RGB |
| PCS | XYZ |
| CMM Type | HOYT (non-standard) |
| Platform | HOYT (non-standard) |
| Creator | ADBE (Adobe) |
| Rendering Intent | Relative Colorimetric |
| Description | e-sRGB |
| Copyright | Copyright 2022 Hoyt LLC |
| Header Date | 2002-10-15 |
| Tag Count | 11 |
| MD5 | 529294e457025111dbcb23be10ab12e4 |

## Findings Summary

| Severity | Count | Description |
|----------|-------|-------------|
| CRITICAL | 1 | Crafted curve count OOM/DoS vector (4 instances) |
| HIGH | 2 | Duplicate tag signature, type confusion |
| MEDIUM | 3 | Tag aliasing, non-monotonic curve, non-standard signatures |
| INFO | 3 | Validation failure, date mismatch, missing tags |

## CRITICAL: Crafted Curve Count - OOM/DoS Vector

All four transform tags in this profile contain a B-curve (channel 1 / green) with
a curve entry count of **0x7FFFFFF4** (2,147,483,636). A parser allocating memory
based on this count would attempt a **~4 GB allocation** (`count * sizeof(uint16)`
= 4,294,967,272 bytes), triggering out-of-memory conditions or denial of service.

The crafted count also risks **signed integer overflow** when computed as
`count * 2` in 32-bit arithmetic (result exceeds INT32_MAX).

### Affected Tags

| Tag | Offset (abs) | Curve Position | Count Value |
|-----|-------------|----------------|-------------|
| A2B0 | 0x0228 | B-curve ch1 | 0x7FFFFFF4 |
| A2B1 | 0x08C0 | B-curve ch1 | 0x7FFFFFF4 |
| B2A0 | 0x0F58 | B-curve ch1 | 0x7FFFFFF4 |
| B2A1 | 0x1658 | B-curve ch1 | 0x7FFFFFF4 |

The aliased B2A2 entries inherit the same vector from A2B0 and B2A0.

### Impact

- **OOM/DoS**: Any ICC library that allocates based on the untrusted curve count
  will attempt a ~4 GB allocation per transform load
- **Integer overflow**: `count * sizeof(uint16)` overflows signed 32-bit integers
- **Buffer over-read**: Parsers reading `count` entries from the 7460-byte file
  will read far beyond file boundaries
- **Attack surface**: The vector is embedded in every rendering intent (perceptual,
  relative colorimetric, saturation), maximizing trigger probability regardless of
  which intent the application requests

### Mitigation

ICC parsers must validate curve entry counts against both:
1. A reasonable upper bound (e.g., 65536 entries)
2. The remaining bytes in the tag/file before allocation

## HIGH: Duplicate Tag Signature (B2A2)

The tag signature `B2A2` (0x42324132) appears **twice** in the tag table:

| Index | Signature | Offset | Size | Tag Type |
|-------|-----------|--------|------|----------|
| 6 | B2A2 | 0x000001F4 | 0x0698 | mAB |
| 9 | B2A2 | 0x00000F24 | 0x0700 | mBA |

The ICC specification requires tag signatures to be unique within the tag table.
Duplicate signatures create ambiguity: the parser's behavior depends on whether it
uses the first or last matching entry, potentially leading to inconsistent results
across implementations.

## HIGH: Type Confusion (B2A2 -> mAB)

The first B2A2 entry (index 6) points to data at offset 0x01F4 with tag type
`mAB`. B2A (B-to-A) transforms should use `mBA` type data structures. The
`mAB` and `mBA` types have different processing pipelines:

- **mAB** (A-to-B): B curves -> Matrix -> M curves -> CLUT -> A curves
- **mBA** (B-to-A): B curves -> CLUT -> M curves -> Matrix -> A curves

A parser loading B2A2 and interpreting the data as `mBA` when it is actually
`mAB` would misinterpret the offset table and curve/matrix/CLUT organization,
potentially causing memory corruption, incorrect offsets, or crashes.

## MEDIUM: Tag Aliasing (A2B/B2A Shared Data)

Two pairs of tags share the same data offset and size:

| Tags | Shared Offset | Size | Type |
|------|--------------|------|------|
| A2B0 + B2A2 | 0x000001F4 | 0x0698 | mAB |
| B2A0 + B2A2 | 0x00000F24 | 0x0700 | mBA |

While tag sharing (aliasing) is permitted by the ICC specification, sharing data
between structurally different transform directions (A-to-B and B-to-A) is
semantically incorrect. The forward and reverse transforms are not interchangeable.

## MEDIUM: Non-Monotonic Curve Entries

The first M-curve (channel 0) in the A2B0 tag contains non-monotonic entries
at indices 70-71:

| Index | Value | Delta |
|-------|-------|-------|
| 69 | 14571 (0x38EB) | - |
| 70 | 14136 (0x3738) | -435 |
| 71 | 13694 (0x357E) | -442 |
| 72 | 14787 (0x39C3) | +1093 |

Tone reproduction curves (TRCs) in well-formed ICC profiles are expected to be
monotonically increasing. Non-monotonic values can trigger undefined behavior
in parsers or color management systems that assume monotonicity for
interpolation or inverse lookup operations.

## MEDIUM: Non-Standard Platform/CMM Signature

The CMM type and platform signature `HOYT` (0x484F5954) is not a registered
ICC signature. Non-standard signatures may trigger unexpected code paths in
platform-specific ICC implementations that switch on known platform values.

## INFO: Profile Fails Standard Validation

The profile cannot be parsed through the standard ICC validation pathway
(round-trip validation fails with "Error reading ICC profile"). This confirms
structural anomalies that prevent normal processing.

## INFO: Date/Copyright Mismatch

The profile header date is 2002-10-15 while the copyright text reads
"Copyright 2022 Hoyt LLC". The profile creator field shows ADBE (Adobe).

## INFO: Missing Optional Tags

The profile lacks manufacturer description (`dmnd`) and device model
description (`dmdd`) tags. While optional, their absence combined with other
anomalies contributes to the overall assessment.

## Tag Table

```
Idx  Sig   Offset      Size        Type   Notes
---  ----  ----------  ----------  -----  -----
 0   cprt  0x00000108  0x0000006E  mluc   Copyright text
 1   desc  0x00000178  0x00000028  mluc   Description: e-sRGB
 2   wtpt  0x000001A0  0x00000014  XYZ    White point
 3   bkpt  0x000001B4  0x00000014  XYZ    Black point
 4   chad  0x000001C8  0x0000002C  sf32   Chromatic adaptation
 5   A2B0  0x000001F4  0x00000698  mAB    [CRITICAL] OOM in B-curve ch1
 6   B2A2  0x000001F4  0x00000698  mAB    [HIGH] Duplicate + type confusion
 7   A2B1  0x0000088C  0x00000698  mAB    [CRITICAL] OOM in B-curve ch1
 8   B2A0  0x00000F24  0x00000700  mBA    [CRITICAL] OOM in B-curve ch1
 9   B2A2  0x00000F24  0x00000700  mBA    [HIGH] Duplicate tag
10   B2A1  0x00001624  0x00000700  mBA    [CRITICAL] OOM in B-curve ch1
```

## Assessment

This ICC profile is a **crafted security test case** designed to exercise parser
edge cases in ICC library implementations. The primary attack vector is a
systematically embedded OOM/DoS trigger (curve count 0x7FFFFFF4) present in every
color transform tag, ensuring that any rendering intent selection will encounter the
malicious value. Secondary vectors include type confusion through tag aliasing and
duplicate signatures.

**Recommendation**: Do NOT use in production color workflows. This profile is
suitable as a test corpus entry for fuzzing and regression testing of ICC parsers.

## Tools Used

- iccanalyzer-lite v2.9.1 (19-phase security heuristic analysis)
- iccanalyzer-lite ninja-full mode (structural inspection)
- Custom Python analysis scripts (tag table, curve count, monotonicity validation)
- ICC Profile MCP Server (round-trip validation, XML conversion)

## Analysis Date

2026-02-15
