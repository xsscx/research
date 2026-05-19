# fuzz/ Instructions - Shared Security Corpus

Use these instructions for `fuzz/` corpus and PoC material.

## Role

`fuzz/` stores reusable malicious inputs, signatures, CVE PoCs, malformed media,
and promoted findings. It is a source corpus for AFL, CFL, analyzer, and image
fuzzer work.

Keep exact file counts and byte totals out of this instruction file. Inspect the
current checkout when inventory matters.

## Tracking Policy

Track durable corpus material:

- named CVE or crash PoCs
- minimized inputs with a stable repro purpose
- reusable malicious signatures
- malformed media fixtures used by tests or fuzzing
- short metadata or README updates that explain provenance

Do not use `fuzz/` as a dumping ground for raw runtime output. Promote only the
artifacts needed for repeatable testing on another VM.

## Promotion Checklist

1. Name the file by bug class, component, and variant when possible.
2. Keep the smallest reproducing input that still triggers the behavior.
3. Add or update a short note when provenance is not obvious from the filename.
4. Record the exact replay command in `docs/pocs/` for security findings.
5. Avoid committing logs, coverage files, or duplicate queue output.

## Seeding Relationships

| Source | Typical Consumer |
|--------|------------------|
| `fuzz/graphics/icc/` | CFL ICC-profile harnesses, AFL ICC tool targets |
| `fuzz/xml/icc/` | `icc_fromxml_fuzzer`, AFL `fromxml` |
| `fuzz/graphics/tif/` | `icc_tiffdump_fuzzer`, AFL `tiffdump` |
| `fuzz/graphics/png/` | AFL `pngdump` and image tooling |
| `fuzz/graphics/jpg/` | AFL `jpegdump` and image tooling |

Use scripts or documented copy commands for seeding. Do not replace curated
source corpus files with transient fuzzer output.

## Safety

Files under `fuzz/` are intentionally hostile. Use sanitizer-instrumented tools
or isolated test environments. Do not open them in normal desktop applications.
