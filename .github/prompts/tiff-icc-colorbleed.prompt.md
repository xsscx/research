---
mode: agent
description: Dump a TIFF and preserve its embedded ICC profile with ColorBleed diagnostics
---

# TIFF and embedded ICC ColorBleed analysis

Use the sandboxed unsafe TIFF reader before invoking profile-only tools:

```bash
out_dir=$(mktemp -d) && colorbleed_tools/iccTiffDump_unsafe --evidence-json INPUT.tif "$out_dir/embedded.icc" >"$out_dir/evidence.json" 2>"$out_dir/tiff.err"; rc=$?; printf 'exit=%d evidence=%s output=%s\n' "$rc" "$out_dir/evidence.json" "$out_dir/embedded.icc"
```

Validate the JSON with `jq` and report the command exit code, sandbox status,
TIFF directory and ICC-bearing-directory counts, selected directory, embedded
profile length and SHA-256, extraction path, and whether ICC open, recursive tag
loading, and validation ran. Preserve stderr separately from the JSON evidence.
The output ICC is the TIFF field's original byte sequence; do not replace it
with a profile reserialized by `SaveIccProfile`.

Interpret exit 6 as a validation finding with a preserved artifact. Treat exit
86 as a strict sanitizer finding before applying the generic 1-127 soft-failure
rule. Treat exit 128 or greater, a sanitizer report, or a sandbox crash status as
a crash. External timeout exit 124 is a harness timeout. If
the profile exists, continue with `iccDumpAll --diag --read` and
`iccDiagnosticLoad --all` even when the TIFF command returned nonzero.

Interpret exit 66 as an unresolved input path and verify the source file before
investigating libtiff or iccDEV. The repository QA fixture is
`colorbleed_tools/test-data/1x1-rgb8--sRGB_v4_ICC_preference.tiff`; keep fixture
references inside the owning component rather than the ignored `fuzz/` checkout.

With upstream iccDEV `3e348201` or later, bounded recursive tag loading can make
a deeply nested embedded profile exit 5 after byte-exact extraction. Preserve
and compare the extracted artifact; do not classify that soft failure as a
crash unless sanitizer or signal evidence is also present.

Use the complete exit and artifact contract in `colorbleed_tools/Readme.md`.
Do not infer extraction success from file existence alone; require
`icc.extracted=true` and compare the recorded digest with the artifact.
