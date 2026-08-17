---
mode: agent
description: Dump a TIFF and preserve its embedded ICC profile with ColorBleed diagnostics
---

# TIFF and embedded ICC ColorBleed analysis

Use the sandboxed unsafe TIFF reader before invoking profile-only tools:

```bash
out_dir=$(mktemp -d) && colorbleed_tools/iccTiffDump_unsafe INPUT.tif "$out_dir/embedded.icc" >"$out_dir/tiff.log" 2>"$out_dir/tiff.err"; rc=$?; printf 'exit=%d output=%s\n' "$rc" "$out_dir/embedded.icc"
```

Report the command exit code, sandbox status, TIFF directory count, embedded
profile length, extraction path, and whether ICC parsing and validation ran.
The output ICC is the TIFF field's original byte sequence; do not replace it
with a profile reserialized by `SaveIccProfile`.

Interpret exit 6 as a validation finding with a preserved artifact. Treat exit
128 or greater, a sanitizer report, or a sandbox crash status as a crash. If
the profile exists, continue with `iccDumpAll --diag --read` and
`iccDiagnosticLoad --all` even when the TIFF command returned nonzero.
