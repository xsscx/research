# CFL ToXML composite-directory expansion QA - 2026-11-12

## Outcome

Two 49 KiB ToXML slow units used nested `tagArrayType` (`tary`) children whose
offsets overlapped their own position tables. The malformed directories were
accepted by `CIccTagArray::Read()`, after which shared nested children multiplied
core validation, profile description, and XML or JSON serialization work.

Optional CFL patch `017-composite-tag-directory-bounds.patch` validates every
nonempty array and struct child range against the end of its complete serialized
directory before any child is loaded. It also corrects the tag-array fixed header
from 20 bytes to the 16 bytes that the reader consumes and the writer emits.

No regression test, test script, or fixture was added to the research repository.
Verification used the two external artifacts, existing CFL fuzzers, an existing
iccDEV composite-recursion helper, and an existing valid composite profile.

## Evidence and vulnerable path

- Artifact `toxml-slow-unit-9c76dd84c120203a20b64b56695ae0f1b5a33f25`
  - 49,072 bytes
  - SHA-256: `8141186c1a7d74b53ddd76610053e461130072dc440f7749762e3a1ffe7eb5df`
- Artifact `toxml-slow-unit-e7bdf51ae8c0f2a43fbed09e228d8cec9dfcd2b0`
  - 49,995 bytes
  - SHA-256: `311ab1972396471e4e5dd09e876572e095ef3f605491e3e05d92ec2d2dd2301c`
- iccDEV baseline: `93eb27922619e826e13a049ce9d8a9440582909a`

In the first artifact, the array at file offset `0xc0` declares 500 entries.
Its 16-byte fixed header and 4,000-byte position table end at relative offset
4,016, but its first child begins at relative offset 24. In the second artifact,
the array at file offset `0xa8` declares 512 entries and also places its first
child at relative offset 24 instead of at or after directory offset 4,112.

The array reader previously checked child extents only against the whole tag.
The struct reader similarly allowed a child after its fixed header but before
the end of its member directory. Both writers reserve the entire directory
before writing children, so the shared reader invariant is that each nonempty
child begins at or after the complete directory end.

Before patch 017, contained runs on the patch-016 CFL build produced:

- both `icc_toxml_fuzzer` replays: timeout after 45 seconds, exit 124;
- `icc_tojson_fuzzer` on the first artifact: timeout after 45 seconds;
- `icc_dump_fuzzer` on the first artifact: 20.9 seconds;
- `icc_proflib_fuzzer` on the first artifact: 3.5 seconds.

The unpatched `iccToXml` product tool expanded the first 49 KiB input to exactly
67,108,864 output bytes before the containment file-size limit stopped it. The
wrapper returned status 153, consistent with SIGXFSZ at the 64 MiB limit.

This is an uncontrolled resource-consumption issue (CWE-400/CWE-834) reachable
through untrusted ICC input. Severity beyond local tool availability depends on
how a downstream application exposes iccDEV profile conversion.

## Patch boundary

Patch 017 changes only `IccProfLib/IccTagComposite.cpp`:

- the array fixed-header calculation now represents its four 32-bit fields;
- widened arithmetic computes each complete array or struct directory end;
- every nonempty child extent is validated before any nested child is loaded;
- the array reader retains its existing null-slot behavior when either the
  serialized offset or size is zero;
- exact-boundary children and shared child offsets remain supported.

The patch does not impose a serializer output budget. A well-formed nested array
with many legal shared child offsets can still expand when each logical array
slot is serialized. That is a separate format and resource-policy question, not
a reason to accept children that reinterpret their own directory bytes.

## Verification

The fresh patched build command was:

```bash
./cfl/build.sh clean && ./cfl/build.sh --with-patches
```

It cloned upstream `master`, applied patches 001 through 017, and built 24/24
AddressSanitizer/UBSan/integer sanitizer fuzzers. The libraries reported 2,446
ASan, 381 UBSan, and 3,198 coverage symbols. The patched ToXML fuzzer SHA-256 is
`3c10d3fbd5ce1f631c62f6f93d6c067d3652ef432cb70685eb30d8b9b009e4c9`.

Contained post-patch results were:

- first ToXML artifact: exit 0 in 1 ms;
- second ToXML artifact: exit 0 in 2 ms;
- first artifact through ToJSON: exit 0 in 1 ms;
- first artifact through DumpProfile coverage: exit 0 in 3 ms;
- `iccDEV/Testing/Named/NamedColor.icc` through ToXML: exit 0 in 14 ms;
- the same valid profile through the core profile harness: exit 0 in 13 ms.

All contained runs reported no sanitizer finding, timeout, or memory resource
limit. The existing composite-recursion helper printed
`composite tag recursion-depth guard OK` when compiled and linked with the exact
CFL sanitizer flags. Its wrapper script could not infer sanitizer flags from
this CMake configuration and initially failed at link time on unresolved ASan
symbols; the helper itself passed once invoked with the build's actual flags.

The patch-stack applicability command was:

```bash
.github/scripts/check-afl-cfl-patches.sh
```

It accepted every AFL and CFL patch, including patch 017.
