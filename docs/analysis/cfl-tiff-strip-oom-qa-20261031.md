# CFL TIFF decoded-strip OOM QA — 2026-10-31

## Result

Three 143-byte TIFF artifacts deterministically made unpatched
`CTiffImg::Open()` request 3.40–3.42 GiB. The file size did not bound the
decoded strip geometry. The allocation happened before any pixel read, so
libFuzzer reported OOM immediately.

Optional patch `014-tiff-strip-buffer-limit.patch` applies the existing
256 MiB/caller tile-band budget to strip-backed images before `malloc()`.
Metadata-only inspection remains available.

## Artifacts and replay

| SHA-1 / filename | SHA-256 | Unpatched request | Patched ASan |
|---|---|---:|---:|
| `0463e739480580f090fe7caad39f181ec66e582e` | `0f9c2e731b11733379bfd03214ca23b02440a514b8088149ef7e259e7176a1d2` | 3,422,546,544 B | 0.04 s / 49,672 KiB |
| `3fbe42154553191fe00deb3047d90f85ffc9a60a` | `e261bd06972933bdf4cdc6e5595e4632b07afb133a94add37862f64eb24cee64` | 3,404,655,216 B | 0.04 s / 49,424 KiB |
| `ff3a72e7f4a2bcfa162f0598a994cae8759ddfe0` | `dfd14cf85fadb3aec1f73f92c8b3b52afafc10e36887505a08efaed4fcc3dac8` | 3,409,963,632 B | 0.04 s / 49,416 KiB |

The unpatched replays exited 71 in 0.11–0.14 s at about 49 MiB actual RSS
because libFuzzer rejected the requested allocation. All patched replays
exited 0 with no sanitizer finding.

The files were reported as originating from
`/mnt/f/iccdev-spectral-corpus/`. The current local 152-file corpus contains
no exact SHA-1 match, so the artifacts are mutations/minimizations or came from
a different remote corpus snapshot. All 60 TIFFs currently in that corpus
passed the patched ASan harness in 1.82 s (397,996 KiB peak RSS).

## Product-tool reproduction

`iccTiffDump` is metadata-only and does not reach this allocation.
`iccApplyProfiles` does. This bounded one-liner is safe for an unpatched
Release build:

```bash
(ulimit -v 524288; strace -f -e trace=brk,mmap,mmap2 iccApplyProfiles /mnt/f/artifacts/oom-0463e739480580f090fe7caad39f181ec66e582e /tmp/iccdev-oom-repro-out.tif 0 0 0 0 0 Testing/sRGB_v4_ICC_preference.icc 0)
```

The unpatched trace contained failed anonymous mappings of 3,422,547,968 and
3,422,679,040 bytes. The patched Release tool instead reported:

```text
Invalid or oversized TIFF strip buffer (maximum 256 MiB per image or caller memory limit).
```

No large mapping appeared in the patched trace.

## Regression coverage

The existing `iccdev.tiff-create-overflow` regression now creates a tiny
deflate-compressed TIFF with a genuine 2.1 MiB decoded strip. Metadata-only
open succeeds with a 1 MiB caller budget; pixel open must fail. The test passed
in both Release and ASan configurations. The full optional patch inventory
also passed `.github/scripts/check-afl-cfl-patches.sh`.
