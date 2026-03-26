# ICC Profile Analysis Report

**Profile**: `test-profiles/fuzzed-xnu-non_premultiplied_alpha.tif`
**File Size**: 962 bytes
**SHA-256**: `c0b20307635b3427858a80f0845cda68ecf242a54fb062dec450aacd4c51c803`
**File Type**: TIFF image data, big-endian, direntries=14, height=16, bps=0, compression=none, PhotometricInterpretation=RGB, orientation=upper-left, width=16
**Date**: 2026-03-26T16:57:49Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 0 | Clean |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 2 | Error |
| `-xt` (LUT text export) | 2 | Error |
| `-cube` (cube export) | 1 | No 3D CLUT |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 0**

```
=======================================================================
IMAGE FILE ANALYSIS â€” TIFF
=======================================================================
File: /home/h02332/po/research/test-profiles/fuzzed-xnu-non_premultiplied_alpha.tif

--- TIFF Metadata ---
  Dimensions:      16 Ã— 16 pixels
  Bits/Sample:     8
  Samples/Pixel:   3
  Compression:     None (Uncompressed) (1)
  Photometric:     RGB (2)
  Planar Config:   Contiguous (Chunky) (1)
  Sample Format:   Unsigned Integer (1)
  Orientation:     1
  Rows/Strip:      16
  Strip Count:     1

--- TIFF Security Heuristics ---
[H139] TIFF Strip Geometry Validation (CWE-122/CWE-190)
      [OK] Strip geometry valid

[H140] TIFF Dimension and Sample Validation (CWE-400/CWE-131)
      [OK] Dimensions valid

[H141] TIFF IFD Offset Bounds Validation (CWE-125)
      [OK] All IFD offsets within file bounds

[H149] TIFF IFD Chain Cycle Detection (CWE-835)
      [OK] IFD chain is acyclic

[H150] TIFF Tile Geometry Validation (CWE-122/CWE-131)
      [OK] Strip-based image â€” tile geometry N/A


--- Injection Signature Scan ---
  [OK] No injection signatures detected

--- Embedded ICC Profile ---
  [INFO] No embedded ICC profile (TIFFTAG_ICCPROFILE absent)
  This TIFF relies on implicit color space from Photometric tag.
  [INFO] Photometric=RGB without ICC â†’ assumed sRGB

=======================================================================
IMAGE ANALYSIS SUMMARY
=======================================================================
Format:     TIFF
Dimensions: 16 Ã— 16
Findings:   0
=======================================================================
```

---

## Command 2: Ninja Full Dump (`-nf`)

**Exit Code: 0**

```

=========================================================================
|                   *** REDUCED SECURITY MODE ***                       |
|                                                                       |
|             Copyright (c) 2021-2026 David H Hoyt LLC                 |
|                          hoyt.net                                     |
=========================================================================

WARNING: Analyzing malformed/corrupted ICC profile without validation.
         This mode bypasses all safety checks and may expose parser bugs.
         Use only for security research, fuzzing, or forensic analysis.

File: /home/h02332/po/research/test-profiles/fuzzed-xnu-non_premultiplied_alpha.tif
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 962 bytes (0x3C2)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 4D 4D 00 2A 00 00 03 08  1A 4F 59 F9 5E C7 0B 47  |MM.*.....OY.^..G|
0x0010: 09 07 41 01 00 62 00 14  A1 33 F8 BE FE 39 5F 67  |..A..b...3...9_g|
0x0020: 00 00 00 66 44 8C 7D 35  75 54 E5 EE 7D 35 75 84  |...fD.}5uT..}5u.|
0x0030: 26 6E 7D 75 35 C3 93 C6  C6 8A 98 67 39 75 18 38  |&n}u5......g9u.8|
0x0040: 00 01 41 07 07 41 01 87  96 91 F8 BE FE 50 48 58  |..A..A.......PHX|
0x0050: 7D 75 35 64 24 20 8A CA  82 7D 35 75 00 00 00 84  |}u5d$ ...}5u....|
0x0060: 44 8C 00 00 00 8A CA 82  67 75 39 0C D3 3A F6 B8  |D.......gu9..:..|
0x0070: F4 7B 6B B4 01 41 07 07  01 41 01 41 07 50 48 58  |.{k..A...A.A.PHX|

Header Fields (RAW - no validation):
  Profile Size:    0x4D4D002A (1296891946 bytes) MISMATCH
  CMM:             0x00000308  '....'
  Version:         0x1A4F59F9  (26.4.15)
  Device Class:    0x5EC70B47  '^..G'
  Color Space:     0x09074101  '..A.'
  PCS:             0x00620014  '.b..'
  Date/Time:       41267-63678-65081 24423:00:102
  Magic:           0x448C7D35  [INVALID]
  Platform:        0x7554E5EE  'uT..'
  Flags:           0x7D357584
  Manufacturer:    0x266E7D75  '&n}u'
  Model:           0x35C393C6  '5...'
  Dev Attributes:  0xC68A986739751838
  Rendering Intent:0x00014107  UNKNOWN
  PCS Illuminant:  X=1857.0060 Y=-26990.0293 Z=-431.7174
  Creator:         0x7D753564  '}u5d'
  Profile ID:      24208aca827d357500000084448c0000
  Reserved 100-127: NON-ZERO [VIOLATION]

  --- V5/iccMAX Extended Header ---
  Spectral PCS:    0x00620014  '.b..'
  Spectral Range:  1909.0 - 0.6 nm, 54074 steps
  BiSpectral:      -27520.0 - -18352.0 nm, 27572 steps
  MCS:             0x01410707  '.A..'

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 2676127370 (0x9F82768A)
WARNING: Suspicious tag count (>1000) - possible corruption

Tag Table Raw Data:
0x0080: 9F 82 76 8A CA 82 5A 97  BA 8D 24 6C 7D 35 75 0D  |..v...Z...$l}5u.|
0x0090: 7C 06 84 4B 81 75 35 7D  00 00 00 39 67 75 00 38  ||..K.u5}...9gu.8|
0x00A0: 1A 07 01 41 07 41 01 01  07 41 00 53 00 39 5F 67  |...A.A...A.S.9_g|
0x00B0: 00 00 00 7D 35 75 7D 75  35 7D 35 75 61 7D BB 7D  |...}5u}u5}5ua}.}|
0x00C0: 35 75 7D 75 35 8B CB 83  48 66 76 10 8B 5D 0A 08  |5u}u5...Hfv..]..|
0x00D0: 46 F9 BF FF 71 13 01 00  00 00 F9 BF FF 5F 39 67  |F...q........_9g|
0x00E0: 84 44 6E 48 52 7E 75 7D  35 75 25 4B 66 26 6E 00  |.DnHR~u}5u%Kf&n.|
0x00F0: 00 00 74 7C 34 75 35 7D  74 38 66 74 38 66 37 55  |..t|4u5}t8ft8f7U|
0x0100: 65 00 00 00 91 B9 BE 35  53 63 62 34 52 94 A2 F0  |e......5Scb4R...|
0x0110: 7D 35 75 84 26 6E 75 35  7D 84 44 8C 8B CB 83 47  |}5u.&nu5}.D....G|
0x0120: 0F 12 8A CA 82 62 57 70  66 74 38 67 39 75 66 38  |.....bWpft8g9uf8|
0x0130: 74 75 39 67 39 67 75 67  75 39 29 83 57 6B 65 15  |tu9g9gugu9).Wke.|
0x0140: 8A C4 80 9A 3C 69 A1 0F  7F 8A C4 80 00 00 00 42  |....<i.........B|
0x0150: 44 AA 65 2B 8D 7F 3B 75  C7 8B 99 00 00 00 C7 8B  |D.e+..;u........|
0x0160: 99 DC 2E DB 48 66 58 2A  84 76 67 39 75 67 39 75  |....HfX*.vg9ug9u|
0x0170: F8 FE 0D 47 83 75 38 74  66 67 75 39 C6 8A 98 38  |...G.u8tfgu9...8|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------
0    0xCA825A97   'Ê‚Z—'        0xBA8D246C   0x7D35750D   '----'        OOB offset
1    0x7C06844B   '|„K'        0x8175357D   0x00000039   '----'        OOB offset
2    0x67750038   'gu  '        0x1A070141   0x07410101   '----'        OOB offset
3    0x07410053   'A  '        0x00395F67   0x0000007D   '----'        OOB offset
4    0x35757D75   '5u}u'        0x357D3575   0x617DBB7D   '----'        OOB offset
5    0x35757D75   '5u}u'        0x358BCB83   0x48667610   '----'        OOB offset
6    0x8B5D0A08   '‹]
'        0x46F9BFFF   0x71130100   '----'        OOB offset
7    0x0000F9BF   '    '        0xFF5F3967   0x84446E48   '----'        OOB offset
8    0x527E757D   'R~u}'        0x3575254B   0x66266E00   '----'        OOB offset
9    0x0000747C   '    '        0x3475357D   0x74386674   '----'        OOB offset
10   0x38663755   '8f7U'        0x65000000   0x91B9BE35   '----'        OOB offset
11   0x53636234   'Scb4'        0x5294A2F0   0x7D357584   '----'        OOB offset
12   0x266E7535   '&nu5'        0x7D84448C   0x8BCB8347   '----'        OOB offset
13   0x0F128ACA   'ŠÊ'        0x82625770   0x66743867   '----'        OOB offset
14   0x39756638   '9uf8'        0x74753967   0x39677567   '----'        OOB offset
15   0x75392983   'u9)ƒ'        0x576B6515   0x8AC4809A   '----'        OOB offset
16   0x3C69A10F   '<i¡'        0x7F8AC480   0x00000042   '----'        OOB offset
17   0x44AA652B   'Dªe+'        0x8D7F3B75   0xC78B9900   '----'        OOB offset
18   0x0000C78B   '    '        0x99DC2EDB   0x4866582A   '----'        OOB offset
19   0x84766739   '„vg9'        0x75673975   0xF8FE0D47   '----'        OOB offset
20   0x83753874   'ƒu8t'        0x66677539   0xC68A9838   '----'        OOB offset
21   0x66743263   'ft2c'        0xA3667438   0xC78B9900   '----'        OOB offset
22   0x00007539   '    '        0x67269B84   0x00000066   '----'        OOB offset
23   0x7D69C78B   '}iÇ‹'        0x99673975   0x00000000   '----'        OOB offset
24   0x00007539   '    '        0x67753967   0x4D686158   '----'        OOB offset
25   0x7A814D99   'zM™'        0x64387466   0x138E3F67   '----'        OOB offset
26   0x75393874   'u98t'        0x66677539   0x74386646   '----'        OOB offset
27   0x76890000   'v‰  '        0x007F9151   0x74386667   '----'        OOB offset
28   0x75390C6D   'u9m'        0x3F376A46   0x0DAFEA3A   '----'        OOB offset
29   0x9F7CC78B   'Ÿ|Ç‹'        0x99156C68   0x000000CD   '----'        OOB offset
30   0x82E24F5A   '‚âOZ'        0x39387466   0xEA91AD38   '----'        OOB offset
31   0x7466C68A   'tfÆŠ'        0x981F976C   0x67753947   '----'        OOB offset
32   0x65577539   'eWu9'        0x67000000   0x663874C6   '----'        OOB offset
33   0x8A9860AD   'Š˜`­'        0x44C68A98   0x66743800   '----'        OOB offset
34   0x0000C78B   '    '        0x99C78B99   0xF9D81C19   '----'        OOB offset
35   0x8765C68A   '‡eÆŠ'        0x98C68A98   0x574A5BC7   '----'        OOB offset
36   0x8B993975   '‹™9u'        0x67677539   0x47655766   '----'        OOB offset
37   0x38746739   '8tg9'        0x7570CE05   0xC78B99CD   '----'        OOB offset
38   0x5D216739   ']!g9'        0x752D5D8D   0x67753967   '----'        OOB offset
39   0x39755AD2   '9uZÒ'        0xCBB0FFE5   0x478375C6   '----'        OOB offset
40   0x8A984652   'Š˜FR'        0x3A1ECE33   0x66743866   '----'        OOB offset
41   0x3874C78B   '8tÇ‹'        0x99C68A98   0xC78B990F   '----'        OOB offset
42   0x6444C68A   'dDÆŠ'        0x98000000   0x8AFDA667   '----'        OOB offset
43   0x7539018A   'u9Š'        0x3B673975   0xA5B4C074   '----'        OOB offset
44   0x3866C78B   '8fÇ‹'        0x99C68A98   0x00000038   '----'        OOB offset
45   0x66744884   'ftH„'        0x76C78B99   0x67753948   '----'        OOB offset
46   0x66760B86   'fv†'        0x74C68A98   0x667438C6   '----'        OOB offset
47   0x8A98C78B   'Š˜Ç‹'        0x99C50A0A   0x39677500   '----'        OOB offset
48   0x00006638   '    '        0x74397567   0x39677567   '----'        OOB offset
49   0x39753347   '9u3G'        0x624E8982   0x38667428   '----'        OOB offset
50   0x57996739   'W™g9'        0x7507C616   0x38746667   '----'        OOB offset
51   0x3975C78B   '9uÇ‹'        0x992A8458   0x38746600   '----'        OOB offset
52   0x00002965   '    '        0x57753967   0x076A6A66   '----'        OOB offset
53   0x38740000   '8t  '        0x00C68A98   0x000E0100   '----'        OOB offset
54   0x00030000   '    '        0x00010010   0x00000101   '----'        OOB offset
55   0x00030000   '    '        0x00010010   0x00000102   '----'        OOB offset
56   0x00030000   '    '        0x00030000   0x03B60103   '----'        OOB offset
57   0x00030000   '    '        0x00010001   0x00000106   '----'        OOB offset
58   0x00030000   '    '        0x00010002   0x0000010A   '----'        OOB offset
59   0x00030000   '    '        0x00010001   0x00000111   '----'        OOB offset
60   0x00040000   '    '        0x00010000   0x00080112   '----'        OOB offset
61   0x00030000   '    '        0x00010001   0x00000115   '----'        OOB offset
62   0x00030000   '    '        0x00010003   0x00000116   '----'        OOB offset
63   0x00030000   '    '        0x00010010   0x00000117   '----'        OOB offset
64   0x00040000   '    '        0x00010000   0x0300011C   '----'        OOB offset
65   0x00030000   '    '        0x00010001   0x00000128   '----'        OOB offset
66   0x00030000   '    '        0x00010002   0x00000153   '----'        OOB offset
67   0x00030000   '    '        0x00030000   0x03BC0000   '----'        OOB offset
68   0x00000008   '    '        0x00080008   0x00010001   '----'        OOB offset
... (2676127270 more tags not shown)

[WARN] SIZE INFLATION: Header claims 1296891946 bytes, file is 962 bytes (1348121x)
   Risk: OOM via tag-internal allocations based on inflated header size

[WARN] TAG OVERLAP: 1049 overlapping tag pair(s) detected
   Risk: Data corruption, possible exploit crafting

=== FULL FILE HEX DUMP (all 962 bytes) ===
0x0000: 4D 4D 00 2A 00 00 03 08  1A 4F 59 F9 5E C7 0B 47  |MM.*.....OY.^..G|
0x0010: 09 07 41 01 00 62 00 14  A1 33 F8 BE FE 39 5F 67  |..A..b...3...9_g|
0x0020: 00 00 00 66 44 8C 7D 35  75 54 E5 EE 7D 35 75 84  |...fD.}5uT..}5u.|
0x0030: 26 6E 7D 75 35 C3 93 C6  C6 8A 98 67 39 75 18 38  |&n}u5......g9u.8|
0x0040: 00 01 41 07 07 41 01 87  96 91 F8 BE FE 50 48 58  |..A..A.......PHX|
0x0050: 7D 75 35 64 24 20 8A CA  82 7D 35 75 00 00 00 84  |}u5d$ ...}5u....|
0x0060: 44 8C 00 00 00 8A CA 82  67 75 39 0C D3 3A F6 B8  |D.......gu9..:..|
0x0070: F4 7B 6B B4 01 41 07 07  01 41 01 41 07 50 48 58  |.{k..A...A.A.PHX|
0x0080: 9F 82 76 8A CA 82 5A 97  BA 8D 24 6C 7D 35 75 0D  |..v...Z...$l}5u.|
0x0090: 7C 06 84 4B 81 75 35 7D  00 00 00 39 67 75 00 38  ||..K.u5}...9gu.8|
0x00A0: 1A 07 01 41 07 41 01 01  07 41 00 53 00 39 5F 67  |...A.A...A.S.9_g|
0x00B0: 00 00 00 7D 35 75 7D 75  35 7D 35 75 61 7D BB 7D  |...}5u}u5}5ua}.}|
0x00C0: 35 75 7D 75 35 8B CB 83  48 66 76 10 8B 5D 0A 08  |5u}u5...Hfv..]..|
0x00D0: 46 F9 BF FF 71 13 01 00  00 00 F9 BF FF 5F 39 67  |F...q........_9g|
0x00E0: 84 44 6E 48 52 7E 75 7D  35 75 25 4B 66 26 6E 00  |.DnHR~u}5u%Kf&n.|
0x00F0: 00 00 74 7C 34 75 35 7D  74 38 66 74 38 66 37 55  |..t|4u5}t8ft8f7U|
0x0100: 65 00 00 00 91 B9 BE 35  53 63 62 34 52 94 A2 F0  |e......5Scb4R...|
0x0110: 7D 35 75 84 26 6E 75 35  7D 84 44 8C 8B CB 83 47  |}5u.&nu5}.D....G|
0x0120: 0F 12 8A CA 82 62 57 70  66 74 38 67 39 75 66 38  |.....bWpft8g9uf8|
0x0130: 74 75 39 67 39 67 75 67  75 39 29 83 57 6B 65 15  |tu9g9gugu9).Wke.|
0x0140: 8A C4 80 9A 3C 69 A1 0F  7F 8A C4 80 00 00 00 42  |....<i.........B|
0x0150: 44 AA 65 2B 8D 7F 3B 75  C7 8B 99 00 00 00 C7 8B  |D.e+..;u........|
0x0160: 99 DC 2E DB 48 66 58 2A  84 76 67 39 75 67 39 75  |....HfX*.vg9ug9u|
0x0170: F8 FE 0D 47 83 75 38 74  66 67 75 39 C6 8A 98 38  |...G.u8tfgu9...8|
0x0180: 66 74 32 63 A3 66 74 38  C7 8B 99 00 00 00 75 39  |ft2c.ft8......u9|
0x0190: 67 26 9B 84 00 00 00 66  7D 69 C7 8B 99 67 39 75  |g&.....f}i...g9u|
0x01A0: 00 00 00 00 00 00 75 39  67 75 39 67 4D 68 61 58  |......u9gu9gMhaX|
0x01B0: 7A 81 4D 99 64 38 74 66  13 8E 3F 67 75 39 38 74  |z.M.d8tf..?gu98t|
0x01C0: 66 67 75 39 74 38 66 46  76 89 00 00 00 7F 91 51  |fgu9t8fFv......Q|
0x01D0: 74 38 66 67 75 39 0C 6D  3F 37 6A 46 0D AF EA 3A  |t8fgu9.m?7jF...:|
0x01E0: 9F 7C C7 8B 99 15 6C 68  00 00 00 CD 82 E2 4F 5A  |.|....lh......OZ|
0x01F0: 39 38 74 66 EA 91 AD 38  74 66 C6 8A 98 1F 97 6C  |98tf...8tf.....l|
0x0200: 67 75 39 47 65 57 75 39  67 00 00 00 66 38 74 C6  |gu9GeWu9g...f8t.|
0x0210: 8A 98 60 AD 44 C6 8A 98  66 74 38 00 00 00 C7 8B  |..`.D...ft8.....|
0x0220: 99 C7 8B 99 F9 D8 1C 19  87 65 C6 8A 98 C6 8A 98  |.........e......|
0x0230: 57 4A 5B C7 8B 99 39 75  67 67 75 39 47 65 57 66  |WJ[...9uggu9GeWf|
0x0240: 38 74 67 39 75 70 CE 05  C7 8B 99 CD 5D 21 67 39  |8tg9up......]!g9|
0x0250: 75 2D 5D 8D 67 75 39 67  39 75 5A D2 CB B0 FF E5  |u-].gu9g9uZ.....|
0x0260: 47 83 75 C6 8A 98 46 52  3A 1E CE 33 66 74 38 66  |G.u...FR:..3ft8f|
0x0270: 38 74 C7 8B 99 C6 8A 98  C7 8B 99 0F 64 44 C6 8A  |8t..........dD..|
0x0280: 98 00 00 00 8A FD A6 67  75 39 01 8A 3B 67 39 75  |.......gu9..;g9u|
0x0290: A5 B4 C0 74 38 66 C7 8B  99 C6 8A 98 00 00 00 38  |...t8f.........8|
0x02A0: 66 74 48 84 76 C7 8B 99  67 75 39 48 66 76 0B 86  |ftH.v...gu9Hfv..|
0x02B0: 74 C6 8A 98 66 74 38 C6  8A 98 C7 8B 99 C5 0A 0A  |t...ft8.........|
0x02C0: 39 67 75 00 00 00 66 38  74 39 75 67 39 67 75 67  |9gu...f8t9ug9gug|
0x02D0: 39 75 33 47 62 4E 89 82  38 66 74 28 57 99 67 39  |9u3GbN..8ft(W.g9|
0x02E0: 75 07 C6 16 38 74 66 67  39 75 C7 8B 99 2A 84 58  |u...8tfg9u...*.X|
0x02F0: 38 74 66 00 00 00 29 65  57 75 39 67 07 6A 6A 66  |8tf...)eWu9g.jjf|
0x0300: 38 74 00 00 00 C6 8A 98  00 0E 01 00 00 03 00 00  |8t..............|
0x0310: 00 01 00 10 00 00 01 01  00 03 00 00 00 01 00 10  |................|
0x0320: 00 00 01 02 00 03 00 00  00 03 00 00 03 B6 01 03  |................|
0x0330: 00 03 00 00 00 01 00 01  00 00 01 06 00 03 00 00  |................|
0x0340: 00 01 00 02 00 00 01 0A  00 03 00 00 00 01 00 01  |................|
0x0350: 00 00 01 11 00 04 00 00  00 01 00 00 00 08 01 12  |................|
0x0360: 00 03 00 00 00 01 00 01  00 00 01 15 00 03 00 00  |................|
0x0370: 00 01 00 03 00 00 01 16  00 03 00 00 00 01 00 10  |................|
0x0380: 00 00 01 17 00 04 00 00  00 01 00 00 03 00 01 1C  |................|
0x0390: 00 03 00 00 00 01 00 01  00 00 01 28 00 03 00 00  |...........(....|
0x03A0: 00 01 00 02 00 00 01 53  00 03 00 00 00 03 00 00  |.......S........|
0x03B0: 03 BC 00 00 00 00 00 08  00 08 00 08 00 01 00 01  |................|
0x03C0: 00 01                                             |..|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/fuzzed-xnu-non_premultiplied_alpha.tif

[NOT RUN] Profile TRUNCATED â€” round-trip validation not run
       Header claims more bytes than file contains (CWE-125)
```

---

## LUT Text Export (`-xt`)

**Exit Code: 2**

```
Error reading ICC profile
Exported 0 text file(s) to /tmp/tmp.mRUTfC54ZX/
```

---

## Cube Export (`-cube`)

**Exit Code: 1**

```
No 3D CLUT found in any standard LUT tag
```
