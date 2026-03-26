# ICC Profile Analysis Report

**Profile**: `test-profiles/sbo-CIccProfile-LoadTag-IccProfile_cpp-specsep.icc`
**File Size**: 3196 bytes
**SHA-256**: `457786e2c96ba0e88a4fe78ce7a15be0a16c9f4754031a398eba7c745e5eebb5`
**File Type**: data
**Date**: 2026-03-26T16:57:53Z
**Analyzer**: iccanalyzer-lite (pre-built, ASAN+UBSAN instrumented)

## Exit Code Summary

| Command | Exit Code | Meaning |
|---------|-----------|---------|
| `-a` (comprehensive) | 1 | Finding detected |
| `-nf` (ninja full dump) | 0 | Dump completed |
| `-r` (round-trip) | 2 | Error |
| `-xt` (LUT text export) | 2 | Error |
| `-cube` (cube export) | 1 | No 3D CLUT |

**ASAN/UBSAN**: No sanitizer errors detected

---

## Command 1: Comprehensive Analysis (`-a`)

**Exit Code: 1**

```

=======================================================================
  ICC PROFILE CONFORMANCE AUDIT
=======================================================================

File: /home/h02332/po/research/test-profiles/sbo-CIccProfile-LoadTag-IccProfile_cpp-specsep.icc

[H173] Signature Conversion Shift Overflow (IccUtil.cpp signature formatting helpers)
      [WARN]  HEURISTIC: 4/6 FourCC signatures trigger UBSAN shift overflow in icGetSig()/icGetSigStr()/icGetColorSig()/icGetColorSigStr() — IccUtil.cpp:1088,1130,1167,1187,1228,1253
       CWE-190: sig<<=8 on uint32 with first byte non-zero produces value > UINT32_MAX (upstream iccDEV library pattern)

[H174] Half-Float Conversion Unsigned Underflow (IccUtil.cpp icF16toF)
      [WARN]  HEURISTIC: 2 half-float value(s) would trigger UBSAN unsigned-wrap in icF16toF() — IccUtil.cpp:665,677 / IccIO.cpp:328
       CWE-190: exponent rebias uses unsigned subtraction for non-zero half-floats with exponent < 15 (values below 1.0)
      header spectralRange.start raw=0x323A at file+0x68
      header spectralRange.end raw=0x32D8 at file+0x6A

[DEFENSE] H174 half-float fingerprint reaches upstream validation paths — skipping Validate() phase but continuing with safe deep conformance checks
=======================================================================
PHASE 1: ICC SPECIFICATION CONFORMANCE
=======================================================================

[NOT RUN] Library validation not run — half-float fields would hit upstream icF16toF UB during Validate()
       Deep conformance checks will continue using analyzer-owned safe conversions

[NOT RUN] Deep conformance checks not run — profile failed to load

=======================================================================
PHASE 3: ROUND-TRIP TAG VALIDATION
=======================================================================


=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/sbo-CIccProfile-LoadTag-IccProfile_cpp-specsep.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/h02332/po/research/test-profiles/sbo-CIccProfile-LoadTag-IccProfile_cpp-specsep.icc
Result: NOT round-trip capable
[ERROR] Profile failed to load - skipping remaining phases
        Use -n (ninja mode) for raw analysis of malformed profiles
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

File: /home/h02332/po/research/test-profiles/sbo-CIccProfile-LoadTag-IccProfile_cpp-specsep.icc
Mode: FULL DUMP (entire file will be displayed)

Raw file size: 3196 bytes (0xC7C)

=== RAW HEADER DUMP (0x0000-0x007F) ===
0x0000: 00 00 09 34 00 00 00 00  54 00 6A 00 00 00 00 01  |...4....T.j.....|
0x0010: 00 00 00 00 04 FF 01 00  F0 FF 00 FF FF FF 37 EB  |..............7.|
0x0020: DE 0F B1 60 51 00 00 61  63 6E 63 00 51 5A 00 00  |...`Q..acnc.QZ..|
0x0030: 00 07 EA 5D 02 00 11 00  08 00 26 00 0F 61 63 73  |...]......&..acs|
0x0040: 70 00 00 61 00 00 00 00  01 00 08 8D 79 00 3C 00  |p..a........y.<.|
0x0050: 00 00 00 3C 00 3C 01 00  1A FF 00 FF FF FF 33 E9  |...<.<........3.|
0x0060: FF 00 00 00 00 50 20 00  32 3A 32 D8 B0 00 00 00  |.....P .2:2.....|
0x0070: 00 00 56 96 B1 0F 1B BC  8B 43 39 0C 00 00 00 00  |..V......C9.....|

Header Fields (RAW - no validation):
  Profile Size:    0x00000934 (2356 bytes) MISMATCH
  CMM:             0x00000000  '....'
  Version:         0x54006A00  (84.0.0)
  Device Class:    0x00000001  '....'
  Color Space:     0x00000000  '....'
  PCS:             0x04FF0100  '....'
  Date/Time:       61695-255-65535 14315:56847:45408
  Magic:           0x51000061  [INVALID]
  Platform:        0x636E6300  'cnc.'
  Flags:           0x515A0000
  Manufacturer:    0x0007EA5D  '...]'
  Model:           0x02001100  '....'
  Dev Attributes:  0x080026000F616373 [Transparency] [Matte]
  Rendering Intent:0x70000061  UNKNOWN
  PCS Illuminant:  X=0.0000 Y=256.0334 Z=30976.2344
  Creator:         0x0000003C  '...<'
  Profile ID:      003c01001aff00ffffff33e9ff000000
  Reserved 100-127: NON-ZERO [VIOLATION]

  --- V5/iccMAX Extended Header ---
  Spectral PCS:    0x04FF0100  '....'
  Spectral Range:  0.2 - 0.2 nm, 45056 steps
  BiSpectral:      0.0 - 0.0 nm, 22166 steps
  MCS:             0xB10F1BBC  '....'

=== RAW TAG TABLE (0x0080+) ===
Tag Count: 0 (0x00000000)

Tag Table Raw Data:
0x0080: 00 00 00 00                                       |....|

Tag Entries (RAW - no validation):
Idx  Signature    FourCC       Offset       Size         TagType      Status
---  ------------ ------------ ------------ ------------ ------------ ------

=== FULL FILE HEX DUMP (all 3196 bytes) ===
0x0000: 00 00 09 34 00 00 00 00  54 00 6A 00 00 00 00 01  |...4....T.j.....|
0x0010: 00 00 00 00 04 FF 01 00  F0 FF 00 FF FF FF 37 EB  |..............7.|
0x0020: DE 0F B1 60 51 00 00 61  63 6E 63 00 51 5A 00 00  |...`Q..acnc.QZ..|
0x0030: 00 07 EA 5D 02 00 11 00  08 00 26 00 0F 61 63 73  |...]......&..acs|
0x0040: 70 00 00 61 00 00 00 00  01 00 08 8D 79 00 3C 00  |p..a........y.<.|
0x0050: 00 00 00 3C 00 3C 01 00  1A FF 00 FF FF FF 33 E9  |...<.<........3.|
0x0060: FF 00 00 00 00 50 20 00  32 3A 32 D8 B0 00 00 00  |.....P .2:2.....|
0x0070: 00 00 56 96 B1 0F 1B BC  8B 43 39 0C 00 00 00 00  |..V......C9.....|
0x0080: 00 00 00 00 00 00 00 01  00 00 00 00 00 00 00 00  |................|
0x0090: 00 70 63 63 20 00 00 00  00 00 00 00 08 74 65 75  |.pcc ........teu|
0x00A0: 76 00 00 00 E4 00 00 00  EC 41 32 42 33 00 00 01  |v........A2B3...|
0x00B0: D0 00 00 00 54 42 32 41  33 00 00 02 24 00 00 00  |....TB2A3...$...|
0x00C0: 52 FB 8C B2 A3 1D 8E 23  34 00 00 00 54 73 32 63  |R......#4...Ts2c|
0x00D0: 70 00 00 02 88 00 00 00  54 73 76 63 6E 00 00 02  |p.......Tsvcn...|
0x00E0: DC 00 00 05 4C 43 4C 77  74 70 89 00 00 5D 28 00  |....LCLwtp...](.|
0x00F0: 00 00 14 63 70 72 74 2C  30 0B 00 20 51 00 00 87  |...cprt,0.. Q...|
0x0100: 6D A1 A1 10 10 10 10 00  35 00 00 53 01 00 01 00  |m.......5..S....|
0x0110: 00 00 00 00 00 0A 01 00  00 00 00 00 00 00 1F 1F  |................|
0x0120: 1F BD FF FF 00 D0 1F 1F  1F 1F 1F 1F 7A 05 00 00  |............z...|
0x0130: 00 00 00 00 00 00 00 08  00 00 0F 00 00 00 00 00  |................|
0x0140: 00 00 00 E0 BF FF FF 00  00 02 28 00 00 00 00 00  |..........(.....|
0x0150: 00 00 00 00 00 00 00 FF  FF 00 00 00 00 00 00 50  |...............P|
0x0160: 20 00 13 64 36 00 00 40  00 20 50 00 00 00 00 00  | ..d6..@. P.....|
0x0170: 00 00 3E 00 00 00 00 00  00 00 00 00 00 00 03 00  |..>.............|
0x0180: 00 F6 D9 00 01 00 00 00  00 D3 1E 00 00 80 00 E9  |................|
0x0190: D1 CB AC AC 62 59 2A 45  53 A2 1C 86 2D 86 4B 72  |....bY*ES...-.Kr|
0x01A0: 73 00 51 5D F0 62 18 00  14 51 00 00 00 44 00 00  |s.Q].b...Q...D..|
0x01B0: 7E 74 00 00 07 00 61 00  75 00 00 00 00 00 00 FF  |~t....a.u.......|
0x01C0: 9C 28 08 8C 28 00 79 00  00 6D 00 28 00 00 FC 00  |.(..(.y..m.(....|
0x01D0: 00 00 14 73 77 70 10 74  93 00 00 08 00 00 AA 66  |...swp.t.......f|
0x01E0: 00 00 FF 08 00 00 BC BC  BC 74 61 72 79 00 00 7F  |.........tary...|
0x01F0: 39 6B 87 B2 E5 00 00 00  04 00 00 00 FF FF FF FF  |9k..............|
0x0200: 2F FE FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |/...............|
0x0210: FF FF FF FF FF FF FF FF  FF FF FF FF FF FF FF FF  |................|
0x0220: FF FF FF FF FF FF FF FF  FF FF FF 01 00 9D B3 23  |...............#|
0x0230: C5 3E 48 B2 1C FF FF 00  30 72 73 00 7E 5D F0 00  |.>H.....0rs.~]..|
0x0240: 00 09 34 40 00 00 40 54  00 6A 00 00 00 00 01 00  |..4@..@T.j......|
0x0250: 00 00 00 00 FF 01 00 F0  FF 00 FF FF FF 37 00 00  |.............7..|
0x0260: 05 00 01 6B 73 63 9C 8D  91 9C FD 00 7F 79 CF DF  |...ksc.......y..|
0x0270: F8 15 FF 02 FF FF 51 40  00 4A E5 7C 61 63 73 70  |......Q@.J.|acsp|
0x0280: 00 00 00 00 6C 6B 00 2C  98 15 00 D0 50 00 00 00  |....lk.,....P...|
0x0290: 00 00 00 00 00 00 00 00  73 6F 41 FF FF 00 00 00  |........soA.....|
0x02A0: 00 FF FF FF FF FF FF FF  06 00 00 00 00 00 00 1E  |................|
0x02B0: 1E 1E 1E 1E 1E 1E E2 D7  1E 4D 43 1E 43 FD 75 FF  |.........MC.C.u.|
0x02C0: FF 1E 1E 52 00 00 00 00  41 00 00 00 00 00 60 00  |...R....A.....`.|
0x02D0: CF FF FF FF FF FF 00 00  00 00 00 01 63 6C 70 74  |............clpt|
0x02E0: 00 00 00 90 00 00 00 08  49 43 43 70 01 00 29 00  |........ICCp..).|
0x02F0: 00 00 00 00 00 FF FF FF  FF 66 6D 72 70 73 6E 72  |.........fmrpsnr|
0x0300: 6E 63 FD 00 7F 79 CF DF  F8 15 FF 02 00 11 00 08  |nc...y..........|
0x0310: 00 26 00 0F 61 63 73 70  00 00 01 00 08 E0 00 00  |.&..acsp........|
0x0320: 00 00 00 00 00 00 00 00  57 00 00 00 00 00 00 00  |........W.......|
0x0330: 73 6F 3C FF FF 00 00 00  00 00 00 00 00 00 00 00  |so<.............|
0x0340: 00 00 00 00 00 00 00 1E  1E 1E 1E 1E 1E 1E E2 D7  |................|
0x0350: 1E 4D 43 1E 43 FD 75 FF  FF 1E 1E 52 00 00 00 00  |.MC.C.u....R....|
0x0360: 41 00 00 00 00 00 04 00  CF FF FF FF FF FF 00 00  |A...............|
0x0370: 00 00 00 01 63 6C 70 74  00 00 00 90 00 00 00 08  |....clpt........|
0x0380: 49 43 43 70 01 00 09 00  00 00 00 00 00 FF FF 4F  |ICCp...........O|
0x0390: 20 00 01 6B 73 63 9C 8D  91 9C FD 00 7F 79 CF DF  | ..ksc.......y..|
0x03A0: F8 15 FF 02 FF FF 51 40  00 4A E5 7C 61 63 73 70  |......Q@.J.|acsp|
0x03B0: 00 00 60 51 00 00 61 63  6E 63 00 51 5A 00 00 00  |..`Q..acnc.QZ...|
0x03C0: 07 EA 5D 02 00 11 00 08  00 26 00 0F 61 63 73 70  |..]......&..acsp|
0x03D0: 00 00 61 00 00 00 00 01  00 08 8D 79 00 3C 00 00  |..a........y.<..|
0x03E0: 00 00 3C 00 3C 01 00 1A  FF 00 00 A9 00 00 00 99  |..<.<...........|
0x03F0: 00 00 00 AB 00 00 00 AA  00 00 00 9A 00 00 00 AC  |................|
0x0400: 00 00 00 AB 00 00 00 9B  00 00 00 AD 00 00 00 AC  |................|
0x0410: 00 00 00 9C 00 00 00 AE  00 00 00 AD 00 00 00 9D  |................|
0x0420: 00 00 00 AF 00 00 00 97  FF FF FD 97 00 00 00 F8  |................|
0x0430: B7 00 02 00 11 00 08 00  26 00 0F 61 63 73 70 00  |........&..acsp.|
0x0440: 00 00 00 00 00 00 00 17  11 00 00 00 00 00 00 00  |................|
0x0450: 00 00 00 00 FF 01 00 00  00 00 95 00 00 92 00 00  |................|
0x0460: 00 AE 00 00 00 9E 00 00  00 B0 00 00 00 AF 00 00  |................|
0x0470: 00 9F 00 00 00 B1 00 00  00 B0 00 00 00 A0 00 00  |................|
0x0480: 00 B2 00 00 00 B1 00 00  00 A1 00 00 00 B3 00 00  |................|
0x0490: 00 B2 00 00 00 A2 00 00  00 B4 00 00 00 B3 00 00  |................|
0x04A0: 00 A3 00 00 00 B5 00 00  00 C6 00 00 00 A4 00 00  |................|
0x04B0: 00 B6 00 00 00 B5 00 00  00 A5 00 00 00 B7 00 00  |................|
0x04C0: 00 B6 00 00 00 A6 00 00  00 B8 00 00 00 B7 00 00  |................|
0x04D0: 00 A7 00 00 00 B9 00 00  00 B8 00 00 00 A8 00 00  |................|
0x04E0: 00 BA 00 00 00 B9 00 00  00 A9 00 00 00 BB 00 00  |................|
0x04F0: 00 BA 00 00 00 AA 00 00  00 BC 00 00 00 BB 00 00  |................|
0x0500: 00 AB 00 00 00 BD 00 00  00 BC 00 3A 63 33 73 70  |...........:c3sp|
0x0510: 00 00 AC 00 00 00 BE 00  00 00 BD 00 00 00 AD 00  |................|
0x0520: 00 00 BF 00 00 00 BE 00  00 00 AE 00 00 00 C0 00  |................|
0x0530: 7E 00 BF 00 00 00 AF 00  00 00 C1 00 00 00 C0 00  |~...............|
0x0540: 00 00 B0 00 00 00 C2 00  00 00 C1 00 00 00 B1 00  |................|
0x0550: 00 00 C3 00 00 00 C2 00  00 00 B2 00 00 04 C4 00  |................|
0x0560: 00 00 C3 00 00 25 B3 00  00 00 C5 00 00 00 C4 00  |.....%..........|
0x0570: 00 00 B4 00 00 00 C6 00  00 00 C5 00 00 00 4C 07  |..............L.|
0x0580: 00 00 C7 00 00 00 D8 00  00 00 B6 00 00 00 C8 00  |................|
0x0590: 00 00 C7 00 00 00 B7 00  00 00 C9 00 00 00 C8 00  |................|
0x05A0: 00 00 B8 00 00 00 CA 00  00 00 C9 00 00 00 B9 00  |................|
0x05B0: 00 00 CB 00 00 00 CA 00  00 00 BA 00 00 00 CC 00  |................|
0x05C0: 00 00 CB 00 00 00 BB 00  00 00 CD 00 00 00 CC 00  |................|
0x05D0: 00 00 BC 00 00 00 CE 00  00 00 CD 00 00 00 BD 00  |................|
0x05E0: 00 00 CF 00 00 00 CE 00  00 00 BE 00 00 00 D0 00  |................|
0x05F0: 00 00 CF 00 00 00 BF 00  00 00 D1 00 00 00 D0 00  |................|
0x0600: 00 00 C0 00 00 00 D2 00  00 00 D1 00 00 00 C1 00  |................|
0x0610: 00 00 D3 00 00 00 D2 00  00 00 C2 00 00 00 D4 00  |................|
0x0620: 00 00 D3 00 00 00 C3 00  00 00 D5 00 00 00 D6 D4  |................|
0x0630: 00 00 00 C4 00 00 00 D6  00 00 00 D5 00 00 00 C5  |................|
0x0640: 00 00 00 D7 00 00 00 D6  00 00 00 C6 00 00 00 D8  |................|
0x0650: 00 00 00 D7 00 00 00 C7  00 00 00 D9 00 00 00 EA  |................|
0x0660: 00 00 00 C8 00 00 00 DA  00 00 00 D9 00 00 00 C9  |................|
0x0670: 00 00 00 DB 00 20 00 DA  00 00 00 CA 00 00 00 DC  |..... ..........|
0x0680: 00 00 00 DB 00 00 00 CB  00 00 00 DD 00 00 00 DC  |................|
0x0690: 00 00 00 CC 00 00 00 DE  00 00 00 DD 00 00 00 CD  |................|
0x06A0: 00 00 00 DF 00 00 00 DE  00 00 00 CE 00 00 00 E0  |................|
0x06B0: 00 00 00 DF 00 00 00 CF  00 00 00 E1 00 00 00 E0  |................|
0x06C0: 00 00 00 D0 00 00 00 E2  00 00 00 E1 00 00 00 D1  |................|
0x06D0: 00 00 00 E3 00 00 00 E2  00 00 00 D2 00 00 00 E4  |................|
0x06E0: 00 00 00 E3 00 00 00 D3  00 00 00 E5 00 00 00 E4  |................|
0x06F0: 00 00 00 D4 00 00 00 E6  00 00 00 E5 00 00 00 D5  |................|
0x0700: 00 00 00 E7 00 00 00 E6  00 00 00 08 00 00 01 07  |................|
0x0710: 00 00 00 F7 00 00 01 09  00 00 01 08 00 00 00 F8  |................|
0x0720: 00 00 01 0A 00 00 01 09  00 00 00 F9 00 00 01 0B  |................|
0x0730: 00 00 01 0A 00 00 00 FA  00 00 01 0C 00 00 01 0B  |................|
0x0740: 00 00 00 FB 00 00 01 0D  00 00 01 0C 00 00 00 FC  |................|
0x0750: 00 00 01 0E 00 00 01 0D  00 00 00 FD 00 00 01 0F  |................|
0x0760: 00 00 01 20 00 00 00 FE  00 00 01 10 00 00 01 0F  |... ............|
0x0770: 00 00 00 FF 00 00 01 11  00 00 01 10 00 00 01 00  |................|
0x0780: 00 00 01 12 00 00 01 11  00 00 01 01 00 00 01 13  |................|
0x0790: 00 00 01 12 00 00 01 02  00 00 01 19 00 00 01 18  |................|
0x07A0: 00 00 01 08 00 00 01 1A  00 00 01 19 00 00 01 09  |................|
0x07B0: 00 00 01 3C 00 00 01 3B  00 00 01 2B 00 00 01 3D  |...<...;...+...=|
0x07C0: 00 00 01 3C 00 00 01 2C  00 00 01 3E 00 00 01 3D  |...<...,...>...=|
0x07D0: 00 00 01 2D 00 00 01 3F  00 00 01 3E 00 00 01 2E  |...-...?...>....|
0x07E0: 00 00 01 40 00 00 01 3F  00 00 01 2F 00 00 01 41  |...@...?.../...A|
0x07F0: 00 00 01 40 00 00 01 30  00 00 01 42 00 00 01 41  |...@...0...B...A|
0x0800: 00 00 01 31 00 00 01 43  04 00 00 00 00 00 01 42  |...1...C.......B|
0x0810: 00 00 01 32 00 00 01 44  00 00 01 43 00 00 01 33  |...2...D...C...3|
0x0820: 00 00 01 45 00 00 01 56  00 00 01 34 00 00 01 46  |...E...V...4...F|
0x0830: 00 00 00 06 00 73 70 65  3C FF FF 00 00 00 00 00  |.....spe<.......|
0x0840: 00 00 00 00 00 00 00 00  00 00 00 00 0F 61 63 73  |.............acs|
0x0850: 70 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |p...............|
0x0860: 00 00 00 00 00 00 00 06  00 73 70 65 00 00 01 45  |.........spe...E|
0x0870: 00 00 01 35 00 00 01 47  00 00 01 46 00 00 01 36  |...5...G...F...6|
0x0880: 00 00 01 48 00 00 01 47  00 00 01 37 00 00 01 49  |...H...G...7...I|
0x0890: 00 00 01 48 00 00 01 00  00 00 00 00 00 04 97 97  |...H............|
0x08A0: 97 97 97 97 97 97 97 00  00 00 F7 00 00 00 05 6E  |...............n|
0x08B0: 69 6C 32 00 00 00 C0 00  00 00 05 6E B2 6C 32 00  |il2........n.l2.|
0x08C0: 00 00 E0 00 00 00 7D 01  00 00 00 00 00 00 BB F8  |......}.........|
0x08D0: 00 00 0A 00 00 00 00 01  00 00 00 00 00 00 47 40  |..............G@|
0x08E0: 00 00 73 70 65 3C 00 00  0B 00 00 00 00 00 FF FF  |..spe<..........|
0x08F0: 00 00 01 46 00 00 01 58  00 00 01 57 00 00 01 47  |...F...X...W...G|
0x0900: 00 00 01 59 00 00 01 58  00 00 01 48 00 00 01 5A  |...Y...X...H...Z|
0x0910: 00 00 01 59 00 00 01 49  00 00 01 5B 00 00 01 5A  |...Y...I...[...Z|
0x0920: 00 00 01 4A 00 00 01 5C  00 00 01 5B 00 00 01 4B  |...J...\...[...K|
0x0930: 00 00 01 5D 00 00 01 5C  00 00 01 4C 00 00 01 5E  |...]...\...L...^|
0x0940: 00 00 01 5D 00 00 01 4D  00 00 01 5F 00 00 01 5E  |...]...M..._...^|
0x0950: 00 00 01 4E 00 00 01 30  75 32 41 60 00 00 01 5F  |...N...0u2A`..._|
0x0960: 00 00 01 4F 00 00 01 61  00 00 01 60 00 00 01 50  |...O...a...`...P|
0x0970: 00 00 01 62 00 00 01 61  00 00 01 51 00 00 01 63  |...b...a...Q...c|
0x0980: 00 00 01 62 00 00 01 52  00 00 01 64 00 00 01 63  |...b...R...d...c|
0x0990: 00 00 01 53 00 00 01 65  00 00 01 64 00 00 01 54  |...S...e...d...T|
0x09A0: 00 00 01 66 00 00 01 65  00 00 01 55 00 00 01 67  |...f...e...U...g|
0x09B0: 00 00 01 66 00 00 01 56  00 00 01 68 00 00 01 67  |...f...V...h...g|
0x09C0: 00 00 01 A3 A3 A3 A3 A3  A3 A3 A3 A3 A3 A3 A3 A3  |................|
0x09D0: A3 A3 A3 A3 A3 A3 A3 A3  A3 A3 A3 A3 A3 A3 A3 A3  |................|
0x09E0: A3 A3 A3 A3 A3 A3 A3 A3  A3 A3 A3 A3 A3 A3 A3 A3  |................|
0x09F0: A3 A3 A3 A3 A3 A3 A3 A3  A3 A3 A3 A3 A3 A3 A3 A3  |................|
0x0A00: A3 A3 A3 A3 A3 A3 A3 A3  A3 A3 A3 A3 A3 A3 A3 A3  |................|
0x0A10: A3 A3 A3 A3 A3 A3 A3 A3  A3 A3 A3 A3 A3 A3 A3 A3  |................|
0x0A20: A3 A3 A3 A3 A3 A3 A3 A3  A3 A3 A3 A3 A3 A3 57 00  |..............W.|
0x0A30: 00 01 69 00 00 01 7A 00  00 01 58 00 00 01 6A 00  |..i...z...X...j.|
0x0A40: 00 01 69 00 00 01 59 00  00 01 6B 00 00 01 6A 00  |..i...Y...k...j.|
0x0A50: 00 01 5A 00 00 01 6C 00  00 01 6B 00 00 01 5B 00  |..Z...l...k...[.|
0x0A60: 00 01 6D 00 00 01 6C 00  00 01 5C 00 00 01 6E 00  |..m...l...\...n.|
0x0A70: 00 01 F3 6D 00 00 01 5D  00 00 01 6F 00 00 01 6E  |...m...]...o...n|
0x0A80: 00 00 01 5E 00 00 01 70  00 00 01 6F 00 00 01 5F  |...^...p...o..._|
0x0A90: 00 00 01 71 00 00 01 70  00 00 01 60 00 00 01 72  |...q...p...`...r|
0x0AA0: 00 00 01 71 00 00 01 61  00 00 01 73 00 00 01 72  |...q...a...s...r|
0x0AB0: 00 00 01 62 00 00 01 74  00 00 01 73 00 00 01 63  |...b...t...s...c|
0x0AC0: 00 00 01 75 00 00 01 74  00 00 01 64 00 00 01 00  |...u...t...d....|
0x0AD0: 00 00 6C 6B 00 2C 98 15  00 D0 50 00 00 00 00 00  |..lk.,....P.....|
0x0AE0: 00 00 00 00 00 00 73 6F  3C FF FF 00 00 00 00 00  |......so<.......|
0x0AF0: 00 00 00 00 00 00 00 00  20 00 00 00 00 1E 1E 1E  |........ .......|
0x0B00: 1E 1E 1E 1E E2 D7 1E 4D  43 1E 43 FD 75 FF FF 1E  |.......MC.C.u...|
0x0B10: 1E 52 00 00 00 00 41 00  00 00 00 00 04 00 CF FF  |.R....A.........|
0x0B20: FF FF FF FF 00 00 00 00  00 01 63 6C 70 74 00 00  |..........clpt..|
0x0B30: 00 90 00 00 00 08 49 43  43 70 01 00 29 00 00 00  |......ICCp..)...|
0x0B40: 00 00 00 FF 01 00 00 00  00 00 00 00 6E FD 6E 72  |............n.nr|
0x0B50: 73 DF 00 7F F8 CF 79 15  FF 02 00 11 00 08 00 26  |s.....y........&|
0x0B60: 00 0F 61 63 73 70 00 00  01 00 08 6B 00 2C 98 15  |..acsp.....k.,..|
0x0B70: 00 D0 50 00 00 00 00 00  00 00 00 00 00 00 73 6F  |..P...........so|
0x0B80: 3C FF FF 00 00 00 00 00  00 00 00 47 40 00 00 73  |<..........G@..s|
0x0B90: 70 65 3C 00 00 00 00 00  00 00 00 00 00 00 00 00  |pe<.............|
0x0BA0: 00 00 00 00 00 1E 1E 1E  1E 1E 1E 1E E2 D7 1E 4D  |...............M|
0x0BB0: 43 1E 43 FD 75 FF FF 1E  1E 52 00 00 00 00 41 00  |C.C.u....R....A.|
0x0BC0: 00 00 00 00 04 00 CF FF  FF FF FF FF 00 00 00 00  |................|
0x0BD0: 00 01 63 6C 00 70 00 74  00 90 00 00 00 08 49 43  |..cl.p.t......IC|
0x0BE0: 43 70 01 00 29 00 00 00  00 00 00 FF FE FF FF FF  |Cp..)...........|
0x0BF0: FF 63 FF 73 6E 72 6E 63  FD 00 7F 79 CF DF F8 15  |.c.snrnc...y....|
0x0C00: FF 02 00 11 00 08 00 26  00 0F 61 63 73 70 00 00  |.......&..acsp..|
0x0C10: 01 00 08 E0 00 00 00 00  00 00 FC 00 00 00 00 00  |................|
0x0C20: 00 00 00 00 00 00 73 6F  3C FF FF 04 00 00 00 00  |......so<.......|
0x0C30: 00 00 1E 1E 1E 1E 1E 1E  1E E2 D7 1E 4D 43 1E 43  |............MC.C|
0x0C40: B6 B6 B6 B6 B6 B6 B6 B6  B6 B6 B6 B6 B6 B6 B6 B6  |................|
0x0C50: B6 B6 B6 B6 B6 B6 B6 B6  B6 B6 B6 B6 B6 B6 B6 B6  |................|
0x0C60: B6 B6 B6 B6 B6 FD 75 FF  FF 1E 1E 52 00 00 00 00  |......u....R....|
0x0C70: 41 00 00 00 00 00 04 00  CF FF FF FF              |A...........|

=== NINJA MODE ANALYSIS COMPLETE ===
Raw data inspection complete. No validation performed.
Use this information for debugging malformed profiles.
```

---

## Command 3: Round-Trip Test (`-r`)

**Exit Code: 2**

```

=== Round-Trip Tag Pair Analysis ===
Profile: /home/h02332/po/research/test-profiles/sbo-CIccProfile-LoadTag-IccProfile_cpp-specsep.icc

Error reading ICC profile

Profile failed validation. Try ninja mode: iccAnalyzer -n /home/h02332/po/research/test-profiles/sbo-CIccProfile-LoadTag-IccProfile_cpp-specsep.icc
```

---

## LUT Text Export (`-xt`)

**Exit Code: 2**

```
Error reading ICC profile
Exported 0 text file(s) to /tmp/tmp.EqVGjjWbFj/
```

---

## Cube Export (`-cube`)

**Exit Code: 1**

```
No 3D CLUT found in any standard LUT tag
```
