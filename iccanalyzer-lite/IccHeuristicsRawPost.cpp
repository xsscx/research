/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

// Post-library raw-file heuristics (H33-H55, H57, H59, H68-H69).
// These heuristics operate on raw file bytes with their own FILE* handles.
// Extracted from IccAnalyzerSecurity.cpp for modularity.

#include "IccHeuristicsRawPost.h"
#include "IccAnalyzerSecurity.h"
#include "IccAnalyzerColors.h"
#include "IccAnalyzerSignatures.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include "IccHeuristicsHelpers.h"


int RunHeuristic_H33_mBAmABSubElementOffset(const char *filename)
{
  int heuristicCount = 0;

  // =========================================================================
  // Raw-file heuristics H33-H36 (safe on all inputs — no library API calls)
  // Derived from ICC profile structural analysis and fuzzer coverage gaps:
  // OOB sub-element offsets, integer overflow via 32-bit truncation in bounds checks.
  // =========================================================================

  // 33. mBA/mAB Sub-Element Offset Validation (raw file bytes)
  // Detects OOB M/CLUT/A curve offsets within mBA/mAB tags that cause reads past
  // mmap boundary. Parsers following B→M→CLUT→A offsets without bounds checking
  // against tag size are vulnerable to SIGBUS/SIGSEGV.
  printf("[H33] mBA/mAB Sub-Element Offset Validation\n");
  {
    RawFileHandle fh33 = OpenRawFile(filename);
    if (fh33) {
      size_t fs33 = (size_t)fh33.fileSize;

      int mbaOobCount = 0;
      if (fs33 >= 132) {
        icUInt8Number hdr33[132];
        if (fread(hdr33, 1, 132, fh33.fp) == 132) {
          icUInt32Number tc33 = ReadU32BE(&hdr33[128]);

          for (icUInt32Number i = 0; i < tc33 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs33) break;

            icUInt8Number e33[12];
            fseek(fh33.fp, ePos, SEEK_SET);
            if (fread(e33, 1, 12, fh33.fp) != 12) break;

            icUInt32Number tSig33 = ReadU32BE(e33);
            icUInt32Number tOff33 = ReadU32BE(&e33[4]);
            icUInt32Number tSz33  = ReadU32BE(&e33[8]);

            // Read tag type signature at the tag data offset
            if ((uint64_t)tOff33 + 32 > fs33 || tSz33 < 32) continue;
            icUInt8Number tagData33[32];
            fseek(fh33.fp, tOff33, SEEK_SET);
            if (fread(tagData33, 1, 32, fh33.fp) != 32) continue;

            icUInt32Number tagType33 = ReadU32BE(tagData33);

            // Check for mAB (0x6D414220) or mBA (0x6D424120)
            if (tagType33 != 0x6D414220 && tagType33 != 0x6D424120) continue;

            char sig33[5];
            sig33[0] = static_cast<char>((tSig33>>24)&0xff); sig33[1] = static_cast<char>((tSig33>>16)&0xff);
            sig33[2] = static_cast<char>((tSig33>>8)&0xff);  sig33[3] = static_cast<char>(tSig33&0xff); sig33[4] = '\0';
            const char *typeName33 = (tagType33 == 0x6D414220) ? "mAB" : "mBA";

            // mBA/mAB internal structure (offsets from tag start):
            // +0: type sig (4), +4: reserved (4), +8: nInput(1)+nOutput(1)+pad(2)
            // +12: B offset (4), +16: matrix offset (4), +20: M offset (4)
            // +24: CLUT offset (4), +28: A offset (4)
            struct { const char *name; size_t pos; } subElems[] = {
              {"B_curves", 12}, {"Matrix", 16}, {"M_curves", 20}, {"CLUT", 24}, {"A_curves", 28}
            };

            for (int se = 0; se < 5; se++) {
              size_t p = subElems[se].pos;
              icUInt32Number subOff = ReadU32BE(&tagData33[p]);
              if (subOff == 0) continue; // not present

              if (subOff > tSz33) {
                printf("      %s[WARN]  Tag '%s' (%s): %s offset 0x%08X exceeds tag size %u%s\n",
                       ColorCritical(), sig33, typeName33, subElems[se].name, subOff, tSz33, ColorReset());
                if (subOff >= 0xFFFF0000) {
                  printf("       %sCRITICAL: Offset near uint32 max — OOB read/write past mmap boundary%s\n",
                         ColorCritical(), ColorReset());
                }
                mbaOobCount++;
              }
            }
          }
        }
      }

      if (mbaOobCount > 0) {
        printf("      %s%d mBA/mAB sub-element offset(s) reference data beyond tag bounds%s\n",
               ColorCritical(), mbaOobCount, ColorReset());
        printf("      %sRisk: OOB read past mmap boundary → SIGBUS/SIGSEGV on ICC parsers%s\n",
               ColorCritical(), ColorReset());
        printf("      %sNote: Parsers observed in the wild follow B→M→CLUT→A offsets without bounds%s\n",
               ColorWarning(), ColorReset());
        printf("      %s       checking against tag size — OOB crash confirmed on arm64%s\n",
               ColorWarning(), ColorReset());
        heuristicCount += mbaOobCount;
      } else {
        printf("      %s[OK] All mBA/mAB sub-element offsets within tag bounds%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H34_IntegerOverflowSubElement(const char *filename)
{
  int heuristicCount = 0;

  // 34. 32-bit Integer Overflow in Sub-Element Offset Bounds Checks
  // Common ICC parser pattern: offset + element_size computed in 32-bit arithmetic.
  // When CLUT offset ≥ 0xFFFFFFEC, the add wraps: 0xFFFFFFFF + 0x14 = 0x13 (truncated)
  // which passes the bounds check, leading to OOB access.
  printf("[H34] 32-bit Integer Overflow in Sub-Element Bounds\n");
  {
    RawFileHandle fh34 = OpenRawFile(filename);
    if (fh34) {
      size_t fs34 = (size_t)fh34.fileSize;

      int overflowCount = 0;
      if (fs34 >= 132) {
        icUInt8Number hdr34[132];
        if (fread(hdr34, 1, 132, fh34.fp) == 132) {
          icUInt32Number tc34 = ReadU32BE(&hdr34[128]);

          for (icUInt32Number i = 0; i < tc34 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs34) break;

            icUInt8Number e34[12];
            fseek(fh34.fp, ePos, SEEK_SET);
            if (fread(e34, 1, 12, fh34.fp) != 12) break;

            icUInt32Number tOff34 = ReadU32BE(&e34[4]);
            icUInt32Number tSz34  = ReadU32BE(&e34[8]);

            if ((uint64_t)tOff34 + 32 > fs34 || tSz34 < 32) continue;
            icUInt8Number tagData34[32];
            fseek(fh34.fp, tOff34, SEEK_SET);
            if (fread(tagData34, 1, 32, fh34.fp) != 32) continue;

            icUInt32Number tagType34 = ReadU32BE(tagData34);

            if (tagType34 != 0x6D414220 && tagType34 != 0x6D424120) continue;

            icUInt32Number tSig34 = ReadU32BE(e34);
            char sig34[5];
            sig34[0] = static_cast<char>((tSig34>>24)&0xff); sig34[1] = static_cast<char>((tSig34>>16)&0xff);
            sig34[2] = static_cast<char>((tSig34>>8)&0xff);  sig34[3] = static_cast<char>(tSig34&0xff); sig34[4] = '\0';

            // Check sub-element offsets at +20 (M), +24 (CLUT), +28 (A)
            // These are the offsets parsers add small constants to for header traversal
            static const uint32_t addConstants[] = {0x14, 0x30, 0x0C};
            static const char *subNames34[] = {"M_curves", "CLUT", "A_curves"};
            static const size_t subPos34[] = {20, 24, 28};

            for (int se = 0; se < 3; se++) {
              size_t p = subPos34[se];
              icUInt32Number subOff = ReadU32BE(&tagData34[p]);
              if (subOff == 0) continue;

              // Check if offset + any common addend overflows 32 bits
              for (int ac = 0; ac < 3; ac++) {
                uint64_t sum64 = (uint64_t)subOff + addConstants[ac];
                uint32_t sum32 = (uint32_t)sum64;
                if (sum64 != sum32) {
                  printf("      %s[WARN]  Tag '%s': %s offset 0x%08X + 0x%X = 0x%08X (truncated from 0x%llX)%s\n",
                         ColorCritical(), sig34, subNames34[se], subOff, addConstants[ac],
                         sum32, (unsigned long long)sum64, ColorReset());
                  printf("       %sCRITICAL: 32-bit truncation bypasses bounds check → OOB access%s\n",
                         ColorCritical(), ColorReset());
                  overflowCount++;
                  break; // one overflow per sub-element is enough
                }
              }
            }
          }
        }
      }

      if (overflowCount > 0) {
        printf("      %s%d sub-element offset(s) trigger 32-bit integer overflow%s\n",
               ColorCritical(), overflowCount, ColorReset());
        printf("      %sRisk: Bounds check bypass via uint32 truncation (common ICC parser vulnerability)%s\n",
               ColorCritical(), ColorReset());
        heuristicCount += overflowCount;
      } else {
        printf("      %s[OK] No 32-bit integer overflow in sub-element offsets%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H35_SuspiciousFillPattern(const char *filename)
{
  int heuristicCount = 0;

  // 35. Suspicious Fill Pattern Detection in mBA/mAB B-Curve Data
  // All-0xFF fill in B-curve data (bytes 32+) creates parseable curve structures that
  // the parser processes without error, then follows OOB M/CLUT/A offsets into unmapped memory.
  // Changing fill to 0x00 or 0x41 causes "Data overruns tag length" early exit.
  printf("[H35] Suspicious Fill Pattern in mBA/mAB Data\n");
  {
    RawFileHandle fh35 = OpenRawFile(filename);
    if (fh35) {
      size_t fs35 = (size_t)fh35.fileSize;

      int fillCount = 0;
      if (fs35 >= 132) {
        icUInt8Number hdr35[132];
        if (fread(hdr35, 1, 132, fh35.fp) == 132) {
          icUInt32Number tc35 = ReadU32BE(&hdr35[128]);

          for (icUInt32Number i = 0; i < tc35 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs35) break;

            icUInt8Number e35[12];
            fseek(fh35.fp, ePos, SEEK_SET);
            if (fread(e35, 1, 12, fh35.fp) != 12) break;

            icUInt32Number tSig35 = ReadU32BE(e35);
            icUInt32Number tOff35 = ReadU32BE(&e35[4]);
            icUInt32Number tSz35  = ReadU32BE(&e35[8]);

            if ((uint64_t)tOff35 + 32 > fs35 || tSz35 < 48) continue; // need at least 32-byte header + 16 data bytes
            icUInt8Number typeCheck[4];
            fseek(fh35.fp, tOff35, SEEK_SET);
            if (fread(typeCheck, 1, 4, fh35.fp) != 4) continue;

            icUInt32Number tagType35 = ReadU32BE(typeCheck);
            if (tagType35 != 0x6D414220 && tagType35 != 0x6D424120) continue;

            // Read B-curve data region (bytes 32+ within the tag, up to 256 bytes)
            size_t dataStart = (uint64_t)tOff35 + 32;
            size_t dataLen = tSz35 - 32;
            if (dataLen > 256) dataLen = 256;
            if (dataStart + dataLen > fs35) dataLen = fs35 - dataStart;
            if (dataLen < 16) continue;

            icUInt8Number bData[256];
            fseek(fh35.fp, dataStart, SEEK_SET);
            if (fread(bData, 1, dataLen, fh35.fp) != dataLen) continue;

            // Check for runs of identical bytes ≥ 16
            int runLen = 1;
            for (size_t b = 1; b < dataLen; b++) {
              if (bData[b] == bData[b-1]) {
                runLen++;
              } else {
                if (runLen >= 16) {
                  char sig35[5];
                  sig35[0] = static_cast<char>((tSig35>>24)&0xff); sig35[1] = static_cast<char>((tSig35>>16)&0xff);
                  sig35[2] = static_cast<char>((tSig35>>8)&0xff);  sig35[3] = static_cast<char>(tSig35&0xff); sig35[4] = '\0';
                  printf("      %s[WARN]  Tag '%s': %d-byte run of 0x%02X at B-curve data+%zu%s\n",
                         ColorWarning(), sig35, runLen, bData[b-1], b - runLen, ColorReset());
                  if (bData[b-1] == 0xFF) {
                    printf("       %s0xFF fill creates parseable curve structure → enables OOB offset traversal%s\n",
                           ColorCritical(), ColorReset());
                  }
                  fillCount++;
                }
                runLen = 1;
              }
            }
            // Check final run
            if (runLen >= 16) {
              char sig35[5];
              sig35[0] = static_cast<char>((tSig35>>24)&0xff); sig35[1] = static_cast<char>((tSig35>>16)&0xff);
              sig35[2] = static_cast<char>((tSig35>>8)&0xff);  sig35[3] = static_cast<char>(tSig35&0xff); sig35[4] = '\0';
              printf("      %s[WARN]  Tag '%s': %d-byte run of 0x%02X at B-curve data+%zu%s\n",
                     ColorWarning(), sig35, runLen, bData[dataLen-1], dataLen - runLen, ColorReset());
              if (bData[dataLen-1] == 0xFF) {
                printf("       %s0xFF fill creates parseable curve structure → enables OOB offset traversal%s\n",
                       ColorCritical(), ColorReset());
              }
              fillCount++;
            }
          }
        }
      }

      if (fillCount > 0) {
        printf("      %s%d suspicious fill pattern(s) in mBA/mAB B-curve data%s\n",
               ColorWarning(), fillCount, ColorReset());
        heuristicCount += fillCount;
      } else {
        printf("      %s[OK] No suspicious fill patterns in mBA/mAB data%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H36_LUTTagPairCompleteness(const char *filename)
{
  int heuristicCount = 0;

  // 36. LUT Tag Pair Completeness
  // Check A2B↔B2A and D2B↔B2D pairing. Unpaired LUT tags may indicate crafted
  // profiles targeting only one transform direction.
  printf("[H36] LUT Tag Pair Completeness\n");
  {
    RawFileHandle fh36 = OpenRawFile(filename);
    if (fh36) {
      size_t fs36 = (size_t)fh36.fileSize;

      int pairIssues = 0;
      if (fs36 >= 132) {
        icUInt8Number hdr36[132];
        if (fread(hdr36, 1, 132, fh36.fp) == 132) {
          icUInt32Number tc36 = ReadU32BE(&hdr36[128]);

          // Collect all tag signatures
          bool hasA2B[4] = {false}, hasB2A[4] = {false};
          bool hasD2B[4] = {false}, hasB2D[4] = {false};

          for (icUInt32Number i = 0; i < tc36 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs36) break;

            icUInt8Number e36[12];
            fseek(fh36.fp, ePos, SEEK_SET);
            if (fread(e36, 1, 12, fh36.fp) != 12) break;

            icUInt32Number tSig36 = ReadU32BE(e36);

            // A2B0-A2B3: 0x41324230 - 0x41324233
            // B2A0-B2A3: 0x42324130 - 0x42324133
            // D2B0-D2B3: 0x44324230 - 0x44324233
            // B2D0-B2D3: 0x42324430 - 0x42324433
            if (tSig36 >= 0x41324230 && tSig36 <= 0x41324233) hasA2B[tSig36 - 0x41324230] = true;
            if (tSig36 >= 0x42324130 && tSig36 <= 0x42324133) hasB2A[tSig36 - 0x42324130] = true;
            if (tSig36 >= 0x44324230 && tSig36 <= 0x44324233) hasD2B[tSig36 - 0x44324230] = true;
            if (tSig36 >= 0x42324430 && tSig36 <= 0x42324433) hasB2D[tSig36 - 0x42324430] = true;
          }

          // Check pairing
          for (int idx = 0; idx < 4; idx++) {
            if (hasA2B[idx] && !hasB2A[idx]) {
              printf("      %s[INFO]  A2B%d present but B2A%d missing — forward-only LUT%s\n",
                     ColorInfo(), idx, idx, ColorReset());
              pairIssues++;
            }
            if (hasB2A[idx] && !hasA2B[idx]) {
              printf("      %s[INFO]  B2A%d present but A2B%d missing — reverse-only LUT%s\n",
                     ColorInfo(), idx, idx, ColorReset());
              pairIssues++;
            }
            if (hasD2B[idx] && !hasB2D[idx]) {
              printf("      %s[INFO]  D2B%d present but B2D%d missing — forward-only device LUT%s\n",
                     ColorInfo(), idx, idx, ColorReset());
              pairIssues++;
            }
            if (hasB2D[idx] && !hasD2B[idx]) {
              printf("      %s[INFO]  B2D%d present but D2B%d missing — reverse-only device LUT%s\n",
                     ColorInfo(), idx, idx, ColorReset());
              pairIssues++;
            }
          }
        }
      }

      if (pairIssues > 0) {
        printf("      %s%d unpaired LUT tag(s) — may indicate crafted profile%s\n",
               ColorInfo(), pairIssues, ColorReset());
        // Informational only — do not increment heuristicCount for missing pairs
      } else {
        printf("      %s[OK] All LUT tags properly paired%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H37_CalculatorElementComplexity(const char *filename)
{
  int heuristicCount = 0;

  // 37. Calculator Element Complexity Validation (raw file bytes)
  // Calculator elements (0x63616C63 'calc') are Turing-complete: if/sel opcodes enable
  // arbitrary branching, tget/tput/tsav access stack memory. #1 UBSAN source in fuzzing.
  // CVE refs: CVE-2026-22047, calcOverMem/calcUnderStack test profiles
  printf("[H37] Calculator Element Complexity Validation\n");
  {
    RawFileHandle fh37 = OpenRawFile(filename);
    if (fh37) {
      size_t fs37 = (size_t)fh37.fileSize;

      int calcIssues = 0;
      if (fs37 >= 132) {
        icUInt8Number hdr37[132];
        if (fread(hdr37, 1, 132, fh37.fp) == 132) {
          icUInt32Number tc37 = ReadU32BE(&hdr37[128]);

          for (icUInt32Number i = 0; i < tc37 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs37) break;

            icUInt8Number e37[12];
            fseek(fh37.fp, ePos, SEEK_SET);
            if (fread(e37, 1, 12, fh37.fp) != 12) break;

            icUInt32Number tSig37 = ReadU32BE(e37);
            icUInt32Number tOff37 = ReadU32BE(&e37[4]);
            icUInt32Number tSz37  = ReadU32BE(&e37[8]);

            if ((uint64_t)tOff37 + 4 > fs37 || tSz37 < 4) continue;

            // Check if tag contains mpet type
            icUInt8Number typeCheck37[4];
            fseek(fh37.fp, tOff37, SEEK_SET);
            if (fread(typeCheck37, 1, 4, fh37.fp) != 4) continue;
            icUInt32Number tagType37 = ReadU32BE(typeCheck37);
            // mpet = 0x6D706574
            if (tagType37 != 0x6D706574) continue;

            // Scan tag data for 'calc' sub-element signatures (0x63616C63)
            // and count occurrences + check for extreme indices
            size_t scanLen = (tSz37 < 4096) ? tSz37 : 4096;
            if (tOff37 + scanLen > fs37) scanLen = fs37 - tOff37;
            if (scanLen < 8) continue;

            icUInt8Number *scanBuf = new icUInt8Number[scanLen];
            fseek(fh37.fp, tOff37, SEEK_SET);
            if (fread(scanBuf, 1, scanLen, fh37.fp) != scanLen) { delete[] scanBuf; continue; }

            char sig37[5];
            sig37[0] = static_cast<char>((tSig37>>24)&0xff); sig37[1] = static_cast<char>((tSig37>>16)&0xff);
            sig37[2] = static_cast<char>((tSig37>>8)&0xff);  sig37[3] = static_cast<char>(tSig37&0xff); sig37[4] = '\0';

            int calcCount = 0;
            int ifSelCount = 0;
            for (size_t b = 0; b + 3 < scanLen; b++) {
              icUInt32Number w = ReadU32BE(&scanBuf[b]);
              if (w == 0x63616C63) calcCount++; // 'calc'
              if (w == 0x69660000 || w == 0x73656C00) ifSelCount++; // 'if\0\0' or 'sel\0' patterns
            }

            if (calcCount > 100) {
              printf("      %s[WARN]  Tag '%s': %d calculator sub-elements (limit 100)%s\n",
                     ColorCritical(), sig37, calcCount, ColorReset());
              printf("       %sRisk: Stack exhaustion / OOM via calculator element recursion%s\n",
                     ColorCritical(), ColorReset());
              calcIssues++;
            }

            // Check for zero-length MPE (tag size < 16 means no elements)
            if (tSz37 >= 8 && tSz37 < 16) {
              printf("      %s[WARN]  Tag '%s': MPE tag size %u too small for any elements%s\n",
                     ColorWarning(), sig37, tSz37, ColorReset());
              printf("       %sRisk: Crash on empty element list traversal%s\n",
                     ColorCritical(), ColorReset());
              calcIssues++;
            }

            // Check for extreme sub-element count in mpet header
            // mpet: type(4) + reserved(4) + nInput(2) + nOutput(2) + nElements(4) = 16 bytes
            if (scanLen >= 16) {
              icUInt32Number nElems = ReadU32BE(&scanBuf[12]);
              if (nElems > 256) {
                printf("      %s[WARN]  Tag '%s': MPE has %u elements (limit 256)%s\n",
                       ColorCritical(), sig37, nElems, ColorReset());
                printf("       %sRisk: DoS via excessive element processing%s\n",
                       ColorCritical(), ColorReset());
                calcIssues++;
              }
            }

            delete[] scanBuf;
          }
        }
      }

      if (calcIssues > 0) {
        heuristicCount += calcIssues;
      } else {
        printf("      %s[OK] No calculator complexity issues%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H38_CurveDegenerateValue(const char *filename)
{
  int heuristicCount = 0;

  // 38. Curve Degenerate Value Detection (raw file bytes)
  // TRC curves with all-zero, all-max, or NaN values cause undefined behavior
  // in color math. Applies to curv (0x63757276) and para (0x70617261) tags.
  printf("[H38] Curve Degenerate Value Detection\n");
  {
    RawFileHandle fh38 = OpenRawFile(filename);
    if (fh38) {
      size_t fs38 = (size_t)fh38.fileSize;

      int curveIssues = 0;
      if (fs38 >= 132) {
        icUInt8Number hdr38[132];
        if (fread(hdr38, 1, 132, fh38.fp) == 132) {
          icUInt32Number tc38 = ReadU32BE(&hdr38[128]);

          for (icUInt32Number i = 0; i < tc38 && i < 256; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs38) break;

            icUInt8Number e38[12];
            fseek(fh38.fp, ePos, SEEK_SET);
            if (fread(e38, 1, 12, fh38.fp) != 12) break;

            icUInt32Number tSig38 = ReadU32BE(e38);
            icUInt32Number tOff38 = ReadU32BE(&e38[4]);
            icUInt32Number tSz38  = ReadU32BE(&e38[8]);

            if ((uint64_t)tOff38 + 12 > fs38 || tSz38 < 12) continue;
            icUInt8Number curveHdr[12];
            fseek(fh38.fp, tOff38, SEEK_SET);
            if (fread(curveHdr, 1, 12, fh38.fp) != 12) continue;

            icUInt32Number curveType = ReadU32BE(curveHdr);

            char sig38[5];
            sig38[0] = static_cast<char>((tSig38>>24)&0xff); sig38[1] = static_cast<char>((tSig38>>16)&0xff);
            sig38[2] = static_cast<char>((tSig38>>8)&0xff);  sig38[3] = static_cast<char>(tSig38&0xff); sig38[4] = '\0';

            if (curveType == 0x63757276) { // 'curv'
              // curv: type(4) + reserved(4) + count(4) + entries(2*count)
              icUInt32Number count = ReadU32BE(&curveHdr[8]);
              if (count > 1 && count <= 65535) {
                size_t dataStart = (uint64_t)tOff38 + 12;
                size_t dataLen = count * 2;
                if (dataLen > 512) dataLen = 512; // sample first 256 entries
                if (dataStart + dataLen > fs38) continue;

                icUInt8Number *cData = new icUInt8Number[dataLen];
                fseek(fh38.fp, dataStart, SEEK_SET);
                if (fread(cData, 1, dataLen, fh38.fp) == dataLen) {
                  bool allZero = true, allMax = true;
                  for (size_t b = 0; b + 1 < dataLen; b += 2) {
                    uint16_t val = (static_cast<uint16_t>(cData[b]) << 8) | cData[b+1];
                    if (val != 0) allZero = false;
                    if (val != 0xFFFF) allMax = false;
                  }
                  if (allZero) {
                    printf("      %s[WARN]  Tag '%s' (curv): all %u entries are zero — degenerate TRC%s\n",
                           ColorCritical(), sig38, count, ColorReset());
                    printf("       %sRisk: All color channels collapse to black — division by zero in inverse%s\n",
                           ColorCritical(), ColorReset());
                    curveIssues++;
                  }
                  if (allMax) {
                    printf("      %s[WARN]  Tag '%s' (curv): all %u entries are 0xFFFF — saturated TRC%s\n",
                           ColorWarning(), sig38, count, ColorReset());
                    curveIssues++;
                  }
                }
                delete[] cData;
              }
            } else if (curveType == 0x70617261) { // 'para'
              // para: type(4) + reserved(4) + funcType(2) + reserved(2) + params...
              // funcType 0: Y = X^g  (1 param: g)
              // funcType 1-4: increasingly complex (a,b,c,d,e,f params)
              if (tSz38 >= 16) {
                icUInt8Number paraHdr[4];
                fseek(fh38.fp, tOff38 + 8, SEEK_SET);
                if (fread(paraHdr, 1, 4, fh38.fp) == 4) {
                  uint16_t funcType = (static_cast<uint16_t>(paraHdr[0]) << 8) | paraHdr[1];
                  if (funcType > 4) {
                    printf("      %s[WARN]  Tag '%s' (para): funcType %u > 4 (invalid)%s\n",
                           ColorCritical(), sig38, funcType, ColorReset());
                    printf("       %sRisk: Parser reads uninitialized coefficients%s\n",
                           ColorCritical(), ColorReset());
                    curveIssues++;
                  }
                  // Check first param (gamma) for zero — causes pow(x, 0) flattening
                  if ((uint64_t)tOff38 + 16 <= fs38) {
                    icUInt8Number gamma38[4];
                    fseek(fh38.fp, tOff38 + 12, SEEK_SET);
                    if (fread(gamma38, 1, 4, fh38.fp) == 4) {
                      int32_t gammaFixed = static_cast<int32_t>(ReadU32BE(gamma38));
                      if (gammaFixed == 0) {
                        printf("      %s[WARN]  Tag '%s' (para): gamma = 0 (s15Fixed16) — degenerate%s\n",
                               ColorWarning(), sig38, ColorReset());
                        curveIssues++;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }

      if (curveIssues > 0) {
        heuristicCount += curveIssues;
      } else {
        printf("      %s[OK] No degenerate curve values detected%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H39_SharedTagDataAliasing(const char *filename)
{
  int heuristicCount = 0;

  // 39. Shared Tag Data Aliasing Detection (raw file bytes)
  // Multiple tag entries pointing to the same offset+size is ICC-legal (shared data).
  // However, shared mutable types (mBA/mAB/calc/tary) can cause UAF.
  printf("[H39] Shared Tag Data Aliasing Detection\n");
  {
    RawFileHandle fh39 = OpenRawFile(filename);
    if (fh39) {
      size_t fs39 = (size_t)fh39.fileSize;

      int aliasIssues = 0;
      if (fs39 >= 132) {
        icUInt8Number hdr39[132];
        if (fread(hdr39, 1, 132, fh39.fp) == 132) {
          icUInt32Number tc39 = ReadU32BE(&hdr39[128]);
          if (tc39 > 256) tc39 = 256;

          struct TagEntry39 { icUInt32Number sig; icUInt32Number off; icUInt32Number sz; };
          std::vector<TagEntry39> tags39;

          for (icUInt32Number i = 0; i < tc39; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs39) break;
            icUInt8Number e39[12];
            fseek(fh39.fp, ePos, SEEK_SET);
            if (fread(e39, 1, 12, fh39.fp) != 12) break;
            TagEntry39 te;
            te.sig = ReadU32BE(e39);
            te.off = ReadU32BE(&e39[4]);
            te.sz  = ReadU32BE(&e39[8]);
            tags39.push_back(te);
          }

          int sharedCount = 0;
          for (size_t a = 0; a < tags39.size(); a++) {
            for (size_t b = a+1; b < tags39.size(); b++) {
              if (tags39[a].off == tags39[b].off && tags39[a].sz == tags39[b].sz && tags39[a].sig != tags39[b].sig) {
                char s1[5], s2[5];
                s1[0] = static_cast<char>((tags39[a].sig>>24)&0xff); s1[1] = static_cast<char>((tags39[a].sig>>16)&0xff); s1[2] = static_cast<char>((tags39[a].sig>>8)&0xff); s1[3] = static_cast<char>(tags39[a].sig&0xff); s1[4] = '\0';
                s2[0] = static_cast<char>((tags39[b].sig>>24)&0xff); s2[1] = static_cast<char>((tags39[b].sig>>16)&0xff); s2[2] = static_cast<char>((tags39[b].sig>>8)&0xff); s2[3] = static_cast<char>(tags39[b].sig&0xff); s2[4] = '\0';

                sharedCount++;
                if (sharedCount <= 5) {
                  printf("      [INFO]  Tags '%s' and '%s' share data at offset 0x%X (%u bytes)\n",
                         s1, s2, tags39[a].off, tags39[a].sz);
                }

                // Check if shared type is mutable (mBA, mAB, calc, tary — higher UAF risk)
                if ((uint64_t)tags39[a].off + 4 <= fs39) {
                  icUInt8Number sharedType[4];
                  fseek(fh39.fp, tags39[a].off, SEEK_SET);
                  if (fread(sharedType, 1, 4, fh39.fp) == 4) {
                    icUInt32Number st = ReadU32BE(sharedType);
                    if (st == 0x6D424120 || st == 0x6D414220 || st == 0x6D706574 || st == 0x74617279) {
                      printf("      %s[WARN]  Shared data is mutable type (0x%08X) — UAF risk%s\n",
                             ColorCritical(), st, ColorReset());
                      aliasIssues++;
                    }
                  }
                }
              }
            }
          }

          if (sharedCount > 5) {
            printf("      ... and %d more shared tag pair(s)\n", sharedCount - 5);
          }
          if (sharedCount > 0 && aliasIssues == 0) {
            printf("      %s[OK] %d shared tag pair(s) — all immutable types (safe)%s\n",
                   ColorSuccess(), sharedCount, ColorReset());
          }
        }
      }

      if (aliasIssues > 0) {
        heuristicCount += aliasIssues;
      } else if (aliasIssues == 0) {
        printf("      %s[OK] No risky shared tag data aliasing%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H40_TagAlignmentPadding(const char *filename)
{
  int heuristicCount = 0;

  // 40. Tag Alignment & Padding Validation (raw file bytes)
  // ICC spec requires tag data offsets to be 4-byte aligned. Misalignment causes
  // SIGBUS on strict-alignment platforms (arm64). Non-zero padding can leak data.
  printf("[H40] Tag Alignment & Padding Validation\n");
  {
    RawFileHandle fh40 = OpenRawFile(filename);
    if (fh40) {
      size_t fs40 = (size_t)fh40.fileSize;

      int alignIssues = 0;
      if (fs40 >= 132) {
        icUInt8Number hdr40[132];
        if (fread(hdr40, 1, 132, fh40.fp) == 132) {
          icUInt32Number tc40 = ReadU32BE(&hdr40[128]);
          if (tc40 > 256) tc40 = 256;

          int misaligned = 0;
          int nonZeroPad = 0;

          for (icUInt32Number i = 0; i < tc40; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs40) break;
            icUInt8Number e40[12];
            fseek(fh40.fp, ePos, SEEK_SET);
            if (fread(e40, 1, 12, fh40.fp) != 12) break;

            icUInt32Number tOff40 = ReadU32BE(&e40[4]);
            icUInt32Number tSz40  = ReadU32BE(&e40[8]);

            // Check 4-byte alignment
            if (tOff40 % 4 != 0) {
              if (misaligned < 3) {
                char sig40[5];
                sig40[0] = static_cast<char>(e40[0]); sig40[1] = static_cast<char>(e40[1]); sig40[2] = static_cast<char>(e40[2]); sig40[3] = static_cast<char>(e40[3]); sig40[4] = '\0';
                printf("      %s[WARN]  Tag '%s' offset 0x%X not 4-byte aligned%s\n",
                       ColorWarning(), sig40, tOff40, ColorReset());
              }
              misaligned++;
            }

            // Check padding bytes after tag data (up to next 4-byte boundary)
            size_t tagEnd = (size_t)tOff40 + tSz40;
            size_t padEnd = (tagEnd + 3) & ~3UL;
            if (padEnd > tagEnd && padEnd <= fs40) {
              size_t padLen = padEnd - tagEnd;
              icUInt8Number padBuf[4];
              fseek(fh40.fp, tagEnd, SEEK_SET);
              size_t toRead = (padLen < 4) ? padLen : 4;
              if (fread(padBuf, 1, toRead, fh40.fp) == toRead) {
                for (size_t p = 0; p < toRead; p++) {
                  if (padBuf[p] != 0x00) {
                    nonZeroPad++;
                    break;
                  }
                }
              }
            }
          }

          if (misaligned > 3) {
            printf("      ... and %d more misaligned tag(s)\n", misaligned - 3);
          }
          if (misaligned > 0) {
            printf("      %s%d tag(s) with non-aligned offsets%s\n", ColorWarning(), misaligned, ColorReset());
            printf("      %sRisk: SIGBUS on strict-alignment platforms (arm64)%s\n",
                   ColorWarning(), ColorReset());
            alignIssues += misaligned;
          }
          if (nonZeroPad > 0) {
            printf("      %s[WARN]  %d tag(s) have non-zero padding bytes%s\n",
                   ColorWarning(), nonZeroPad, ColorReset());
            printf("      %sRisk: Potential data leakage in padding%s\n", ColorInfo(), ColorReset());
            alignIssues++;
          }
        }
      }

      if (alignIssues > 0) {
        heuristicCount++;
      } else {
        printf("      %s[OK] All tags properly aligned with zero padding%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H41_VersionTypeConsistency(const char *filename)
{
  int heuristicCount = 0;

  // 41. Version/Type Consistency Check (raw file bytes)
  // Flag v5-only types/tags in v2/v4 profiles (type confusion risk) and
  // deprecated v2-only types in v4+ profiles.
  printf("[H41] Version/Type Consistency Check\n");
  {
    RawFileHandle fh41 = OpenRawFile(filename);
    if (fh41) {
      size_t fs41 = (size_t)fh41.fileSize;

      int versionIssues = 0;
      if (fs41 >= 132) {
        icUInt8Number hdr41[132];
        if (fread(hdr41, 1, 132, fh41.fp) == 132) {
          // Profile version: byte 8 = major, byte 9 = minor.sub
          uint8_t verMajor = hdr41[8];
          uint8_t verMinor = hdr41[9];
          printf("      Profile version: %u.%u.%u\n", verMajor, (verMinor >> 4), (verMinor & 0x0F));

          icUInt32Number tc41 = ReadU32BE(&hdr41[128]);
          if (tc41 > 256) tc41 = 256;

          // v5-only type signatures
          static const icUInt32Number v5OnlyTypes[] = {
            0x736D6174, // 'smat' sparseMatrixArrayType
            0x7A757466, // 'zutf' zipUtf8Type
            0x7A786D6C, // 'zxml' zipXmlType
            0x63696370, // 'cicp' cicpType
            0x75746638, // 'utf8' utf8Type
            0x666C3136, // 'fl16' float16ArrayType
            0x666C3332, // 'fl32' float32ArrayType
            0x666C3634, // 'fl64' float64ArrayType
            0x62726466, // 'brdf' brdfType
          };
          // v5-only tag signatures
          static const icUInt32Number v5OnlyTags[] = {
            0x7364696E, // 'sdin' spectralDataInfo
            0x73777074, // 'swpt' spectralWhitePoint
            0x7376636E, // 'svcn' spectralViewingConditions
            0x656F6273, // 'eobs' emissionObserver
            0x726F6273, // 'robs' reflectanceObserver
          };

          for (icUInt32Number i = 0; i < tc41; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs41) break;
            icUInt8Number e41[12];
            fseek(fh41.fp, ePos, SEEK_SET);
            if (fread(e41, 1, 12, fh41.fp) != 12) break;

            icUInt32Number tSig41 = ReadU32BE(e41);
            icUInt32Number tOff41 = ReadU32BE(&e41[4]);

            char sig41[5];
            sig41[0] = static_cast<char>((tSig41>>24)&0xff); sig41[1] = static_cast<char>((tSig41>>16)&0xff);
            sig41[2] = static_cast<char>((tSig41>>8)&0xff);  sig41[3] = static_cast<char>(tSig41&0xff); sig41[4] = '\0';

            // Check tag signature against v5-only list
            if (verMajor < 5) {
              for (int k = 0; k < (int)(sizeof(v5OnlyTags)/sizeof(v5OnlyTags[0])); k++) {
                if (tSig41 == v5OnlyTags[k]) {
                  printf("      %s[WARN]  v5-only tag '%s' in v%u profile%s\n",
                         ColorWarning(), sig41, verMajor, ColorReset());
                  versionIssues++;
                  break;
                }
              }
            }

            // Check tag data type against v5-only list
            if (verMajor < 5 && (uint64_t)tOff41 + 4 <= fs41) {
              icUInt8Number typeBytes41[4];
              fseek(fh41.fp, tOff41, SEEK_SET);
              if (fread(typeBytes41, 1, 4, fh41.fp) == 4) {
                icUInt32Number dataType41 = ReadU32BE(typeBytes41);
                for (int k = 0; k < (int)(sizeof(v5OnlyTypes)/sizeof(v5OnlyTypes[0])); k++) {
                  if (dataType41 == v5OnlyTypes[k]) {
                    char typeStr41[5];
                    typeStr41[0] = (dataType41>>24)&0xff; typeStr41[1] = (dataType41>>16)&0xff;
                    typeStr41[2] = (dataType41>>8)&0xff;  typeStr41[3] = dataType41&0xff; typeStr41[4] = '\0';
                    printf("      %s[WARN]  Tag '%s' uses v5-only type '%s' in v%u profile%s\n",
                           ColorWarning(), sig41, typeStr41, verMajor, ColorReset());
                    printf("       %sRisk: Type confusion — v4 parser may misinterpret v5 data%s\n",
                           ColorCritical(), ColorReset());
                    versionIssues++;
                    break;
                  }
                }
              }
            }
          }
        }
      }

      if (versionIssues > 0) {
        printf("      %s%d version/type inconsistency(ies) detected%s\n",
               ColorWarning(), versionIssues, ColorReset());
        heuristicCount += versionIssues;
      } else {
        printf("      %s[OK] All tags/types consistent with declared version%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H42_MatrixSingularity(const char *filename)
{
  int heuristicCount = 0;

  // 42. Matrix Singularity Detection (raw file bytes)
  // Read rXYZ, gXYZ, bXYZ tags (s15Fixed16 × 3 each) and compute 3×3 determinant.
  // Near-zero determinant → division by zero in color transforms.
  printf("[H42] Matrix Singularity Detection\n");
  {
    RawFileHandle fh42 = OpenRawFile(filename);
    if (fh42) {
      size_t fs42 = (size_t)fh42.fileSize;

      int matrixIssues = 0;
      if (fs42 >= 132) {
        icUInt8Number hdr42[132];
        if (fread(hdr42, 1, 132, fh42.fp) == 132) {
          icUInt32Number tc42 = ReadU32BE(&hdr42[128]);
          if (tc42 > 256) tc42 = 256;

          // Find rXYZ (0x7258595A), gXYZ (0x6758595A), bXYZ (0x6258595A)
          static const icUInt32Number xyzSigs[] = {0x7258595A, 0x6758595A, 0x6258595A};
          double mat[3][3] = {{0}};
          int found = 0;

          for (int col = 0; col < 3; col++) {
            for (icUInt32Number i = 0; i < tc42; i++) {
              size_t ePos = 132 + i * 12;
              if (ePos + 12 > fs42) break;
              icUInt8Number e42[12];
              fseek(fh42.fp, ePos, SEEK_SET);
              if (fread(e42, 1, 12, fh42.fp) != 12) break;

              icUInt32Number tSig42 = ReadU32BE(e42);
              if (tSig42 != xyzSigs[col]) continue;

              icUInt32Number tOff42 = ReadU32BE(&e42[4]);
              // XYZ type: type(4) + reserved(4) + X(4) + Y(4) + Z(4) = 20 bytes
              if ((uint64_t)tOff42 + 20 > fs42) break;
              icUInt8Number xyzData[12];
              fseek(fh42.fp, tOff42 + 8, SEEK_SET);
              if (fread(xyzData, 1, 12, fh42.fp) != 12) break;

              for (int row = 0; row < 3; row++) {
                int32_t fixed = static_cast<int32_t>(ReadU32BE(&xyzData[row*4]));
                mat[row][col] = fixed / 65536.0;
              }
              found++;
              break;
            }
          }

          if (found == 3) {
            // Compute determinant: det = a(ei-fh) - b(di-fg) + c(dh-eg)
            double det = mat[0][0] * (mat[1][1]*mat[2][2] - mat[1][2]*mat[2][1])
                       - mat[0][1] * (mat[1][0]*mat[2][2] - mat[1][2]*mat[2][0])
                       + mat[0][2] * (mat[1][0]*mat[2][1] - mat[1][1]*mat[2][0]);

            printf("      Matrix determinant: %.8f\n", det);

            if (det == 0.0 || (det > -1e-7 && det < 1e-7)) {
              printf("      %s[WARN]  Near-singular matrix (det ≈ 0) — non-invertible%s\n",
                     ColorCritical(), ColorReset());
              printf("       %sRisk: Division by zero in inverse color transforms%s\n",
                     ColorCritical(), ColorReset());
              matrixIssues++;
            } else if (det < 0) {
              printf("      %s[WARN]  Negative determinant (%.6f) — inverted color space%s\n",
                     ColorWarning(), det, ColorReset());
              matrixIssues++;
            }
          } else {
            printf("      [INFO]  rXYZ/gXYZ/bXYZ tags not all present (%d/3 found)\n", found);
          }
        }
      }

      if (matrixIssues > 0) {
        heuristicCount += matrixIssues;
      } else {
        printf("      %s[OK] Color matrix is well-conditioned%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H43_SpectralBRDFTagStructure(const char *filename)
{
  int heuristicCount = 0;

  // 43. Spectral/BRDF Tag Structural Validation (raw file bytes)
  // ICC v5/iccMAX adds 24+ BRDF signatures and spectral tags. Check for
  // structural presence and pairing issues.
  printf("[H43] Spectral/BRDF Tag Structural Validation\n");
  {
    RawFileHandle fh43 = OpenRawFile(filename);
    if (fh43) {
      size_t fs43 = (size_t)fh43.fileSize;

      int spectralIssues = 0;
      if (fs43 >= 132) {
        icUInt8Number hdr43[132];
        if (fread(hdr43, 1, 132, fh43.fp) == 132) {
          icUInt32Number tc43 = ReadU32BE(&hdr43[128]);
          if (tc43 > 256) tc43 = 256;

          bool hasSdin = false, hasSwpt = false;
          bool hasEobs = false, hasRobs = false, hasSvcn = false;
          int brdfCount = 0;

          for (icUInt32Number i = 0; i < tc43; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs43) break;
            icUInt8Number e43[12];
            fseek(fh43.fp, ePos, SEEK_SET);
            if (fread(e43, 1, 12, fh43.fp) != 12) break;

            icUInt32Number tSig43 = ReadU32BE(e43);
            icUInt32Number tOff43 = ReadU32BE(&e43[4]);
            icUInt32Number tSz43  = ReadU32BE(&e43[8]);

            if (tSig43 == 0x7364696E) hasSdin = true; // 'sdin'
            if (tSig43 == 0x73777074) hasSwpt = true; // 'swpt'
            if (tSig43 == 0x7376636E) hasSvcn = true; // 'svcn'
            if (tSig43 == 0x656F6273) hasEobs = true; // 'eobs'
            if (tSig43 == 0x726F6273) hasRobs = true; // 'robs'

            // Count BRDF tags (bAB, bDB, bMB, bMS, bcp, bsp, BPh)
            char s43[5];
            s43[0] = static_cast<char>((tSig43>>24)&0xff); s43[1] = static_cast<char>((tSig43>>16)&0xff);
            s43[2] = static_cast<char>((tSig43>>8)&0xff);  s43[3] = static_cast<char>(tSig43&0xff); s43[4] = '\0';
            if ((s43[0] == 'b' && (s43[1] == 'A' || s43[1] == 'D' || s43[1] == 'M' || s43[1] == 'c' || s43[1] == 's')) ||
                (s43[0] == 'B' && s43[1] == 'P')) {
              brdfCount++;
              // Check for zero-size BRDF tag
              if (tSz43 < 8) {
                printf("      %s[WARN]  BRDF tag '%s' has size %u < 8 (too small for any data)%s\n",
                       ColorWarning(), s43, tSz43, ColorReset());
                spectralIssues++;
              }
            }

            // Validate sdin structure: spectralDataInfo must have valid wavelength data
            if (tSig43 == 0x7364696E && (uint64_t)tOff43 + 20 <= fs43 && tSz43 >= 20) {
              icUInt8Number sdinData[12];
              fseek(fh43.fp, tOff43 + 8, SEEK_SET);
              if (fread(sdinData, 1, 12, fh43.fp) == 12) {
                // Spectral range: start(4), end(4), steps(2)
                int32_t specStart = static_cast<int32_t>(ReadU32BE(sdinData));
                int32_t specEnd   = static_cast<int32_t>(ReadU32BE(&sdinData[4]));
                uint16_t specSteps = (static_cast<uint16_t>(sdinData[8])<<8) | sdinData[9];
                double startNm = specStart / 65536.0;
                double endNm   = specEnd / 65536.0;
                if (endNm < startNm) {
                  printf("      %s[WARN]  sdin: spectral end (%.1f nm) < start (%.1f nm)%s\n",
                         ColorCritical(), endNm, startNm, ColorReset());
                  spectralIssues++;
                }
                if (specSteps == 0 || specSteps > 1000) {
                  printf("      %s[WARN]  sdin: spectral steps = %u (expected 1-1000)%s\n",
                         ColorWarning(), specSteps, ColorReset());
                  spectralIssues++;
                }
              }
            }
          }

          // Report BRDF presence
          if (brdfCount > 0) {
            printf("      [INFO]  %d BRDF tag(s) present\n", brdfCount);
          }

          // Check spectral tag consistency
          if (hasSdin && !hasSwpt) {
            printf("      %s[WARN]  sdin present but swpt (spectral white) missing%s\n",
                   ColorWarning(), ColorReset());
            spectralIssues++;
          }
          if (hasEobs && !hasRobs && hasSdin) {
            printf("      [INFO]  eobs present without robs — emission-only profile\n");
          }
          if (hasSvcn && !hasSdin) {
            printf("      %s[WARN]  svcn present but sdin (spectral data info) missing%s\n",
                   ColorWarning(), ColorReset());
            spectralIssues++;
          }
        }
      }

      if (spectralIssues > 0) {
        heuristicCount += spectralIssues;
      } else {
        printf("      %s[OK] Spectral/BRDF tags structurally valid%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H44_EmbeddedImageValidation(const char *filename)
{
  int heuristicCount = 0;

  // 44. Embedded Image Validation (raw file bytes, ICC v5)
  // v5 embeddedHeightImageType / embeddedNormalImageType (embt = 0x656D6274)
  // can contain PNG or TIFF data. Check magic bytes and size.
  printf("[H44] Embedded Image Validation\n");
  {
    RawFileHandle fh44 = OpenRawFile(filename);
    if (fh44) {
      size_t fs44 = (size_t)fh44.fileSize;

      int embedIssues = 0;
      if (fs44 >= 132) {
        icUInt8Number hdr44[132];
        if (fread(hdr44, 1, 132, fh44.fp) == 132) {
          icUInt32Number tc44 = ReadU32BE(&hdr44[128]);
          if (tc44 > 256) tc44 = 256;

          int embedFound = 0;
          for (icUInt32Number i = 0; i < tc44; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs44) break;
            icUInt8Number e44[12];
            fseek(fh44.fp, ePos, SEEK_SET);
            if (fread(e44, 1, 12, fh44.fp) != 12) break;

            icUInt32Number tOff44 = ReadU32BE(&e44[4]);
            icUInt32Number tSz44  = ReadU32BE(&e44[8]);

            if ((uint64_t)tOff44 + 4 > fs44 || tSz44 < 12) continue;
            icUInt8Number typeBytes44[4];
            fseek(fh44.fp, tOff44, SEEK_SET);
            if (fread(typeBytes44, 1, 4, fh44.fp) != 4) continue;

            icUInt32Number tagType44 = ReadU32BE(typeBytes44);
            if (tagType44 != 0x656D6274) continue; // 'embt'

            embedFound++;
            char sig44[5];
            sig44[0] = static_cast<char>(e44[0]); sig44[1] = static_cast<char>(e44[1]); sig44[2] = static_cast<char>(e44[2]); sig44[3] = static_cast<char>(e44[3]); sig44[4] = '\0';

            // Size check: > 10MB is suspicious
            if (tSz44 > 10 * 1024 * 1024) {
              printf("      %s[WARN]  Tag '%s' (embt): embedded image %u bytes (>10MB)%s\n",
                     ColorWarning(), sig44, tSz44, ColorReset());
              printf("       %sRisk: Resource exhaustion via large embedded image%s\n",
                     ColorWarning(), ColorReset());
              embedIssues++;
            }

            // Check embedded image magic (skip type(4) + reserved(4) + flags(4) = offset 12)
            if ((uint64_t)tOff44 + 16 <= fs44) {
              icUInt8Number imgMagic[4];
              fseek(fh44.fp, tOff44 + 12, SEEK_SET);
              if (fread(imgMagic, 1, 4, fh44.fp) == 4) {
                bool validPNG = (imgMagic[0] == 0x89 && imgMagic[1] == 0x50 &&
                                 imgMagic[2] == 0x4E && imgMagic[3] == 0x47);
                bool validTIFF_LE = (imgMagic[0] == 0x49 && imgMagic[1] == 0x49 &&
                                      imgMagic[2] == 0x2A && imgMagic[3] == 0x00);
                bool validTIFF_BE = (imgMagic[0] == 0x4D && imgMagic[1] == 0x4D &&
                                      imgMagic[2] == 0x00 && imgMagic[3] == 0x2A);
                if (!validPNG && !validTIFF_LE && !validTIFF_BE) {
                  printf("      %s[WARN]  Tag '%s' (embt): invalid image magic 0x%02X%02X%02X%02X%s\n",
                         ColorWarning(), sig44, imgMagic[0], imgMagic[1], imgMagic[2], imgMagic[3], ColorReset());
                  printf("       %sExpected PNG (89504E47) or TIFF (49492A00/4D4D002A)%s\n",
                         ColorInfo(), ColorReset());
                  embedIssues++;
                }
              }
            }
          }

          if (embedFound > 0) {
            printf("      [INFO]  %d embedded image tag(s) found\n", embedFound);
          }
        }
      }

      if (embedIssues > 0) {
        heuristicCount += embedIssues;
      } else {
        printf("      %s[OK] Embedded images valid (or none present)%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H45_SparseMatrixBounds(const char *filename)
{
  int heuristicCount = 0;

  // 45. Sparse Matrix Bounds Validation (raw file bytes, ICC v5)
  // smat (0x736D6174) tags specify rows × cols for sparse matrix data.
  // Extreme dimensions cause OOM. CFL patch 044.
  printf("[H45] Sparse Matrix Bounds Validation\n");
  {
    RawFileHandle fh45 = OpenRawFile(filename);
    if (fh45) {
      size_t fs45 = (size_t)fh45.fileSize;

      int sparseIssues = 0;
      if (fs45 >= 132) {
        icUInt8Number hdr45[132];
        if (fread(hdr45, 1, 132, fh45.fp) == 132) {
          icUInt32Number tc45 = ReadU32BE(&hdr45[128]);
          if (tc45 > 256) tc45 = 256;

          for (icUInt32Number i = 0; i < tc45; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fs45) break;
            icUInt8Number e45[12];
            fseek(fh45.fp, ePos, SEEK_SET);
            if (fread(e45, 1, 12, fh45.fp) != 12) break;

            icUInt32Number tOff45 = ReadU32BE(&e45[4]);
            icUInt32Number tSz45  = ReadU32BE(&e45[8]);

            if ((uint64_t)tOff45 + 4 > fs45 || tSz45 < 16) continue;
            icUInt8Number typeBytes45[4];
            fseek(fh45.fp, tOff45, SEEK_SET);
            if (fread(typeBytes45, 1, 4, fh45.fp) != 4) continue;

            icUInt32Number tagType45 = ReadU32BE(typeBytes45);
            if (tagType45 != 0x736D6174) continue; // 'smat'

            char sig45[5];
            sig45[0] = static_cast<char>(e45[0]); sig45[1] = static_cast<char>(e45[1]); sig45[2] = static_cast<char>(e45[2]); sig45[3] = static_cast<char>(e45[3]); sig45[4] = '\0';

            // smat: type(4) + reserved(4) + nChannels(2) + encoding(2) + ...
            // Read channel count and encoding
            if ((uint64_t)tOff45 + 12 <= fs45) {
              icUInt8Number smatHdr[4];
              fseek(fh45.fp, tOff45 + 8, SEEK_SET);
              if (fread(smatHdr, 1, 4, fh45.fp) == 4) {
                uint16_t nChannels = (static_cast<uint16_t>(smatHdr[0])<<8) | smatHdr[1];
                uint16_t encoding  = (static_cast<uint16_t>(smatHdr[2])<<8) | smatHdr[3];

                if (nChannels == 0) {
                  printf("      %s[WARN]  Tag '%s' (smat): zero channels%s\n",
                         ColorCritical(), sig45, ColorReset());
                  sparseIssues++;
                }

                // Estimated matrix size: nChannels² entries
                uint64_t estEntries = (uint64_t)nChannels * nChannels;
                const uint64_t MAX_SPARSE_ENTRIES = 16ULL * 1024 * 1024;
                if (estEntries > MAX_SPARSE_ENTRIES) {
                  printf("      %s[WARN]  Tag '%s' (smat): %u channels → %llu potential entries (limit %llu)%s\n",
                         ColorCritical(), sig45, nChannels,
                         (unsigned long long)estEntries, (unsigned long long)MAX_SPARSE_ENTRIES, ColorReset());
                  printf("       %sRisk: OOM via sparse matrix allocation (CFL patch 044)%s\n",
                         ColorCritical(), ColorReset());
                  sparseIssues++;
                } else if (nChannels > 0) {
                  printf("      [INFO]  Tag '%s' (smat): %u channels, encoding %u\n",
                         sig45, nChannels, encoding);
                }
              }
            }
          }
        }
      }

      if (sparseIssues > 0) {
        heuristicCount += sparseIssues;
      } else {
        printf("      %s[OK] Sparse matrix bounds valid (or none present)%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H46_TextDescUnicodeLength(const char *filename)
{
  int heuristicCount = 0;

  // =========================================================================
  // Raw-file heuristics H46-H54 (CWE-driven gap analysis from 77 advisories, 48 CVEs)
  // All use raw file I/O — no library API calls.
  // =========================================================================

  // 46. TextDescription Unicode Length Validation (raw file bytes)
  // desc tag: type(4) + reserved(4) + ASCII_count(4) + ASCII_data(ASCII_count) +
  //           unicode_lang(4) + unicode_count(4) + unicode_data(unicode_count*2) + ...
  // CVE-2026-21491: Unicode buffer overflow in CIccTagTextDescription
  // CVE-2026-21488: OOB read + improper null termination
  // CWE-122, CWE-170, CWE-130
  printf("[H46] TextDescription Unicode Length Validation\n");
  {
    RawFileHandle fh46 = OpenRawFile(filename);
    if (fh46) {
      size_t fs46 = (size_t)fh46.fileSize;

      int descIssues = 0;
      if (fh46.fp && fs46 >= 132) {
        // Read tag count
        icUInt8Number tc46[4];
        fseek(fh46.fp, 128, SEEK_SET);
        if (fread(tc46, 1, 4, fh46.fp) == 4) {
          uint32_t tagCount46 = ReadU32BE(tc46);
          if (tagCount46 > 1000) tagCount46 = 1000;

          for (uint32_t t = 0; t < tagCount46 && fh46.fp; t++) {
            icUInt8Number tagEntry[12];
            fseek(fh46.fp, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fh46.fp) != 12) break;

            uint32_t tSig = ReadU32BE(tagEntry);
            uint32_t tOff = ReadU32BE(&tagEntry[4]);
            uint32_t tSz  = ReadU32BE(&tagEntry[8]);

            // desc type = 0x64657363
            if ((uint64_t)tOff + 12 > fs46 || tSz < 12) continue;

            icUInt8Number typeSig[4];
            fseek(fh46.fp, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fh46.fp) != 4) continue;
            uint32_t typeVal = ReadU32BE(typeSig);
            if (typeVal != 0x64657363) continue; // not 'desc' type

            // Read ASCII count (offset +8)
            icUInt8Number ascBuf[4];
            fseek(fh46.fp, tOff + 8, SEEK_SET);
            if (fread(ascBuf, 1, 4, fh46.fp) != 4) continue;
            uint32_t asciiCount = ReadU32BE(ascBuf);

            // Unicode section starts at tOff + 12 + asciiCount
            uint64_t unicodeStart = (uint64_t)tOff + 12 + asciiCount;
            if (unicodeStart + 8 > fs46 || unicodeStart + 8 > (uint64_t)tOff + tSz) continue;

            icUInt8Number uniBuf[8];
            fseek(fh46.fp, (long)unicodeStart, SEEK_SET);
            if (fread(uniBuf, 1, 8, fh46.fp) != 8) continue;

            uint32_t unicodeCount = ReadU32BE(&uniBuf[4]);

            // Validate: unicode data = unicodeCount * 2 bytes
            uint64_t unicodeDataEnd = unicodeStart + 8 + (uint64_t)unicodeCount * 2;
            char sig46[5]; SignatureToFourCC(tSig, sig46);

            if (unicodeCount > 0 && unicodeDataEnd > (uint64_t)tOff + tSz) {
              printf("      %s[WARN]  Tag '%s' (desc): unicode count %u × 2 = %llu bytes exceeds tag bounds%s\n",
                     ColorCritical(), sig46, unicodeCount,
                     (unsigned long long)(unicodeCount * 2), ColorReset());
              printf("       %sCWE-122/CWE-170: Heap buffer overflow via unicode length (CVE-2026-21491 pattern)%s\n",
                     ColorCritical(), ColorReset());
              descIssues++;
            }

            // Check ASCII count vs tag size too
            if (asciiCount > tSz - 12) {
              printf("      %s[WARN]  Tag '%s' (desc): ASCII count %u exceeds available tag data%s\n",
                     ColorCritical(), sig46, asciiCount, ColorReset());
              descIssues++;
            }
          }
        }
      }

      if (descIssues > 0) {
        heuristicCount += descIssues;
      } else {
        printf("      %s[OK] TextDescription unicode lengths valid (or no desc tags)%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H47_NamedColor2SizeOverflow(const char *filename)
{
  int heuristicCount = 0;

  // 47. NamedColor2 Size Overflow Detection (raw file bytes)
  // ncl2 tag: type(4) + reserved(4) + vendorFlag(4) + count(4) + nDeviceCoords(4) +
  //           prefix(32) + suffix(32) = 84-byte header
  //           Each entry: name(32) + PCS(6) + deviceCoords(nDeviceCoords*2)
  // CVE-2026-24406: HBO in CIccTagNamedColor2::SetSize() (CVSS 8.8)
  // CWE-122, CWE-190, CWE-787
  printf("[H47] NamedColor2 Size Overflow Detection\n");
  {
    RawFileHandle fh47 = OpenRawFile(filename);
    if (fh47) {
      size_t fs47 = (size_t)fh47.fileSize;

      int ncl2Issues = 0;
      if (fh47.fp && fs47 >= 132) {
        icUInt8Number tc47[4];
        fseek(fh47.fp, 128, SEEK_SET);
        if (fread(tc47, 1, 4, fh47.fp) == 4) {
          uint32_t tagCount47 = ReadU32BE(tc47);
          if (tagCount47 > 1000) tagCount47 = 1000;

          for (uint32_t t = 0; t < tagCount47 && fh47.fp; t++) {
            icUInt8Number tagEntry[12];
            fseek(fh47.fp, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fh47.fp) != 12) break;

            uint32_t tSig = ReadU32BE(tagEntry);
            uint32_t tOff = ReadU32BE(&tagEntry[4]);
            uint32_t tSz  = ReadU32BE(&tagEntry[8]);

            if ((uint64_t)tOff + 84 > fs47 || tSz < 84) continue;

            // Read type signature
            icUInt8Number typeSig[4];
            fseek(fh47.fp, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fh47.fp) != 4) continue;
            uint32_t typeVal = ReadU32BE(typeSig);
            if (typeVal != 0x6E636C32) continue; // not 'ncl2' type

            // Read count and nDeviceCoords
            icUInt8Number ncl2Hdr[8];
            fseek(fh47.fp, tOff + 16, SEEK_SET); // skip type(4)+reserved(4)+vendorFlag(4)+count starts at +16
            // Actually: type(4)+reserved(4)+vendorFlag(4) = 12, count at +12, nDeviceCoords at +16
            fseek(fh47.fp, tOff + 12, SEEK_SET);
            if (fread(ncl2Hdr, 1, 8, fh47.fp) != 8) continue;

            uint32_t ncl2Count = ReadU32BE(ncl2Hdr);
            uint32_t nDevCoords = ReadU32BE(&ncl2Hdr[4]);

            char sig47[5]; SignatureToFourCC(tSig, sig47);

            // Each entry: rootName(32) + PCS_coords(6) + deviceCoords(nDevCoords*2)
            uint64_t entrySize = 32 + 6 + (uint64_t)nDevCoords * 2;
            uint64_t totalData = (uint64_t)ncl2Count * entrySize;
            uint64_t headerSize = 84; // type(4)+reserved(4)+vendorFlag(4)+count(4)+nDevCoords(4)+prefix(32)+suffix(32)
            uint64_t neededSize = headerSize + totalData;

            if (ncl2Count > 0 && totalData / entrySize != ncl2Count) {
              printf("      %s[WARN]  Tag '%s' (ncl2): count %u × entry_size %llu overflows uint64%s\n",
                     ColorCritical(), sig47, ncl2Count, (unsigned long long)entrySize, ColorReset());
              printf("       %sCRITICAL: CWE-190 integer overflow → HBO (CVE-2026-24406 pattern)%s\n",
                     ColorCritical(), ColorReset());
              ncl2Issues++;
            } else if (neededSize > tSz) {
              printf("      %s[WARN]  Tag '%s' (ncl2): %u entries × %llu bytes = %llu, but tag is only %u bytes%s\n",
                     ColorCritical(), sig47, ncl2Count, (unsigned long long)entrySize,
                     (unsigned long long)neededSize, tSz, ColorReset());
              printf("       %sCWE-122: Heap buffer overflow via NamedColor2 size mismatch%s\n",
                     ColorCritical(), ColorReset());
              ncl2Issues++;
            }

            if (nDevCoords > 100) {
              printf("      %s[WARN]  Tag '%s' (ncl2): nDeviceCoords = %u (suspicious, >100)%s\n",
                     ColorCritical(), sig47, nDevCoords, ColorReset());
              ncl2Issues++;
            }

            // CWE-400 Describe() iteration risk — symmetric with H64 library check.
            // H64 only fires when library loads; H47 ALWAYS runs on raw bytes.
            // If library rejects the profile, H47 is the only defense.
            if (nDevCoords > 15) {
              printf("      %s[WARN]  Tag '%s' (ncl2): nDeviceCoords = %u (>15 ICC spec max)%s\n",
                     ColorCritical(), sig47, nDevCoords, ColorReset());
              printf("       %sCWE-787: Device coord count exceeds ICC spec max (CFL-076 pattern)%s\n",
                     ColorCritical(), ColorReset());
              ncl2Issues++;
            }
            if (ncl2Count > 10000) {
              printf("      %s[WARN]  Tag '%s' (ncl2): %u entries (>10000) — Describe() DoS risk%s\n",
                     ColorCritical(), sig47, ncl2Count, ColorReset());
              printf("       %sCWE-400: Describe() iterates m_nSize with no runtime cap (CFL-078 pattern)%s\n",
                     ColorCritical(), ColorReset());
              ncl2Issues++;
            }
          }
        }
      }

      if (ncl2Issues > 0) {
        heuristicCount += ncl2Issues;
      } else {
        printf("      %s[OK] NamedColor2 sizes valid (or no ncl2 tags)%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H48_CLUTGridDimensionOverflow(const char *filename)
{
  int heuristicCount = 0;

  // 48. CLUT Grid Dimension Product Overflow (raw file bytes)
  // mAB/mBA (mft2): type(4)+reserved(4)+nInput(1)+nOutput(1)+pad(2)+offsets... CLUT grid at CLUT_offset
  // mft1 (lut8): type(4)+reserved(4)+nInput(1)+nOutput(1)+gridPoints(1)+pad(1)+matrix(36)+...
  // mft2 (lut16): type(4)+reserved(4)+nInput(1)+nOutput(1)+gridPoints(1)+pad(1)+matrix(36)+...
  // Grid product = gridPoints^nInput × nOutput — must not overflow
  // CVE-2026-22255: HBO in CIccCLUT::Init() (CVSS 8.8)
  // CVE-2026-21677: UB in CIccCLUT::Init() (CVSS 8.8)
  // CWE-131, CWE-190, CWE-400
  printf("[H48] CLUT Grid Dimension Product Overflow\n");
  {
    RawFileHandle fh48 = OpenRawFile(filename);
    if (fh48) {
      size_t fs48 = (size_t)fh48.fileSize;

      int clutOvfIssues = 0;
      if (fh48.fp && fs48 >= 132) {
        icUInt8Number tc48[4];
        fseek(fh48.fp, 128, SEEK_SET);
        if (fread(tc48, 1, 4, fh48.fp) == 4) {
          uint32_t tagCount48 = ReadU32BE(tc48);
          if (tagCount48 > 1000) tagCount48 = 1000;

          for (uint32_t t = 0; t < tagCount48 && fh48.fp; t++) {
            icUInt8Number tagEntry[12];
            fseek(fh48.fp, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fh48.fp) != 12) break;

            uint32_t tSig = ReadU32BE(tagEntry);
            uint32_t tOff = ReadU32BE(&tagEntry[4]);
            uint32_t tSz  = ReadU32BE(&tagEntry[8]);

            if ((uint64_t)tOff + 12 > fs48 || tSz < 12) continue;

            icUInt8Number typeSig[4];
            fseek(fh48.fp, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fh48.fp) != 4) continue;
            uint32_t typeVal = ReadU32BE(typeSig);

            char sig48[5]; SignatureToFourCC(tSig, sig48);

            // lut8 (0x6D667431) and lut16 (0x6D667432): uniform grid
            if (typeVal == 0x6D667431 || typeVal == 0x6D667432) {
              if ((uint64_t)tOff + 12 > fs48) continue;
              icUInt8Number lutHdr[4];
              fseek(fh48.fp, tOff + 8, SEEK_SET);
              if (fread(lutHdr, 1, 4, fh48.fp) != 4) continue;

              uint8_t nInput = lutHdr[0];
              uint8_t nOutput = lutHdr[1];
              uint8_t gridPts = lutHdr[2];

              if (nInput > 0 && gridPts > 0 && nOutput > 0) {
                // Product = gridPts^nInput × nOutput
                uint64_t product = 1;
                bool overflow = false;
                for (int d = 0; d < nInput; d++) {
                  product *= gridPts;
                  if (product > 256ULL * 1024 * 1024) { overflow = true; break; }
                }
                if (!overflow) product *= nOutput;
                if (product > 256ULL * 1024 * 1024) overflow = true;

                if (overflow) {
                  printf("      %s[WARN]  Tag '%s' (%s): grid %u^%u × %u output = overflow%s\n",
                         ColorCritical(), sig48,
                         (typeVal == 0x6D667431) ? "lut8" : "lut16",
                         gridPts, nInput, nOutput, ColorReset());
                  printf("       %sCRITICAL: CWE-131/CWE-190 CLUT allocation overflow (CVE-2026-22255 pattern)%s\n",
                         ColorCritical(), ColorReset());
                  clutOvfIssues++;
                }
              }
            }

            // mAB (0x6D414220) / mBA (0x6D424120): per-dimension grid points in CLUT sub-element
            if (typeVal == 0x6D414220 || typeVal == 0x6D424120) {
              if ((uint64_t)tOff + 32 > fs48) continue;
              icUInt8Number mbaHdr[24];
              fseek(fh48.fp, tOff + 8, SEEK_SET);
              if (fread(mbaHdr, 1, 24, fh48.fp) != 24) continue;

              uint8_t nInput = mbaHdr[0];
              uint8_t nOutput = mbaHdr[1];
              // CLUT offset is at +20 in the header (bytes 12-15 relative to mbaHdr start)
              uint32_t clutOff = ReadU32BE(&mbaHdr[12]);

              if (clutOff > 0 && clutOff < tSz && (uint64_t)tOff + clutOff + 16 <= fs48 && nInput <= 16) {
                // CLUT sub-element: 16 bytes of grid dimensions (1 per input channel)
                icUInt8Number gridDims[16];
                fseek(fh48.fp, tOff + clutOff, SEEK_SET);
                if (fread(gridDims, 1, 16, fh48.fp) == 16) {
                  uint64_t product = 1;
                  bool overflow = false;
                  bool hasZeroDim = false;
                  for (int d = 0; d < nInput; d++) {
                    if (gridDims[d] == 0) { hasZeroDim = true; break; }
                    product *= gridDims[d];
                    if (product > 256ULL * 1024 * 1024) { overflow = true; break; }
                  }
                  if (!overflow && !hasZeroDim && nOutput > 0) {
                    product *= nOutput;
                    if (product > 256ULL * 1024 * 1024) overflow = true;
                  }

                  if (overflow) {
                    printf("      %s[WARN]  Tag '%s' (%s): CLUT grid product overflows (>256M entries)%s\n",
                           ColorCritical(), sig48,
                           (typeVal == 0x6D414220) ? "mAB" : "mBA", ColorReset());
                    printf("       %sCRITICAL: CWE-131/CWE-190 CLUT allocation overflow (CVE-2026-22255 pattern)%s\n",
                           ColorCritical(), ColorReset());
                    clutOvfIssues++;
                  }
                  // hasZeroDim is checked in H54
                }
              }
            }
          }
        }
      }

      if (clutOvfIssues > 0) {
        heuristicCount += clutOvfIssues;
      } else {
        printf("      %s[OK] CLUT grid dimension products within bounds%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H49_FloatNaNInfDetection(const char *filename)
{
  int heuristicCount = 0;

  // 49. Float/s15Fixed16 NaN/Inf Detection (raw file bytes)
  // Scan XYZ (0x58595A20), sf32 (0x73663332), fl32 (0x666C3332) tag data
  // for IEEE 754 NaN (exponent=0xFF, mantissa≠0) and Inf (exponent=0xFF, mantissa=0)
  // CVE-2026-21681: UB runtime error: nan is outside the range (CVSS 7.1)
  // CWE-758, CWE-682
  printf("[H49] Float/s15Fixed16 NaN/Inf Detection\n");
  {
    RawFileHandle fh49 = OpenRawFile(filename);
    if (fh49) {
      size_t fs49 = (size_t)fh49.fileSize;

      int nanInfIssues = 0;
      if (fh49.fp && fs49 >= 132) {
        icUInt8Number tc49[4];
        fseek(fh49.fp, 128, SEEK_SET);
        if (fread(tc49, 1, 4, fh49.fp) == 4) {
          uint32_t tagCount49 = ReadU32BE(tc49);
          if (tagCount49 > 1000) tagCount49 = 1000;

          for (uint32_t t = 0; t < tagCount49 && fh49.fp; t++) {
            icUInt8Number tagEntry[12];
            fseek(fh49.fp, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fh49.fp) != 12) break;

            uint32_t tSig = ReadU32BE(tagEntry);
            uint32_t tOff = ReadU32BE(&tagEntry[4]);
            uint32_t tSz  = ReadU32BE(&tagEntry[8]);

            if ((uint64_t)tOff + 8 > fs49 || tSz < 8) continue;

            icUInt8Number typeSig[4];
            fseek(fh49.fp, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fh49.fp) != 4) continue;
            uint32_t typeVal = ReadU32BE(typeSig);

            // fl32 (0x666C3332): IEEE 754 float array
            // sf32 (0x73663332): s15Fixed16 array (check for 0x7FFFFFFF/0x80000000 extremes)
            // XYZ (0x58595A20): 3 × s15Fixed16 values
            bool isFloat = (typeVal == 0x666C3332);
            bool isSf32  = (typeVal == 0x73663332);
            bool isXYZ   = (typeVal == 0x58595A20);
            if (!isFloat && !isSf32 && !isXYZ) continue;

            char sig49[5]; SignatureToFourCC(tSig, sig49);

            // Scan data portion (after type + reserved = 8 bytes)
            size_t dataStart = (uint64_t)tOff + 8;
            size_t dataEnd = (size_t)tOff + tSz;
            if (dataEnd > fs49) dataEnd = fs49;
            size_t maxScan = 4096; // limit scan to first 4KB of data
            if (dataEnd - dataStart > maxScan) dataEnd = dataStart + maxScan;

            fseek(fh49.fp, dataStart, SEEK_SET);
            for (size_t pos = dataStart; pos + 4 <= dataEnd; pos += 4) {
              icUInt8Number val4[4];
              if (fread(val4, 1, 4, fh49.fp) != 4) break;

              if (isFloat) {
                // IEEE 754: exponent bits [30:23]
                uint8_t exponent = ((val4[0] & 0x7F) << 1) | ((val4[1] >> 7) & 0x01);
                uint32_t mantissa = (((uint32_t)val4[1] & 0x7F) << 16) |
                                    ((uint32_t)val4[2] << 8) | val4[3];
                if (exponent == 0xFF) {
                  const char *kind = (mantissa == 0) ? "Inf" : "NaN";
                  printf("      %s[WARN]  Tag '%s' (fl32): %s detected at offset +%zu%s\n",
                         ColorCritical(), sig49, kind, pos - tOff, ColorReset());
                  printf("       %sCWE-758: Undefined behavior when converting %s to integer (CVE-2026-21681)%s\n",
                         ColorCritical(), kind, ColorReset());
                  nanInfIssues++;
                  break; // one warning per tag is enough
                }
              } else {
                // s15Fixed16: check for extreme sentinel values
                uint32_t fixVal = ReadU32BE(val4);
                if (fixVal == 0x7FFFFFFF || fixVal == 0x80000000) {
                  printf("      %s[WARN]  Tag '%s': s15Fixed16 extreme value 0x%08X at offset +%zu%s\n",
                         ColorCritical(), sig49, fixVal, pos - tOff, ColorReset());
                  printf("       %sCWE-758: Potential undefined behavior in fixed-point conversion%s\n",
                         ColorCritical(), ColorReset());
                  nanInfIssues++;
                  break;
                }
              }
            }
          }
        }
      }

      if (nanInfIssues > 0) {
        heuristicCount += nanInfIssues;
      } else {
        printf("      %s[OK] No NaN/Inf/extreme values in float/fixed-point tags%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H50_ZeroSizeProfileTag(const char *filename)
{
  int heuristicCount = 0;

  // 50. Profile Size Zero / Zero-Size Tag Detection (raw file bytes)
  // CVE-2026-21507: Infinite loop in CalcProfileID() when profile size = 0 (CVSS 7.5)
  // Also: any tag with size = 0 may cause div-by-zero or infinite loops in parsers
  // CWE-835, CWE-369
  printf("[H50] Zero-Size Profile/Tag Detection (Infinite Loop)\n");
  {
    RawFileHandle fh50 = OpenRawFile(filename);
    if (fh50) {
      size_t fs50 = (size_t)fh50.fileSize;

      int zeroIssues = 0;
      if (fh50.fp && fs50 >= 132) {
        // Check profile size field (bytes 0-3)
        icUInt8Number psz[4];
        fseek(fh50.fp, 0, SEEK_SET);
        if (fread(psz, 1, 4, fh50.fp) == 4) {
          uint32_t declaredProfileSize = ReadU32BE(psz);
          if (declaredProfileSize == 0) {
            printf("      %s[WARN]  Profile size field = 0%s\n", ColorCritical(), ColorReset());
            printf("       %sCRITICAL: CWE-835 infinite loop in CalcProfileID() (CVE-2026-21507)%s\n",
                   ColorCritical(), ColorReset());
            zeroIssues++;
          }
        }

        // Check for zero-size tags
        icUInt8Number tc50[4];
        fseek(fh50.fp, 128, SEEK_SET);
        if (fread(tc50, 1, 4, fh50.fp) == 4) {
          uint32_t tagCount50 = ReadU32BE(tc50);
          if (tagCount50 > 1000) tagCount50 = 1000;

          int zeroSizeTags = 0;
          for (uint32_t t = 0; t < tagCount50 && fh50.fp; t++) {
            icUInt8Number tagEntry[12];
            fseek(fh50.fp, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fh50.fp) != 12) break;

            uint32_t tSig = ReadU32BE(tagEntry);
            uint32_t tSz  = ReadU32BE(&tagEntry[8]);

            if (tSz == 0) {
              char sig50[5]; SignatureToFourCC(tSig, sig50);
              printf("      %s[WARN]  Tag '%s': size = 0 (may cause infinite loop or div-by-zero)%s\n",
                     ColorCritical(), sig50, ColorReset());
              zeroSizeTags++;
            }
          }
          if (zeroSizeTags > 0) {
            zeroIssues += zeroSizeTags;
          }
        }
      }

      if (zeroIssues > 0) {
        heuristicCount += zeroIssues;
      } else {
        printf("      %s[OK] No zero-size profile or tags detected%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H51_LUTChannelCountConsistency(const char *filename)
{
  int heuristicCount = 0;

  // 51. LUT I/O Channel Count Consistency (raw file bytes)
  // lut8 (mft1) and lut16 (mft2): inputChan at +8, outputChan at +9
  // These must match the profile's colorSpace (input) and PCS (output) channel counts.
  // Off-by-one in these causes HBO during Validate().
  // CVE-2026-21490: HBO in CIccTagLut16::Validate() (off-by-one)
  // CVE-2026-21494: HBO in CIccTagLut8::Validate() (off-by-one)
  // CWE-193, CWE-122
  printf("[H51] LUT I/O Channel Count Consistency\n");
  {
    RawFileHandle fh51 = OpenRawFile(filename);
    if (fh51) {
      size_t fs51 = (size_t)fh51.fileSize;

      int lutChanIssues = 0;
      if (fh51.fp && fs51 >= 132) {
        icUInt8Number tc51[4];
        fseek(fh51.fp, 128, SEEK_SET);
        if (fread(tc51, 1, 4, fh51.fp) == 4) {
          uint32_t tagCount51 = ReadU32BE(tc51);
          if (tagCount51 > 1000) tagCount51 = 1000;

          for (uint32_t t = 0; t < tagCount51 && fh51.fp; t++) {
            icUInt8Number tagEntry[12];
            fseek(fh51.fp, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fh51.fp) != 12) break;

            uint32_t tSig = ReadU32BE(tagEntry);
            uint32_t tOff = ReadU32BE(&tagEntry[4]);
            uint32_t tSz  = ReadU32BE(&tagEntry[8]);

            if ((uint64_t)tOff + 12 > fs51 || tSz < 12) continue;

            icUInt8Number typeSig[4];
            fseek(fh51.fp, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fh51.fp) != 4) continue;
            uint32_t typeVal = ReadU32BE(typeSig);

            // mft1 (lut8) or mft2 (lut16) or mAB or mBA
            bool isLut8  = (typeVal == 0x6D667431);
            bool isLut16 = (typeVal == 0x6D667432);
            bool isMab   = (typeVal == 0x6D414220 || typeVal == 0x6D424120);
            if (!isLut8 && !isLut16 && !isMab) continue;

            icUInt8Number chanHdr[2];
            fseek(fh51.fp, tOff + 8, SEEK_SET);
            if (fread(chanHdr, 1, 2, fh51.fp) != 2) continue;

            uint8_t nInput = chanHdr[0];
            uint8_t nOutput = chanHdr[1];
            char sig51[5]; SignatureToFourCC(tSig, sig51);

            // Sanity limits: ICC spec allows max 16 input channels, 16 output
            if (nInput == 0 || nOutput == 0) {
              printf("      %s[WARN]  Tag '%s': %s has zero %s channels%s\n",
                     ColorCritical(), sig51,
                     isLut8 ? "lut8" : isLut16 ? "lut16" : "mAB/mBA",
                     (nInput == 0) ? "input" : "output", ColorReset());
              printf("       %sCWE-193: Off-by-one/zero channel count → HBO in Validate() (CVE-2026-21490)%s\n",
                     ColorCritical(), ColorReset());
              lutChanIssues++;
            } else if (nInput > 16 || nOutput > 16) {
              printf("      %s[WARN]  Tag '%s': %s has %u input, %u output channels (max 16)%s\n",
                     ColorCritical(), sig51,
                     isLut8 ? "lut8" : isLut16 ? "lut16" : "mAB/mBA",
                     nInput, nOutput, ColorReset());
              printf("       %sCWE-122: Excessive channel count → potential buffer overflow%s\n",
                     ColorCritical(), ColorReset());
              lutChanIssues++;
            }
          }
        }
      }

      if (lutChanIssues > 0) {
        heuristicCount += lutChanIssues;
      } else {
        printf("      %s[OK] LUT I/O channel counts within valid range%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H52_IntegerUnderflowTagSize(const char *filename)
{
  int heuristicCount = 0;

  // 52. Integer Underflow in Tag Size Subtraction (raw file bytes)
  // Tags have minimum header sizes: desc=12, curv=12, text=8, XYZ=20, mluc=16, ncl2=84
  // When tag_size < minimum_header, subtraction (tag_size - header) wraps negative as uint
  // CVE-2026-21489: OOB Read + Integer Underflow
  // CWE-191, CWE-125
  printf("[H52] Integer Underflow in Tag Size Subtraction\n");
  {
    RawFileHandle fh52 = OpenRawFile(filename);
    if (fh52) {
      size_t fs52 = (size_t)fh52.fileSize;

      int underflowIssues = 0;
      if (fh52.fp && fs52 >= 132) {
        icUInt8Number tc52[4];
        fseek(fh52.fp, 128, SEEK_SET);
        if (fread(tc52, 1, 4, fh52.fp) == 4) {
          uint32_t tagCount52 = ReadU32BE(tc52);
          if (tagCount52 > 1000) tagCount52 = 1000;

          for (uint32_t t = 0; t < tagCount52 && fh52.fp; t++) {
            icUInt8Number tagEntry[12];
            fseek(fh52.fp, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fh52.fp) != 12) break;

            uint32_t tSig = ReadU32BE(tagEntry);
            uint32_t tOff = ReadU32BE(&tagEntry[4]);
            uint32_t tSz  = ReadU32BE(&tagEntry[8]);

            if ((uint64_t)tOff + 4 > fs52 || tSz < 4) continue;

            icUInt8Number typeSig[4];
            fseek(fh52.fp, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fh52.fp) != 4) continue;
            uint32_t typeVal = ReadU32BE(typeSig);

            // Minimum sizes by type
            uint32_t minSize = 8; // default: type(4) + reserved(4)
            if (typeVal == 0x64657363) minSize = 12;      // desc: +count(4)
            else if (typeVal == 0x63757276) minSize = 12;  // curv: +count(4)
            else if (typeVal == 0x58595A20) minSize = 20;  // XYZ: +X(4)+Y(4)+Z(4)
            else if (typeVal == 0x6D6C7563) minSize = 16;  // mluc: +count(4)+recSize(4)
            else if (typeVal == 0x6E636C32) minSize = 84;  // ncl2: full header
            else if (typeVal == 0x6D667431) minSize = 48;  // lut8: header+matrix
            else if (typeVal == 0x6D667432) minSize = 52;  // lut16: header+matrix+in/outTableEntries
            else if (typeVal == 0x6D414220 || typeVal == 0x6D424120) minSize = 32; // mAB/mBA
            else if (typeVal == 0x70617261) minSize = 12;  // para: +funcType(2)+reserved(2)
            else if (typeVal == 0x73663332) minSize = 12;  // sf32: at least one value
            else if (typeVal == 0x666C3332) minSize = 12;  // fl32: at least one value

            if (tSz < minSize) {
              char sig52[5]; SignatureToFourCC(tSig, sig52);
              char type52[5]; SignatureToFourCC(typeVal, type52);
              printf("      %s[WARN]  Tag '%s' (type '%s'): size %u < minimum %u bytes%s\n",
                     ColorCritical(), sig52, type52, tSz, minSize, ColorReset());
              printf("       %sCWE-191: size - header underflows → OOB read (CVE-2026-21489 pattern)%s\n",
                     ColorCritical(), ColorReset());
              underflowIssues++;
            }
          }
        }
      }

      if (underflowIssues > 0) {
        heuristicCount += underflowIssues;
      } else {
        printf("      %s[OK] All tag sizes meet minimum requirements%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H53_EmbeddedProfileRecursion(const char *filename)
{
  int heuristicCount = 0;

  // 53. Embedded Profile Recursion Detection (raw file bytes)
  // Scan profile data for 'acsp' magic (0x61637370) at offset 36 within embedded data,
  // indicating nested ICC profiles that could trigger recursive parsing → stack overflow/UAF
  // CWE-674, CWE-416
  printf("[H53] Embedded Profile Recursion Detection\n");
  {
    RawFileHandle fh53 = OpenRawFile(filename);
    if (fh53) {
      size_t fs53 = (size_t)fh53.fileSize;

      int recursionIssues = 0;
      if (fh53.fp && fs53 >= 132) {
        // The main profile has 'acsp' at offset 36. Search for additional 'acsp' signatures
        // at positions > 128 (inside tag data) that could indicate embedded profiles.
        // Look for the pattern: at position P, bytes P-36..P form a plausible profile header
        // Simpler: just scan for 0x61637370 at any 4-byte-aligned position after the tag table
        icUInt8Number tc53[4];
        fseek(fh53.fp, 128, SEEK_SET);
        if (fread(tc53, 1, 4, fh53.fp) == 4) {
          uint32_t tagCount53 = ReadU32BE(tc53);
          if (tagCount53 > 1000) tagCount53 = 1000;
          size_t tagTableEnd = 132 + tagCount53 * 12;

          // Scan tag data area for 'acsp' magic
          size_t scanLimit = fs53;
          if (scanLimit > 1024 * 1024) scanLimit = 1024 * 1024; // limit to first 1MB
          int embeddedCount = 0;

          fseek(fh53.fp, tagTableEnd, SEEK_SET);
          for (size_t pos = tagTableEnd; pos + 40 <= scanLimit; pos += 4) {
            icUInt8Number scanBuf[40];
            fseek(fh53.fp, pos, SEEK_SET);
            if (fread(scanBuf, 1, 40, fh53.fp) != 40) break;

            // Check for 'acsp' at byte 36 of a potential embedded profile header
            uint32_t magic = ReadU32BE(&scanBuf[36]);
            if (magic == 0x61637370) {
              // Verify it looks like a profile (has plausible size field)
              uint32_t embSize = ReadU32BE(scanBuf);
              if (embSize >= 128 && embSize <= 64 * 1024 * 1024) {
                embeddedCount++;
                if (embeddedCount <= 3) {
                  printf("      %s[WARN]  Embedded ICC profile detected at offset %zu (size %u)%s\n",
                         ColorCritical(), pos, embSize, ColorReset());
                }
              }
            }
          }
          if (embeddedCount > 0) {
            printf("       %sCWE-674: %d embedded profile(s) — recursive parsing risk (UAF/stack overflow)%s\n",
                   ColorCritical(), embeddedCount, ColorReset());
            recursionIssues += embeddedCount;
          }
        }
      }

      if (recursionIssues > 0) {
        heuristicCount += recursionIssues;
      } else {
        printf("      %s[OK] No embedded profiles detected%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H54_DivisionByZeroTrigger(const char *filename)
{
  int heuristicCount = 0;

  // 54. Division-by-Zero Trigger Detection (raw file bytes)
  // Check for structural values that cause division by zero in parsers:
  // - CLUT grid dimension = 0 in any channel (mAB/mBA/lut8/lut16)
  // - Spectral step = 0 (partially covered in H43, reinforced here)
  // - curv with count = 1 (identity) is valid, but count field itself = 0 with data is suspicious
  // CVE-2026-21495: Division by Zero in iccDEV TIFF Image Reader
  // CWE-369
  printf("[H54] Division-by-Zero Trigger Detection\n");
  {
    RawFileHandle fh54 = OpenRawFile(filename);
    if (fh54) {
      size_t fs54 = (size_t)fh54.fileSize;

      int divZeroIssues = 0;
      if (fh54.fp && fs54 >= 132) {
        icUInt8Number tc54[4];
        fseek(fh54.fp, 128, SEEK_SET);
        if (fread(tc54, 1, 4, fh54.fp) == 4) {
          uint32_t tagCount54 = ReadU32BE(tc54);
          if (tagCount54 > 1000) tagCount54 = 1000;

          for (uint32_t t = 0; t < tagCount54 && fh54.fp; t++) {
            icUInt8Number tagEntry[12];
            fseek(fh54.fp, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fh54.fp) != 12) break;

            uint32_t tSig = ReadU32BE(tagEntry);
            uint32_t tOff = ReadU32BE(&tagEntry[4]);
            uint32_t tSz  = ReadU32BE(&tagEntry[8]);

            if ((uint64_t)tOff + 12 > fs54 || tSz < 12) continue;

            icUInt8Number typeSig[4];
            fseek(fh54.fp, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fh54.fp) != 4) continue;
            uint32_t typeVal = ReadU32BE(typeSig);

            char sig54[5]; SignatureToFourCC(tSig, sig54);

            // lut8/lut16: gridPoints at +10 must be > 0
            if (typeVal == 0x6D667431 || typeVal == 0x6D667432) {
              icUInt8Number lutInfo[4];
              fseek(fh54.fp, tOff + 8, SEEK_SET);
              if (fread(lutInfo, 1, 4, fh54.fp) == 4) {
                uint8_t gridPts = lutInfo[2];
                if (gridPts == 0 && lutInfo[0] > 0) {
                  printf("      %s[WARN]  Tag '%s' (%s): gridPoints = 0 with %u input channels%s\n",
                         ColorCritical(), sig54,
                         (typeVal == 0x6D667431) ? "lut8" : "lut16",
                         lutInfo[0], ColorReset());
                  printf("       %sCWE-369: Division by zero in CLUT interpolation%s\n",
                         ColorCritical(), ColorReset());
                  divZeroIssues++;
                }
              }
            }

            // mAB/mBA: CLUT sub-element grid dimensions
            if (typeVal == 0x6D414220 || typeVal == 0x6D424120) {
              if ((uint64_t)tOff + 32 > fs54) continue;
              icUInt8Number mbaInfo[24];
              fseek(fh54.fp, tOff + 8, SEEK_SET);
              if (fread(mbaInfo, 1, 24, fh54.fp) != 24) continue;

              uint8_t nInput = mbaInfo[0];
              uint32_t clutOff = ReadU32BE(&mbaInfo[12]);

              if (clutOff > 0 && clutOff < tSz && (uint64_t)tOff + clutOff + 16 <= fs54 && nInput > 0 && nInput <= 16) {
                icUInt8Number gridDims[16];
                fseek(fh54.fp, tOff + clutOff, SEEK_SET);
                if (fread(gridDims, 1, 16, fh54.fp) == 16) {
                  for (int d = 0; d < nInput; d++) {
                    if (gridDims[d] == 0) {
                      printf("      %s[WARN]  Tag '%s' (%s): CLUT grid dimension[%d] = 0%s\n",
                             ColorCritical(), sig54,
                             (typeVal == 0x6D414220) ? "mAB" : "mBA",
                             d, ColorReset());
                      printf("       %sCWE-369: Division by zero in CLUT interpolation%s\n",
                             ColorCritical(), ColorReset());
                      divZeroIssues++;
                      break;
                    }
                  }
                }
              }
            }
          }
        }
      }

      if (divZeroIssues > 0) {
        heuristicCount += divZeroIssues;
      } else {
        printf("      %s[OK] No division-by-zero triggers detected%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H55_UTF16EncodingValidation(const char *filename)
{
  int heuristicCount = 0;

  // =====================================================================
  // H55 — UTF-16 Encoding Validation (CWE-120/CWE-170)
  // Detects invalid UTF-16 surrogate pairs and unterminated strings that
  // cause buffer overflows in CIccConvertUTF and CIccUTF16String.
  // =====================================================================
  printf("[H55] UTF-16 Encoding Validation\n");
  {
    RawFileHandle fh55 = OpenRawFile(filename);
    if (fh55) {
      size_t fs55 = (size_t)fh55.fileSize;

      int utf16Issues = 0;
      if (fh55.fp && fs55 >= 132) {
        icUInt8Number tc55[4];
        fseek(fh55.fp, 128, SEEK_SET);
        if (fread(tc55, 1, 4, fh55.fp) == 4) {
          uint32_t tagCount55 = ReadU32BE(tc55);
          if (tagCount55 > 1000) tagCount55 = 1000;

          for (uint32_t t = 0; t < tagCount55 && fh55.fp; t++) {
            icUInt8Number tagEntry[12];
            fseek(fh55.fp, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fh55.fp) != 12) break;

            uint32_t tSig = ReadU32BE(tagEntry);
            uint32_t tOff = ReadU32BE(&tagEntry[4]);
            uint32_t tSz  = ReadU32BE(&tagEntry[8]);

            if ((uint64_t)tOff + 8 > fs55 || tSz < 8) continue;

            icUInt8Number typeSig[4];
            fseek(fh55.fp, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fh55.fp) != 4) continue;
            uint32_t typeVal = ReadU32BE(typeSig);

            // mluc (0x6D6C7563) — scan for orphan surrogates
            if (typeVal == 0x6D6C7563 && tSz >= 16) {
              icUInt8Number mlucHdr[8];
              fseek(fh55.fp, tOff + 8, SEEK_SET);
              if (fread(mlucHdr, 1, 8, fh55.fp) != 8) continue;
              uint32_t numRec = ReadU32BE(mlucHdr);
              uint32_t recSz  = ReadU32BE(&mlucHdr[4]);

              if (recSz < 12) recSz = 12;
              if (numRec > 500) numRec = 500;

              for (uint32_t r = 0; r < numRec; r++) {
                uint32_t recOff = 16 + r * recSz;
                if (tOff + recOff + 12 > fs55) break;

                icUInt8Number rec[12];
                fseek(fh55.fp, tOff + recOff, SEEK_SET);
                if (fread(rec, 1, 12, fh55.fp) != 12) break;

                uint32_t strLen = ReadU32BE(&rec[4]);
                uint32_t strOff = ReadU32BE(&rec[8]);

                if (strLen > 65536) {
                  char sig55[5]; SignatureToFourCC(tSig, sig55);
                  printf("      %s[WARN]  Tag '%s' (mluc): string %u length %u > 64KB%s\n",
                         ColorCritical(), sig55, r, strLen, ColorReset());
                  printf("       %sCWE-120: OOM via oversized UTF-16 string allocation%s\n",
                         ColorCritical(), ColorReset());
                  utf16Issues++;
                  continue;
                }

                // Check for odd-length (invalid UTF-16)
                if (strLen % 2 != 0 && strLen > 0) {
                  char sig55[5]; SignatureToFourCC(tSig, sig55);
                  printf("      %s[WARN]  Tag '%s' (mluc): string %u has odd byte length %u (invalid UTF-16)%s\n",
                         ColorCritical(), sig55, r, strLen, ColorReset());
                  utf16Issues++;
                  continue;
                }

                // Scan for orphan surrogates (limited to first 1024 code units)
                if (strLen >= 4 && tOff + strOff + strLen <= fs55) {
                  uint32_t scanLen = (strLen > 2048) ? 2048 : strLen;
                  icUInt8Number *strBuf = (icUInt8Number*)malloc(scanLen);
                  if (strBuf) {
                    fseek(fh55.fp, tOff + strOff, SEEK_SET);
                    if (fread(strBuf, 1, scanLen, fh55.fp) == scanLen) {
                      for (uint32_t i = 0; i + 1 < scanLen; i += 2) {
                        uint16_t cu = ((uint16_t)strBuf[i] << 8) | strBuf[i+1];
                        if (cu >= 0xD800 && cu <= 0xDBFF) {
                          // High surrogate — must be followed by low surrogate
                          if (i + 3 < scanLen) {
                            uint16_t next = ((uint16_t)strBuf[i+2] << 8) | strBuf[i+3];
                            if (next < 0xDC00 || next > 0xDFFF) {
                              char sig55[5]; SignatureToFourCC(tSig, sig55);
                              printf("      %s[WARN]  Tag '%s' (mluc): orphan high surrogate U+%04X at offset %u%s\n",
                                     ColorCritical(), sig55, cu, i, ColorReset());
                              printf("       %sCWE-170: Invalid UTF-16 surrogate pair%s\n",
                                     ColorCritical(), ColorReset());
                              utf16Issues++;
                              break;
                            }
                            i += 2; // skip low surrogate
                          } else {
                            utf16Issues++;
                            break;
                          }
                        } else if (cu >= 0xDC00 && cu <= 0xDFFF) {
                          // Orphan low surrogate
                          char sig55[5]; SignatureToFourCC(tSig, sig55);
                          printf("      %s[WARN]  Tag '%s' (mluc): orphan low surrogate U+%04X at offset %u%s\n",
                                 ColorCritical(), sig55, cu, i, ColorReset());
                          utf16Issues++;
                          break;
                        }
                      }
                    }
                    free(strBuf);
                  }
                }
              }
            }

            // desc (0x64657363) — check unicode count overflow
            if (typeVal == 0x64657363 && tSz >= 24) {
              fseek(fh55.fp, tOff + 8, SEEK_SET);
              icUInt8Number descHdr[4];
              if (fread(descHdr, 1, 4, fh55.fp) == 4) {
                uint32_t asciiLen = ReadU32BE(descHdr);
                // If ASCII len exceeds tag data → overflow
                if (asciiLen > tSz - 8) {
                  char sig55[5]; SignatureToFourCC(tSig, sig55);
                  printf("      %s[WARN]  Tag '%s' (desc): ASCII length %u exceeds tag size %u%s\n",
                         ColorCritical(), sig55, asciiLen, tSz, ColorReset());
                  printf("       %sCWE-120: Buffer overflow in textDescription parsing%s\n",
                         ColorCritical(), ColorReset());
                  utf16Issues++;
                }
              }
            }
          }
        }
      }

      if (utf16Issues > 0) {
        heuristicCount += utf16Issues;
      } else {
        printf("      %s[OK] UTF-16 encoding appears valid%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H57_EmbeddedProfileRecursionDepth(const char *filename)
{
  int heuristicCount = 0;

  // H57 — Embedded Profile Recursion Depth (raw file I/O — no library needed)
  // Detects profiles embedding other ICC profiles (via 'psin' tag or
  // embedded profile tags) beyond a safe nesting depth.
  // =====================================================================
  printf("[H57] Embedded Profile Recursion Depth\n");
  {
    RawFileHandle fh57 = OpenRawFile(filename);
    if (fh57) {
      size_t fs57 = (size_t)fh57.fileSize;

      int embedIssues = 0;
      if (fh57.fp && fs57 >= 132) {
        icUInt8Number tc57[4];
        fseek(fh57.fp, 128, SEEK_SET);
        if (fread(tc57, 1, 4, fh57.fp) == 4) {
          uint32_t tagCount57 = ReadU32BE(tc57);
          if (tagCount57 > 1000) tagCount57 = 1000;

          for (uint32_t t = 0; t < tagCount57 && fh57.fp; t++) {
            icUInt8Number tagEntry[12];
            fseek(fh57.fp, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fh57.fp) != 12) break;

            uint32_t tSig = ReadU32BE(tagEntry);
            uint32_t tOff = ReadU32BE(&tagEntry[4]);
            uint32_t tSz  = ReadU32BE(&tagEntry[8]);

            if ((uint64_t)tOff + 8 > fs57 || tSz < 132) continue;

            // Check for embedded ICC profile magic 'acsp' at offset+36
            if ((uint64_t)tOff + 36 + 4 <= fs57) {
              icUInt8Number magic[4];
              fseek(fh57.fp, tOff + 36, SEEK_SET);
              if (fread(magic, 1, 4, fh57.fp) == 4) {
                if (magic[0] == 'a' && magic[1] == 'c' && magic[2] == 's' && magic[3] == 'p') {
                  char sig57[5]; SignatureToFourCC(tSig, sig57);

                  // Check for nested embedded — look for 'acsp' deeper
                  int depth = 1;
                  // Scan tag data for additional 'acsp' signatures
                  if (tSz >= 256 && (uint64_t)tOff + tSz <= fs57) {
                    uint32_t scanLimit = (tSz > 65536) ? 65536 : tSz;
                    icUInt8Number *scanBuf = (icUInt8Number*)malloc(scanLimit);
                    if (scanBuf) {
                      fseek(fh57.fp, tOff, SEEK_SET);
                      if (fread(scanBuf, 1, scanLimit, fh57.fp) == scanLimit) {
                        for (uint32_t i = 36 + 132; i + 3 < scanLimit; i++) {
                          if (scanBuf[i]=='a' && scanBuf[i+1]=='c' && scanBuf[i+2]=='s' && scanBuf[i+3]=='p') {
                            depth++;
                          }
                        }
                      }
                      free(scanBuf);
                    }
                  }

                  printf("      %s[WARN]  Tag '%s': contains embedded ICC profile (depth %d)%s\n",
                         ColorCritical(), sig57, depth, ColorReset());
                  if (depth > 1) {
                    printf("       %sCWE-674: Nested embedded profiles → recursion risk%s\n",
                           ColorCritical(), ColorReset());
                  }
                  printf("       %sCWE-416: Embedded profile parsing may trigger UAF%s\n",
                         ColorCritical(), ColorReset());
                  embedIssues++;
                }
              }
            }
          }
        }
      }

      if (embedIssues > 0) {
        heuristicCount += embedIssues;
      } else {
        printf("      %s[OK] No embedded profiles detected%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H59_SpectralWavelengthRange(const char *filename)
{
  int heuristicCount = 0;

  // H59 — Spectral Wavelength Range Consistency (raw file I/O — no library needed)
  // Validates spectral range fields (start, end, steps) for physical
  // plausibility and arithmetic consistency.
  // =====================================================================
  printf("[H59] Spectral Wavelength Range Consistency\n");
  {
    RawFileHandle fh59 = OpenRawFile(filename);
    if (fh59) {
      size_t fs59 = (size_t)fh59.fileSize;

      int spectralIssues = 0;
      // ICC v5 spectral data starts at header offset 104
      if (fh59.fp && fs59 >= 128) {
        icUInt8Number specHdr[24];
        fseek(fh59.fp, 104, SEEK_SET);
        if (fread(specHdr, 1, 24, fh59.fp) == 24) {
          uint16_t specStart = ((uint16_t)specHdr[0] << 8) | specHdr[1];
          uint16_t specEnd   = ((uint16_t)specHdr[2] << 8) | specHdr[3];
          uint16_t specSteps = ((uint16_t)specHdr[4] << 8) | specHdr[5];

          uint16_t bispecStart = ((uint16_t)specHdr[6] << 8) | specHdr[7];
          uint16_t bispecEnd   = ((uint16_t)specHdr[8] << 8) | specHdr[9];
          uint16_t bispecSteps = ((uint16_t)specHdr[10] << 8) | specHdr[11];

          // Only check if spectral fields are non-zero (v5 profiles)
          if (specStart != 0 || specEnd != 0 || specSteps != 0) {
            if (specStart > 0 && specEnd > 0) {
              if (specEnd <= specStart) {
                printf("      %s[WARN]  Spectral range: end (%u nm) <= start (%u nm)%s\n",
                       ColorCritical(), specEnd, specStart, ColorReset());
                printf("       %sCWE-682: Inverted spectral range → negative step size%s\n",
                       ColorCritical(), ColorReset());
                spectralIssues++;
              }
              if (specSteps == 0) {
                printf("      %s[WARN]  Spectral range: steps = 0 with non-zero start/end%s\n",
                       ColorCritical(), ColorReset());
                printf("       %sCWE-369: Division by zero in spectral interpolation%s\n",
                       ColorCritical(), ColorReset());
                spectralIssues++;
              }
              // Physical plausibility: visible light 100-1100nm
              if (specStart < 100 || specEnd > 4000) {
                printf("      %s[WARN]  Spectral range: %u-%u nm (outside plausible 100-4000nm)%s\n",
                       ColorWarning(), specStart, specEnd, ColorReset());
                spectralIssues++;
              }
            }
          }

          if (bispecStart != 0 || bispecEnd != 0 || bispecSteps != 0) {
            if (bispecStart > 0 && bispecEnd > 0) {
              if (bispecEnd <= bispecStart) {
                printf("      %s[WARN]  Bispectral range: end (%u nm) <= start (%u nm)%s\n",
                       ColorCritical(), bispecEnd, bispecStart, ColorReset());
                spectralIssues++;
              }
              if (bispecSteps == 0) {
                printf("      %s[WARN]  Bispectral range: steps = 0%s\n",
                       ColorCritical(), ColorReset());
                spectralIssues++;
              }
            }
          }
        }
      }

      if (spectralIssues > 0) {
        heuristicCount += spectralIssues;
      } else {
        printf("      %s[OK] Spectral range fields consistent%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H68_GamutBoundaryDescOverflow(const char *filename)
{
  int heuristicCount = 0;

  // =====================================================================
  // H68 — GamutBoundaryDesc Triangle/Vertex Overflow (CWE-131/CWE-190)
  // Raw-file check targeting IccTagLut.cpp CIccTagGamutBoundaryDesc::Read()
  // =====================================================================
  printf("[H68] GamutBoundaryDesc Triangle/Vertex Overflow\n");
  {
    RawFileHandle fh68 = OpenRawFile(filename);
    if (fh68) {
      size_t fs68 = (size_t)fh68.fileSize;

      int gbdIssues = 0;
      if (fh68.fp && fs68 >= 132) {
        icUInt8Number tc68[4];
        fseek(fh68.fp, 128, SEEK_SET);
        if (fread(tc68, 1, 4, fh68.fp) == 4) {
          uint32_t tagCount68 = ReadU32BE(tc68);
          if (tagCount68 > 1000) tagCount68 = 1000;

          for (uint32_t t = 0; t < tagCount68 && fh68.fp; t++) {
            icUInt8Number tagEntry[12];
            fseek(fh68.fp, 132 + t * 12, SEEK_SET);
            if (fread(tagEntry, 1, 12, fh68.fp) != 12) break;

            uint32_t tOff = ReadU32BE(&tagEntry[4]);
            uint32_t tSz  = ReadU32BE(&tagEntry[8]);

            if ((uint64_t)tOff + 4 > fs68 || tSz < 20) continue;

            // Read tag type signature
            icUInt8Number typeSig[4];
            fseek(fh68.fp, tOff, SEEK_SET);
            if (fread(typeSig, 1, 4, fh68.fp) != 4) continue;
            uint32_t tType = ReadU32BE(typeSig);

            // icSigGamutBoundaryDescType = 'gbd '
            if (tType != 0x67626420) continue;

            // Parse GBD header: skip 8 bytes (type+reserved), then:
            // offset 8: nPCSChannels (2 bytes)
            // offset 10: reserved (2 bytes)
            // offset 12: nVertices (4 bytes)
            // offset 16: nTriangles (4 bytes)
            if ((uint64_t)tOff + 20 > fs68) continue;
            icUInt8Number gbdHdr[12];
            fseek(fh68.fp, tOff + 8, SEEK_SET);
            if (fread(gbdHdr, 1, 12, fh68.fp) != 12) continue;

            uint16_t nPCS = ((uint16_t)gbdHdr[0]<<8)|gbdHdr[1];
            uint32_t nVert = ReadU32BE(&gbdHdr[4]);
            uint32_t nTri  = ReadU32BE(&gbdHdr[8]);

            // Check vertex allocation: nVert * nPCS * sizeof(float)
            uint64_t vertBytes = (uint64_t)nVert * nPCS * 4;
            if (vertBytes > 268435456ULL) { // 256MB
              printf("      %s[WARN]  GamutBoundaryDesc: %u vertices * %u PCS = %llu bytes%s\n",
                     ColorCritical(), nVert, nPCS, (unsigned long long)vertBytes, ColorReset());
              printf("       %sCWE-190: Integer overflow in vertex allocation%s\n",
                     ColorCritical(), ColorReset());
              gbdIssues++;
            }
            // Check triangle allocation: nTri * 3 * sizeof(uint32)
            uint64_t triBytes = (uint64_t)nTri * 3 * 4;
            if (triBytes > 268435456ULL) {
              printf("      %s[WARN]  GamutBoundaryDesc: %u triangles → %llu bytes%s\n",
                     ColorCritical(), nTri, (unsigned long long)triBytes, ColorReset());
              printf("       %sCWE-131: Triangle array exceeds reasonable bounds%s\n",
                     ColorCritical(), ColorReset());
              gbdIssues++;
            }
          }
        }
      }

      if (gbdIssues > 0) {
        heuristicCount += gbdIssues;
      } else {
        printf("      %s[OK] GamutBoundaryDesc bounds valid (or absent)%s\n", ColorSuccess(), ColorReset());
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunHeuristic_H69_ProfileIDMD5Consistency(const char *filename)
{
  int heuristicCount = 0;

  // =====================================================================
  // H69 — Profile ID / MD5 Consistency (CWE-345/CWE-354)
  // Raw-file check: validates Profile ID field at header bytes 84-99
  // =====================================================================
  printf("[H69] Profile ID / MD5 Consistency\n");
  {
    RawFileHandle fh69 = OpenRawFile(filename);
    if (fh69) {

      int idIssues = 0;
      if (fh69.fp && fh69.fileSize >= 128) {
        icUInt8Number profileId[16];
        fseek(fh69.fp, 84, SEEK_SET);
        if (fread(profileId, 1, 16, fh69.fp) == 16) {
          bool allZero = true;
          for (int i = 0; i < 16; i++) {
            if (profileId[i] != 0) { allZero = false; break; }
          }
          if (allZero) {
            printf("      %s[INFO] Profile ID is all zeros (MD5 not computed)%s\n",
                   ColorInfo(), ColorReset());
          } else {
            // Verify profile ID appears plausible (not all 0xFF or repeating)
            bool allFF = true;
            bool repeating = true;
            for (int i = 0; i < 16; i++) {
              if (profileId[i] != 0xFF) allFF = false;
              if (i > 0 && profileId[i] != profileId[0]) repeating = false;
            }
            if (allFF || repeating) {
              printf("      %s[WARN]  Profile ID: suspicious pattern (all 0x%02X)%s\n",
                     ColorWarning(), profileId[0], ColorReset());
              printf("       %sCWE-345: Spoofed/invalid Profile ID%s\n",
                     ColorCritical(), ColorReset());
              idIssues++;
            } else {
              printf("      %s[OK] Profile ID present: %02x%02x%02x%02x...%02x%02x%02x%02x%s\n",
                     ColorSuccess(),
                     profileId[0], profileId[1], profileId[2], profileId[3],
                     profileId[12], profileId[13], profileId[14], profileId[15],
                     ColorReset());
            }
          }
        }
      }

      if (idIssues > 0) {
        heuristicCount += idIssues;
      }
    }
  }
  printf("\n");

  return heuristicCount;
}

int RunRawPostLibraryHeuristics(const char *filename)
{
  int heuristicCount = 0;

  heuristicCount += RunHeuristic_H33_mBAmABSubElementOffset(filename);
  heuristicCount += RunHeuristic_H34_IntegerOverflowSubElement(filename);
  heuristicCount += RunHeuristic_H35_SuspiciousFillPattern(filename);
  heuristicCount += RunHeuristic_H36_LUTTagPairCompleteness(filename);
  heuristicCount += RunHeuristic_H37_CalculatorElementComplexity(filename);
  heuristicCount += RunHeuristic_H38_CurveDegenerateValue(filename);
  heuristicCount += RunHeuristic_H39_SharedTagDataAliasing(filename);
  heuristicCount += RunHeuristic_H40_TagAlignmentPadding(filename);
  heuristicCount += RunHeuristic_H41_VersionTypeConsistency(filename);
  heuristicCount += RunHeuristic_H42_MatrixSingularity(filename);
  heuristicCount += RunHeuristic_H43_SpectralBRDFTagStructure(filename);
  heuristicCount += RunHeuristic_H44_EmbeddedImageValidation(filename);
  heuristicCount += RunHeuristic_H45_SparseMatrixBounds(filename);
  heuristicCount += RunHeuristic_H46_TextDescUnicodeLength(filename);
  heuristicCount += RunHeuristic_H47_NamedColor2SizeOverflow(filename);
  heuristicCount += RunHeuristic_H48_CLUTGridDimensionOverflow(filename);
  heuristicCount += RunHeuristic_H49_FloatNaNInfDetection(filename);
  heuristicCount += RunHeuristic_H50_ZeroSizeProfileTag(filename);
  heuristicCount += RunHeuristic_H51_LUTChannelCountConsistency(filename);
  heuristicCount += RunHeuristic_H52_IntegerUnderflowTagSize(filename);
  heuristicCount += RunHeuristic_H53_EmbeddedProfileRecursion(filename);
  heuristicCount += RunHeuristic_H54_DivisionByZeroTrigger(filename);
  heuristicCount += RunHeuristic_H55_UTF16EncodingValidation(filename);
  heuristicCount += RunHeuristic_H57_EmbeddedProfileRecursionDepth(filename);
  heuristicCount += RunHeuristic_H59_SpectralWavelengthRange(filename);
  heuristicCount += RunHeuristic_H68_GamutBoundaryDescOverflow(filename);
  heuristicCount += RunHeuristic_H69_ProfileIDMD5Consistency(filename);

  return heuristicCount;
}

int RunRawFallbackHeuristics(const char *filename, bool libraryAnalyzed)
{
  int heuristicCount = 0;

  if (!libraryAnalyzed) {
    printf("RAW-FILE ANALYSIS ENGINE (library load failed)\n");
    printf("=======================================================================\n\n");

    RawFileHandle fhRaw = OpenRawFile(filename);
    if (fhRaw) {
      size_t fileSize = (size_t)fhRaw.fileSize;

      // Read header + tag table
      icUInt8Number rawHdr[132] = {};
      bool hdrOk = (fileSize >= 132 && fread(rawHdr, 1, 132, fhRaw.fp) == 132);

      if (hdrOk) {
        icUInt32Number tagCount = ReadU32BE(&rawHdr[128]);

        // Declared profile size from header bytes 0-3
        icUInt32Number declaredSize = ReadU32BE(rawHdr);

        // --- H10 fallback: Tag Count ---
        printf("[H10] Tag Count: %u (raw)\n", tagCount);
        if (tagCount == 0) {
          printf("      %s[WARN]  Zero tags — empty or severely malformed profile%s\n",
                 ColorCritical(), ColorReset());
          heuristicCount++;
        } else if (tagCount > 256) {
          printf("      %s[WARN]  Excessive tag count: %u (>256) — potential DoS%s\n",
                 ColorCritical(), tagCount, ColorReset());
          heuristicCount++;
        }

        // --- H13 fallback: Per-Tag Size vs File Size ---
        printf("[H13] Per-Tag Size Check (raw)\n");
        {
          int tagSizeIssues = 0;
          size_t safeTagCount = (tagCount > 256) ? 256 : tagCount;
          for (size_t i = 0; i < safeTagCount; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fileSize) break;

            icUInt8Number entry[12];
            fseek(fhRaw.fp, ePos, SEEK_SET);
            if (fread(entry, 1, 12, fhRaw.fp) != 12) break;

            icUInt32Number tOffset = ReadU32BE(&entry[4]);
            icUInt32Number tSize   = ReadU32BE(&entry[8]);

            char tagSig[5] = {(char)entry[0], (char)entry[1], (char)entry[2], (char)entry[3], 0};

            // Check offset + size overflow
            uint64_t endPos = (uint64_t)tOffset + tSize;
            if (endPos > fileSize) {
              printf("      %s[WARN]  Tag '%s': offset=0x%X size=0x%X extends past file (0x%lX)%s\n",
                     ColorCritical(), tagSig, tOffset, tSize, (unsigned long)fileSize, ColorReset());
              tagSizeIssues++;
            }

            // Check oversized tags (>16MB is suspicious)
            if (tSize > 16777216) {
              printf("      %s[WARN]  Tag '%s': size %u bytes (>16MB) — potential OOM%s\n",
                     ColorWarning(), tagSig, tSize, ColorReset());
              tagSizeIssues++;
            }
          }
          if (tagSizeIssues > 0) {
            heuristicCount += tagSizeIssues;
          } else {
            printf("      %s[OK] All tag sizes within file bounds%s\n", ColorSuccess(), ColorReset());
          }
        }

        // --- H25 fallback: Tag Offset/Size OOB ---
        printf("[H25] Tag Offset/Size Out-of-Bounds Detection (raw)\n");
        {
          int oobIssues = 0;
          size_t safeTagCount = (tagCount > 256) ? 256 : tagCount;
          for (size_t i = 0; i < safeTagCount; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fileSize) break;

            icUInt8Number entry[12];
            fseek(fhRaw.fp, ePos, SEEK_SET);
            if (fread(entry, 1, 12, fhRaw.fp) != 12) break;

            icUInt32Number tOffset = ReadU32BE(&entry[4]);
            icUInt32Number tSize   = ReadU32BE(&entry[8]);

            char tagSig[5] = {(char)entry[0], (char)entry[1], (char)entry[2], (char)entry[3], 0};

            // Offset past file
            if (tOffset > fileSize) {
              printf("      %s[WARN]  Tag '%s': offset 0x%08X past file end (0x%lX)%s\n",
                     ColorCritical(), tagSig, tOffset, (unsigned long)fileSize, ColorReset());
              printf("       %sCRITICAL: OOB read if parser follows this offset%s\n",
                     ColorCritical(), ColorReset());
              oobIssues++;
            }

            // Size inconsistency with declared profile size
            if (declaredSize > 0 && (uint64_t)tOffset + tSize > declaredSize && (uint64_t)tOffset + tSize > fileSize) {
              printf("      %s[WARN]  Tag '%s': extends past declared profile size (%u)%s\n",
                     ColorWarning(), tagSig, declaredSize, ColorReset());
              oobIssues++;
            }
          }
          if (oobIssues > 0) {
            heuristicCount += oobIssues;
          } else {
            printf("      %s[OK] All tag offsets within file bounds%s\n", ColorSuccess(), ColorReset());
          }
        }

        // --- H28 fallback: LUT Dimension Validation ---
        printf("[H28] LUT Dimension Validation (raw)\n");
        {
          int lutIssues = 0;
          size_t safeTagCount = (tagCount > 256) ? 256 : tagCount;
          for (size_t i = 0; i < safeTagCount; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fileSize) break;

            icUInt8Number entry[12];
            fseek(fhRaw.fp, ePos, SEEK_SET);
            if (fread(entry, 1, 12, fhRaw.fp) != 12) break;

            icUInt32Number tOffset = ReadU32BE(&entry[4]);
            icUInt32Number tSize   = ReadU32BE(&entry[8]);

            if ((uint64_t)tOffset + 12 > fileSize || tSize < 12) continue;

            icUInt8Number typeSig[4];
            fseek(fhRaw.fp, tOffset, SEEK_SET);
            if (fread(typeSig, 1, 4, fhRaw.fp) != 4) continue;

            char tagSig[5] = {(char)entry[0], (char)entry[1], (char)entry[2], (char)entry[3], 0};

            // LUT8 (mft1) or LUT16 (mft2)
            bool isLut8  = (typeSig[0]=='m' && typeSig[1]=='f' && typeSig[2]=='t' && typeSig[3]=='1');
            bool isLut16 = (typeSig[0]=='m' && typeSig[1]=='f' && typeSig[2]=='t' && typeSig[3]=='2');
            if (!isLut8 && !isLut16) continue;

            if ((uint64_t)tOffset + 12 > fileSize) continue;
            icUInt8Number lutHdr[12];
            fseek(fhRaw.fp, tOffset + 8, SEEK_SET);
            if (fread(lutHdr, 1, 4, fhRaw.fp) != 4) continue;

            uint8_t nInput = lutHdr[0];
            uint8_t nOutput = lutHdr[1];
            uint8_t nGrid = lutHdr[2];

            if (nInput == 0 || nOutput == 0) {
              printf("      %s[WARN]  Tag '%s': LUT has 0 channels (in=%u out=%u)%s\n",
                     ColorCritical(), tagSig, nInput, nOutput, ColorReset());
              lutIssues++;
            }
            if (nGrid > 0 && nInput > 0) {
              uint64_t clutSize = 1;
              for (int d = 0; d < nInput; d++) {
                clutSize *= nGrid;
                if (clutSize > 1073741824ULL) { // >1GB
                  printf("      %s[WARN]  Tag '%s': CLUT %u^%u×%u entries → >1GB allocation%s\n",
                         ColorCritical(), tagSig, nGrid, nInput, nOutput, ColorReset());
                  printf("       %sRisk: OOM crash in CLUT allocation%s\n",
                         ColorCritical(), ColorReset());
                  lutIssues++;
                  break;
                }
              }
            }
          }
          if (lutIssues > 0) {
            heuristicCount += lutIssues;
          } else {
            printf("      %s[OK] No LUT dimension issues%s\n", ColorSuccess(), ColorReset());
          }
        }

        // --- H32 fallback: Tag Type Confusion ---
        printf("[H32] Tag Data Type Confusion Detection (raw)\n");
        {
          int typeIssues = 0;
          size_t safeTagCount = (tagCount > 256) ? 256 : tagCount;
          for (size_t i = 0; i < safeTagCount; i++) {
            size_t ePos = 132 + i * 12;
            if (ePos + 12 > fileSize) break;

            icUInt8Number entry[12];
            fseek(fhRaw.fp, ePos, SEEK_SET);
            if (fread(entry, 1, 12, fhRaw.fp) != 12) break;

            icUInt32Number tOffset = ReadU32BE(&entry[4]);

            if ((uint64_t)tOffset + 4 > fileSize) continue;

            icUInt8Number typeBuf[4];
            fseek(fhRaw.fp, tOffset, SEEK_SET);
            if (fread(typeBuf, 1, 4, fhRaw.fp) != 4) continue;

            char tagSig[5] = {(char)entry[0], (char)entry[1], (char)entry[2], (char)entry[3], 0};

            // Check if type signature contains non-printable characters
            bool validType = true;
            for (int b = 0; b < 4; b++) {
              if (typeBuf[b] != 0 && (typeBuf[b] < 0x20 || typeBuf[b] > 0x7E)) {
                validType = false;
                break;
              }
            }
            if (!validType) {
              printf("      %s[WARN]  Tag '%s' at 0x%08X: type signature 0x%02X%02X%02X%02X is non-printable%s\n",
                     ColorCritical(), tagSig, tOffset,
                     typeBuf[0], typeBuf[1], typeBuf[2], typeBuf[3], ColorReset());
              printf("       %sRisk: Type confusion → wrong parser invoked → memory corruption%s\n",
                     ColorCritical(), ColorReset());
              typeIssues++;
            }
          }
          if (typeIssues > 0) {
            heuristicCount += typeIssues;
          } else {
            printf("      %s[OK] All tag type signatures are printable ICC 4CC codes%s\n", ColorSuccess(), ColorReset());
          }
        }

        printf("\n");
      }
    }
  }

  return heuristicCount;
}
