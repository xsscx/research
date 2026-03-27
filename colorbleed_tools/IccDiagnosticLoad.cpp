/*!
 *  @file IccDiagnosticLoad.cpp
 *  @brief Deep diagnostic ICC profile loader with IO tracing
 *  @author David Hoyt / Copilot
 *  @date 26 MAR 2026
 *  @version 1.0.0
 *
 *  Traces every IO operation during profile loading to diagnose
 *  where malformed tag Read() calls fail. Designed for CFL patch
 *  PoC development and A/B testing against iccDumpAll/iccDumpProfile.
 *
 *  Output modes:
 *    --trace    Full IO position trace for each tag load
 *    --compare  A/B comparison: OpenIccProfile vs ReadIccProfile
 *    --raw      Raw hex dump of tag data regions
 *
 *  Copyright (c) 2026 David H Hoyt LLC
 *  License: GPL-3.0-or-later
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cerrno>
#include <vector>
#include <string>

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagBasic.h"
#include "IccTagLut.h"
#include "IccTagMPE.h"
#include "IccUtil.h"
#include "IccIO.h"
#include "IccProfLibVer.h"

// ANSI color helpers
#define C_RED    "\033[31m"
#define C_GREEN  "\033[32m"
#define C_YELLOW "\033[33m"
#define C_CYAN   "\033[36m"
#define C_BOLD   "\033[1m"
#define C_RESET  "\033[0m"

static void sigToStr(icUInt32Number sig, char out[5]) {
    out[0] = (char)((sig >> 24) & 0xFF);
    out[1] = (char)((sig >> 16) & 0xFF);
    out[2] = (char)((sig >>  8) & 0xFF);
    out[3] = (char)( sig        & 0xFF);
    out[4] = '\0';
}

static void hexDump(const uint8_t *data, size_t len, size_t baseOffset) {
    for (size_t i = 0; i < len; i += 16) {
        printf("  %06zx: ", baseOffset + i);
        for (size_t j = 0; j < 16 && (i+j) < len; j++)
            printf("%02x ", data[i+j]);
        for (size_t j = (len - i < 16) ? (len - i) : 16; j < 16; j++)
            printf("   ");
        printf(" |");
        for (size_t j = 0; j < 16 && (i+j) < len; j++) {
            uint8_t c = data[i+j];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("|\n");
    }
}

// Read raw file into buffer
static std::vector<uint8_t> readFile(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return {};
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf(sz);
    if (fread(buf.data(), 1, sz, f) != (size_t)sz)
        buf.clear();
    fclose(f);
    return buf;
}

static uint32_t readBE32(const uint8_t *p) {
    return ((uint32_t)p[0]<<24) | ((uint32_t)p[1]<<16) | ((uint32_t)p[2]<<8) | p[3];
}

static uint16_t readBE16(const uint8_t *p) {
    return ((uint16_t)p[0]<<8) | p[1];
}

// Phase 1: Raw binary analysis — no library, just raw bytes
static void rawAnalyze(const char *path) {
    auto buf = readFile(path);
    if (buf.empty()) {
        printf(C_RED "ERROR: Cannot read file '%s'\n" C_RESET, path);
        return;
    }

    size_t fileLen = buf.size();
    printf(C_BOLD "\n=== RAW BINARY ANALYSIS ===" C_RESET "\n");
    printf("File: %s (%zu bytes)\n\n", path, fileLen);

    if (fileLen < 132) {
        printf(C_RED "File too small for ICC header + tag table\n" C_RESET);
        return;
    }

    // Header
    uint32_t profileSize = readBE32(&buf[0]);
    char magic[5]; sigToStr(readBE32(&buf[36]), magic);
    uint8_t verMajor = buf[8], verMinor = buf[9];
    char devClass[5]; sigToStr(readBE32(&buf[12]), devClass);
    char colorSpace[5]; sigToStr(readBE32(&buf[16]), colorSpace);
    char pcs[5]; sigToStr(readBE32(&buf[20]), pcs);

    printf("  Header.size     = %u (file=%zu) %s\n", profileSize, fileLen,
           profileSize != fileLen ? C_YELLOW "MISMATCH" C_RESET : C_GREEN "OK" C_RESET);
    printf("  Header.magic    = '%s' %s\n", magic,
           strcmp(magic, "acsp") ? C_RED "BAD" C_RESET : C_GREEN "OK" C_RESET);
    printf("  Header.version  = %u.%u.%u\n", verMajor, (verMinor>>4)&0xF, verMinor&0xF);
    printf("  Header.class    = '%s'\n", devClass);
    printf("  Header.dataCS   = '%s'\n", colorSpace);
    printf("  Header.PCS      = '%s'\n", pcs);

    // Tag table
    uint32_t tagCount = readBE32(&buf[128]);
    printf("\n  Tag count = %u\n", tagCount);

    size_t tagTableEnd = 132 + tagCount * 12;
    if (tagTableEnd > fileLen) {
        printf(C_RED "  Tag table extends past EOF!\n" C_RESET);
        return;
    }

    printf("\n  %-6s  %-10s %-10s %-10s  %s\n", "Sig", "Offset", "Size", "End", "Status");
    printf("  %-6s  %-10s %-10s %-10s  %s\n", "------", "----------", "----------", "----------", "------");

    for (uint32_t t = 0; t < tagCount; t++) {
        size_t entryOff = 132 + t * 12;
        uint32_t tSig = readBE32(&buf[entryOff]);
        uint32_t tOff = readBE32(&buf[entryOff + 4]);
        uint32_t tSize = readBE32(&buf[entryOff + 8]);

        char sigStr[5]; sigToStr(tSig, sigStr);
        uint64_t tEnd = (uint64_t)tOff + tSize;

        const char *status = C_GREEN "OK" C_RESET;
        if (tOff < 128) status = C_RED "OFFSET_IN_HEADER" C_RESET;
        else if (tEnd > fileLen) status = C_RED "PAST_EOF" C_RESET;
        else if (tSize == 0) status = C_YELLOW "ZERO_SIZE" C_RESET;

        printf("  '%-4s'  %-10u %-10u %-10llu  %s\n", sigStr, tOff, tSize,
               (unsigned long long)tEnd, status);

        // For LUT-type tags, decode the inner structure
        if (tOff + 32 <= fileLen && tSize >= 32) {
            uint32_t typeSig = readBE32(&buf[tOff]);
            char typeStr[5]; sigToStr(typeSig, typeStr);

            if (typeSig == 0x6D414220 || typeSig == 0x6D424120) {
                // lutAtoBType or lutBtoAType
                uint8_t nInput = buf[tOff + 8];
                uint8_t nOutput = buf[tOff + 9];
                uint32_t offB = readBE32(&buf[tOff + 12]);
                uint32_t offMat = readBE32(&buf[tOff + 16]);
                uint32_t offM = readBE32(&buf[tOff + 20]);
                uint32_t offCLUT = readBE32(&buf[tOff + 24]);
                uint32_t offA = readBE32(&buf[tOff + 28]);

                printf(C_CYAN "         type='%s' in=%u out=%u\n" C_RESET, typeStr, nInput, nOutput);
                printf(C_CYAN "         B-curves offset=%u (abs=%u)\n" C_RESET, offB, tOff+offB);
                printf(C_CYAN "         Matrix   offset=%u\n" C_RESET, offMat);
                printf(C_CYAN "         M-curves offset=%u\n" C_RESET, offM);
                printf(C_CYAN "         CLUT     offset=%u\n" C_RESET, offCLUT);
                printf(C_CYAN "         A-curves offset=%u\n" C_RESET, offA);

                // Check B-curves absolute position
                if (offB) {
                    uint64_t absB = (uint64_t)tOff + offB;
                    uint64_t tagEnd = (uint64_t)tOff + tSize;
                    printf("         " C_BOLD "nStart=%u nEnd=%llu\n" C_RESET,
                           tOff, (unsigned long long)tagEnd);
                    printf("         " C_BOLD "B-curves absolute=%llu\n" C_RESET,
                           (unsigned long long)absB);

                    if (absB > tagEnd) {
                        printf("         " C_RED "*** B-CURVES PAST TAG END! "
                               "absB(%llu) > nEnd(%llu) ***\n" C_RESET,
                               (unsigned long long)absB, (unsigned long long)tagEnd);
                        printf("         " C_RED "*** nEnd - Tell() will UNDERFLOW to ~%llu ***\n" C_RESET,
                               (unsigned long long)(tagEnd - absB));

                        // Show what's at the B-curves position
                        if (absB + 12 <= fileLen) {
                            printf("         Data at B-curves offset:\n");
                            size_t dumpLen = fileLen - absB;
                            if (dumpLen > 64) dumpLen = 64;
                            hexDump(&buf[absB], dumpLen, absB);
                        }
                    }

                    // Trace Read() underflow arithmetic
                    if (absB < fileLen && absB > tagEnd) {
                        printf("\n         " C_YELLOW "=== CFL-065 Underflow Trace ===" C_RESET "\n");
                        printf("         nEnd (size_t)          = %llu\n", (unsigned long long)tagEnd);
                        printf("         pIO->Tell() after seek = %llu\n", (unsigned long long)absB);
                        size_t nEnd_val = tagEnd;
                        size_t tell_val = absB;
                        size_t underflow = nEnd_val - tell_val;
                        uint32_t truncated = (uint32_t)underflow;
                        printf("         nEnd - Tell() (size_t) = %zu (0x%016zx)\n", underflow, underflow);
                        printf("         cast to uint32         = %u (0x%08x)\n", truncated, truncated);
                        printf("         " C_RED "CIccTagCurve::Read(%u, pIO) called with ~4GB size!\n" C_RESET,
                               truncated);
                    }
                }
            }
        }
    }

    // Raw hex dump of tag data regions
    printf(C_BOLD "\n=== RAW TAG DATA HEX DUMP ===" C_RESET "\n");
    for (uint32_t t = 0; t < tagCount; t++) {
        size_t entryOff = 132 + t * 12;
        uint32_t tSig = readBE32(&buf[entryOff]);
        uint32_t tOff = readBE32(&buf[entryOff + 4]);
        uint32_t tSize = readBE32(&buf[entryOff + 8]);
        char sigStr[5]; sigToStr(tSig, sigStr);

        if (tOff < fileLen) {
            size_t dumpLen = tSize;
            if (tOff + dumpLen > fileLen) dumpLen = fileLen - tOff;
            if (dumpLen > 128) dumpLen = 128;
            printf("\n  Tag '%s' (offset %u, size %u):\n", sigStr, tOff, tSize);
            hexDump(&buf[tOff], dumpLen, tOff);
        }
    }
}

// Phase 2: Library-based A/B comparison
static void libraryCompare(const char *path) {
    printf(C_BOLD "\n=== LIBRARY A/B COMPARISON ===" C_RESET "\n");

    // Method A: OpenIccProfile (lazy Attach)
    printf("\n" C_BOLD "--- Method A: OpenIccProfile (lazy Attach) ---" C_RESET "\n");
    CIccProfile *pA = OpenIccProfile(path);
    if (!pA) {
        printf(C_RED "  OpenIccProfile FAILED!\n" C_RESET);
    } else {
        printf(C_GREEN "  OpenIccProfile OK" C_RESET " — %zu tags in directory\n", pA->m_Tags.size());

        const size_t bsz = 64;
        char buf[bsz];
        CIccInfo Fmt;
        int loaded = 0, failed = 0;

        for (auto &entry : pA->m_Tags) {
            sigToStr(entry.TagInfo.sig, buf);
            printf("  Tag '%s' offset=%u size=%u ", buf,
                   entry.TagInfo.offset, entry.TagInfo.size);

            CIccTag *pTag = pA->FindTag(entry);
            if (pTag) {
                char typeBuf[5];
                sigToStr(pTag->GetType(), typeBuf);
                printf(C_GREEN "[LOADED]" C_RESET " type='%s'", typeBuf);
                loaded++;

                // For MBB types, show channel info
                if (pTag->IsMBBType()) {
                    CIccMBB *pMBB = (CIccMBB*)pTag;
                    printf(" in=%u out=%u", pMBB->InputChannels(), pMBB->OutputChannels());
                    printf(" B=%s", pMBB->GetCurvesB() ? "yes" : "no");
                    printf(" M=%s", pMBB->GetCurvesM() ? "yes" : "no");
                    printf(" A=%s", pMBB->GetCurvesA() ? "yes" : "no");
                    printf(" CLUT=%s", pMBB->GetCLUT() ? "yes" : "no");
                }
            } else {
                printf(C_RED "[FAILED]" C_RESET);
                failed++;
            }
            printf("\n");
        }
        printf("  Summary: %d loaded, %d failed\n", loaded, failed);
        delete pA;
    }

    // Method B: ReadIccProfile (eager full Read)
    printf("\n" C_BOLD "--- Method B: ReadIccProfile (eager Read) ---" C_RESET "\n");
    CIccProfile *pB = ReadIccProfile(path);
    if (!pB) {
        printf(C_RED "  ReadIccProfile FAILED!\n" C_RESET);
        printf("  This means CIccProfile::Read() returned false.\n");
        printf("  Read() loads ALL tags eagerly — any one tag failure aborts.\n");
    } else {
        printf(C_GREEN "  ReadIccProfile OK" C_RESET " — %zu tags loaded\n", pB->m_Tags.size());

        for (auto &entry : pB->m_Tags) {
            char buf[5];
            sigToStr(entry.TagInfo.sig, buf);
            CIccTag *pTag = pB->FindTag(entry);
            printf("  Tag '%s' %s\n", buf, pTag ? C_GREEN "[OK]" C_RESET : C_RED "[MISSING]" C_RESET);
        }
        delete pB;
    }

    // Method C: ValidateIccProfile (full validate)
    printf("\n" C_BOLD "--- Method C: ValidateIccProfile (validate) ---" C_RESET "\n");
    std::string sReport;
    icValidateStatus nStatus = icValidateOK;
    CIccProfile *pC = ValidateIccProfile(path, sReport, nStatus);
    if (!pC) {
        printf(C_RED "  ValidateIccProfile FAILED!\n" C_RESET);
    } else {
        printf(C_GREEN "  ValidateIccProfile OK" C_RESET " — status=%d\n", (int)nStatus);
        delete pC;
    }

    // Show validation report (trimmed)
    if (!sReport.empty()) {
        printf("\n  Validation messages (first 2000 chars):\n");
        printf("  %.2000s\n", sReport.c_str());
        if (sReport.size() > 2000) printf("  ... (%zu more chars)\n", sReport.size() - 2000);
    }
}

// Phase 3: Manual LoadTag simulation with IO tracing
static void traceLoadTag(const char *path) {
    auto buf = readFile(path);
    if (buf.empty() || buf.size() < 132) return;

    printf(C_BOLD "\n=== MANUAL LoadTag TRACE ===" C_RESET "\n");
    printf("Simulating CIccProfile::LoadTag() + CIccTagLutAtoB::Read() flow\n\n");

    size_t fileLen = buf.size();
    uint32_t tagCount = readBE32(&buf[128]);

    for (uint32_t t = 0; t < tagCount; t++) {
        size_t eOff = 132 + t * 12;
        uint32_t tSig = readBE32(&buf[eOff]);
        uint32_t tOff = readBE32(&buf[eOff + 4]);
        uint32_t tSize = readBE32(&buf[eOff + 8]);
        char sigStr[5]; sigToStr(tSig, sigStr);

        printf(C_BOLD "Tag '%s': offset=%u size=%u\n" C_RESET, sigStr, tOff, tSize);

        // LoadTag boundary checks
        if (tOff < 128) {
            printf("  " C_RED "REJECT: offset < sizeof(header)\n" C_RESET);
            continue;
        }
        if (tSize == 0) {
            printf("  " C_RED "REJECT: size == 0\n" C_RESET);
            continue;
        }
        if ((uint64_t)tOff + tSize > fileLen) {
            printf("  " C_RED "REJECT: offset+size > fileLen (%llu > %zu)\n" C_RESET,
                   (unsigned long long)((uint64_t)tOff + tSize), fileLen);
            continue;
        }
        printf("  LoadTag boundary check: " C_GREEN "PASS" C_RESET "\n");

        // Read type signature
        if (tOff + 4 > fileLen) continue;
        uint32_t typeSig = readBE32(&buf[tOff]);
        char typeStr[5]; sigToStr(typeSig, typeStr);
        printf("  Tag type signature: '%s' (0x%08x)\n", typeStr, typeSig);

        // Only deep-trace LUT types
        if (typeSig != 0x6D414220 && typeSig != 0x6D424120) {
            printf("  (not LUT AtoB/BtoA — skipping deep trace)\n\n");
            continue;
        }

        printf("\n  " C_CYAN "--- CIccTagLutAtoB::Read(%u, pIO) trace ---" C_RESET "\n", tSize);
        printf("  size = %u, 8*sizeof(uint32) = %zu\n", tSize, 8*sizeof(uint32_t));

        if (tSize < 8*sizeof(uint32_t)) {
            printf("  " C_RED "REJECT: size < 32 bytes\n" C_RESET);
            continue;
        }

        size_t nStart = tOff;
        size_t nEnd = nStart + tSize;
        printf("  nStart = %zu (pIO->Tell() after Seek to tag offset)\n", nStart);
        printf("  nEnd   = %zu (nStart + size)\n", nEnd);

        // Read header fields
        uint8_t nInput = buf[tOff + 8];
        uint8_t nOutput = buf[tOff + 9];
        printf("  m_nInput = %u, m_nOutput = %u\n", nInput, nOutput);

        if (nInput < 1 || nOutput < 1 || nInput > 15 || nOutput > 15) {
            printf("  " C_RED "REJECT: channel count out of range\n" C_RESET);
            continue;
        }

        // Offsets
        uint32_t offB = readBE32(&buf[tOff + 12]);
        uint32_t offMat = readBE32(&buf[tOff + 16]);
        uint32_t offM = readBE32(&buf[tOff + 20]);
        uint32_t offCLUT = readBE32(&buf[tOff + 24]);
        uint32_t offA = readBE32(&buf[tOff + 28]);

        printf("  Offset[0] (B-curves) = %u\n", offB);
        printf("  Offset[1] (Matrix)   = %u\n", offMat);
        printf("  Offset[2] (M-curves) = %u\n", offM);
        printf("  Offset[3] (CLUT)     = %u\n", offCLUT);
        printf("  Offset[4] (A-curves) = %u\n", offA);

        // After reading 32-byte header, IO at nStart+32
        size_t ioPos = nStart + 32;
        printf("  pIO->Tell() after header read = %zu\n", ioPos);

        // B-curves
        if (offB) {
            bool isInputB = (typeSig == 0x6D424120); // BtoA has InputMatrix=true
            uint8_t nCurves = isInputB ? nInput : nOutput;
            printf("\n  " C_BOLD "B-curves: nCurves=%u, isInputB=%s\n" C_RESET,
                   nCurves, isInputB ? "true" : "false");

            size_t seekTarget = nStart + offB;
            printf("  Seek(nStart + Offset[0]) = Seek(%zu + %u) = Seek(%zu)\n",
                   nStart, offB, seekTarget);
            if (seekTarget >= fileLen) {
                printf("  " C_RED "Seek past EOF! (%zu >= %zu)\n" C_RESET, seekTarget, fileLen);
            } else if ((int64_t)seekTarget < 0) {
                printf("  " C_RED "Seek returns negative!\n" C_RESET);
            } else {
                printf("  Seek " C_GREEN "OK" C_RESET "\n");
            }

            ioPos = seekTarget;

            for (int i = 0; i < nCurves && ioPos < fileLen; i++) {
                printf("\n  Curve[%d]:\n", i);
                printf("    nPos = pIO->Tell() = %zu\n", ioPos);

                if (ioPos + 4 > fileLen) {
                    printf("    " C_RED "Cannot read curve sig (past EOF)\n" C_RESET);
                    break;
                }

                uint32_t curveSig = readBE32(&buf[ioPos]);
                char curveSigStr[5]; sigToStr(curveSig, curveSigStr);
                printf("    Read32(&sig) = '%s' (0x%08x)\n", curveSigStr, curveSig);

                if (curveSig != 0x63757276 && curveSig != 0x70617261) {
                    printf("    " C_RED "Not curv(0x63757276) or para(0x70617261) — REJECT\n" C_RESET);
                    break;
                }

                // The key underflow calculation
                printf("    nEnd = %zu, pIO->Tell() = %zu\n", nEnd, ioPos);
                if (ioPos > nEnd) {
                    size_t underflow = nEnd - ioPos;
                    uint32_t truncated = (uint32_t)underflow;
                    printf("    " C_RED "*** UNDERFLOW: nEnd(%zu) - Tell(%zu) = %zu (0x%016zx)\n" C_RESET,
                           nEnd, ioPos, underflow, underflow);
                    printf("    " C_RED "*** cast to uint32 = %u (0x%08x)\n" C_RESET, truncated, truncated);
                    printf("    " C_RED "*** CIccTagCurve::Read(%u, pIO) — passes ~4GB as 'size'!\n" C_RESET,
                           truncated);
                } else {
                    uint32_t readSize = (uint32_t)(nEnd - ioPos);
                    printf("    Read size = nEnd - Tell = %u " C_GREEN "OK" C_RESET "\n", readSize);
                }

                // Simulate CIccTagCurve::Read
                if (curveSig == 0x63757276 && ioPos + 12 <= fileLen) {
                    uint32_t curveCount = readBE32(&buf[ioPos + 8]);
                    printf("    curv: count = %u\n", curveCount);
                    if (curveCount == 0) {
                        printf("    Identity curve (0 entries) — reads 12 bytes header only\n");
                        ioPos += 12;
                    } else {
                        size_t curveDataSize = 12 + curveCount * 2;
                        printf("    Data curve: %zu bytes total (12 hdr + %u * 2)\n",
                               curveDataSize, curveCount);
                        ioPos += curveDataSize;
                    }
                } else if (curveSig == 0x70617261 && ioPos + 12 <= fileLen) {
                    uint16_t funcType = readBE16(&buf[ioPos + 8]);
                    printf("    para: funcType = %u\n", funcType);
                    // parametric curve sizes vary by funcType
                    static const size_t paramSizes[] = {4, 12, 16, 20, 28};
                    size_t pSize = (funcType < 5) ? paramSizes[funcType] : 0;
                    ioPos += 12 + pSize;
                } else {
                    printf("    " C_RED "Cannot read curve header\n" C_RESET);
                    break;
                }

                // Sync32
                uint32_t syncOff = offB & 0x3;
                size_t syncPos = ((ioPos - syncOff + 3) >> 2) << 2;
                size_t syncTarget = syncPos + syncOff;
                printf("    Sync32(%u): syncOff=%u nPos=%zu target=%zu",
                       offB, syncOff, syncPos, syncTarget);
                if (syncTarget > fileLen) {
                    printf(" " C_RED "PAST_EOF" C_RESET);
                } else {
                    printf(" " C_GREEN "OK" C_RESET);
                }
                printf("\n");
                ioPos = syncTarget;
            }
        }

        printf("\n  End of Read() trace\n\n");
    }
}

static void printUsage(void) {
    printf("IccDiagnosticLoad v1.0.0 — Deep ICC profile loading diagnostics\n");
    printf("Built with IccProfLib " ICCPROFLIBVER "\n\n");
    printf("Usage: iccDiagnosticLoad [options] <profile.icc>\n\n");
    printf("Options:\n");
    printf("  --raw      Raw binary analysis + hex dump (no library)\n");
    printf("  --compare  A/B: OpenIccProfile vs ReadIccProfile vs ValidateIccProfile\n");
    printf("  --trace    Manual LoadTag + Read() simulation with IO tracing\n");
    printf("  --all      All of the above (default)\n");
    printf("  --dump     Also run iccDumpAll-style tag dump via library\n");
    printf("\nDesigned for CFL patch PoC development and A/B testing.\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printUsage();
        return 0;
    }

    bool doRaw = false, doCompare = false, doTrace = false, doDump = false;
    const char *profilePath = nullptr;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--raw") == 0) doRaw = true;
        else if (strcmp(argv[i], "--compare") == 0) doCompare = true;
        else if (strcmp(argv[i], "--trace") == 0) doTrace = true;
        else if (strcmp(argv[i], "--dump") == 0) doDump = true;
        else if (strcmp(argv[i], "--all") == 0) { doRaw = doCompare = doTrace = true; }
        else if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            printUsage();
            return 0;
        }
        else profilePath = argv[i];
    }

    if (!profilePath) {
        fprintf(stderr, "Error: no profile path specified\n");
        return 1;
    }

    // Default to --all
    if (!doRaw && !doCompare && !doTrace && !doDump)
        doRaw = doCompare = doTrace = true;

    printf(C_BOLD "IccDiagnosticLoad v1.0.0" C_RESET "\n");
    printf("Profile: %s\n", profilePath);

    if (doRaw) rawAnalyze(profilePath);
    if (doTrace) traceLoadTag(profilePath);
    if (doCompare) libraryCompare(profilePath);

    if (doDump) {
        printf(C_BOLD "\n=== LIBRARY TAG DUMP (via FindTag + Describe) ===" C_RESET "\n");
        CIccProfile *pIcc = OpenIccProfile(profilePath);
        if (pIcc) {
            CIccInfo Fmt;
            const size_t bsz = 64;
            char buf[bsz];
            for (auto &entry : pIcc->m_Tags) {
                CIccTag *pTag = pIcc->FindTag(entry);
                if (pTag) {
                    printf("\nTag '%s' type='%s':\n",
                           icGetSig(buf, bsz, entry.TagInfo.sig),
                           Fmt.GetTagTypeSigName(pTag->GetType()));
                    std::string desc;
                    pTag->Describe(desc, 100);
                    if (desc.size() > 4000) {
                        printf("%.4000s\n... (%zu more chars)\n", desc.c_str(), desc.size()-4000);
                    } else {
                        printf("%s\n", desc.c_str());
                    }
                } else {
                    printf("\nTag '%s': " C_RED "LOAD FAILED\n" C_RESET,
                           icGetSig(buf, bsz, entry.TagInfo.sig));
                }
            }
            delete pIcc;
        }
    }

    printf("\n");
    return 0;
}
