/*
 * IccTest Library — CheckHelpers.h
 * Utility functions for implementing checks.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#ifndef ICCTEST_CHECK_HELPERS_H
#define ICCTEST_CHECK_HELPERS_H

#include "icctest/CheckResult.h"
#include "icctest/ProfileView.h"

#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>

namespace icctest {

// ── String formatting ──

/// Safe printf-style string formatting (max 2048 chars).
inline std::string sfmt(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
inline std::string sfmt(const char* fmt, ...) {
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    int n = std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n < 0) return std::string(fmt);
    return std::string(buf, static_cast<size_t>(n < 2048 ? n : 2047));
}

/// Convert a 4-byte big-endian signature to a printable string.
inline std::string sigStr(uint32_t sig) {
    char buf[5];
    buf[0] = static_cast<char>((sig >> 24) & 0xFF);
    buf[1] = static_cast<char>((sig >> 16) & 0xFF);
    buf[2] = static_cast<char>((sig >>  8) & 0xFF);
    buf[3] = static_cast<char>((sig      ) & 0xFF);
    buf[4] = '\0';
    // Replace non-printable with '?'
    for (int i = 0; i < 4; i++) {
        unsigned char c = static_cast<unsigned char>(buf[i]);
        if (c < 0x20 || c > 0x7E) buf[i] = '?';
    }
    return std::string(buf);
}

// ── Finding construction helpers ──

/// Create a Finding with level + message.
inline Finding makeFinding(Severity level, std::string message) {
    return Finding{{}, level, std::move(message), {}, {}};
}

/// Create a Finding with level + message + CWE note.
inline Finding makeFinding(Severity level, std::string message, std::string cweNote) {
    return Finding{{}, level, std::move(message), {}, std::move(cweNote)};
}

/// Create a Finding with level + message + detail + CWE note.
inline Finding makeFindingFull(Severity level, std::string message,
                                std::string detail, std::string cweNote) {
    return Finding{{}, level, std::move(message), std::move(detail), std::move(cweNote)};
}

// ── Raw byte reading (big-endian) ──

inline uint32_t readU32BE(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) << 8)  |  uint32_t(p[3]);
}

inline uint16_t readU16BE(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

inline bool halfFloatTriggersIccUtilUB(icFloat16Number raw) {
    icUInt16Number mag = static_cast<icUInt16Number>(raw & 0x7FFFu);
    icUInt16Number exp = static_cast<icUInt16Number>((mag >> 10) & 0x1Fu);
    return mag != 0 && exp < 15;
}

inline float safeF16ToF(icFloat16Number num) {
    icUInt16Number signBits = static_cast<icUInt16Number>(num & 0x8000u);
    icUInt16Number expBits = static_cast<icUInt16Number>((num >> 10) & 0x1Fu);
    icUInt16Number mantBits = static_cast<icUInt16Number>(num & 0x03FFu);
    icUInt32Number bits = static_cast<icUInt32Number>(signBits) << 16;

    if ((num & 0x7FFFu) == 0) {
        bits = static_cast<icUInt32Number>(num) << 16;
    } else if (expBits == 0) {
        int exp = -14;
        icUInt16Number mant = mantBits;
        while ((mant & 0x0400u) == 0) {
            mant <<= 1;
            --exp;
        }
        mant = static_cast<icUInt16Number>(mant & 0x03FFu);
        bits |= (static_cast<icUInt32Number>(exp + 127) << 23) |
                (static_cast<icUInt32Number>(mant) << 13);
    } else if (expBits == 0x1Fu) {
        bits |= 0x7F800000u | (static_cast<icUInt32Number>(mantBits) << 13);
        if (mantBits) bits |= 0x00400000u;
    } else {
        int exp = static_cast<int>(expBits) - 15 + 127;
        bits |= (static_cast<icUInt32Number>(exp) << 23) |
                (static_cast<icUInt32Number>(mantBits) << 13);
    }

    float out = 0.0f;
    std::memcpy(&out, &bits, sizeof(out));
    return out;
}

inline int32_t readS32BE(const uint8_t* p) {
    return static_cast<int32_t>(readU32BE(p));
}

/// Read s15Fixed16Number as double.
inline double readS15Fixed16(const uint8_t* p) {
    int32_t raw = readS32BE(p);
    return raw / 65536.0;
}

struct RawMpePositionIssue {
    uint32_t tagSig = 0;
    uint32_t tagSize = 0;
    uint32_t procElementCount = 0;
    uint32_t entryIndex = 0;
    uint32_t elementOffset = 0;
    uint32_t elementSize = 0;
    uint32_t elementSig = 0;
    bool positionTableTruncated = false;
    bool offsetSizeWrap = false;
    bool exceedsTagSize = false;
};

inline std::string formatRawMpePositionIssue(const RawMpePositionIssue& issue) {
    if (issue.positionTableTruncated) {
        return sfmt("Tag '%s': mpet position table requires %u entries (%llu bytes) but tag size is %u",
                    sigStr(issue.tagSig).c_str(),
                    issue.procElementCount,
                    static_cast<unsigned long long>(issue.procElementCount) * 8ull,
                    issue.tagSize);
    }

    if (issue.elementSig) {
        return sfmt("Tag '%s': mpet element table entry %u ('%s') offset=%u size=%u %s%s tag size=%u",
                    sigStr(issue.tagSig).c_str(),
                    issue.entryIndex,
                    sigStr(issue.elementSig).c_str(),
                    issue.elementOffset,
                    issue.elementSize,
                    issue.offsetSizeWrap ? "wraps 32-bit offset+size" : "extends beyond tag bounds",
                    issue.exceedsTagSize ? " and exceeds" : "",
                    issue.tagSize);
    }

    return sfmt("Tag '%s': mpet element table entry %u offset=%u size=%u %s%s tag size=%u",
                sigStr(issue.tagSig).c_str(),
                issue.entryIndex,
                issue.elementOffset,
                issue.elementSize,
                issue.offsetSizeWrap ? "wraps 32-bit offset+size" : "extends beyond",
                issue.exceedsTagSize ? " and exceeds" : "",
                issue.tagSize);
}

inline std::vector<RawMpePositionIssue>
scanRawMpePositionIssues(const ProfileView& pv, size_t maxIssues = 8) {
    std::vector<RawMpePositionIssue> issues;
    const uint8_t* data = pv.rawData();
    size_t len = pv.rawSize();
    if (!data || len < 16) return issues;

    constexpr uint32_t kMpeType = 0x6D706574u; // 'mpet'
    constexpr uint32_t kMpeHeaderSize = 16u;

    for (const auto& tag : pv.rawTagTable()) {
        if (tag.size < kMpeHeaderSize) continue;
        if ((uint64_t)tag.offset + kMpeHeaderSize > len) continue;
        if (readU32BE(data + tag.offset) != kMpeType) continue;

        uint32_t nProcElements = readU32BE(data + tag.offset + 12);
        uint64_t requiredTableBytes =
            (uint64_t)kMpeHeaderSize + (uint64_t)nProcElements * 8ull;

        if (requiredTableBytes > tag.size) {
            RawMpePositionIssue issue;
            issue.tagSig = tag.signature;
            issue.tagSize = tag.size;
            issue.procElementCount = nProcElements;
            issue.positionTableTruncated = true;
            issues.push_back(issue);
            if (issues.size() >= maxIssues) return issues;
        }

        uint64_t availableSlots64 = tag.size > kMpeHeaderSize
            ? ((uint64_t)tag.size - kMpeHeaderSize) / 8ull
            : 0ull;
        uint32_t scanCount = nProcElements;
        if ((uint64_t)scanCount > availableSlots64) {
            scanCount = static_cast<uint32_t>(availableSlots64);
        }
        if (scanCount > 4096u) scanCount = 4096u;

        for (uint32_t i = 0; i < scanCount; ++i) {
            size_t posOff = static_cast<size_t>(tag.offset) + kMpeHeaderSize + (size_t)i * 8u;
            if (posOff + 8 > len) break;

            uint32_t elemOff = readU32BE(data + posOff);
            uint32_t elemSize = readU32BE(data + posOff + 4);
            uint64_t sum64 = (uint64_t)elemOff + (uint64_t)elemSize;
            bool wrap = sum64 > 0xFFFFFFFFull;
            bool beyondTag = sum64 > tag.size;
            if (!wrap && !beyondTag) continue;

            RawMpePositionIssue issue;
            issue.tagSig = tag.signature;
            issue.tagSize = tag.size;
            issue.procElementCount = nProcElements;
            issue.entryIndex = i;
            issue.elementOffset = elemOff;
            issue.elementSize = elemSize;
            issue.offsetSizeWrap = wrap;
            issue.exceedsTagSize = beyondTag;
            if ((uint64_t)elemOff + 4ull <= tag.size &&
                (uint64_t)tag.offset + elemOff + 4ull <= len) {
                issue.elementSig = readU32BE(data + tag.offset + elemOff);
            }
            issues.push_back(issue);
            if (issues.size() >= maxIssues) return issues;
        }
    }

    return issues;
}

inline bool rawHasGbdQuarantineSignature(const ProfileView& pv) {
    const uint8_t* raw = pv.rawData();
    size_t len = pv.rawSize();
    if (!raw || len < 132) {
        return false;
    }

    auto riskyGbdRecord = [&](size_t off, size_t sz) {
        if (sz < 20 || off > len || len - off < 20) {
            return false;
        }
        if (readU32BE(raw + off) != 0x67626420u) {  // 'gbd '
            return false;
        }
        uint16_t pcs = readU16BE(raw + off + 8);
        uint16_t dev = readU16BE(raw + off + 10);
        uint32_t tri = readU32BE(raw + off + 16);
        return pcs > 0x7FFFu || dev > 0x7FFFu || tri > 715827882u;
    };

    for (const auto& tag : pv.rawTagTable()) {
        if (riskyGbdRecord(tag.offset, tag.size)) {
            return true;
        }

        if (tag.size < 16 || tag.offset > len || len - tag.offset < 16) {
            continue;
        }
        if (readU32BE(raw + tag.offset) != 0x74617279u) {  // 'tary'
            continue;
        }

        uint32_t elemCount = readU32BE(raw + tag.offset + 12);
        if (elemCount == 0 || elemCount > 256) {
            continue;
        }
        uint64_t tableEnd = static_cast<uint64_t>(tag.offset) + 16ull +
                            static_cast<uint64_t>(elemCount) * 8ull;
        uint64_t ownerEnd = static_cast<uint64_t>(tag.offset) +
                            static_cast<uint64_t>(tag.size);
        if (tableEnd > len || tableEnd > ownerEnd) {
            continue;
        }

        for (uint32_t i = 0; i < elemCount; ++i) {
            size_t recOff = tag.offset + 16 + static_cast<size_t>(i) * 8;
            uint32_t childOff = readU32BE(raw + recOff);
            uint32_t childSz = readU32BE(raw + recOff + 4);
            if (!childOff || childSz < 20) {
                continue;
            }
            uint64_t childAbs = static_cast<uint64_t>(tag.offset) +
                                static_cast<uint64_t>(childOff);
            if (childAbs + 20 > len || childAbs + childSz > ownerEnd) {
                continue;
            }
            if (riskyGbdRecord(static_cast<size_t>(childAbs), childSz)) {
                return true;
            }
        }
    }

    return false;
}

enum class RawMpeNullApplyIssueKind : uint8_t {
    MissingClutWithActiveCurves,
    ZeroChannelMpe,
};

struct RawMpeNullApplyIssue {
    RawMpeNullApplyIssueKind kind = RawMpeNullApplyIssueKind::MissingClutWithActiveCurves;
    uint32_t tagSig = 0;
    uint32_t typeSig = 0;
    uint16_t inputChannels = 0;
    uint16_t outputChannels = 0;
    uint32_t clutOffset = 0;
    uint32_t bCurveOffset = 0;
    uint32_t aCurveOffset = 0;
    uint32_t procElementCount = 0;
};

inline const char* mpeTypeName(uint32_t sig) {
    switch (sig) {
        case 0x6D414220u: return "mAB";
        case 0x6D424120u: return "mBA";
        case 0x6D706574u: return "MPET";
        default: return "MPE";
    }
}

inline std::string formatRawMpeNullApplyIssue(const RawMpeNullApplyIssue& issue) {
    if (issue.kind == RawMpeNullApplyIssueKind::MissingClutWithActiveCurves) {
        return sfmt("HEURISTIC: Tag '%s' (%s) has %u→%u channels with CLUT offset=0 but active curves — "
                    "m_pCLUT will be NULL in Apply() — ICC.1-2022-05 §10.10",
                    sigStr(issue.tagSig).c_str(),
                    mpeTypeName(issue.typeSig),
                    static_cast<unsigned>(issue.inputChannels),
                    static_cast<unsigned>(issue.outputChannels));
    }

    return sfmt("HEURISTIC: Tag '%s' MPET has %u elements with %u→%u channels — "
                "zero channels create null internal state in Begin() — ICC.2-2023 §10.14",
                sigStr(issue.tagSig).c_str(),
                issue.procElementCount,
                static_cast<unsigned>(issue.inputChannels),
                static_cast<unsigned>(issue.outputChannels));
}

inline std::string mpeNullApplyIssueCweNote(const RawMpeNullApplyIssue& issue) {
    if (issue.kind == RawMpeNullApplyIssueKind::MissingClutWithActiveCurves) {
        return "CWE-476: IccMpeBasic.cpp:5712 — m_pCLUT->InterpNd() null deref";
    }
    return "CWE-476: CIccMpeCurveSet::Begin() returns false → Apply() null deref";
}

inline std::vector<RawMpeNullApplyIssue>
scanRawMpeNullApplyIssues(const ProfileView& pv, size_t maxIssues = 8) {
    std::vector<RawMpeNullApplyIssue> issues;
    const uint8_t* data = pv.rawData();
    size_t len = pv.rawSize();
    if (!data || len < 16) return issues;

    constexpr uint32_t kMabType = 0x6D414220u;  // 'mAB '
    constexpr uint32_t kMbaType = 0x6D424120u;  // 'mBA '
    constexpr uint32_t kMpetType = 0x6D706574u; // 'mpet'

    for (const auto& tag : pv.rawTagTable()) {
        if (issues.size() >= maxIssues) break;
        if (tag.size < 8 || static_cast<uint64_t>(tag.offset) + 8 > len) continue;

        uint32_t type = readU32BE(data + tag.offset);

        if ((type == kMabType || type == kMbaType) &&
            tag.size >= 32 &&
            static_cast<uint64_t>(tag.offset) + 32 <= len) {
            const uint8_t* mabHdr = data + tag.offset + 8;

            RawMpeNullApplyIssue issue;
            issue.kind = RawMpeNullApplyIssueKind::MissingClutWithActiveCurves;
            issue.tagSig = tag.signature;
            issue.typeSig = type;
            issue.inputChannels = mabHdr[0];
            issue.outputChannels = mabHdr[1];
            issue.bCurveOffset = readU32BE(mabHdr + 4);
            issue.clutOffset = readU32BE(mabHdr + 20);

            if (tag.size >= 40 &&
                static_cast<uint64_t>(tag.offset) + 40 <= len) {
                issue.aCurveOffset = readU32BE(data + tag.offset + 36);
            }

            if (issue.clutOffset == 0 &&
                issue.inputChannels > 0 &&
                issue.outputChannels > 0 &&
                (issue.bCurveOffset != 0 || issue.aCurveOffset != 0)) {
                issues.push_back(issue);
                if (issues.size() >= maxIssues) return issues;
            }
            continue;
        }

        if (type == kMpetType &&
            tag.size >= 16 &&
            static_cast<uint64_t>(tag.offset) + 16 <= len) {
            const uint8_t* mpetHdr = data + tag.offset + 8;
            uint16_t nInputCh = static_cast<uint16_t>(mpetHdr[0]) << 8 | mpetHdr[1];
            uint16_t nOutputCh = static_cast<uint16_t>(mpetHdr[2]) << 8 | mpetHdr[3];
            uint32_t nElements = readU32BE(mpetHdr + 4);

            if ((nInputCh == 0 || nOutputCh == 0) && nElements > 0) {
                RawMpeNullApplyIssue issue;
                issue.kind = RawMpeNullApplyIssueKind::ZeroChannelMpe;
                issue.tagSig = tag.signature;
                issue.typeSig = type;
                issue.inputChannels = nInputCh;
                issue.outputChannels = nOutputCh;
                issue.procElementCount = nElements;
                issues.push_back(issue);
                if (issues.size() >= maxIssues) return issues;
            }
        }
    }

    return issues;
}

enum class RawCurveElementIssueKind : uint8_t {
    OversizedSampleCount,
    SegmentedCurveTruncation,
};

struct RawCurveElementIssue {
    RawCurveElementIssueKind kind = RawCurveElementIssueKind::OversizedSampleCount;
    uint32_t elementSig = 0;
    uint64_t fileOffset = 0;
    uint32_t count = 0;
    uint64_t allocBytes = 0;
    uint64_t requiredBytes = 0;
    uint64_t remainingBytes = 0;
};

inline const char* curveElementName(uint32_t sig) {
    switch (sig) {
        case 0x736E6766u: return "SingleSampledCurve";      // 'sngf'
        case 0x73616D66u: return "SampledCurveSegment";     // 'samf'
        case 0x636C6366u: return "SampledCalculatorCurve";  // 'clcf'
        case 0x63757266u: return "SegmentedCurve";          // 'curf'
        default: return "CurveElement";
    }
}

inline const char* curveElementFixRef(const RawCurveElementIssue& issue) {
    switch (issue.elementSig) {
        case 0x736E6766u: return "IccMpeBasic.cpp:1638, CFL-021";
        case 0x73616D66u: return "IccMpeBasic.cpp:1070";
        case 0x636C6366u: return "IccMpeBasic.cpp:2446";
        case 0x63757266u: return "IccMpeBasic.cpp:2779, CFL-064";
        default: return "iccDEV sampled-curve parsing path";
    }
}

inline std::string formatRawCurveElementIssue(const RawCurveElementIssue& issue) {
    if (issue.kind == RawCurveElementIssueKind::SegmentedCurveTruncation) {
        return sfmt("SegmentedCurve at offset 0x%llX: nSegments=%u needs %llu bytes minimum, only %llu available",
                    static_cast<unsigned long long>(issue.fileOffset),
                    static_cast<unsigned>(issue.count),
                    static_cast<unsigned long long>(issue.requiredBytes),
                    static_cast<unsigned long long>(issue.remainingBytes));
    }

    return sfmt("%s at offset 0x%llX: nCount=%u -> %.1f GB allocation (file has %llu bytes remaining)",
                curveElementName(issue.elementSig),
                static_cast<unsigned long long>(issue.fileOffset),
                static_cast<unsigned>(issue.count),
                static_cast<double>(issue.allocBytes) / (1024.0 * 1024.0 * 1024.0),
                static_cast<unsigned long long>(issue.remainingBytes));
}

inline std::string curveElementIssueCweNote(const RawCurveElementIssue& issue) {
    if (issue.kind == RawCurveElementIssueKind::SegmentedCurveTruncation) {
        return sfmt("CWE-191: Unsigned underflow in CIccSegmentedCurve::Read() "
                    "size-(pos-startPos) at %s",
                    curveElementFixRef(issue));
    }

    return sfmt("CWE-770: Allocation without limits — OOM abort (%s)",
                curveElementFixRef(issue));
}

inline std::vector<RawCurveElementIssue>
scanRawCurveElementIssues(const ProfileView& pv, size_t maxIssues = 8) {
    std::vector<RawCurveElementIssue> issues;
    const uint8_t* data = pv.rawData();
    size_t len = pv.rawSize();
    if (!data || len < 12) return issues;

    for (size_t off = 0; off + 11 < len; ++off) {
        uint32_t sig = readU32BE(data + off);

        if (sig == 0x63757266u) { // 'curf'
            uint16_t nSeg = readU16BE(data + off + 8);
            if (!nSeg) continue;

            uint64_t bpBytes = nSeg > 1 ? (static_cast<uint64_t>(nSeg) - 1ull) * 4ull : 0ull;
            uint64_t segMin = static_cast<uint64_t>(nSeg) * 12ull;
            uint64_t totalMin = 12ull + bpBytes + segMin;
            uint64_t remaining = static_cast<uint64_t>(len) - static_cast<uint64_t>(off);
            if (totalMin > remaining) {
                RawCurveElementIssue issue;
                issue.kind = RawCurveElementIssueKind::SegmentedCurveTruncation;
                issue.elementSig = sig;
                issue.fileOffset = off;
                issue.count = nSeg;
                issue.requiredBytes = totalMin;
                issue.remainingBytes = remaining;
                issues.push_back(issue);
                if (issues.size() >= maxIssues) return issues;
            }
            continue;
        }

        if (sig != 0x736E6766u && // 'sngf'
            sig != 0x73616D66u && // 'samf'
            sig != 0x636C6366u) { // 'clcf'
            continue;
        }

        uint32_t nCount = readU32BE(data + off + 8);
        uint64_t allocBytes = static_cast<uint64_t>(nCount) * 4ull;
        uint64_t remaining = static_cast<uint64_t>(len) - static_cast<uint64_t>(off) - 12ull;
        if (allocBytes > 256ull * 1024ull * 1024ull ||
            allocBytes > remaining * 64ull) {
            RawCurveElementIssue issue;
            issue.kind = RawCurveElementIssueKind::OversizedSampleCount;
            issue.elementSig = sig;
            issue.fileOffset = off;
            issue.count = nCount;
            issue.allocBytes = allocBytes;
            issue.remainingBytes = remaining;
            issues.push_back(issue);
            if (issues.size() >= maxIssues) return issues;
        }
    }

    return issues;
}

enum class RawSpectralMpeIssueKind : uint8_t {
    MatrixZeroChannels,
    MatrixExcessiveChannels,
    DescribeRowOverflow,
    DescribeStrideMismatch,
    MatrixPayloadTooShort,
    ClutZeroChannels,
    ObserverZeroChannels,
};

struct RawSpectralMpeIssue {
    RawSpectralMpeIssueKind kind = RawSpectralMpeIssueKind::MatrixZeroChannels;
    uint32_t tagSig = 0;
    uint32_t elemSig = 0;
    uint32_t entryIndex = 0;
    uint32_t elementOffset = 0;
    uint32_t elementSize = 0;
    uint16_t inputChannels = 0;
    uint16_t outputChannels = 0;
    uint16_t steps = 0;
    uint64_t minPayloadBytes = 0;
};

struct RawSpectralMpeScanResult {
    uint32_t spectralElementCount = 0;
    std::vector<RawSpectralMpeIssue> issues;
};

inline bool rawRangeAccessible(uint64_t totalSize, uint64_t offset, uint64_t need) {
    return offset <= totalSize && need <= (totalSize - offset);
}

struct RawGbdRecord {
    uint32_t ownerSig = 0;
    bool nestedInTagArray = false;
    uint32_t logicalSize = 0;
    bool headerAccessible = false;
    uint16_t pcsChannels = 0;
    uint16_t deviceChannels = 0;
    uint32_t vertices = 0;
    uint32_t triangles = 0;
};

inline std::string rawGbdOwnerName(const RawGbdRecord& record) {
    if (record.nestedInTagArray) {
        return sfmt("%s[tary]", sigStr(record.ownerSig).c_str());
    }
    return sigStr(record.ownerSig);
}

inline std::vector<RawGbdRecord>
scanRawGbdRecords(const ProfileView& pv, size_t maxRecords = 16) {
    std::vector<RawGbdRecord> records;
    const uint8_t* data = pv.rawData();
    size_t len = pv.rawSize();
    if (!data || len < 16) return records;

    constexpr uint32_t kGbdType = 0x67626420u;      // 'gbd '
    constexpr uint32_t kTagArrayType = 0x74617279u; // 'tary'

    auto push_record = [&](const RawGbdRecord& record) {
        if (records.size() < maxRecords) {
            records.push_back(record);
        }
    };

    for (const auto& tag : pv.rawTagTable()) {
        uint64_t tagStart = static_cast<uint64_t>(tag.offset);
        uint64_t tagSize = static_cast<uint64_t>(tag.size);
        if (!rawRangeAccessible(len, tagStart, 4)) continue;

        uint32_t typeSig = readU32BE(data + tag.offset);
        if (typeSig == kGbdType) {
            RawGbdRecord record;
            record.ownerSig = tag.signature;
            record.logicalSize = tag.size;
            if (tag.size >= 20 && rawRangeAccessible(len, tagStart, 20)) {
                record.headerAccessible = true;
                record.pcsChannels = readU16BE(data + tag.offset + 8);
                record.deviceChannels = readU16BE(data + tag.offset + 10);
                record.vertices = readU32BE(data + tag.offset + 12);
                record.triangles = readU32BE(data + tag.offset + 16);
            }
            push_record(record);
            continue;
        }

        if (typeSig != kTagArrayType || tag.size < 16 ||
            !rawRangeAccessible(len, tagStart, 16)) {
            continue;
        }

        uint32_t elemCount = readU32BE(data + tag.offset + 12);
        if (elemCount == 0 || elemCount > 256) continue;

        uint64_t ownerEnd = tagStart + tagSize;
        uint64_t tableEnd = tagStart + 16ull + static_cast<uint64_t>(elemCount) * 8ull;
        if (tableEnd > len || tableEnd > ownerEnd) continue;

        for (uint32_t i = 0; i < elemCount; ++i) {
            uint64_t recOff = tagStart + 16ull + static_cast<uint64_t>(i) * 8ull;
            if (!rawRangeAccessible(len, recOff, 8) || recOff + 8 > ownerEnd) break;

            uint32_t childOff = readU32BE(data + recOff);
            uint32_t childSz = readU32BE(data + recOff + 4);
            if (!childOff || childSz < 4) continue;

            uint64_t childAbs = tagStart + static_cast<uint64_t>(childOff);
            if (!rawRangeAccessible(len, childAbs, 4) || childAbs + childSz > ownerEnd) continue;
            if (readU32BE(data + childAbs) != kGbdType) continue;

            RawGbdRecord record;
            record.ownerSig = tag.signature;
            record.nestedInTagArray = true;
            record.logicalSize = childSz;
            if (childSz >= 20 && rawRangeAccessible(len, childAbs, 20)) {
                record.headerAccessible = true;
                record.pcsChannels = readU16BE(data + childAbs + 8);
                record.deviceChannels = readU16BE(data + childAbs + 10);
                record.vertices = readU32BE(data + childAbs + 12);
                record.triangles = readU32BE(data + childAbs + 16);
            }
            push_record(record);
        }
    }

    return records;
}

inline const char* spectralElementName(uint32_t sig) {
    switch (sig) {
        case 0x656d7478u: return "EmissionMatrix";    // 'emtx'
        case 0x69656d78u: return "InvEmissionMatrix"; // 'iemx'
        case 0x65636c74u: return "EmissionCLUT";      // 'eclt'
        case 0x72636c74u: return "ReflectanceCLUT";   // 'rclt'
        case 0x656f6273u: return "EmissionObserver";  // 'eobs'
        case 0x726f6273u: return "ReflectanceObserver"; // 'robs'
        default: return "SpectralElement";
    }
}

inline std::string formatRawSpectralMpeIssue(const RawSpectralMpeIssue& issue) {
    switch (issue.kind) {
        case RawSpectralMpeIssueKind::MatrixZeroChannels:
            return sfmt("HEURISTIC: %s in tag '%s' entry %u has zero channels (in=%u, out=%u) — ICC.2-2023 §10.2.4",
                        spectralElementName(issue.elemSig),
                        sigStr(issue.tagSig).c_str(),
                        issue.entryIndex,
                        static_cast<unsigned>(issue.inputChannels),
                        static_cast<unsigned>(issue.outputChannels));
        case RawSpectralMpeIssueKind::MatrixExcessiveChannels:
            return sfmt("HEURISTIC: %s in tag '%s' entry %u uses excessive channels (in=%u, out=%u) — ICC.2-2023 §10.2.4",
                        spectralElementName(issue.elemSig),
                        sigStr(issue.tagSig).c_str(),
                        issue.entryIndex,
                        static_cast<unsigned>(issue.inputChannels),
                        static_cast<unsigned>(issue.outputChannels));
        case RawSpectralMpeIssueKind::DescribeRowOverflow:
            return sfmt("HEURISTIC: EmissionMatrix out(%u) > in(%u) — Describe() iterates %u rows but allocation has %u — ICC.2-2023 §10.2.4",
                        static_cast<unsigned>(issue.outputChannels),
                        static_cast<unsigned>(issue.inputChannels),
                        static_cast<unsigned>(issue.outputChannels),
                        static_cast<unsigned>(issue.inputChannels));
        case RawSpectralMpeIssueKind::DescribeStrideMismatch:
            return sfmt("HEURISTIC: SpectralMatrix in(%u) != steps(%u) — Describe() pointer advance mismatch — ICC.2-2023 §10.2.4",
                        static_cast<unsigned>(issue.inputChannels),
                        static_cast<unsigned>(issue.steps));
        case RawSpectralMpeIssueKind::MatrixPayloadTooShort:
            return sfmt("HEURISTIC: %s in tag '%s' entry %u is truncated: size=%u, need>=%llu for white+matrix payload — ICC.2-2023 §10.2.4",
                        spectralElementName(issue.elemSig),
                        sigStr(issue.tagSig).c_str(),
                        issue.entryIndex,
                        issue.elementSize,
                        static_cast<unsigned long long>(issue.minPayloadBytes));
        case RawSpectralMpeIssueKind::ClutZeroChannels:
            return sfmt("HEURISTIC: %s in tag '%s' entry %u has zero channels (in=%u, out=%u) — ICC.2-2023 §10.2.5",
                        spectralElementName(issue.elemSig),
                        sigStr(issue.tagSig).c_str(),
                        issue.entryIndex,
                        static_cast<unsigned>(issue.inputChannels),
                        static_cast<unsigned>(issue.outputChannels));
        case RawSpectralMpeIssueKind::ObserverZeroChannels:
            return sfmt("HEURISTIC: %s in tag '%s' entry %u has zero channels (in=%u, out=%u) — ICC.2-2023 §10.2.6",
                        spectralElementName(issue.elemSig),
                        sigStr(issue.tagSig).c_str(),
                        issue.entryIndex,
                        static_cast<unsigned>(issue.inputChannels),
                        static_cast<unsigned>(issue.outputChannels));
    }

    return sfmt("HEURISTIC: spectral MPE issue in tag '%s' entry %u",
                sigStr(issue.tagSig).c_str(),
                issue.entryIndex);
}

inline std::string spectralMpeIssueCweNote(const RawSpectralMpeIssue& issue) {
    switch (issue.kind) {
        case RawSpectralMpeIssueKind::DescribeRowOverflow:
            return "CWE-122: Heap-based Buffer Overflow in CIccMpeSpectralMatrix::Describe() (CFL-006)";
        case RawSpectralMpeIssueKind::DescribeStrideMismatch:
            return "CWE-125: Out-of-bounds Read via spectral matrix pointer drift in Describe()";
        case RawSpectralMpeIssueKind::MatrixPayloadTooShort:
            return "CWE-476: Spectral Describe() null/short-read guard required after truncated payload (CFL-056)";
        case RawSpectralMpeIssueKind::MatrixZeroChannels:
        case RawSpectralMpeIssueKind::MatrixExcessiveChannels:
        case RawSpectralMpeIssueKind::ClutZeroChannels:
        case RawSpectralMpeIssueKind::ObserverZeroChannels:
            return "CWE-682: Incorrect Calculation / invalid spectral element channel topology";
    }

    return {};
}

inline RawSpectralMpeScanResult
scanRawSpectralMpeIssues(const ProfileView& pv, size_t maxIssues = 8) {
    RawSpectralMpeScanResult result;
    const uint8_t* data = pv.rawData();
    size_t len = pv.rawSize();
    if (!data || len < 16) return result;

    constexpr uint32_t kMpeType = 0x6D706574u; // 'mpet'
    constexpr uint32_t kMpeHeaderSize = 16u;
    constexpr uint32_t kPositionSize = 8u;
    constexpr uint32_t kEmissionMatrix = 0x656d7478u;    // 'emtx'
    constexpr uint32_t kInvEmissionMatrix = 0x69656d78u; // 'iemx'
    constexpr uint32_t kEmissionClut = 0x65636c74u;      // 'eclt'
    constexpr uint32_t kReflectanceClut = 0x72636c74u;   // 'rclt'
    constexpr uint32_t kEmissionObserver = 0x656f6273u;  // 'eobs'
    constexpr uint32_t kReflectanceObserver = 0x726f6273u; // 'robs'
    constexpr uint32_t kSpectralMatrixHeaderSize = 20u;
    constexpr uint32_t kSpectralClutHeaderSize = 36u;
    constexpr uint32_t kSpectralObserverHeaderSize = 20u;

    auto push_issue = [&](const RawSpectralMpeIssue& issue) {
        if (result.issues.size() < maxIssues) {
            result.issues.push_back(issue);
        }
    };

    for (const auto& tag : pv.rawTagTable()) {
        uint64_t tagStart = static_cast<uint64_t>(tag.offset);
        uint64_t tagSize = static_cast<uint64_t>(tag.size);
        if (tagSize < kMpeHeaderSize) continue;
        if (!rawRangeAccessible(len, tagStart, kMpeHeaderSize)) continue;
        if (readU32BE(data + tag.offset) != kMpeType) continue;

        uint32_t nElements = readU32BE(data + tag.offset + 12);
        uint64_t availableSlots = tagSize > kMpeHeaderSize
            ? (tagSize - kMpeHeaderSize) / kPositionSize
            : 0ull;
        uint32_t scanCount = nElements;
        if (static_cast<uint64_t>(scanCount) > availableSlots) {
            scanCount = static_cast<uint32_t>(availableSlots);
        }
        if (scanCount > 4096u) scanCount = 4096u;

        for (uint32_t i = 0; i < scanCount; ++i) {
            uint64_t posOff = tagStart + kMpeHeaderSize + static_cast<uint64_t>(i) * kPositionSize;
            if (!rawRangeAccessible(len, posOff, kPositionSize)) break;

            uint32_t elemOff = readU32BE(data + posOff);
            uint32_t elemSize = readU32BE(data + posOff + 4);
            uint64_t elemEnd = static_cast<uint64_t>(elemOff) + static_cast<uint64_t>(elemSize);
            if (elemEnd > tagSize || elemEnd < elemOff) continue;

            uint64_t elemFileOff = tagStart + static_cast<uint64_t>(elemOff);
            if (!rawRangeAccessible(len, elemFileOff, 4)) continue;
            uint32_t elemSig = readU32BE(data + elemFileOff);

            bool isSpectralMatrix = elemSig == kEmissionMatrix || elemSig == kInvEmissionMatrix;
            bool isSpectralClut = elemSig == kEmissionClut || elemSig == kReflectanceClut;
            bool isSpectralObserver = elemSig == kEmissionObserver || elemSig == kReflectanceObserver;
            if (!isSpectralMatrix && !isSpectralClut && !isSpectralObserver) {
                continue;
            }

            result.spectralElementCount++;

            if (isSpectralMatrix) {
                if (!rawRangeAccessible(len, elemFileOff, kSpectralMatrixHeaderSize)) continue;

                uint16_t inCh = readU16BE(data + elemFileOff + 8);
                uint16_t outCh = readU16BE(data + elemFileOff + 10);
                uint16_t steps = readU16BE(data + elemFileOff + 16);

                if (inCh == 0 || outCh == 0) {
                    push_issue({RawSpectralMpeIssueKind::MatrixZeroChannels, tag.signature, elemSig,
                                i, elemOff, elemSize, inCh, outCh, steps, 0});
                }
                if (inCh > 256 || outCh > 256) {
                    push_issue({RawSpectralMpeIssueKind::MatrixExcessiveChannels, tag.signature, elemSig,
                                i, elemOff, elemSize, inCh, outCh, steps, 0});
                }
                if (elemSig == kEmissionMatrix && outCh > inCh) {
                    push_issue({RawSpectralMpeIssueKind::DescribeRowOverflow, tag.signature, elemSig,
                                i, elemOff, elemSize, inCh, outCh, steps, 0});
                }
                if (inCh != steps) {
                    push_issue({RawSpectralMpeIssueKind::DescribeStrideMismatch, tag.signature, elemSig,
                                i, elemOff, elemSize, inCh, outCh, steps, 0});
                }

                uint16_t numVectors = elemSig == kEmissionMatrix ? inCh : outCh;
                uint64_t minPayload = static_cast<uint64_t>(kSpectralMatrixHeaderSize) +
                    static_cast<uint64_t>(steps) * 4ull +
                    static_cast<uint64_t>(numVectors) * static_cast<uint64_t>(steps) * 4ull;
                if (elemSize < minPayload) {
                    push_issue({RawSpectralMpeIssueKind::MatrixPayloadTooShort, tag.signature, elemSig,
                                i, elemOff, elemSize, inCh, outCh, steps, minPayload});
                }
                continue;
            }

            if (isSpectralClut) {
                if (!rawRangeAccessible(len, elemFileOff, kSpectralClutHeaderSize)) continue;
                uint16_t inCh = readU16BE(data + elemFileOff + 8);
                uint16_t outCh = readU16BE(data + elemFileOff + 10);
                uint16_t steps = readU16BE(data + elemFileOff + 18);
                if (inCh == 0 || outCh == 0) {
                    push_issue({RawSpectralMpeIssueKind::ClutZeroChannels, tag.signature, elemSig,
                                i, elemOff, elemSize, inCh, outCh, steps, 0});
                }
                continue;
            }

            if (isSpectralObserver) {
                if (!rawRangeAccessible(len, elemFileOff, kSpectralObserverHeaderSize)) continue;
                uint16_t inCh = readU16BE(data + elemFileOff + 8);
                uint16_t outCh = readU16BE(data + elemFileOff + 10);
                uint16_t steps = readU16BE(data + elemFileOff + 16);
                if (inCh == 0 || outCh == 0) {
                    push_issue({RawSpectralMpeIssueKind::ObserverZeroChannels, tag.signature, elemSig,
                                i, elemOff, elemSize, inCh, outCh, steps, 0});
                }
            }
        }
    }

    return result;
}

// ── Signature constants ──

constexpr uint32_t kIccMagic = 0x61637370; // 'acsp'

// Profile classes
constexpr uint32_t kClassInput       = 0x73636E72; // 'scnr'
constexpr uint32_t kClassDisplay     = 0x6D6E7472; // 'mntr'
constexpr uint32_t kClassOutput      = 0x70727472; // 'prtr'
constexpr uint32_t kClassLink        = 0x6C696E6B; // 'link'
constexpr uint32_t kClassColorSpace  = 0x73706163; // 'spac'
constexpr uint32_t kClassAbstract    = 0x61627374; // 'abst'
constexpr uint32_t kClassNamedColor  = 0x6E6D636C; // 'nmcl'
constexpr uint32_t kClassColorEncoding = 0x63656E63; // 'cenc'

// Common tag signatures
constexpr uint32_t kSigDesc   = 0x64657363; // 'desc'
constexpr uint32_t kSigWtpt   = 0x77747074; // 'wtpt'
constexpr uint32_t kSigCprt   = 0x63707274; // 'cprt'
constexpr uint32_t kSigRfnm   = 0x72666E6D; // 'rfnm'
constexpr uint32_t kSigChad   = 0x63686164; // 'chad'
constexpr uint32_t kSigAToB0  = 0x41324230; // 'A2B0'
constexpr uint32_t kSigBToA0  = 0x42324130; // 'B2A0'

// D50 illuminant values (s15Fixed16)
constexpr int32_t kD50X = 0x0000F6D6; //  0.9642
constexpr int32_t kD50Y = 0x00010000; //  1.0000
constexpr int32_t kD50Z = 0x0000D32D; //  0.8249

// ── CheckResult builder ──

/// Helper to build CheckResult with accumulated findings.
class CheckBuilder {
public:
    void warn(std::string message) {
        m_findings.push_back(makeFinding(Severity::MEDIUM, std::move(message)));
    }
    void warn(std::string message, std::string cwe) {
        m_findings.push_back(makeFinding(Severity::MEDIUM, std::move(message), std::move(cwe)));
    }
    void high(std::string message) {
        m_findings.push_back(makeFinding(Severity::HIGH, std::move(message)));
    }
    void high(std::string message, std::string cwe) {
        m_findings.push_back(makeFinding(Severity::HIGH, std::move(message), std::move(cwe)));
    }
    void critical(std::string message) {
        m_findings.push_back(makeFinding(Severity::CRITICAL, std::move(message)));
    }
    void critical(std::string message, std::string cwe) {
        m_findings.push_back(makeFinding(Severity::CRITICAL, std::move(message), std::move(cwe)));
    }
    void info(std::string message) {
        m_findings.push_back(makeFinding(Severity::INFO, std::move(message)));
    }

    CheckResult done(std::string okSummary) {
        if (m_findings.empty()) return CheckResult::ok(std::move(okSummary));
        CheckResult r;
        r.status = CheckResult::Status::FINDINGS;
        r.summary = sfmt("%d issue(s)", static_cast<int>(m_findings.size()));
        r.findings = std::move(m_findings);
        return r;
    }

    bool empty() const { return m_findings.empty(); }
    size_t count() const { return m_findings.size(); }

private:
    std::vector<Finding> m_findings;
};

} // namespace icctest

#endif // ICCTEST_CHECK_HELPERS_H
