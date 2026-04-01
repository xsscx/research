/*
 * IccTest Library - ComplianceChecks.cpp
 * Heuristic checks H103-H120: ICC specification compliance.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "util/CheckHelpers.h"

#include "IccProfile.h"
#include "IccPcc.h"
#include "IccTagBasic.h"
#include "IccTagLut.h"
#include "IccTagMPE.h"
#include "IccMpeBasic.h"
#include "IccMpeCalc.h"
#include "IccUtil.h"

#include <cmath>
#include <cstring>
#include <vector>

namespace icctest {

template<typename T>
static T* FindAndCast(CIccProfile* pIcc, icTagSignature sig) {
    if (!pIcc) return nullptr;
    CIccTag* tag = pIcc->FindTag(sig);
    if (!tag) return nullptr;
    return dynamic_cast<T*>(tag);
}

static bool rawTagEntryAccessible(const ProfileView& pv,
                                  const RawTagEntry& entry,
                                  uint32_t minSize = 8u) {
    return pv.rawData() &&
           entry.size >= minSize &&
           rawRangeAccessible(pv.rawSize(), entry.offset, entry.size) &&
           rawRangeAccessible(pv.rawSize(), entry.offset, minSize);
}

static std::optional<uint32_t> rawTagTypeSig(const ProfileView& pv, uint32_t sig) {
    auto entry = pv.rawTag(sig);
    if (!entry || !rawTagEntryAccessible(pv, *entry, 8u)) return std::nullopt;
    return readU32BE(pv.rawData() + entry->offset);
}

static bool rawDeclaredTagTableFits(const ProfileView& pv) {
    if (!pv.rawData() || pv.rawSize() < 132u) return false;
    uint32_t tagCount = readU32BE(pv.rawData() + 128);
    return 132ull + static_cast<uint64_t>(tagCount) * 12ull <= pv.rawSize();
}

static bool rawTagHeaderReadable(const ProfileView& pv, uint32_t sig, uint32_t minSize) {
    auto entry = pv.rawTag(sig);
    return entry && rawTagEntryAccessible(pv, *entry, minSize);
}

static bool rawTagPresentOnFallback(const ProfileView& pv, uint32_t sig) {
    return rawTagHeaderReadable(pv, sig, 8u);
}

static bool rawXyzTagUsable(const ProfileView& pv, uint32_t sig) {
    auto entry = pv.rawTag(sig);
    if (!entry || !rawTagEntryAccessible(pv, *entry, 20u)) return false;
    auto type = rawTagTypeSig(pv, sig);
    return type && *type == static_cast<uint32_t>(icSigXYZType);
}

static bool rawCurveTagUsable(const ProfileView& pv, uint32_t sig) {
    auto entry = pv.rawTag(sig);
    if (!entry || !rawTagEntryAccessible(pv, *entry, 12u)) return false;
    auto type = rawTagTypeSig(pv, sig);
    return type &&
           (*type == static_cast<uint32_t>(icSigCurveType) ||
            *type == static_cast<uint32_t>(icSigParametricCurveType));
}

static bool rawS15Fixed16ArrayTagUsable(const ProfileView& pv,
                                        uint32_t sig,
                                        uint32_t minPayloadBytes) {
    auto entry = pv.rawTag(sig);
    uint32_t minSize = 8u + minPayloadBytes;
    if (!entry || !rawTagEntryAccessible(pv, *entry, minSize)) return false;
    auto type = rawTagTypeSig(pv, sig);
    return type && *type == static_cast<uint32_t>(icSigS15Fixed16ArrayType);
}

static bool rawAToBTagUsableOnFallback(const ProfileView& pv, uint32_t sig) {
    auto entry = pv.rawTag(sig);
    if (!entry || !rawTagEntryAccessible(pv, *entry, 12u)) return false;

    auto type = rawTagTypeSig(pv, sig);
    if (!type) return false;

    switch (*type) {
        case icSigLut8Type:
        case icSigLut16Type:
            return entry->size >= 52u;

        case icSigLutAtoBType:
            return entry->size >= 32u;

        case icSigMultiProcessElementType:
            return false;

        default:
            return false;
    }
}

static CheckResult check_h110_class_tag_validation_raw_fallback(const ProfileView& pv) {
    constexpr uint32_t kMagicAcsp = 0x61637370u;
    const auto& hdr = pv.header();
    if (hdr.magic != kMagicAcsp) {
        return CheckResult::skip("Header magic invalid");
    }
    if (!rawDeclaredTagTableFits(pv) || pv.rawTagTable().empty()) {
        return CheckResult::skip("Raw tag table unavailable");
    }

    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    uint32_t profileClass = hdr.deviceClass;

    if (profileClass != kClassLink) {
        if (!rawTagHeaderReadable(pv, icSigProfileDescriptionTag, 24u)) {
            cb.warn("Missing required tag 'desc' for non-DeviceLink class");
        }
        if (!rawTagPresentOnFallback(pv, icSigCopyrightTag)) {
            cb.warn("Missing required tag 'cprt' for non-DeviceLink class");
        }
        if (!rawXyzTagUsable(pv, icSigMediaWhitePointTag)) {
            cb.warn("Missing required tag 'wtpt' for non-DeviceLink class");
        }
    }

    const char* className = "unknown";
    bool needsA2B = false;
    switch (profileClass) {
        case kClassInput:
            className = "Input (scnr)";
            needsA2B = true;
            break;
        case kClassDisplay:
            className = "Display (mntr)";
            needsA2B = true;
            break;
        case kClassOutput:
            className = "Output (prtr)";
            needsA2B = true;
            break;
        case kClassLink:
            className = "DeviceLink (link)";
            if (!rawAToBTagUsableOnFallback(pv, icSigAToB0Tag)) {
                cb.warn("DeviceLink missing required AToB0 tag");
            }
            if (!rawTagHeaderReadable(pv, icSigProfileDescriptionTag, 24u)) {
                cb.warn("DeviceLink missing required desc tag");
            }
            break;
        case kClassAbstract:
            className = "Abstract (abst)";
            needsA2B = true;
            break;
        case kClassColorSpace:
            className = "ColorSpace (spac)";
            needsA2B = true;
            break;
        case kClassNamedColor:
            className = "NamedColor (nmcl)";
            break;
        default:
            cb.warn(sfmt("Unknown profile class: 0x%08X", profileClass));
            break;
    }

    if (needsA2B && !rawAToBTagUsableOnFallback(pv, icSigAToB0Tag)) {
        bool hasRgbTrc = rawCurveTagUsable(pv, icSigRedTRCTag) &&
                         rawCurveTagUsable(pv, icSigGreenTRCTag) &&
                         rawCurveTagUsable(pv, icSigBlueTRCTag);
        if ((profileClass == kClassDisplay || profileClass == kClassInput) && hasRgbTrc) {
            // Legacy heuristic accepts Matrix/TRC here.
        } else if (profileClass == kClassInput &&
                   rawCurveTagUsable(pv, icSigGrayTRCTag)) {
            // Legacy heuristic accepts grayscale input here.
        } else {
            cb.warn(sfmt("Missing AToB0 tag (required for %s class)", className));
        }
    }

    if (profileClass != kClassLink) {
        if (hdr.pcs != icSigLabData && hdr.pcs != icSigXYZData) {
            if (hdr.pcs < 0x72300000u || hdr.pcs > 0x72FFFFFFu) {
                cb.warn(
                    sfmt("Non-DeviceLink PCS is not Lab/XYZ/spectral: 0x%08X", hdr.pcs),
                    "CWE-20: Invalid PCS for profile class");
            }
        }
    }

    if (profileClass != kClassLink &&
        rawXyzTagUsable(pv, icSigMediaWhitePointTag) &&
        !rawS15Fixed16ArrayTagUsable(pv, icSigChromaticAdaptationTag, 12u)) {
        auto wtpt = pv.rawTag(icSigMediaWhitePointTag);
        if (wtpt && wtpt->size >= 20u &&
            rawRangeAccessible(rawLen, wtpt->offset, 20u) &&
            raw) {
            const uint8_t* p = raw + wtpt->offset + 8;
            double wpX = readS15Fixed16(p);
            double wpY = readS15Fixed16(p + 4);
            double wpZ = readS15Fixed16(p + 8);
            if (std::fabs(wpX - 0.9642) > 0.01 ||
                std::fabs(wpY - 1.0) > 0.01 ||
                std::fabs(wpZ - 0.8249) > 0.01) {
                cb.warn(
                    "wtpt != D50 but 'chad' tag missing (ICC.1-2022-05 Annex G)",
                    "CWE-20: chromaticAdaptationTag required when adopted white != D50");
            }
        }
    }

    return cb.done("Profile class and required tags are consistent");
}

// -- H103: Profile ID (MD5) Validation --
static CheckResult check_h103_profile_id(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 100) return CheckResult::skip("File too small");
    const uint8_t* d = pv.rawData();

    // Profile ID is at bytes 84-99
    bool allZero = true;
    for (int i = 84; i < 100; i++) {
        if (d[i] != 0) { allZero = false; break; }
    }

    if (allZero) {
        cb.info("Profile ID is all zeros (not computed)");
    }
    // Full MD5 validation would require computing MD5 with zeroed fields

    return cb.done("Profile ID checked");
}

// -- H104: CMM Type Validation --
static CheckResult check_h104_cmm(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 8) return CheckResult::skip("File too small");
    const uint8_t* d = pv.rawData();
    uint32_t cmm = readU32BE(d + 4);

    if (cmm != 0) {
        // CMM type should be printable if non-zero
        bool printable = true;
        for (int i = 0; i < 4; i++) {
            uint8_t c = (cmm >> (24 - i*8)) & 0xFF;
            if (c != 0 && (c < 0x20 || c > 0x7E)) { printable = false; break; }
        }
        if (!printable) {
            cb.warn(sfmt("Non-printable CMM type 0x%08X", cmm));
        }
    }

    return cb.done("CMM type validated");
}

// -- H105: Data Color Space vs PCS Consistency --
static CheckResult check_h105_cs_pcs(const ProfileView& pv) {
    CheckBuilder cb;
    const auto& hdr = pv.header();

    // For DeviceLink, PCS must match output color space (not enforced here)
    // For non-DeviceLink, PCS must be XYZ or Lab
    if (hdr.deviceClass != kClassLink) {
        if (hdr.pcs != 0x58595A20 && hdr.pcs != 0x4C616220) {
            cb.high(sfmt("Non-DeviceLink profile has invalid PCS '%s'",
                          sigStr(hdr.pcs).c_str()),
                    "CWE-20: Improper Input Validation");
        }
    }

    return cb.done("ColorSpace/PCS consistency validated");
}

// -- H108: Encoding Validation --
static CheckResult check_h108_encoding(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 128) return CheckResult::skip("File too small");
    const uint8_t* d = pv.rawData();

    // Rendering intent upper 16 bits must be zero (bytes 66-67)
    uint16_t intentHi = readU16BE(d + 66);
    if (intentHi != 0) {
        cb.warn(sfmt("Rendering intent upper 16 bits = 0x%04X (must be 0)", intentHi));
    }

    return cb.done("Encoding validated");
}

// -- H111: Reserved Bytes (100-127) All Zeros --
static CheckResult check_h111_reserved_zeros(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 128) return CheckResult::skip("File too small");
    const uint8_t* d = pv.rawData();

    if (d[44] != 0 || d[45] != 0 || d[46] != 0 || d[47] != 0) {
        cb.warn(sfmt("Header bytes 44-47 non-zero: %02X %02X %02X %02X",
                     d[44], d[45], d[46], d[47]));
    }

    int nonZero = 0;
    for (int i = 100; i < 128; i++) {
        if (d[i] != 0) nonZero++;
    }

    if (nonZero > 0) {
        cb.warn("Header bytes 100-127 contain non-zero reserved data");
    }

    return cb.done("Reserved bytes validated");
}

// -- H112: D50 Illuminant Precision --
static CheckResult check_h112_d50_precision(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 80) return CheckResult::skip("File too small");
    const uint8_t* d = pv.rawData();

    // D50 at bytes 68-79 (3 x s15Fixed16Number)
    int32_t xi = readS32BE(d + 68);
    int32_t yi = readS32BE(d + 72);
    int32_t zi = readS32BE(d + 76);

    // Exact ICC D50 values
    if (xi != kD50X || yi != kD50Y || zi != kD50Z) {
        double x = xi / 65536.0, y = yi / 65536.0, z = zi / 65536.0;
        cb.warn(sfmt("D50 illuminant values (%.6f, %.6f, %.6f) differ from ICC spec "
                      "(0.9642, 1.0000, 0.8249)", x, y, z));
    }

    return cb.done("D50 precision validated");
}

// -- Registration --

REGISTER_HEURISTIC(103, "Profile ID Validation",
    "ICC.1-2022-05 Sec.7.2.18", "ICC.1-2022-05",
    "CWE-345", "", Severity::LOW, CheckPhase::LIBRARY, check_h103_profile_id);

REGISTER_HEURISTIC(104, "CMM Type Validation",
    "ICC.1-2022-05 Sec.7.2.3", "ICC.1-2022-05",
    "CWE-20", "", Severity::LOW, CheckPhase::HEADER, check_h104_cmm);

REGISTER_HEURISTIC(105, "ColorSpace/PCS Consistency",
    "ICC.1-2022-05 Sec.7.2.6-7", "ICC.1-2022-05",
    "CWE-20", "", Severity::HIGH, CheckPhase::HEADER, check_h105_cs_pcs);

REGISTER_HEURISTIC(108, "Encoding Validation",
    "ICC.1-2022-05 Sec.7.2.15", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::HEADER, check_h108_encoding);

REGISTER_HEURISTIC(111, "Reserved Bytes",
    "ICC.1-2022-05 Sec.7.2.19", "ICC.1-2022-05",
    "CWE-20", "", Severity::LOW, CheckPhase::HEADER, check_h111_reserved_zeros);

REGISTER_HEURISTIC(112, "D50 Illuminant Precision",
    "ICC.1-2022-05 Sec.7.2.16", "ICC.1-2022-05",
    "CWE-682", "", Severity::MEDIUM, CheckPhase::HEADER, check_h112_d50_precision);


// -- Additional registrations for ComplianceChecks --

static CheckResult check_h106_env_var(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return CheckResult::ok("NOT RUN: Profile failed to load");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::ok("NOT RUN: Profile failed to load");

    CIccTag* pCustomToStd = p->FindTag(static_cast<icTagSignature>(0x63327370)); // 'c2sp'
    CIccTag* pStdToCustom = p->FindTag(static_cast<icTagSignature>(0x73326370)); // 's2cp'
    (void)pCustomToStd;
    (void)pStdToCustom;

    const CIccTagSpectralViewingConditions* pSvc = p->getPccViewingConditions();
    if (pSvc) {
        icSpectralRange illumRange = {};
        const icFloatNumber* pIllumData = pSvc->getIlluminant(illumRange);
        if (illumRange.steps > 0 && pIllumData) {
            icFloatNumber startNm = safeF16ToF(illumRange.start);
            icFloatNumber endNm = safeF16ToF(illumRange.end);
            if (startNm >= endNm) {
                cb.warn(
                    sfmt("Illuminant range inverted: start %.0f >= end %.0f",
                         static_cast<double>(startNm),
                         static_cast<double>(endNm)));
            }
            if (illumRange.steps > 1000u) {
                cb.warn(sfmt("Excessive illuminant steps: %u",
                             static_cast<unsigned>(illumRange.steps)));
            }
        }
    }

    return cb.done("Environment variable tags validated");
}

REGISTER_HEURISTIC(106, "Env Var",
    "", "",
    "CWE-131", "CVE-2026-34537,GHSA-3m63-c4jf-592f",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h106_env_var);

static CheckResult check_h107_channel_cross_check(const ProfileView& pv) {
    CheckBuilder cb;
    auto* p = pv.unsafeLibraryHandle();
    if (!pv.libraryLoaded() || !p) {
        constexpr uint32_t kMagicAcsp = 0x61637370u;
        if (pv.rawSize() < 128u || pv.header().magic != kMagicAcsp) {
            return CheckResult::ok("NOT RUN: Profile failed to load");
        }

        icUInt32Number dataChannels =
            icGetSpaceSamples(static_cast<icColorSpaceSignature>(pv.header().colorSpace));
        icUInt32Number pcsChannels =
            icGetSpaceSamples(static_cast<icColorSpaceSignature>(pv.header().pcs));

        if (dataChannels == 0u || pcsChannels == 0u) {
            cb.warn(sfmt("Cannot determine channel counts (data=%u, PCS=%u)",
                         dataChannels, pcsChannels));
            return cb.done("LUT channel cross-check complete");
        }

        return cb.done("All LUT channel counts match declared colorspace/PCS");
    }

    icUInt32Number dataChannels = icGetSpaceSamples(p->m_Header.colorSpace);
    icUInt32Number pcsChannels = icGetSpaceSamples(p->m_Header.pcs);

    if (dataChannels == 0u || pcsChannels == 0u) {
        cb.warn(sfmt("Cannot determine channel counts (data=%u, PCS=%u)",
                     dataChannels, pcsChannels));
        return cb.done("LUT channel cross-check complete");
    }

    static const icTagSignature atobSigs[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag, static_cast<icTagSignature>(0)
    };
    for (int i = 0; atobSigs[i] != static_cast<icTagSignature>(0); ++i) {
        auto* mbb = FindAndCast<CIccMBB>(p, atobSigs[i]);
        if (!mbb) continue;

        icUInt8Number nIn = mbb->InputChannels();
        icUInt8Number nOut = mbb->OutputChannels();
        if (nIn != dataChannels) {
            cb.warn(
                sfmt("AToB%d: input channels (%u) != data colorspace (%u)",
                     i, static_cast<unsigned>(nIn), dataChannels),
                "CWE-131: Channel/colorspace mismatch - buffer overflow risk");
        }
        if (nOut != pcsChannels) {
            cb.warn(
                sfmt("AToB%d: output channels (%u) != PCS (%u)",
                     i, static_cast<unsigned>(nOut), pcsChannels),
                "CWE-121: Output channel mismatch - SBO risk (see patch 071)");
        }
    }

    static const icTagSignature btoaSigs[] = {
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag, static_cast<icTagSignature>(0)
    };
    for (int i = 0; btoaSigs[i] != static_cast<icTagSignature>(0); ++i) {
        auto* mbb = FindAndCast<CIccMBB>(p, btoaSigs[i]);
        if (!mbb) continue;

        icUInt8Number nIn = mbb->InputChannels();
        icUInt8Number nOut = mbb->OutputChannels();
        if (nIn != pcsChannels) {
            cb.warn(
                sfmt("BToA%d: input channels (%u) != PCS (%u)",
                     i, static_cast<unsigned>(nIn), pcsChannels),
                "CWE-131: Channel/PCS mismatch - buffer overflow risk");
        }
        if (nOut != dataChannels) {
            cb.warn(
                sfmt("BToA%d: output channels (%u) != data colorspace (%u)",
                     i, static_cast<unsigned>(nOut), dataChannels),
                "CWE-121: Output channel mismatch - SBO risk");
        }
    }

    static const icTagSignature dtobSigs[] = {
        static_cast<icTagSignature>(0x44324230), // D2B0
        static_cast<icTagSignature>(0x44324231), // D2B1
        static_cast<icTagSignature>(0x44324232), // D2B2
        static_cast<icTagSignature>(0)
    };
    for (int i = 0; dtobSigs[i] != static_cast<icTagSignature>(0); ++i) {
        auto* mpe = FindAndCast<CIccTagMultiProcessElement>(p, dtobSigs[i]);
        if (!mpe) continue;

        if (mpe->NumInputChannels() != dataChannels) {
            cb.warn(sfmt("DToB%d: input channels (%u) != data colorspace (%u)",
                         i,
                         static_cast<unsigned>(mpe->NumInputChannels()),
                         dataChannels));
        }
        if (mpe->NumOutputChannels() != pcsChannels) {
            cb.warn(sfmt("DToB%d: output channels (%u) != PCS (%u)",
                         i,
                         static_cast<unsigned>(mpe->NumOutputChannels()),
                         pcsChannels));
        }
    }

    return cb.done("All LUT channel counts match declared colorspace/PCS");
}

REGISTER_HEURISTIC(107, "Channel Cross Check",
    "", "",
    "CWE-131", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h107_channel_cross_check);

static CheckResult check_h109_shellcode_patterns(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* raw = pv.rawData();
    size_t rawLen = pv.rawSize();
    if (!raw || rawLen <= 128u || rawLen > 100u * 1024u * 1024u) {
        return CheckResult::skip("File size not suitable for pattern scan");
    }

    size_t scanSize = rawLen > 10485760u ? 10485760u : rawLen;

    for (size_t i = 128; i + 16 <= scanSize; ) {
        if (raw[i] == 0x90u) {
            size_t run = 1;
            while (i + run < scanSize && raw[i + run] == 0x90u && run < 256u) {
                run++;
            }
            if (run >= 16u) {
                cb.warn(sfmt("x86 NOP sled at offset 0x%zX (%zu bytes)", i, run));
                i += run;
                continue;
            }
        }

        if (i + 4 <= scanSize &&
            raw[i] == 0x7Fu && raw[i + 1] == 0x45u &&
            raw[i + 2] == 0x4Cu && raw[i + 3] == 0x46u) {
            cb.warn(sfmt("ELF header at offset 0x%zX", i));
        }

        if (i + 64 <= scanSize && raw[i] == 0x4Du && raw[i + 1] == 0x5Au) {
            uint32_t peOff = static_cast<uint32_t>(raw[i + 60]) |
                             (static_cast<uint32_t>(raw[i + 61]) << 8) |
                             (static_cast<uint32_t>(raw[i + 62]) << 16) |
                             (static_cast<uint32_t>(raw[i + 63]) << 24);
            if (peOff < 1024u && i + peOff + 4u <= scanSize &&
                raw[i + peOff] == 'P' && raw[i + peOff + 1] == 'E') {
                cb.warn(sfmt("PE/MZ executable at offset 0x%zX", i));
            }
        }

        if (i + 16 <= scanSize &&
            raw[i] == 0x1Fu && raw[i + 1] == 0x20u &&
            raw[i + 2] == 0x03u && raw[i + 3] == 0xD5u) {
            int armNops = 1;
            size_t j = i + 4;
            while (j + 4 <= scanSize &&
                   raw[j] == 0x1Fu && raw[j + 1] == 0x20u &&
                   raw[j + 2] == 0x03u && raw[j + 3] == 0xD5u &&
                   armNops < 64) {
                armNops++;
                j += 4;
            }
            if (armNops >= 4) {
                cb.warn(sfmt("ARM64 NOP sled at offset 0x%zX (%d instructions)", i, armNops));
            }
        }

        i++;
    }

    return cb.done("No shellcode or executable patterns detected");
}

REGISTER_HEURISTIC(109, "Shellcode Patterns",
    "", "",
    "CWE-506", "",
    Severity::CRITICAL, CheckPhase::RAW_SCAN,
    check_h109_shellcode_patterns);

static CheckResult check_h110_class_tag_validation(const ProfileView& pv) {
    if (!pv.libraryLoaded()) {
        return check_h110_class_tag_validation_raw_fallback(pv);
    }
    auto* p = pv.unsafeLibraryHandle();
    if (!p) {
        return check_h110_class_tag_validation_raw_fallback(pv);
    }

    CheckBuilder cb;

    icProfileClassSignature profileClass = p->m_Header.deviceClass;

    struct TagReq {
        icTagSignature sig;
        const char* name;
    };
    static const TagReq commonRequired[] = {
        {icSigProfileDescriptionTag, "desc"},
        {icSigCopyrightTag, "cprt"},
        {icSigMediaWhitePointTag, "wtpt"},
        {static_cast<icTagSignature>(0), nullptr}
    };

    if (profileClass != icSigLinkClass) {
        for (int i = 0; commonRequired[i].sig != static_cast<icTagSignature>(0); ++i) {
            if (!p->FindTag(commonRequired[i].sig)) {
                cb.warn(sfmt("Missing required tag '%s' for non-DeviceLink class",
                             commonRequired[i].name));
            }
        }
    }

    const char* className = "unknown";
    bool needsA2B = false;

    switch (profileClass) {
        case icSigInputClass:
            className = "Input (scnr)";
            needsA2B = true;
            break;
        case icSigDisplayClass:
            className = "Display (mntr)";
            needsA2B = true;
            break;
        case icSigOutputClass:
            className = "Output (prtr)";
            needsA2B = true;
            break;
        case icSigLinkClass:
            className = "DeviceLink (link)";
            if (!p->FindTag(icSigAToB0Tag)) {
                cb.warn("DeviceLink missing required AToB0 tag");
            }
            if (!p->FindTag(icSigProfileDescriptionTag)) {
                cb.warn("DeviceLink missing required desc tag");
            }
            break;
        case icSigAbstractClass:
            className = "Abstract (abst)";
            needsA2B = true;
            break;
        case icSigColorSpaceClass:
            className = "ColorSpace (spac)";
            needsA2B = true;
            break;
        case icSigNamedColorClass:
            className = "NamedColor (nmcl)";
            break;
        default:
            cb.warn(sfmt("Unknown profile class: 0x%08X", static_cast<unsigned>(profileClass)));
            break;
    }
    (void)className;

    if (needsA2B && !p->FindTag(icSigAToB0Tag)) {
        bool hasRgbTrc = p->FindTag(icSigRedTRCTag) &&
                         p->FindTag(icSigGreenTRCTag) &&
                         p->FindTag(icSigBlueTRCTag);
        if ((profileClass == icSigDisplayClass || profileClass == icSigInputClass) && hasRgbTrc) {
            // Matrix/TRC path accepted by legacy heuristic.
        } else if (profileClass == icSigInputClass && p->FindTag(icSigGrayTRCTag)) {
            // Grayscale input path accepted by legacy heuristic.
        } else {
            cb.warn(sfmt("Missing AToB0 tag (required for %s class)", className));
        }
    }

    if (profileClass != icSigLinkClass) {
        if (p->m_Header.pcs != icSigLabData && p->m_Header.pcs != icSigXYZData) {
            icUInt32Number pcsVal = static_cast<icUInt32Number>(p->m_Header.pcs);
            if (pcsVal < 0x72300000u || pcsVal > 0x72FFFFFFu) {
                cb.warn(
                    sfmt("Non-DeviceLink PCS is not Lab/XYZ/spectral: 0x%08X",
                         static_cast<unsigned>(p->m_Header.pcs)),
                    "CWE-20: Invalid PCS for profile class");
            }
        }
    }

    if (profileClass != icSigLinkClass) {
        CIccTag* chadTag = p->FindTag(icSigChromaticAdaptationTag);
        CIccTag* wtptTag = p->FindTag(icSigMediaWhitePointTag);
        if (wtptTag && !chadTag) {
            auto* wpXyz = dynamic_cast<CIccTagXYZ*>(wtptTag);
            if (wpXyz && wpXyz->GetSize() >= 1u) {
                double wpX = icFtoD((*wpXyz)[0].X);
                double wpY = icFtoD((*wpXyz)[0].Y);
                double wpZ = icFtoD((*wpXyz)[0].Z);
                if (std::fabs(wpX - 0.9642) > 0.01 ||
                    std::fabs(wpY - 1.0) > 0.01 ||
                    std::fabs(wpZ - 0.8249) > 0.01) {
                    cb.warn(
                        "wtpt != D50 but 'chad' tag missing (ICC.1-2022-05 Annex G)",
                        "CWE-20: chromaticAdaptationTag required when adopted white != D50");
                }
            }
        }
    }

    return cb.done("Profile class and required tags are consistent");
}

REGISTER_HEURISTIC(110, "Class Tag Validation",
    "Sec.8", "ICC.1-2022-05",
    "CWE-20", "",
    Severity::LOW, CheckPhase::RAW_SCAN,
    check_h110_class_tag_validation);

static CheckResult check_h113_round_trip_fidelity(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return CheckResult::ok("NOT RUN: Profile failed to load");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::ok("NOT RUN: Profile failed to load");

    struct IntentPair {
        icTagSignature atob;
        icTagSignature btoa;
        const char* name;
    };
    static const IntentPair pairs[] = {
        {icSigAToB0Tag, icSigBToA0Tag, "Perceptual"},
        {icSigAToB1Tag, icSigBToA1Tag, "Rel. Colorimetric"},
        {icSigAToB2Tag, icSigBToA2Tag, "Saturation"},
    };

    for (int pidx = 0; pidx < 3; ++pidx) {
        CIccTag* tagA = p->FindTag(pairs[pidx].atob);
        CIccTag* tagB = p->FindTag(pairs[pidx].btoa);
        if (!tagA && !tagB) continue;

        auto* mbbA = tagA ? dynamic_cast<CIccMBB*>(tagA) : nullptr;
        auto* mbbB = tagB ? dynamic_cast<CIccMBB*>(tagB) : nullptr;

        if (mbbA && mbbB) {
            if (mbbA->OutputChannels() != mbbB->InputChannels()) {
                cb.warn(
                    sfmt("Channel mismatch: AToB output=%u != BToA input=%u",
                         static_cast<unsigned>(mbbA->OutputChannels()),
                         static_cast<unsigned>(mbbB->InputChannels())),
                    "CWE-682: Incompatible round-trip dimensions");
            }
            if (mbbA->InputChannels() != mbbB->OutputChannels()) {
                cb.warn(
                    sfmt("Channel mismatch: AToB input=%u != BToA output=%u",
                         static_cast<unsigned>(mbbA->InputChannels()),
                         static_cast<unsigned>(mbbB->OutputChannels())));
            }
        }
    }

    return cb.done("Round-trip tag geometry is consistent");
}

REGISTER_HEURISTIC(113, "Round Trip Fidelity",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h113_round_trip_fidelity);

static CheckResult check_h114_curve_smoothness(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return CheckResult::ok("NOT RUN: Profile failed to load");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::ok("NOT RUN: Profile failed to load");

    static const icTagSignature trcTags[] = {
        icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag,
        static_cast<icTagSignature>(0)
    };
    static const char* trcNames[] = {"rTRC", "gTRC", "bTRC", "kTRC"};

    for (int t = 0; trcTags[t] != static_cast<icTagSignature>(0); ++t) {
        auto* curve = FindAndCast<CIccTagCurve>(p, trcTags[t]);
        if (!curve) continue;

        icUInt32Number nEntries = curve->GetSize();
        if (nEntries < 2u) {
            if (nEntries == 1u) {
                icFloatNumber gamma = (*curve)[0];
                if (gamma < 0.1f || gamma > 10.0f) {
                    cb.warn(
                        sfmt("%s: extreme gamma value %.4f",
                             trcNames[t], static_cast<double>(gamma)));
                }
            }
            continue;
        }

        int nonMonotonic = 0;
        double maxJump = 0.0;
        size_t maxJumpIdx = 0;

        for (icUInt32Number i = 1; i < nEntries; ++i) {
            double prev = static_cast<double>((*curve)[i - 1]);
            double curr = static_cast<double>((*curve)[i]);
            if (curr < prev - 0.001) nonMonotonic++;

            double jump = std::fabs(curr - prev);
            if (jump > maxJump) {
                maxJump = jump;
                maxJumpIdx = i;
            }
        }

        double expectedStep = 1.0 / static_cast<double>(nEntries - 1);
        bool extremeJump = maxJump > expectedStep * 50.0 && maxJump > 0.1;

        if (nonMonotonic > 0) {
            cb.warn(sfmt("%s: %d non-monotonic region(s)", trcNames[t], nonMonotonic));
        }
        if (extremeJump) {
            cb.warn(
                sfmt("%s: extreme jump %.4f at [%zu]", trcNames[t], maxJump, maxJumpIdx));
        }
    }

    return cb.done("TRC curves are smooth and monotonic");
}

REGISTER_HEURISTIC(114, "Curve Smoothness",
    "", "",
    "CWE-20", "CVE-2026-21687,GHSA-prmm-g479-4fv7",
    Severity::LOW, CheckPhase::RAW_SCAN,
    check_h114_curve_smoothness);

static CheckResult check_h115_characterization_data(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return CheckResult::skip("Library parse failed");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::skip("No profile");

    CIccTag* targTag = p->FindTag(icSigCharTargetTag);
    if (!targTag) {
        return CheckResult::skip("No characterization data (targ) tag present");
    }

    auto* textTag = dynamic_cast<CIccTagText*>(targTag);
    if (!textTag) {
        cb.warn("targ tag is not text type");
        return cb.done("Characterization data present and valid");
    }

    const char* text = textTag->GetText();
    size_t len = text ? std::strlen(text) : 0u;
    if (len > 10u * 1024u * 1024u) {
        cb.warn(sfmt("Characterization data exceeds 10MB (%zu bytes)", len));
    }

    return cb.done("Characterization data present and valid");
}

REGISTER_HEURISTIC(115, "Characterization Data",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::RAW_SCAN,
    check_h115_characterization_data);

static CheckResult check_h116_cprt_desc_encoding(const ProfileView& pv) {
    CheckBuilder cb;
    constexpr uint32_t kMagicAcsp = 0x61637370u;
    bool useRawFallback = !pv.libraryLoaded();
    if (useRawFallback &&
        (pv.header().magic != kMagicAcsp ||
         !rawDeclaredTagTableFits(pv) ||
         pv.rawTagTable().empty())) {
        return CheckResult::ok("NOT RUN: Profile failed to load");
    }

    auto* p = pv.unsafeLibraryHandle();
    icUInt32Number version = useRawFallback ? pv.header().version : p->m_Header.version;
    int majorVer = (version >> 24) & 0xFF;

    struct TagCheck {
        icTagSignature sig;
        const char* name;
    };
    static const TagCheck checks[] = {
        {icSigCopyrightTag, "cprt"},
        {icSigProfileDescriptionTag, "desc"},
    };

    for (int i = 0; i < 2; ++i) {
        uint32_t tagType = 0u;
        if (useRawFallback) {
            uint32_t minSize = checks[i].sig == icSigProfileDescriptionTag ? 24u : 12u;
            if (!rawTagHeaderReadable(pv, checks[i].sig, minSize)) continue;
            auto rawType = rawTagTypeSig(pv, checks[i].sig);
            if (!rawType) continue;
            tagType = *rawType;
        } else {
            CIccTag* tag = p ? p->FindTag(checks[i].sig) : nullptr;
            if (!tag) continue;
            tagType = static_cast<uint32_t>(tag->GetType());
        }

        if (majorVer >= 4) {
            if (tagType != static_cast<uint32_t>(icSigMultiLocalizedUnicodeType)) {
                cb.warn(
                    sfmt("%s: v%d profile should use multiLocalizedUnicodeType, found '%s'",
                         checks[i].name, majorVer, sigStr(tagType).c_str()),
                    "CWE-20: Encoding does not match specification version");
            }
        } else if (majorVer == 2) {
            bool ok = tagType == static_cast<uint32_t>(icSigTextType) ||
                      tagType == static_cast<uint32_t>(icSigTextDescriptionType) ||
                      tagType == static_cast<uint32_t>(icSigMultiLocalizedUnicodeType);
            if (!ok) {
                cb.warn(
                    sfmt("%s: v2 profile should use textType or textDescriptionType, found '%s'",
                         checks[i].name, sigStr(tagType).c_str()));
            }
        }
    }

    return cb.done("cprt/desc encoding matches profile version");
}

REGISTER_HEURISTIC(116, "Cprt Desc Encoding",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::RAW_SCAN,
    check_h116_cprt_desc_encoding);

static CheckResult check_h117_tag_type_allowed(const ProfileView& pv) {
    CheckBuilder cb;
    constexpr uint32_t kMagicAcsp = 0x61637370u;
    bool useRawFallback = !pv.libraryLoaded();
    if (useRawFallback &&
        (pv.header().magic != kMagicAcsp ||
         !rawDeclaredTagTableFits(pv) ||
         pv.rawTagTable().empty())) {
        return CheckResult::ok("NOT RUN: Profile failed to load");
    }

    auto* p = pv.unsafeLibraryHandle();

    struct AllowedType {
        icTagSignature sig;
        const char* name;
        icTagTypeSignature allowed[6];
        int count;
    };

    static const AllowedType table[] = {
        {icSigCopyrightTag, "cprt",
         {icSigMultiLocalizedUnicodeType, icSigTextType, icSigTextDescriptionType}, 3},
        {icSigProfileDescriptionTag, "desc",
         {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType, icSigTextType}, 3},
        {icSigMediaWhitePointTag, "wtpt", {icSigXYZType}, 1},
        {icSigRedMatrixColumnTag, "rXYZ", {icSigXYZType}, 1},
        {icSigGreenMatrixColumnTag, "gXYZ", {icSigXYZType}, 1},
        {icSigBlueMatrixColumnTag, "bXYZ", {icSigXYZType}, 1},
        {icSigRedTRCTag, "rTRC", {icSigCurveType, icSigParametricCurveType}, 2},
        {icSigGreenTRCTag, "gTRC", {icSigCurveType, icSigParametricCurveType}, 2},
        {icSigBlueTRCTag, "bTRC", {icSigCurveType, icSigParametricCurveType}, 2},
        {icSigGrayTRCTag, "kTRC", {icSigCurveType, icSigParametricCurveType}, 2},
        {icSigChromaticAdaptationTag, "chad", {icSigS15Fixed16ArrayType}, 1},
        {icSigLuminanceTag, "lumi", {icSigXYZType}, 1},
        {icSigMeasurementTag, "meas", {icSigMeasurementType}, 1},
        {icSigViewingConditionsTag, "view", {icSigViewingConditionsType}, 1},
        {icSigTechnologyTag, "tech", {icSigSignatureType}, 1},
        {icSigCalibrationDateTimeTag, "calt", {icSigDateTimeType}, 1},
        {icSigCharTargetTag, "targ", {icSigTextType}, 1},
        {icSigChromaticityTag, "chrm", {icSigChromaticityType}, 1},
        {icSigColorantOrderTag, "clro", {icSigColorantOrderType}, 1},
        {icSigColorantTableTag, "clrt", {icSigColorantTableType}, 1},
        {icSigColorantTableOutTag, "clot", {icSigColorantTableType}, 1},
        {icSigNamedColor2Tag, "ncl2", {icSigNamedColor2Type}, 1},
        {icSigOutputResponseTag, "resp", {icSigResponseCurveSet16Type}, 1},
        {icSigDeviceMfgDescTag, "dmnd", {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType}, 2},
        {icSigDeviceModelDescTag, "dmdd", {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType}, 2},
        {icSigViewingCondDescTag, "vued", {icSigMultiLocalizedUnicodeType, icSigTextDescriptionType}, 2},
    };

    int checked = 0;
    for (size_t t = 0; t < sizeof(table) / sizeof(table[0]); ++t) {
        std::optional<uint32_t> rawType;
        uint32_t actualType = 0u;
        if (useRawFallback) {
            switch (table[t].sig) {
                case icSigCopyrightTag:
                    if (!rawTagHeaderReadable(pv, table[t].sig, 12u)) continue;
                    break;
                case icSigProfileDescriptionTag:
                    if (!rawTagHeaderReadable(pv, table[t].sig, 24u)) continue;
                    break;
                case icSigDeviceMfgDescTag:
                case icSigDeviceModelDescTag:
                case icSigViewingCondDescTag:
                    if (!rawTagHeaderReadable(pv, table[t].sig, 12u)) continue;
                    break;
                default:
                    continue;
            }
            rawType = rawTagTypeSig(pv, table[t].sig);
            if (!rawType) continue;
            actualType = *rawType;
        } else {
            CIccTag* tag = p ? p->FindTag(table[t].sig) : nullptr;
            if (!tag) continue;
            actualType = static_cast<uint32_t>(tag->GetType());
        }

        checked++;
        bool allowed = false;
        for (int a = 0; a < table[t].count; ++a) {
            if (actualType == static_cast<uint32_t>(table[t].allowed[a])) {
                allowed = true;
                break;
            }
        }
        if (!allowed) {
            cb.warn(
                sfmt("'%s': type '%s' (0x%08X) not in allowed set",
                     table[t].name, sigStr(actualType).c_str(),
                     static_cast<unsigned>(actualType)),
                "CWE-20: Tag uses disallowed type for its signature");
        }
    }
    (void)checked;

    return cb.done(sfmt("%d tags checked - all use allowed types", checked));
}

REGISTER_HEURISTIC(117, "Tag Type Allowed",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::RAW_SCAN,
    check_h117_tag_type_allowed);

static CheckResult check_h118_calc_cost_estimate(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return CheckResult::ok("NOT RUN: Profile failed to load");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::ok("NOT RUN: Profile failed to load");

    static const icTagSignature mpeTags[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
        static_cast<icTagSignature>(0x44324230), // D2B0
        static_cast<icTagSignature>(0x44324231), // D2B1
        static_cast<icTagSignature>(0x42324430), // B2D0
        static_cast<icTagSignature>(0x42324431), // B2D1
        static_cast<icTagSignature>(0)
    };

    uint64_t totalCost = 0;
    int tagsWithCalc = 0;

    for (int t = 0; mpeTags[t] != static_cast<icTagSignature>(0); ++t) {
        auto* mpe = FindAndCast<CIccTagMultiProcessElement>(p, mpeTags[t]);
        if (!mpe) continue;

        icUInt32Number numElems = mpe->NumElements();
        if (numElems == 0u) continue;

        uint64_t tagCost = 0;
        int calcCount = 0;

        for (icUInt32Number ei = 0; ei < numElems; ++ei) {
            CIccMultiProcessElement* elem = mpe->GetElement(ei);
            if (!elem) continue;

            uint32_t inCh = elem->NumInputChannels();
            uint32_t outCh = elem->NumOutputChannels();

            if (dynamic_cast<CIccMpeCalculator*>(elem)) {
                calcCount++;
                tagCost += static_cast<uint64_t>(inCh) * static_cast<uint64_t>(outCh) * 100ull;
            }

            if (auto* mpeClut = dynamic_cast<CIccMpeCLUT*>(elem)) {
                CIccCLUT* clut = mpeClut->GetCLUT();
                if (clut) {
                    uint32_t grid = clut->GridPoints();
                    uint64_t clutSize = 1;
                    for (uint32_t d = 0; d < inCh && d < 16u; ++d) {
                        clutSize *= static_cast<uint64_t>(grid);
                    }
                    clutSize *= static_cast<uint64_t>(outCh);
                    tagCost += clutSize;
                }
            }

            if (dynamic_cast<CIccMpeMatrix*>(elem)) {
                tagCost += static_cast<uint64_t>(inCh) * static_cast<uint64_t>(outCh) * 2ull;
            }

            if (dynamic_cast<CIccMpeCurveSet*>(elem)) {
                tagCost += static_cast<uint64_t>(inCh) * 256ull;
            }
        }

        if (calcCount > 0 || tagCost > 0u) {
            tagsWithCalc++;
            if (tagCost > 100000000ull) {
                cb.warn(
                    sfmt("'%s': excessive computation cost (>100M ops per pixel)",
                         sigStr(static_cast<uint32_t>(mpeTags[t])).c_str()),
                    "CWE-400: Potential algorithmic complexity DoS");
            }
        }

        totalCost += tagCost;
    }

    if (tagsWithCalc > 0 && totalCost > 1000000000ull) {
        cb.warn("Total computation cost exceeds 1B ops - extreme DoS risk");
    }

    return cb.done("Computation cost within acceptable limits");
}

REGISTER_HEURISTIC(118, "Calc Cost Estimate",
    "", "",
    "CWE-400", "",
    Severity::HIGH, CheckPhase::RAW_SCAN,
    check_h118_calc_cost_estimate);

static CheckResult check_h119_round_trip_delta_e(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return CheckResult::ok("NOT RUN: Profile failed to load");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::ok("NOT RUN: Profile failed to load");

    struct IntentPair {
        icTagSignature atob;
        icTagSignature btoa;
        const char* name;
    };
    static const IntentPair pairs[] = {
        {icSigAToB0Tag, icSigBToA0Tag, "Perceptual"},
        {icSigAToB1Tag, icSigBToA1Tag, "Rel. Colorimetric"},
        {icSigAToB2Tag, icSigBToA2Tag, "Saturation"},
    };

    bool anyMeasured = false;

    for (int pidx = 0; pidx < 3; ++pidx) {
        CIccTag* tagA = p->FindTag(pairs[pidx].atob);
        CIccTag* tagB = p->FindTag(pairs[pidx].btoa);
        if (!tagA || !tagB) continue;

        auto* mbbA = dynamic_cast<CIccMBB*>(tagA);
        auto* mbbB = dynamic_cast<CIccMBB*>(tagB);
        if (!mbbA || !mbbB) continue;

        CIccCLUT* clutA = mbbA->GetCLUT();
        CIccCLUT* clutB = mbbB->GetCLUT();
        if (!clutA || !clutB) continue;

        if (mbbA->OutputChannels() != mbbB->InputChannels() ||
            mbbA->OutputChannels() < 1u || mbbA->OutputChannels() > 15u) {
            continue;
        }

        clutB->Begin();

        uint32_t pcsChannels = mbbA->OutputChannels();
        uint32_t gridA = static_cast<uint32_t>(clutA->GridPoints());
        uint32_t inputA = mbbA->InputChannels();
        if (inputA < 1u || inputA > 15u || gridA < 2u) continue;

        uint64_t totalNodes = 1;
        for (uint32_t d = 0; d < inputA; ++d) {
            totalNodes *= static_cast<uint64_t>(gridA);
            if (totalNodes > 100000ull) {
                totalNodes = 100000ull;
                break;
            }
        }

        uint32_t stride = totalNodes > 1000ull ? static_cast<uint32_t>(totalNodes / 1000ull) : 1u;
        if (stride < 1u) stride = 1u;

        double sumDE = 0.0;
        double maxDE = 0.0;
        int samples = 0;

        for (uint64_t idx = 0; idx < totalNodes; idx += stride) {
            icFloatNumber pcsOut[16] = {};
            icFloatNumber* nodeData = clutA->GetData(static_cast<icUInt32Number>(idx * pcsChannels));
            if (!nodeData) continue;

            for (uint32_t c = 0; c < pcsChannels && c < 16u; ++c) {
                pcsOut[c] = nodeData[c];
            }

            icFloatNumber roundTrip[16] = {};
            icUInt8Number clutBInput = mbbB->InputChannels();
            if (clutBInput == 3u) {
                clutB->Interp3d(roundTrip, pcsOut);
            } else if (clutBInput == 4u) {
                clutB->Interp4d(roundTrip, pcsOut);
            } else if (clutBInput == 1u) {
                clutB->Interp1d(roundTrip, pcsOut);
            } else {
                continue;
            }

            double de2 = 0.0;
            for (uint32_t c = 0; c < pcsChannels && c < 3u; ++c) {
                double d = static_cast<double>(roundTrip[c]) - static_cast<double>(pcsOut[c]);
                de2 += d * d;
            }
            double de = std::sqrt(de2);
            sumDE += de;
            if (de > maxDE) maxDE = de;
            samples++;
        }

        if (samples > 0) {
            anyMeasured = true;
            double avgDE = sumDE / static_cast<double>(samples);
            (void)avgDE;
            if (maxDE > 5.0) {
                cb.warn("max DeltaE > 5.0 - poor round-trip fidelity");
            }
        }
    }

    if (!anyMeasured) {
        return CheckResult::ok("No AToB/BToA CLUT pairs available for DeltaE measurement");
    }

    return cb.done("Round-trip DeltaE within acceptable range");
}

REGISTER_HEURISTIC(119, "Round Trip Delta E",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h119_round_trip_delta_e);

static CheckResult check_h120_curve_invertibility(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return CheckResult::ok("NOT RUN: Profile failed to load");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return CheckResult::ok("NOT RUN: Profile failed to load");

    static const icTagSignature trcTags[] = {
        icSigRedTRCTag, icSigGreenTRCTag, icSigBlueTRCTag, icSigGrayTRCTag,
        static_cast<icTagSignature>(0)
    };
    static const char* trcNames[] = {"rTRC", "gTRC", "bTRC", "kTRC"};

    int curvesChecked = 0;

    for (int t = 0; trcTags[t] != static_cast<icTagSignature>(0); ++t) {
        auto* curve = FindAndCast<CIccTagCurve>(p, trcTags[t]);
        if (!curve) continue;

        icUInt32Number nEntries = curve->GetSize();
        if (nEntries < 2u) {
            if (nEntries == 1u) {
                icFloatNumber gamma = (*curve)[0];
                if (gamma <= 0.01f) {
                    cb.warn(
                        sfmt("%s: gamma=%.6f approx 0 - NOT invertible",
                             trcNames[t], static_cast<double>(gamma)));
                }
            }
            curvesChecked++;
            continue;
        }

        std::vector<double> fwd(nEntries);
        for (icUInt32Number i = 0; i < nEntries; ++i) {
            fwd[i] = static_cast<double>((*curve)[i]);
        }

        double range = fwd[nEntries - 1] - fwd[0];
        if (std::fabs(range) < 1e-6) {
            cb.warn(
                sfmt("%s: flat curve (range=%.6f) - NOT invertible", trcNames[t], range),
                "CWE-682: Degenerate transform destroys color data");
            curvesChecked++;
            continue;
        }

        double sumErr = 0.0;
        double maxErr = 0.0;
        int testCount = 0;
        int nTests = nEntries > 256u ? 256 : static_cast<int>(nEntries);

        for (int s = 0; s < nTests; ++s) {
            double x = static_cast<double>(s) / static_cast<double>(nTests - 1);
            double y = fwd[0] + x * (fwd[nEntries - 1] - fwd[0]);

            size_t lo = 0;
            size_t hi = nEntries - 1;
            while (lo + 1 < hi) {
                size_t mid = (lo + hi) / 2;
                if (fwd[mid] <= y) lo = mid;
                else hi = mid;
            }

            double denom = fwd[hi] - fwd[lo];
            double invX = std::fabs(denom) < 1e-12
                ? static_cast<double>(lo) / static_cast<double>(nEntries - 1)
                : (static_cast<double>(lo) + (y - fwd[lo]) / denom) /
                  static_cast<double>(nEntries - 1);

            double err = std::fabs(invX - x);
            sumErr += err;
            if (err > maxErr) maxErr = err;
            testCount++;
        }

        double avgErr = testCount > 0 ? sumErr / static_cast<double>(testCount) : 0.0;
        (void)avgErr;
        if (maxErr > 0.01) {
            cb.warn(sfmt("%s: poor invertibility (max err > 1%%)", trcNames[t]));
        }

        curvesChecked++;
    }

    if (curvesChecked == 0) {
        return CheckResult::ok("No TRC curves found for invertibility check");
    }

    return cb.done("TRC curves are invertible");
}

REGISTER_HEURISTIC(120, "Curve Invertibility",
    "", "",
    "CWE-682", "",
    Severity::MEDIUM, CheckPhase::RAW_SCAN,
    check_h120_curve_invertibility);


} // namespace icctest
