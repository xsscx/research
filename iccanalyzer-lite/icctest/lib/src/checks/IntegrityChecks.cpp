/*
 * IccTest Library — IntegrityChecks.cpp
 * Heuristic checks H121-H138: Profile integrity + CWE-400 complexity.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "util/CheckHelpers.h"

#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagLut.h"

#include <openssl/evp.h>
#include <algorithm>
#include <cmath>
#include <cstring>
#include <set>
#include <vector>

namespace icctest {

static bool is_printable_signature(uint32_t sig) {
    for (int i = 0; i < 4; ++i) {
        unsigned char c = static_cast<unsigned char>((sig >> (24 - i * 8)) & 0xFF);
        if (c < 0x20 || c > 0x7E) {
            return false;
        }
    }
    return true;
}

static const icTagSignature* integrity_known_standard_tags() {
    static const icTagSignature knownTags[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigAToB2Tag,
        icSigBToA0Tag, icSigBToA1Tag, icSigBToA2Tag,
        icSigBlueMatrixColumnTag, icSigBlueTRCTag,
        icSigCalibrationDateTimeTag, icSigCharTargetTag,
        icSigChromaticAdaptationTag, icSigChromaticityTag,
        icSigCopyrightTag, icSigDeviceMfgDescTag,
        icSigDeviceModelDescTag, icSigGamutTag,
        icSigGrayTRCTag, icSigGreenMatrixColumnTag,
        icSigGreenTRCTag, icSigLuminanceTag,
        icSigMeasurementTag, icSigMediaBlackPointTag,
        icSigMediaWhitePointTag, icSigNamedColor2Tag,
        icSigOutputResponseTag, icSigPreview0Tag,
        icSigPreview1Tag, icSigPreview2Tag,
        icSigProfileDescriptionTag, icSigProfileSequenceDescTag,
        icSigReferenceNameTag,
        icSigRedMatrixColumnTag, icSigRedTRCTag,
        icSigTechnologyTag, icSigViewingCondDescTag,
        icSigViewingConditionsTag, icSigColorantOrderTag,
        icSigColorantTableTag, icSigColorantTableOutTag,
        icSigProfileSequceIdTag,
        icSigPerceptualRenderingIntentGamutTag,
        icSigSaturationRenderingIntentGamutTag,
        static_cast<icTagSignature>(0x44324230), // D2B0
        static_cast<icTagSignature>(0x44324231), // D2B1
        static_cast<icTagSignature>(0x44324232), // D2B2
        static_cast<icTagSignature>(0x42324430), // B2D0
        static_cast<icTagSignature>(0x42324431), // B2D1
        static_cast<icTagSignature>(0x42324432), // B2D2
        static_cast<icTagSignature>(0)
    };
    return knownTags;
}

static bool is_integrity_known_tag(icTagSignature sig) {
    const auto* knownTags = integrity_known_standard_tags();
    for (int i = 0; knownTags[i] != static_cast<icTagSignature>(0); ++i) {
        if (sig == knownTags[i]) {
            return true;
        }
    }
    return false;
}

static std::set<icTagSignature> build_h123_allowed_tags(uint32_t deviceClass) {
    std::set<icTagSignature> allowed = {
        icSigProfileDescriptionTag,
        icSigCopyrightTag,
        icSigMediaWhitePointTag,
        icSigChromaticAdaptationTag,
        icSigCalibrationDateTimeTag,
        icSigCharTargetTag,
        icSigChromaticityTag,
        icSigDeviceMfgDescTag,
        icSigDeviceModelDescTag,
        icSigMeasurementTag,
        icSigTechnologyTag,
        icSigViewingCondDescTag,
        icSigViewingConditionsTag,
        icSigProfileSequenceDescTag,
        icSigProfileSequceIdTag,
        icSigColorantOrderTag,
        icSigColorantTableTag,
        icSigColorantTableOutTag,
        icSigNamedColor2Tag,
        icSigOutputResponseTag,
        icSigGamutTag,
        icSigPerceptualRenderingIntentGamutTag,
        icSigSaturationRenderingIntentGamutTag,
        icSigPreview0Tag,
        icSigPreview1Tag,
        icSigPreview2Tag
    };

    switch (static_cast<icProfileClassSignature>(deviceClass)) {
        case icSigInputClass:
        case icSigDisplayClass:
        case icSigOutputClass:
        case icSigColorSpaceClass:
            allowed.insert(icSigAToB0Tag); allowed.insert(icSigAToB1Tag); allowed.insert(icSigAToB2Tag);
            allowed.insert(icSigBToA0Tag); allowed.insert(icSigBToA1Tag); allowed.insert(icSigBToA2Tag);
            allowed.insert(icSigRedMatrixColumnTag); allowed.insert(icSigGreenMatrixColumnTag);
            allowed.insert(icSigBlueMatrixColumnTag);
            allowed.insert(icSigRedTRCTag); allowed.insert(icSigGreenTRCTag); allowed.insert(icSigBlueTRCTag);
            allowed.insert(icSigGrayTRCTag);
            allowed.insert(icSigLuminanceTag);
            allowed.insert(icSigMediaBlackPointTag);
            allowed.insert(static_cast<icTagSignature>(0x44324230));
            allowed.insert(static_cast<icTagSignature>(0x44324231));
            allowed.insert(static_cast<icTagSignature>(0x44324232));
            allowed.insert(static_cast<icTagSignature>(0x42324430));
            allowed.insert(static_cast<icTagSignature>(0x42324431));
            allowed.insert(static_cast<icTagSignature>(0x42324432));
            break;
        case icSigLinkClass:
            allowed.insert(icSigAToB0Tag);
            allowed.insert(icSigProfileSequenceDescTag);
            break;
        case icSigAbstractClass:
            allowed.insert(icSigAToB0Tag);
            allowed.insert(static_cast<icTagSignature>(0x44324230));
            allowed.insert(static_cast<icTagSignature>(0x42324430));
            break;
        case icSigNamedColorClass:
            allowed.insert(icSigNamedColor2Tag);
            break;
        case icSigColorEncodingClass:
            allowed.insert(icSigReferenceNameTag);
            break;
        default:
            break;
    }

    return allowed;
}

// ── H121: Profile MD5 Computation ──
static CheckResult check_h121_md5(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 128) return CheckResult::skip("File too small");

    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Check if profile ID is populated (bytes 84-99)
    bool hasId = false;
    for (int i = 84; i < 100; i++) {
        if (d[i] != 0) { hasId = true; break; }
    }
    if (!hasId) return CheckResult::skip("No profile ID to verify");

    // Compute MD5 with zeroed fields: bytes 44-47 (flags), 64-67 (intent), 84-99 (profileID)
    std::vector<uint8_t> buf(d, d + len);
    std::memset(buf.data() + 44, 0, 4);   // flags
    std::memset(buf.data() + 64, 0, 4);   // intent
    std::memset(buf.data() + 84, 0, 16);  // profileID

    unsigned char md5[EVP_MAX_MD_SIZE];
    unsigned int md5Len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (ctx) {
        EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
        EVP_DigestUpdate(ctx, buf.data(), buf.size());
        EVP_DigestFinal_ex(ctx, md5, &md5Len);
        EVP_MD_CTX_free(ctx);

        if (md5Len >= 16 && std::memcmp(md5, d + 84, 16) != 0) {
            cb.warn("Profile ID (MD5) does not match computed hash",
                    "CWE-345: Insufficient Verification of Data Authenticity");
        }
    }

    return cb.done("Profile MD5 verified");
}

// ── H122: Tag Data Alignment Check ──
static CheckResult check_h122_tag_pad(const ProfileView& pv) {
    CheckBuilder cb;

    for (const auto& t : pv.rawTagTable()) {
        uint64_t paddedEnd =
            (static_cast<uint64_t>(t.offset) + static_cast<uint64_t>(t.size) + 3ull) & ~3ull;
        if (paddedEnd > pv.rawSize()) {
            cb.info(sfmt("Tag '%s' padded extent (%llu) exceeds file size %zu",
                         sigStr(t.signature).c_str(),
                         static_cast<unsigned long long>(paddedEnd),
                         pv.rawSize()));
        }
    }

    return cb.done("Tag padding checked");
}

// ── H136: Complexity Estimation (CWE-400) ──
static CheckResult check_h136_complexity(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // Count MPE elements by scanning for 'mpet' type signature
    constexpr uint32_t kMpetSig = 0x6D706574; // 'mpet'
    int mpeCount = 0;
    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 8 || !rawRangeAccessible(len, t.offset, 8)) continue;
        if (readU32BE(d + t.offset) == kMpetSig) {
            mpeCount++;
        }
    }

    if (mpeCount > 20) {
        cb.warn(sfmt("%d MPE tags — high complexity profile, potential timeout", mpeCount),
                "CWE-400: Uncontrolled Resource Consumption");
    }

    // Check total tag data vs profile size ratio
    uint64_t totalTagData = 0;
    for (const auto& t : pv.rawTagTable()) {
        totalTagData += t.size;
    }
    if (totalTagData > len * 2) {
        cb.warn(sfmt("Total tag data (%llu) exceeds 2x profile size (%zu) — possible overlap abuse",
                      (unsigned long long)totalTagData, len),
                "CWE-400: Uncontrolled Resource Consumption");
    }

    return cb.done("Complexity estimation complete");
}

// ── H137: GBD nTriangles Overflow Pre-Check ──
static CheckResult check_h137_gbd_overflow(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();

    // GBD tag type: 'gbd ' = 0x67626420
    constexpr uint32_t kGbdType = 0x67626420;

    auto scanGbdRecord = [&](const uint8_t* hdr) {
        uint32_t nTriangles = readU32BE(hdr + 16);
        if (nTriangles > 715827882U) {
            cb.critical(sfmt("GBD nTriangles=%u — int overflow in nTriangles*3 (max 715827882)",
                             nTriangles),
                        "CWE-190: Integer Overflow or Wraparound");
        }
    };

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 20 || !rawRangeAccessible(len, t.offset, 20)) continue;
        uint32_t typeSig = readU32BE(d + t.offset);
        if (typeSig == kGbdType) {
            scanGbdRecord(d + t.offset);
            continue;
        }

        if (typeSig != 0x74617279 || t.size < 16 || !rawRangeAccessible(len, t.offset, 16)) {
            continue;
        }

        uint32_t elemCount = readU32BE(d + t.offset + 12);
        if (elemCount == 0 || elemCount > 256) {
            continue;
        }
        uint64_t ownerEnd = static_cast<uint64_t>(t.offset) + static_cast<uint64_t>(t.size);
        uint64_t tableEnd = static_cast<uint64_t>(t.offset) + 16ull +
                            static_cast<uint64_t>(elemCount) * 8ull;
        if (tableEnd > len || tableEnd > ownerEnd) {
            continue;
        }

        for (uint32_t i = 0; i < elemCount; i++) {
            size_t recOff = t.offset + 16 + static_cast<size_t>(i) * 8;
            uint32_t childOff = readU32BE(d + recOff);
            uint32_t childSz = readU32BE(d + recOff + 4);
            if (!childOff || childSz < 20) {
                continue;
            }
            uint64_t childAbs = static_cast<uint64_t>(t.offset) + static_cast<uint64_t>(childOff);
            if (childAbs + 20 > len || childAbs + childSz > ownerEnd) {
                continue;
            }
            const uint8_t* child = d + childAbs;
            if (readU32BE(child) != kGbdType) {
                continue;
            }
            scanGbdRecord(child);
        }
    }

    return cb.done("GBD overflow pre-check complete");
}

// ── H138: Total Allocation Budget ──
static CheckResult check_h138_alloc_budget(const ProfileView& pv) {
    CheckBuilder cb;

    // Estimate total allocation from tag sizes
    uint64_t totalAlloc = 0;
    for (const auto& t : pv.rawTagTable()) {
        totalAlloc += t.size;
    }

    // Flag profiles that would cause > 256 MB allocation
    if (totalAlloc > 256ULL * 1024 * 1024) {
        cb.high(sfmt("Total tag allocation %llu MB — potential OOM",
                      (unsigned long long)(totalAlloc / (1024*1024))),
                "CWE-400: Uncontrolled Resource Consumption");
    }

    return cb.done("Allocation budget checked");
}

// ── Registration ──

REGISTER_HEURISTIC(121, "Profile MD5 Verification",
    "ICC.1-2022-05 §7.2.18", "ICC.1-2022-05",
    "CWE-345", "", Severity::MEDIUM, CheckPhase::LIBRARY, check_h121_md5);

REGISTER_HEURISTIC(122, "Tag Data Padding Check",
    "ICC.1-2022-05 §7.3.2", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::TAG_TABLE, check_h122_tag_pad);

REGISTER_HEURISTIC(136, "Profile Complexity Estimation",
    "CWE-400 Pattern", "ICC.1-2022-05",
    "CWE-400", "", Severity::MEDIUM, CheckPhase::RAW_SCAN, check_h136_complexity);

REGISTER_HEURISTIC(137, "GBD nTriangles Overflow",
    "IccTagLut.cpp:5730", "CWE Pattern",
    "CWE-190", "", Severity::CRITICAL, CheckPhase::RAW_SCAN, check_h137_gbd_overflow);

REGISTER_HEURISTIC(138, "Total Allocation Budget",
    "CWE-400 Pattern", "ICC.1-2022-05",
    "CWE-400", "", Severity::HIGH, CheckPhase::RAW_SCAN, check_h138_alloc_budget);


// ── Additional registrations for IntegrityChecks ──

static CheckResult check_h123_non_required_tags(const ProfileView& pv) {
    CheckBuilder cb;
    auto allowed = build_h123_allowed_tags(pv.header().deviceClass);

    int unclassified = 0;
    for (const auto& entry : pv.rawTagTable()) {
        auto sig = static_cast<icTagSignature>(entry.signature);
        if (allowed.find(sig) != allowed.end()) {
            continue;
        }
        if (!is_printable_signature(entry.signature)) {
            continue;
        }
        cb.info(sfmt("'%s' (0x%08X): not required/optional for class '%s'",
                     sigStr(entry.signature).c_str(),
                     entry.signature,
                     sigStr(pv.header().deviceClass).c_str()));
        ++unclassified;
    }

    if (unclassified > 0) {
        cb.warn(sfmt("%d tag(s) not in required/optional set for this profile class", unclassified),
                "CWE-20: Non-standard tags should be registered as private");
    }
    return cb.done("All tags are required or optional for this profile class");
}

REGISTER_HEURISTIC(123, "Non Required Tags",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h123_non_required_tags);

static CheckResult check_h124_version_tags(const ProfileView& pv) {
    CheckBuilder cb;
    int majorVer = static_cast<int>((pv.header().version >> 24) & 0xFF);

    static const icTagSignature v4OnlyTags[] = {
        icSigChromaticAdaptationTag,
        icSigColorantOrderTag,
        icSigColorantTableTag,
        icSigColorantTableOutTag,
        icSigProfileSequceIdTag,
        icSigPerceptualRenderingIntentGamutTag,
        icSigSaturationRenderingIntentGamutTag,
        static_cast<icTagSignature>(0)
    };

    static const icTagSignature v2OnlyTags[] = {
        icSigMediaBlackPointTag,
        static_cast<icTagSignature>(0)
    };

    static const icTagSignature v5Tags[] = {
        static_cast<icTagSignature>(0x44324230),
        static_cast<icTagSignature>(0x44324231),
        static_cast<icTagSignature>(0x44324232),
        static_cast<icTagSignature>(0x42324430),
        static_cast<icTagSignature>(0x42324431),
        static_cast<icTagSignature>(0x42324432),
        static_cast<icTagSignature>(0)
    };

    if (majorVer <= 2) {
        for (int i = 0; v4OnlyTags[i] != static_cast<icTagSignature>(0); ++i) {
            if (pv.hasTag(v4OnlyTags[i])) {
                cb.warn(sfmt("v%d profile contains v4+ tag (0x%08X)", majorVer, static_cast<uint32_t>(v4OnlyTags[i])));
            }
        }
        for (int i = 0; v5Tags[i] != static_cast<icTagSignature>(0); ++i) {
            if (pv.hasTag(v5Tags[i])) {
                cb.warn(sfmt("v%d profile contains v5 tag (0x%08X)", majorVer, static_cast<uint32_t>(v5Tags[i])));
            }
        }
    } else if (majorVer == 4) {
        for (int i = 0; v5Tags[i] != static_cast<icTagSignature>(0); ++i) {
            if (pv.hasTag(v5Tags[i])) {
                cb.warn(sfmt("v4 profile contains v5 tag (0x%08X)", static_cast<uint32_t>(v5Tags[i])));
            }
        }
    }

    if (majorVer >= 4) {
        for (int i = 0; v2OnlyTags[i] != static_cast<icTagSignature>(0); ++i) {
            if (pv.hasTag(v2OnlyTags[i])) {
                cb.info(sfmt("v%d profile contains deprecated v2 tag (0x%08X)", majorVer, static_cast<uint32_t>(v2OnlyTags[i])));
            }
        }
    }
    return cb.done(sfmt("Tags correspond to profile version %d", majorVer));
}

REGISTER_HEURISTIC(124, "Version Tags",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h124_version_tags);

static CheckResult check_h125_transform_smoothness(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return CheckResult::skip("Library failed to load");
    auto* pIcc = pv.unsafeLibraryHandle();
    if (!pIcc) return CheckResult::skip("No profile");

    const icTagSignature lutTags[] = {
        icSigAToB0Tag, icSigAToB1Tag, icSigBToA0Tag, static_cast<icTagSignature>(0)
    };
    const char* lutNames[] = {"AToB0", "AToB1", "BToA0"};

    bool anyMeasured = false;
    for (int t = 0; lutTags[t] != static_cast<icTagSignature>(0); ++t) {
        auto* mbb = dynamic_cast<CIccMBB*>(pIcc->FindTag(lutTags[t]));
        if (!mbb) continue;

        CIccCLUT* clut = mbb->GetCLUT();
        if (!clut) continue;

        uint32_t grid = clut->GridPoints();
        uint32_t inCh = mbb->InputChannels();
        uint32_t outCh = mbb->OutputChannels();
        if (inCh < 1 || inCh > 15 || outCh < 1 || outCh > 15 || grid < 3) continue;

        uint64_t totalNodes = 1;
        for (uint32_t d = 0; d < inCh; ++d) {
            totalNodes *= grid;
            if (totalNodes > 50000) break;
        }
        if (totalNodes > 50000 || totalNodes < 4) continue;

        double maxJump = 0.0;
        int pairs = 0;

        for (uint64_t idx = 1; idx < totalNodes; ++idx) {
            icFloatNumber* currData = clut->GetData(static_cast<int>(idx * outCh));
            icFloatNumber* prevData = clut->GetData(static_cast<int>((idx - 1) * outCh));
            if (!currData || !prevData) continue;

            double dist2 = 0.0;
            for (uint32_t c = 0; c < outCh && c < 3; ++c) {
                double delta = static_cast<double>(currData[c]) - static_cast<double>(prevData[c]);
                dist2 += delta * delta;
            }
            double dist = std::sqrt(dist2);
            if (dist > maxJump) maxJump = dist;
            ++pairs;
        }

        if (pairs <= 0) continue;
        anyMeasured = true;
        if (maxJump > 0.5) {
            cb.warn(sfmt("%s: large discontinuity (max step > 0.5) — poor smoothness",
                         lutNames[t]),
                    "CWE-20: Large LUT discontinuity");
        }
    }

    if (!anyMeasured) {
        return cb.done("No suitable LUT tags for smoothness measurement");
    }
    return cb.done("Smooth transitions");
}

REGISTER_HEURISTIC(125, "Transform Smoothness",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h125_transform_smoothness);

static CheckResult check_h126_private_tag_malware(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* fileData = pv.rawData();
    size_t fileSize = pv.rawSize();
    if (!fileData || fileSize <= 132) {
        return CheckResult::skip("No private tags to scan");
    }

    struct Sig {
        const uint8_t bytes[8];
        size_t len;
        const char* desc;
    };
    static const Sig malwareSigs[] = {
        {{0x4D, 0x5A, 0x90, 0x00}, 4, "PE/MZ executable header"},
        {{0x7F, 0x45, 0x4C, 0x46}, 4, "ELF executable header"},
        {{0xCA, 0xFE, 0xBA, 0xBE}, 4, "Mach-O/Java class header"},
        {{0xFE, 0xED, 0xFA, 0xCE}, 4, "Mach-O 32-bit header"},
        {{0xFE, 0xED, 0xFA, 0xCF}, 4, "Mach-O 64-bit header"},
        {{0xCF, 0xFA, 0xED, 0xFE}, 4, "Mach-O 64-bit (reversed)"},
        {{0x50, 0x4B, 0x03, 0x04}, 4, "ZIP/JAR archive"},
        {{0x23, 0x21, 0x2F, 0x00}, 3, "Script shebang (#!/)"},
        {{0x3C, 0x73, 0x63, 0x72, 0x69, 0x70, 0x74, 0x00}, 7, "HTML <script tag"},
        {{0}, 0, nullptr}
    };

    int privateScanned = 0;
    for (const auto& entry : pv.rawTagTable()) {
        icTagSignature sig = static_cast<icTagSignature>(entry.signature);
        if (is_integrity_known_tag(sig)) {
            continue;
        }
        if (entry.size < 4 || entry.size > 10 * 1024 * 1024u) {
            continue;
        }
        if (!rawRangeAccessible(fileSize, entry.offset, entry.size)) {
            continue;
        }

        ++privateScanned;
        size_t bytesRead = std::min<size_t>(entry.size, 65536);
        const uint8_t* buf = fileData + entry.offset;
        for (int s = 0; malwareSigs[s].desc != nullptr; ++s) {
            size_t sigLen = malwareSigs[s].len;
            for (size_t pos = 0; pos + sigLen <= bytesRead; ++pos) {
                if (std::memcmp(buf + pos, malwareSigs[s].bytes, sigLen) != 0) {
                    continue;
                }
                cb.critical(sfmt("Private tag '%s': %s at offset +%zu",
                                 sigStr(entry.signature).c_str(),
                                 malwareSigs[s].desc,
                                 pos),
                            "CWE-506: Embedded malicious code in private tag data");
                break;
            }
        }
    }

    if (privateScanned == 0) {
        return cb.done("No private tags to scan");
    }
    return cb.done(sfmt("%d private tag(s) scanned — no malware signatures found", privateScanned));
}

REGISTER_HEURISTIC(126, "Private Tag Malware",
    "", "",
    "CWE-506", "",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h126_private_tag_malware);

static CheckResult check_h127_private_tag_registry(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 132) return CheckResult::skip("Cannot read tag count");
    const uint8_t* raw = pv.rawData();
    if (!raw || readU32BE(raw + 36) != 0x61637370u) {
        return CheckResult::skip("Invalid ICC magic");
    }
    uint32_t declaredTagCount = readU32BE(raw + 128);
    if (declaredTagCount > 200) {
        return CheckResult::skip(sfmt("Tag count %u too high for safe iteration", declaredTagCount));
    }
    static const struct {
        uint32_t sig;
        const char* registrant;
    } registry[] = {
        {0x70736564u, "Adobe ('psed')"},
        {0x70736571u, "Adobe ('pseq')"},
        {0x64657363u, "Various ('desc')"},
        {0x76756564u, "Various ('vued')"},
        {0x4D535446u, "Microsoft ('MSTF')"},
        {0x41504C45u, "Apple ('APLE')"},
        {0x61617074u, "Apple ('aapt')"},
        {0x6170706Cu, "Apple ('appl')"},
        {0x43474154u, "CGATS ('CGAT')"},
        {0x44657669u, "Device-specific ('Devi')"},
        {0u, nullptr}
    };

    int privateCount = 0;
    int registered = 0;
    int unregistered = 0;
    for (const auto& entry : pv.rawTagTable()) {
        icTagSignature sig = static_cast<icTagSignature>(entry.signature);
        if (is_integrity_known_tag(sig)) {
            continue;
        }

        ++privateCount;
        bool found = false;
        for (int i = 0; registry[i].registrant != nullptr; ++i) {
            if (entry.signature == registry[i].sig) {
                cb.info(sfmt("'%s': registered by %s",
                             sigStr(entry.signature).c_str(),
                             registry[i].registrant));
                ++registered;
                found = true;
                break;
            }
        }
        if (!found) {
            cb.warn(sfmt("'%s' (0x%08X): not found in private tag registry",
                         sigStr(entry.signature).c_str(),
                         entry.signature),
                    "CWE-20: Undocumented private tag");
            ++unregistered;
        }
    }

    if (privateCount == 0) {
        return cb.done("No private tags present");
    }
    cb.info(sfmt("Summary: %d private tag(s) — %d registered, %d undocumented",
                 privateCount, registered, unregistered));
    return cb.done("Private tag registry check complete");
}

REGISTER_HEURISTIC(127, "Private Tag Registry",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h127_private_tag_registry);

static CheckResult check_h128_version_bcd(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 12) return CheckResult::skip("File too small for version field");

    const uint8_t* d = pv.rawData();
    uint8_t major = d[8];
    uint8_t minorBugfix = d[9];
    uint8_t reserved10 = d[10];
    uint8_t reserved11 = d[11];

    int minorNibble = (minorBugfix >> 4) & 0x0F;
    int bugfixNibble = minorBugfix & 0x0F;

    if (major != 2 && major != 4 && major != 5) {
        cb.warn(sfmt("Major version %u not in {2, 4, 5}", static_cast<unsigned>(major)),
                "CWE-20: Version field BCD encoding violation");
    }

    if (minorNibble > 9 || bugfixNibble > 9) {
        cb.warn(sfmt("Non-BCD nibble in version byte 9: 0x%02X (minor=%d, bugfix=%d)",
                     static_cast<unsigned>(minorBugfix), minorNibble, bugfixNibble),
                "CWE-20: Version field BCD encoding violation");
    }

    if (reserved10 != 0 || reserved11 != 0) {
        cb.warn(sfmt("Version reserved bytes 10-11 non-zero: 0x%02X 0x%02X",
                     static_cast<unsigned>(reserved10), static_cast<unsigned>(reserved11)),
                "CWE-20: Reserved version bytes must be 0 (ICC.1-2022-05 §7.2.4)");
    }

    return cb.done("Version BCD encoding is valid");
}

REGISTER_HEURISTIC(128, "Version BCD",
    "§7.2.4", "ICC.1-2022-05",
    "CWE-20", "CVE-2026-24403,GHSA-ph33-qp8j-5q34",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h128_version_bcd);

static CheckResult check_h129_pcs_illuminant_d50(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 80) return CheckResult::skip("File too small for illuminant field");

    const uint8_t* d = pv.rawData();
    int32_t rawX = readS32BE(d + 68);
    int32_t rawY = readS32BE(d + 72);
    int32_t rawZ = readS32BE(d + 76);
    uint8_t major = d[8];

    if (std::abs(rawX - kD50X) > 1 || std::abs(rawY - kD50Y) > 1 || std::abs(rawZ - kD50Z) > 1) {
        cb.info(sfmt("Raw bytes: X=0x%08X Y=0x%08X Z=0x%08X",
                     static_cast<unsigned>(rawX),
                     static_cast<unsigned>(rawY),
                     static_cast<unsigned>(rawZ)));
        cb.info(sfmt("Float:     X=%.6f   Y=%.6f   Z=%.6f",
                     static_cast<double>(rawX) / 65536.0,
                     static_cast<double>(rawY) / 65536.0,
                     static_cast<double>(rawZ) / 65536.0));
        cb.info("D50 spec:  X=0x0000F6D6 Y=0x00010000 Z=0x0000D32D");
        if (major >= 5) {
            cb.warn("PCS illuminant is not D50 (valid for ICC.2/v5 spectral profiles)");
        } else {
            cb.warn("PCS illuminant does not match D50 (>1 LSB deviation)",
                    "CWE-20: ICC.1-2022-05 §7.2.16 requires exact D50 for v2/v4");
        }
    }

    return cb.done("PCS illuminant is exact D50");
}

REGISTER_HEURISTIC(129, "PCS Illuminant D50",
    "§7.2.16", "ICC.1-2022-05",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h129_pcs_illuminant_d50);

static CheckResult check_h130_tag_alignment(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 132) return CheckResult::skip("File too small for tag table");

    int misaligned = 0;
    int checked = 0;
    for (const auto& tag : pv.rawTagTable()) {
        ++checked;
        if (tag.offset != 0 && (tag.offset % 4) != 0) {
            cb.warn(sfmt("Tag '%s': offset %u not 4-byte aligned (mod 4 = %u)",
                         sigStr(tag.signature).c_str(), tag.offset, tag.offset % 4),
                    "CWE-20: Tag data must be 4-byte aligned");
            ++misaligned;
        }
    }

    if (misaligned > 0) {
        cb.warn(sfmt("%d of %d tag(s) misaligned (ICC.1-2022-05 §7.3.1)", misaligned, checked),
                "CWE-20: Tag data must be 4-byte aligned");
    }

    return cb.done(sfmt("All %d tags are 4-byte aligned", checked));
}

REGISTER_HEURISTIC(130, "Tag Alignment",
    "§7.3.1", "ICC.1-2022-05",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h130_tag_alignment);

static CheckResult check_h131_profile_id_md5(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 128) return CheckResult::skip("File too small for header");

    const uint8_t* d = pv.rawData();
    bool idIsZero = true;
    for (int i = 84; i < 100; ++i) {
        if (d[i] != 0) {
            idIsZero = false;
            break;
        }
    }
    if (idIsZero) {
        return cb.done("Profile ID not computed (zero)");
    }

    std::vector<uint8_t> buf(d, d + pv.rawSize());
    std::memset(buf.data() + 44, 0, 4);
    std::memset(buf.data() + 64, 0, 4);
    std::memset(buf.data() + 84, 0, 16);

    unsigned char md5[EVP_MAX_MD_SIZE];
    unsigned int md5Len = 0;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return CheckResult::error("Failed to allocate MD5 context");
    EVP_DigestInit_ex(ctx, EVP_md5(), nullptr);
    EVP_DigestUpdate(ctx, buf.data(), buf.size());
    EVP_DigestFinal_ex(ctx, md5, &md5Len);
    EVP_MD_CTX_free(ctx);

    if (md5Len < 16) {
        return CheckResult::error("Failed to compute Profile ID MD5");
    }
    if (std::memcmp(md5, d + 84, 16) != 0) {
        cb.warn("Profile ID MD5 MISMATCH — profile may be modified/corrupted",
                "CWE-354: Profile ID does not match computed hash");
    }

    return cb.done("Profile ID matches computed MD5");
}

REGISTER_HEURISTIC(131, "Profile Id MD5",
    "", "",
    "CWE-345", "CVE-2022-26730",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h131_profile_id_md5);

static CheckResult check_h132_chad_determinant(const ProfileView& pv) {
    CheckBuilder cb;
    auto tag = pv.rawTag(kSigChad);
    if (!tag) {
        return cb.done("No chad tag present");
    }

    const uint8_t* d = pv.rawData();
    if (!d || !rawRangeAccessible(pv.rawSize(), tag->offset, tag->size) || tag->size < 44) {
        cb.warn("chad tag present but not valid S15Fixed16 3x3 matrix");
        return cb.done("Chad matrix checked");
    }
    if (readU32BE(d + tag->offset) != 0x73663332u) { // 'sf32'
        cb.warn("chad tag present but not valid S15Fixed16 3x3 matrix");
        return cb.done("Chad matrix checked");
    }

    double m[3][3];
    for (int r = 0; r < 3; ++r) {
        for (int c = 0; c < 3; ++c) {
            m[r][c] = readS15Fixed16(d + tag->offset + 8 + static_cast<size_t>(r * 3 + c) * 4);
        }
    }

    double det = m[0][0] * (m[1][1] * m[2][2] - m[1][2] * m[2][1])
               - m[0][1] * (m[1][0] * m[2][2] - m[1][2] * m[2][0])
               + m[0][2] * (m[1][0] * m[2][1] - m[1][1] * m[2][0]);

    if (std::fabs(det) < 1e-6) {
        cb.warn("chad matrix is singular or near-singular (det ≈ 0)",
                "CWE-369: Division-by-zero in chromatic adaptation inverse");
    } else if (det < 0.0) {
        cb.warn("chad matrix has negative determinant (reflection transform)");
    }

    bool extreme = false;
    for (auto& row : m) {
        for (double value : row) {
            if (std::fabs(value) > 20.0) {
                extreme = true;
            }
        }
    }
    if (extreme) {
        cb.warn("chad matrix contains extreme values (|element| > 20.0)",
                "CWE-682: May cause float overflow in adaptation transforms");
    }

    return cb.done("chad matrix is invertible (det > 0)");
}

REGISTER_HEURISTIC(132, "Chad Determinant",
    "", "",
    "CWE-682", "CVE-2022-26730",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h132_chad_determinant);

static CheckResult check_h133_flags_reserved_bits(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 48) return CheckResult::skip("Cannot read flags at offset 44");
    const uint8_t* raw = pv.rawData();
    if (!raw) return CheckResult::skip("No raw bytes available");
    uint32_t flags = readU32BE(raw + 44);
    uint32_t reservedBits = flags & 0xFFFFFFFCu;
    if (reservedBits != 0) {
        cb.warn(sfmt("Reserved flag bits non-zero (0x%08X)", reservedBits),
                "CWE-20: Bits 2-31 must be zero per spec");
    }

    return cb.done("Reserved flag bits are zero");
}

REGISTER_HEURISTIC(133, "Flags Reserved Bits",
    "§7.2.11", "ICC.1-2022-05",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h133_flags_reserved_bits);

static CheckResult check_h134_tag_type_reserved_bytes(const ProfileView& pv) {
    CheckBuilder cb;
    const uint8_t* d = pv.rawData();
    size_t len = pv.rawSize();
    if (!d || len < 132) return CheckResult::skip("Cannot read tag count");

    int checked = 0;
    for (const auto& tag : pv.rawTagTable()) {
        if (tag.size < 8 || !rawRangeAccessible(len, tag.offset, 8)) {
            continue;
        }
        const uint8_t* reserved = d + tag.offset + 4;
        ++checked;
        if (reserved[0] != 0 || reserved[1] != 0 || reserved[2] != 0 || reserved[3] != 0) {
            cb.warn(sfmt("Tag '%s' (offset %u): reserved bytes 4-7 = %02X %02X %02X %02X (should be 00)",
                         sigStr(tag.signature).c_str(), tag.offset,
                         reserved[0], reserved[1], reserved[2], reserved[3]),
                    "CWE-20: May indicate crafted/malformed tag data");
        }
    }

    if (checked == 0) return CheckResult::skip("No tags to check");
    return cb.done(sfmt("All %d tag types have zeroed reserved bytes", checked));
}

REGISTER_HEURISTIC(134, "Tag Type Reserved Bytes",
    "§10.1", "ICC.1-2022-05",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h134_tag_type_reserved_bytes);

static CheckResult check_h135_duplicate_tag_signatures(const ProfileView& pv) {
    CheckBuilder cb;
    if (pv.rawSize() < 132) return CheckResult::skip("Cannot read tag count");
    const uint8_t* raw = pv.rawData();
    if (!raw || readU32BE(raw + 36) != 0x61637370u) {
        return CheckResult::skip("Invalid ICC magic");
    }
    uint32_t declaredTagCount = readU32BE(raw + 128);
    if (declaredTagCount > 200) {
        return CheckResult::skip(sfmt("Tag count %u too high for safe iteration", declaredTagCount));
    }

    std::vector<uint32_t> signatures;
    signatures.reserve(pv.rawTagTable().size());
    for (const auto& tag : pv.rawTagTable()) {
        signatures.push_back(tag.signature);
    }
    if (signatures.empty()) return CheckResult::skip("No tags to check");

    std::sort(signatures.begin(), signatures.end());
    for (size_t i = 1; i < signatures.size(); ++i) {
        if (signatures[i] == signatures[i - 1]) {
            cb.warn(sfmt("Duplicate tag signature: '%s' (0x%08X)",
                         sigStr(signatures[i]).c_str(), signatures[i]),
                    "CWE-694: Use of Multiple Resources with Duplicate Identifier");
        }
    }

    return cb.done("All tag signatures are unique");
}

REGISTER_HEURISTIC(135, "Duplicate Tag Signatures",
    "§7.3.1", "ICC.1-2022-05",
    "CWE-694", "",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h135_duplicate_tag_signatures);


} // namespace icctest
