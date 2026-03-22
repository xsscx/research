// CfSecurityChecks.cpp — V2 conformance checks (SECURITY)
// 7 checks: CF-091..CF-162
//
// Ported from V1 IccConformanceSecurity.cpp
//
// SPDX-License-Identifier: MIT

#include <icctest/CheckRegistry.h>
#include <icctest/ProfileView.h>
#include <icctest/CheckResult.h>

#include "IccProfile.h"
#include "IccTag.h"
#include "IccUtil.h"

#include <cstring>
#include <cstdint>
#include <vector>
#include <string>

using namespace icctest;

// Helpers for raw byte scanning
static inline uint32_t readU32BE(const uint8_t *p) {
    return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];
}
static inline uint32_t readU32LE(const uint8_t *p) {
    return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}

// ---------------------------------------------------------------------------
// CF-091: Malware Signature Scan
// ---------------------------------------------------------------------------
static CheckResult check_cf091_malware_signature_scan(const ProfileView& pv) {
    const uint8_t *data = pv.rawData();
    size_t size = pv.rawSize();
    if (!data || size <= 128) return CheckResult::skip("Profile too small for malware scan");
    if (size > 100*1024*1024) return CheckResult::skip("Profile too large for scan");

    std::vector<Finding> findings;
    CheckID id{CheckID::Kind::Conformance, 91};

    size_t scanSize = size > 10485760 ? 10485760 : size;
    struct Sig { const uint8_t *bytes; size_t len; const char *desc; };
    static const uint8_t elf[] = {0x7F,'E','L','F'};
    static const uint8_t mz[] = {'M','Z'};
    static const uint8_t macho64[] = {0xCF,0xFA,0xED,0xFE};
    static const uint8_t macho32[] = {0xCE,0xFA,0xED,0xFE};
    static const uint8_t shebang[] = {'#','!','/'};
    static const Sig sigs[] = {
        {elf, 4, "ELF executable header"},
        {mz, 2, "PE/MZ executable header"},
        {macho64, 4, "Mach-O 64-bit header"},
        {macho32, 4, "Mach-O 32-bit header"},
        {shebang, 3, "Script shebang (#!)"},
    };

    for (size_t i = 128; i + 4 <= scanSize && findings.size() < 5; i++) {
        for (const auto& s : sigs) {
            if (i + s.len > scanSize) continue;
            if (memcmp(&data[i], s.bytes, s.len) != 0) continue;
            // PE/MZ needs PE header validation
            if (s.len == 2 && s.bytes[0] == 'M') {
                if (i + 64 > scanSize) continue;
                uint32_t peOff = readU32LE(&data[i+60]);
                if (peOff >= 1024 || i+peOff+4 > scanSize ||
                    data[i+peOff] != 'P' || data[i+peOff+1] != 'E') continue;
            }
            findings.push_back({id, Severity::CRITICAL,
                std::string(s.desc) + " at offset 0x" + ([i]{
                    char buf[20]; snprintf(buf,sizeof(buf),"%zX",i); return std::string(buf);
                })(), "", "CWE-506: Embedded Malicious Code"});
            break;
        }
    }

    if (findings.empty())
        return CheckResult::ok("No malware signatures in tag data");
    return {CheckResult::Status::FINDINGS, "Malware signatures detected", std::move(findings)};
}

// ---------------------------------------------------------------------------
// CF-092: Private Tag Presence
// ---------------------------------------------------------------------------
static CheckResult check_cf092_private_tag_presence(const ProfileView& pv) {
    if (!pv.libraryLoaded()) return CheckResult::skip("Library failed to load");
    auto* pIcc = pv.unsafeLibraryHandle();
    std::vector<Finding> findings;
    CheckID id{CheckID::Kind::Conformance, 92};

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
        icSigRedMatrixColumnTag, icSigRedTRCTag,
        icSigTechnologyTag, icSigViewingCondDescTag,
        icSigViewingConditionsTag, icSigColorantOrderTag,
        icSigColorantTableTag, icSigColorantTableOutTag,
        icSigProfileSequceIdTag,
        icSigPerceptualRenderingIntentGamutTag,
        icSigSaturationRenderingIntentGamutTag,
        (icTagSignature)0x44324230, // D2B0
        (icTagSignature)0x44324231, // D2B1
        (icTagSignature)0x44324232, // D2B2
        (icTagSignature)0x42324430, // B2D0
        (icTagSignature)0x42324431, // B2D1
        (icTagSignature)0x42324432, // B2D2
        (icTagSignature)0
    };

    for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
        icTagSignature sig = it->TagInfo.sig;
        bool isKnown = false;
        for (int k = 0; knownTags[k] != (icTagSignature)0; k++) {
            if (sig == knownTags[k]) { isKnown = true; break; }
        }
        if (!isKnown) {
            char sigStr[5] = {};
            sigStr[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));
            sigStr[1] = static_cast<char>(static_cast<unsigned char>((sig >> 16) & 0xFF));
            sigStr[2] = static_cast<char>(static_cast<unsigned char>((sig >> 8) & 0xFF));
            sigStr[3] = static_cast<char>(static_cast<unsigned char>(sig & 0xFF));
            findings.push_back({id, Severity::INFO,
                "Private/unregistered tag: '" + std::string(sigStr) + "'",
                "offset=" + std::to_string(it->TagInfo.offset) +
                " size=" + std::to_string(it->TagInfo.size), ""});
        }
    }

    if (findings.empty())
        return CheckResult::ok("All tags are registered ICC signatures");
    return {CheckResult::Status::FINDINGS,
        std::to_string(findings.size()) + " private/unregistered tag(s)",
        std::move(findings)};
}

// ---------------------------------------------------------------------------
// CF-093: Private Tag Content Scan
// ---------------------------------------------------------------------------
static CheckResult check_cf093_private_tag_content_scan(const ProfileView& pv) {
    const uint8_t *fileData = pv.rawData();
    size_t fileSize = pv.rawSize();
    if (!fileData || fileSize <= 132) return CheckResult::skip("Profile too small");
    if (!pv.libraryLoaded()) return CheckResult::skip("Library failed to load");
    auto* pIcc = pv.unsafeLibraryHandle();

    std::vector<Finding> findings;
    CheckID id{CheckID::Kind::Conformance, 93};

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
        icSigRedMatrixColumnTag, icSigRedTRCTag,
        icSigTechnologyTag, icSigViewingCondDescTag,
        icSigViewingConditionsTag, icSigColorantOrderTag,
        icSigColorantTableTag, icSigColorantTableOutTag,
        icSigProfileSequceIdTag,
        icSigPerceptualRenderingIntentGamutTag,
        icSigSaturationRenderingIntentGamutTag,
        (icTagSignature)0
    };

    int privateScanned = 0;
    for (auto it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
        icTagSignature sig = it->TagInfo.sig;
        bool isKnown = false;
        for (int k = 0; knownTags[k] != (icTagSignature)0; k++) {
            if (sig == knownTags[k]) { isKnown = true; break; }
        }
        if (isKnown) continue;

        uint32_t off = it->TagInfo.offset;
        uint32_t sz = it->TagInfo.size;
        if (off >= fileSize || off + sz > fileSize || sz < 4) continue;

        privateScanned++;
        const uint8_t *d = &fileData[off];

        char sigStr[5] = {};
        sigStr[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));
        sigStr[1] = static_cast<char>(static_cast<unsigned char>((sig >> 16) & 0xFF));
        sigStr[2] = static_cast<char>(static_cast<unsigned char>((sig >> 8) & 0xFF));
        sigStr[3] = static_cast<char>(static_cast<unsigned char>(sig & 0xFF));

        if (d[0]==0x7F && d[1]=='E' && d[2]=='L' && d[3]=='F') {
            findings.push_back({id, Severity::CRITICAL,
                "ELF executable in private tag '" + std::string(sigStr) + "'",
                "", "CWE-506: Embedded Malicious Code"});
        }
        if (d[0]=='#' && d[1]=='!' && d[2]=='/') {
            findings.push_back({id, Severity::CRITICAL,
                "Script shebang in private tag '" + std::string(sigStr) + "'",
                "", "CWE-506: Embedded Malicious Code"});
        }
        if (sz >= 64 && d[0]=='M' && d[1]=='Z') {
            uint32_t peOff = readU32LE(&d[60]);
            if (peOff < sz - 4 && d[peOff]=='P' && d[peOff+1]=='E') {
                findings.push_back({id, Severity::CRITICAL,
                    "PE executable in private tag '" + std::string(sigStr) + "'",
                    "", "CWE-506: Embedded Malicious Code"});
            }
        }
    }

    if (findings.empty()) {
        if (privateScanned == 0)
            return CheckResult::ok("No private tags to scan");
        return CheckResult::ok(std::to_string(privateScanned) + " private tag(s) scanned — clean");
    }
    return {CheckResult::Status::FINDINGS, "Malware in private tags", std::move(findings)};
}

// ---------------------------------------------------------------------------
// CF-094: NOP/Shellcode Pattern Scan
// ---------------------------------------------------------------------------
static CheckResult check_cf094_nop_shellcode_pattern_scan(const ProfileView& pv) {
    const uint8_t *data = pv.rawData();
    size_t size = pv.rawSize();
    if (!data || size <= 128) return CheckResult::skip("Profile too small");
    if (size > 100*1024*1024) return CheckResult::skip("Profile too large");

    std::vector<Finding> findings;
    CheckID id{CheckID::Kind::Conformance, 94};

    size_t scanSize = size > 10485760 ? 10485760 : size;
    for (size_t i = 128; i + 16 <= scanSize; ) {
        // x86 NOP sled
        if (data[i] == 0x90) {
            size_t run = 1;
            while (i+run < scanSize && data[i+run] == 0x90 && run < 256) run++;
            if (run >= 16) {
                findings.push_back({id, Severity::CRITICAL,
                    "x86 NOP sled at offset 0x" + ([i]{
                        char b[20]; snprintf(b,sizeof(b),"%zX",i); return std::string(b);
                    })(), std::to_string(run) + " bytes",
                    "CWE-506: Suspicious shellcode pattern"});
                i += run; continue;
            }
        }
        // ARM64 NOP sled
        if (i + 16 <= scanSize &&
            data[i]==0x1F && data[i+1]==0x20 && data[i+2]==0x03 && data[i+3]==0xD5) {
            int armNops = 1;
            size_t j = i + 4;
            while (j+4 <= scanSize && data[j]==0x1F && data[j+1]==0x20 &&
                   data[j+2]==0x03 && data[j+3]==0xD5 && armNops < 64) {
                armNops++; j += 4;
            }
            if (armNops >= 4) {
                findings.push_back({id, Severity::CRITICAL,
                    "ARM64 NOP sled at offset 0x" + ([i]{
                        char b[20]; snprintf(b,sizeof(b),"%zX",i); return std::string(b);
                    })(), std::to_string(armNops) + " instructions",
                    "CWE-506: Suspicious shellcode pattern"});
                i = j; continue;
            }
        }
        i++;
    }

    if (findings.empty())
        return CheckResult::ok("No NOP sled or shellcode patterns detected");
    return {CheckResult::Status::FINDINGS, "Shellcode patterns", std::move(findings)};
}

// ---------------------------------------------------------------------------
// CF-157: Embedded Profile Recursive Depth
// ---------------------------------------------------------------------------
static CheckResult check_cf157_embedded_profile_recursive_depth(const ProfileView& pv) {
    const uint8_t *data = pv.rawData();
    size_t size = pv.rawSize();
    if (!data || size < 132) return CheckResult::skip("Profile too small");

    std::vector<Finding> findings;
    CheckID id{CheckID::Kind::Conformance, 157};

    // Scan for 'acsp' magic at offset+36 within tag data (embedded profiles)
    int nestCount = 0;
    static const uint8_t acsp[] = {'a','c','s','p'};
    for (size_t i = 128; i + 40 <= size && nestCount < 20; i += 4) {
        if (memcmp(&data[i + 36 - (i > 36 ? 0 : 36)], acsp, 4) == 0) {
            // Verify it looks like a profile header (size field at offset i)
            if (i + 128 <= size) {
                uint32_t embSize = readU32BE(&data[i]);
                if (embSize >= 128 && embSize <= size - i) {
                    nestCount++;
                }
            }
        }
    }

    // Also check raw tag table for embedded profile tags
    if (pv.libraryLoaded()) {
        auto* pIcc = pv.unsafeLibraryHandle();
        CIccTag *pEmb = pIcc->FindTag((icTagSignature)0x656D6270); // 'embp'
        if (pEmb) nestCount++;
    }

    if (nestCount > 5) {
        findings.push_back({id, Severity::HIGH,
            "Deep embedded profile nesting: " + std::to_string(nestCount) + " levels",
            "Max recommended: 5", "CWE-674: Uncontrolled Recursion"});
    }

    if (findings.empty())
        return CheckResult::ok("Embedded profile depth acceptable (" +
            std::to_string(nestCount) + " levels)");
    return {CheckResult::Status::FINDINGS, "Excessive nesting", std::move(findings)};
}

// ---------------------------------------------------------------------------
// CF-158: Embedded Profile Size Bounds
// ---------------------------------------------------------------------------
static CheckResult check_cf158_embedded_profile_size_bounds(const ProfileView& pv) {
    const uint8_t *data = pv.rawData();
    size_t size = pv.rawSize();
    if (!data || size < 132) return CheckResult::skip("Profile too small");

    std::vector<Finding> findings;
    CheckID id{CheckID::Kind::Conformance, 158};

    // Check tag table for any tag that contains an embedded profile
    auto tags = pv.rawTagTable();
    for (const auto& t : tags) {
        if (t.offset + t.size > size) continue;
        if (t.size < 132) continue;
        // Check if tag data starts with a valid profile header
        if (t.offset + 40 > size) continue;
        uint32_t embSize = readU32BE(&data[t.offset]);
        if (embSize >= 128 && t.offset + 36 + 4 <= size) {
            if (memcmp(&data[t.offset + 36], "acsp", 4) == 0) {
                // Embedded profile found — validate size
                if (embSize > t.size) {
                    findings.push_back({id, Severity::HIGH,
                        "Embedded profile claims " + std::to_string(embSize) +
                        " bytes but tag only has " + std::to_string(t.size),
                        "", "CWE-131: Incorrect Calculation of Buffer Size"});
                }
                if (embSize > size) {
                    findings.push_back({id, Severity::CRITICAL,
                        "Embedded profile size " + std::to_string(embSize) +
                        " exceeds parent profile " + std::to_string(size),
                        "", "CWE-131: Incorrect Calculation of Buffer Size"});
                }
            }
        }
    }

    if (findings.empty())
        return CheckResult::ok("Embedded profile sizes valid");
    return {CheckResult::Status::FINDINGS, "Embedded size issues", std::move(findings)};
}

// ---------------------------------------------------------------------------
// CF-162: Dictionary Entry Count Bounds
// ---------------------------------------------------------------------------
static CheckResult check_cf162_dictionary_entry_count_bounds(const ProfileView& pv) {
    const uint8_t *data = pv.rawData();
    size_t size = pv.rawSize();
    if (!data || size < 132) return CheckResult::skip("Profile too small");

    std::vector<Finding> findings;
    CheckID id{CheckID::Kind::Conformance, 162};

    // Scan tags for dictionary type ('dict' = 0x64696374)
    auto tags = pv.rawTagTable();
    for (const auto& t : tags) {
        if (t.offset + 12 > size || t.size < 12) continue;
        uint32_t typeSig = readU32BE(&data[t.offset]);
        if (typeSig != 0x64696374) continue; // not a dict tag

        // Dictionary type layout: [typeSig:4][reserved:4][count:4]...
        uint32_t count = readU32BE(&data[t.offset + 8]);
        if (count > 10000) {
            findings.push_back({id, Severity::HIGH,
                "Dictionary tag with " + std::to_string(count) + " entries",
                "Threshold: 10000 (potential OOM)", "CWE-400: Uncontrolled Resource Consumption"});
        }
        // Each entry needs at least some bytes — sanity check
        if (count > 0 && t.size / count < 4) {
            findings.push_back({id, Severity::HIGH,
                "Dictionary entries exceed available data",
                std::to_string(count) + " entries in " + std::to_string(t.size) + " bytes",
                "CWE-789: Memory Allocation with Excessive Size"});
        }
    }

    if (findings.empty())
        return CheckResult::ok("Dictionary entry counts valid");
    return {CheckResult::Status::FINDINGS, "Dictionary bounds issues", std::move(findings)};
}

// ── Registrations (7 checks) ──

REGISTER_CONFORMANCE(91, "Malware Signature Scan",
    "PAWG S8 — embedded executable content", "PAWG Checklist",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf091_malware_signature_scan);

REGISTER_CONFORMANCE(92, "Private Tag Presence",
    "§9 (private tag identification)", "ICC.1-2022-05",
    "", "", Severity::INFO, CheckPhase::CONFORMANCE,
    check_cf092_private_tag_presence);

REGISTER_CONFORMANCE(93, "Private Tag Content Scan",
    "§9 (private tag content safety)", "ICC.1-2022-05",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf093_private_tag_content_scan);

REGISTER_CONFORMANCE(94, "NOP/Shellcode Pattern Scan",
    "PAWG S13 — NOP sled and shellcode patterns", "PAWG Checklist",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf094_nop_shellcode_pattern_scan);

REGISTER_CONFORMANCE(157, "Embedded Profile Recursive Depth",
    "Maximum nesting depth for embedded profiles (anti-bomb protection)", "Security",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf157_embedded_profile_recursive_depth);

REGISTER_CONFORMANCE(158, "Embedded Profile Size Bounds",
    "Embedded profile size validation against parent profile size", "Security",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf158_embedded_profile_size_bounds);

REGISTER_CONFORMANCE(162, "Dictionary Entry Count Bounds",
    "Unreasonably large dictionary entry counts indicate potential OOM attack (CWE-400)", "ICC.2-2023 §10.2.6",
    "", "", Severity::HIGH, CheckPhase::CONFORMANCE,
    check_cf162_dictionary_entry_count_bounds);
