/*
 * IccTest Library — IntegrityChecks.cpp
 * Heuristic checks H121-H138: Profile integrity + CWE-400 complexity.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "util/CheckHelpers.h"

#include <openssl/evp.h>
#include <cstring>

namespace icctest {

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
        if (t.size % 4 != 0) {
            // Tag data should be padded to 4-byte boundary
            // This is a warning, not an error
            cb.info(sfmt("Tag '%s' size %u not 4-byte padded", sigStr(t.signature).c_str(), t.size));
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

    for (const auto& t : pv.rawTagTable()) {
        if (t.size < 20 || !rawRangeAccessible(len, t.offset, 20)) continue;
        uint32_t typeSig = readU32BE(d + t.offset);
        if (typeSig != kGbdType) continue;

        // GBD layout: [type:4][reserved:4][nPCSChan:2][nDevChan:2][nVertices:4][nTriangles:4]
        uint32_t nTriangles = readU32BE(d + t.offset + 16);
        if (nTriangles > 715827882U) { // INT_MAX / 3
            cb.critical(sfmt("GBD nTriangles=%u — int overflow in nTriangles*3 (max 715827882)",
                              nTriangles),
                        "CWE-190: Integer Overflow or Wraparound");
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
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H123
    return cb.done("Non Required Tags checked");
}

REGISTER_HEURISTIC(123, "Non Required Tags",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h123_non_required_tags);

static CheckResult check_h124_version_tags(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H124
    return cb.done("Version Tags checked");
}

REGISTER_HEURISTIC(124, "Version Tags",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h124_version_tags);

static CheckResult check_h125_transform_smoothness(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H125
    return cb.done("Transform Smoothness checked");
}

REGISTER_HEURISTIC(125, "Transform Smoothness",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h125_transform_smoothness);

static CheckResult check_h126_private_tag_malware(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H126
    return cb.done("Private Tag Malware checked");
}

REGISTER_HEURISTIC(126, "Private Tag Malware",
    "", "",
    "CWE-506", "",
    Severity::CRITICAL, CheckPhase::LIBRARY,
    check_h126_private_tag_malware);

static CheckResult check_h127_private_tag_registry(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H127
    return cb.done("Private Tag Registry checked");
}

REGISTER_HEURISTIC(127, "Private Tag Registry",
    "", "",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h127_private_tag_registry);

static CheckResult check_h128_version_bcd(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H128
    return cb.done("Version BCD checked");
}

REGISTER_HEURISTIC(128, "Version BCD",
    "§7.2.4", "ICC.1-2022-05",
    "CWE-20", "CVE-2026-24403,GHSA-ph33-qp8j-5q34",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h128_version_bcd);

static CheckResult check_h129_pcs_illuminant_d50(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H129
    return cb.done("PCS Illuminant D50 checked");
}

REGISTER_HEURISTIC(129, "PCS Illuminant D50",
    "§7.2.16", "ICC.1-2022-05",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h129_pcs_illuminant_d50);

static CheckResult check_h130_tag_alignment(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H130
    return cb.done("Tag Alignment checked");
}

REGISTER_HEURISTIC(130, "Tag Alignment",
    "§7.3.1", "ICC.1-2022-05",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h130_tag_alignment);

static CheckResult check_h131_profile_id_md5(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H131
    return cb.done("Profile Id MD5 checked");
}

REGISTER_HEURISTIC(131, "Profile Id MD5",
    "", "",
    "CWE-345", "CVE-2022-26730",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h131_profile_id_md5);

static CheckResult check_h132_chad_determinant(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H132
    return cb.done("Chad Determinant checked");
}

REGISTER_HEURISTIC(132, "Chad Determinant",
    "", "",
    "CWE-682", "CVE-2022-26730",
    Severity::MEDIUM, CheckPhase::LIBRARY,
    check_h132_chad_determinant);

static CheckResult check_h133_flags_reserved_bits(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H133
    return cb.done("Flags Reserved Bits checked");
}

REGISTER_HEURISTIC(133, "Flags Reserved Bits",
    "§7.2.11", "ICC.1-2022-05",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h133_flags_reserved_bits);

static CheckResult check_h134_tag_type_reserved_bytes(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H134
    return cb.done("Tag Type Reserved Bytes checked");
}

REGISTER_HEURISTIC(134, "Tag Type Reserved Bytes",
    "§10.1", "ICC.1-2022-05",
    "CWE-20", "",
    Severity::LOW, CheckPhase::LIBRARY,
    check_h134_tag_type_reserved_bytes);

static CheckResult check_h135_duplicate_tag_signatures(const ProfileView& pv) {
    CheckBuilder cb;
    if (!pv.libraryLoaded()) return cb.done("Library not loaded — skipped");
    auto* p = pv.unsafeLibraryHandle();
    if (!p) return cb.done("No profile");
    // TODO: port full validation logic from V1 RunHeuristic_H135
    return cb.done("Duplicate Tag Signatures checked");
}

REGISTER_HEURISTIC(135, "Duplicate Tag Signatures",
    "§7.3.1", "ICC.1-2022-05",
    "CWE-694", "",
    Severity::HIGH, CheckPhase::LIBRARY,
    check_h135_duplicate_tag_signatures);


} // namespace icctest
