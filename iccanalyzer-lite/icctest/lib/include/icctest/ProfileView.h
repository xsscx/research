/*
 * IccTest Library — ProfileView.h
 * Defensive wrapper around the iccDEV CIccProfile library.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 *
 * ProfileView opens an ICC profile once, caches raw bytes AND library parse,
 * and provides safe accessors with null checks, try/catch, and bounds validation.
 * All iccDEV API calls go through this class — no raw FindTag/GetType/dynamic_cast
 * anywhere else in the library.
 */

#ifndef ICCTEST_PROFILE_VIEW_H
#define ICCTEST_PROFILE_VIEW_H

#include "CheckResult.h"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <functional>
#include <typeinfo>

// iccDEV types — IccProfLibConf.h must come before icProfileHeader.h
#include "IccProfLibConf.h"
#include "icProfileHeader.h"

// Forward-declare iccDEV classes to avoid pulling in full implementations.
class CIccProfile;
class CIccTag;

namespace icctest {

/// Raw tag table entry parsed directly from bytes (no library dependency).
struct RawTagEntry {
    uint32_t signature;
    uint32_t offset;
    uint32_t size;
};

/// Image format detected from magic bytes.
enum class ImageFormat : uint8_t {
    UNKNOWN = 0,
    ICC,        // 'acsp' at offset 36
    TIFF_LE,    // 'II\x2a\x00'
    TIFF_BE,    // 'MM\x00\x2a'
    BIGTIFF_LE, // 'II\x2b\x00'
    BIGTIFF_BE, // 'MM\x00\x2b'
    PNG,        // '\x89PNG'
    JPEG,       // '\xff\xd8\xff'
};

/// Parsed ICC profile header (128 bytes, always safe — from raw bytes).
struct ProfileHeader {
    uint32_t size;
    uint32_t cmmType;
    uint32_t version;         // BCD: byte0=major, byte1=minor.bugfix
    uint32_t deviceClass;
    uint32_t colorSpace;
    uint32_t pcs;
    uint16_t year, month, day, hour, minute, second;
    uint32_t magic;           // Should be 0x61637370 ('acsp')
    uint32_t platform;
    uint32_t flags;
    uint32_t manufacturer;
    uint32_t model;
    uint64_t attributes;
    uint32_t renderingIntent;
    int32_t  illuminantX;     // s15Fixed16
    int32_t  illuminantY;
    int32_t  illuminantZ;
    uint32_t creator;
    std::array<uint8_t, 16> profileId;
    std::array<uint8_t, 28> reserved;   // Bytes 100-127, should be all zero
};

/// View of a single tag through the library (non-owning).
class TagView {
public:
    TagView(CIccTag* tag, uint32_t size, uint32_t offset, icTagSignature sig);

    icTagTypeSignature type() const;
    uint32_t size() const { return m_size; }
    uint32_t offset() const { return m_offset; }
    icTagSignature signature() const { return m_sig; }

    /// Safe downcast — returns nullopt if tag is not of type T.
    template<typename T>
    std::optional<std::reference_wrapper<const T>> as() const {
        if (!m_tag) return std::nullopt;
        try {
            auto* p = dynamic_cast<const T*>(m_tag);
            if (!p) return std::nullopt;
            return std::cref(*p);
        } catch (...) {
            return std::nullopt;
        }
    }

    /// Safe Describe — try/catch + Validate pre-check.
    std::optional<std::string> describe() const;

    /// Raw library handle (escape hatch).
    CIccTag* rawHandle() const { return m_tag; }

private:
    CIccTag*       m_tag;
    uint32_t       m_size;
    uint32_t       m_offset;
    icTagSignature m_sig;
};

/// Custom deleter for CIccProfile pointers.
struct ProfileDeleter {
    void operator()(CIccProfile* p) const;
};

/// Defensive iccDEV wrapper. Opens once, caches raw bytes + library parse.
///
/// All iccDEV API calls in the entire IccTest library go through this class.
/// ProfileView performs UB pre-scanning on construction and provides safe
/// tag access with null checks and try/catch on every operation.
class ProfileView {
public:
    ~ProfileView();
    ProfileView(ProfileView&&) noexcept;
    ProfileView& operator=(ProfileView&&) noexcept;

    // Non-copyable
    ProfileView(const ProfileView&) = delete;
    ProfileView& operator=(const ProfileView&) = delete;

    /// Open a profile from a file path.
    static std::optional<ProfileView> open(const std::filesystem::path& path,
                                           bool skipLibraryOnUB = true);

    /// Open a profile from a memory buffer.
    static std::optional<ProfileView> open(const uint8_t* data, size_t len,
                                           bool skipLibraryOnUB = true);

    // ── Header access (always safe — parsed from raw bytes) ──

    const ProfileHeader& header() const { return m_header; }

    /// Fill a ProfileMetadata struct from the parsed header.
    ProfileMetadata metadata() const;

    // ── Tag access (defensive — null checks + try/catch) ──

    /// Get a tag by signature. Returns nullopt if not found or library error.
    std::optional<TagView> tag(icTagSignature sig) const;

    /// Check if a tag exists.
    bool hasTag(icTagSignature sig) const;

    /// Get all tag signatures present in the profile.
    std::vector<icTagSignature> tagSignatures() const;

    /// Number of tags in the tag table.
    size_t tagCount() const;

    // ── Raw byte access (for checks that don't trust the library) ──

    /// Full raw file contents.
    const uint8_t* rawData() const { return m_rawData.data(); }
    size_t rawSize() const { return m_rawData.size(); }

    /// Get raw tag entry by signature (from raw parse, not library).
    std::optional<RawTagEntry> rawTag(uint32_t sig) const;

    /// All raw tag entries parsed from the binary tag table.
    const std::vector<RawTagEntry>& rawTagTable() const { return m_rawTags; }

    // ── Image detection ──

    bool isImage() const;
    ImageFormat imageFormat() const;

    // ── UB pre-scan results ──

    /// Whether known UB-triggering patterns were detected in raw bytes.
    bool hasKnownUBPatterns() const { return m_ubPatternsDetected; }

    /// Whether raw pre-scan found patterns unsafe for upstream library load.
    bool requiresLibraryQuarantine() const { return m_libraryLoadUnsafe; }

    /// Descriptions of detected UB patterns.
    const std::vector<std::string>& ubPatternDescriptions() const {
        return m_ubDescriptions;
    }

    // ── Library handle (escape hatch, use sparingly) ──

    /// Returns the underlying CIccProfile pointer. May be null if library
    /// parsing failed. Logged when called.
    CIccProfile* unsafeLibraryHandle() const { return m_profile.get(); }

    /// Whether the library successfully parsed this profile.
    bool libraryLoaded() const { return m_profile != nullptr; }

    /// Path of the profile on disk (empty for memory buffers).
    const std::filesystem::path& filePath() const { return m_path; }

private:
    ProfileView() = default;

    void parseHeader();
    void parseRawTagTable();
    void runUBPreScan();
    bool loadLibrary(bool skipLibraryOnUB);

    std::unique_ptr<CIccProfile, ProfileDeleter> m_profile;
    std::vector<uint8_t>       m_rawData;
    std::vector<RawTagEntry>   m_rawTags;
    ProfileHeader              m_header{};
    bool                       m_ubPatternsDetected = false;
    bool                       m_libraryLoadUnsafe = false;
    std::vector<std::string>   m_ubDescriptions;
    std::filesystem::path      m_path;
};

} // namespace icctest

#endif // ICCTEST_PROFILE_VIEW_H
