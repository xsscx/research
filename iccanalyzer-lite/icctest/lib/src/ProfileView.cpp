/*
 * IccTest Library — ProfileView.cpp
 * Defensive wrapper around iccDEV CIccProfile.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/ProfileView.h"
#include "icctest/Logger.h"

// Full iccDEV headers (needed for CIccTag methods, CIccProfile, CIccIO)
#include "IccProfile.h"
#include "IccIO.h"
#include "IccUtil.h"
#include "IccTagBasic.h"
#include "IccTagEmbedIcc.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <limits>

extern void ForceIccDevSafeOverrides();

namespace icctest {

static ImageFormat detectContainerFormat(const uint8_t* b, size_t len) {
    if (!b || len < 4) return ImageFormat::UNKNOWN;

    // TIFF LE: 'II\x2a\x00'
    if (b[0] == 0x49 && b[1] == 0x49 && b[2] == 0x2a && b[3] == 0x00)
        return ImageFormat::TIFF_LE;
    // TIFF BE: 'MM\x00\x2a'
    if (b[0] == 0x4d && b[1] == 0x4d && b[2] == 0x00 && b[3] == 0x2a)
        return ImageFormat::TIFF_BE;
    // BigTIFF LE: 'II\x2b\x00'
    if (b[0] == 0x49 && b[1] == 0x49 && b[2] == 0x2b && b[3] == 0x00)
        return ImageFormat::BIGTIFF_LE;
    // BigTIFF BE: 'MM\x00\x2b'
    if (b[0] == 0x4d && b[1] == 0x4d && b[2] == 0x00 && b[3] == 0x2b)
        return ImageFormat::BIGTIFF_BE;
    // PNG: '\x89PNG'
    if (b[0] == 0x89 && b[1] == 0x50 && b[2] == 0x4e && b[3] == 0x47)
        return ImageFormat::PNG;
    // JPEG: '\xff\xd8\xff'
    if (len >= 3 && b[0] == 0xff && b[1] == 0xd8 && b[2] == 0xff)
        return ImageFormat::JPEG;
    // ICC: 'acsp' at offset 36
    if (len >= 40 &&
        b[36] == 'a' && b[37] == 'c' && b[38] == 's' && b[39] == 'p')
        return ImageFormat::ICC;

    return ImageFormat::UNKNOWN;
}

// ── ProfileDeleter ──

void ProfileDeleter::operator()(CIccProfile* p) const {
    delete p;
}

// ── TagView ──

TagView::TagView(CIccTag* tag, uint32_t size, uint32_t offset, icTagSignature sig)
    : m_tag(tag), m_size(size), m_offset(offset), m_sig(sig) {}

icTagTypeSignature TagView::type() const {
    if (!m_tag) return static_cast<icTagTypeSignature>(0);
    try {
        return m_tag->GetType();
    } catch (...) {
        ICCTEST_WARN("TagView::type() threw for sig=0x%08X", m_sig);
        return static_cast<icTagTypeSignature>(0);
    }
}

std::optional<std::string> TagView::describe() const {
    if (!m_tag) return std::nullopt;
    try {
        // Pre-check: run Validate first, skip if critical errors
        std::string sReport;
        icValidateStatus status = m_tag->Validate(
            std::string("????"), sReport, nullptr);
        if (status == icValidateCriticalError) {
            ICCTEST_DEBUG("TagView::describe() skipped (critical validation error)");
            return std::nullopt;
        }
        std::string desc;
        m_tag->Describe(desc, 0);
        return desc;
    } catch (...) {
        ICCTEST_WARN("TagView::describe() threw for sig=0x%08X", m_sig);
        return std::nullopt;
    }
}

// ── ProfileView move ops ──

ProfileView::~ProfileView() = default;

ProfileView::ProfileView(ProfileView&& other) noexcept
    : m_profile(std::move(other.m_profile)),
      m_rawData(std::move(other.m_rawData)),
      m_rawTags(std::move(other.m_rawTags)),
      m_header(other.m_header),
      m_ubPatternsDetected(other.m_ubPatternsDetected),
      m_ubDescriptions(std::move(other.m_ubDescriptions)),
      m_path(std::move(other.m_path)) {}

ProfileView& ProfileView::operator=(ProfileView&& other) noexcept {
    if (this != &other) {
        m_profile = std::move(other.m_profile);
        m_rawData = std::move(other.m_rawData);
        m_rawTags = std::move(other.m_rawTags);
        m_header = other.m_header;
        m_ubPatternsDetected = other.m_ubPatternsDetected;
        m_ubDescriptions = std::move(other.m_ubDescriptions);
        m_path = std::move(other.m_path);
    }
    return *this;
}

// ── Factory methods ──

std::optional<ProfileView> ProfileView::open(const std::filesystem::path& path,
                                             bool skipLibraryOnUB) {
    ::ForceIccDevSafeOverrides();
    ICCTEST_DEBUG("ProfileView::open(%s)", path.c_str());

    std::ifstream file(path, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        ICCTEST_ERROR("Failed to open file: %s", path.c_str());
        return std::nullopt;
    }

    auto fileSize = file.tellg();
    if (fileSize < 128) {
        std::array<uint8_t, 40> prefix{};
        file.seekg(0);
        auto prefixLen = std::min<std::streamsize>(
            static_cast<std::streamsize>(prefix.size()), fileSize);
        file.read(reinterpret_cast<char*>(prefix.data()), prefixLen);
        auto bytesRead = file.gcount();
        file.clear();
        file.seekg(0);

        auto fmt = detectContainerFormat(prefix.data(), static_cast<size_t>(bytesRead));
        if (fmt == ImageFormat::UNKNOWN || fmt == ImageFormat::ICC) {
            ICCTEST_WARN("File too small for ICC header: %lld bytes", (long long)fileSize);
            return std::nullopt;
        }
    }
    if (fileSize > 256 * 1024 * 1024) {
        ICCTEST_WARN("File exceeds 256MB safety limit: %lld bytes", (long long)fileSize);
        return std::nullopt;
    }

    file.seekg(0);
    ProfileView pv;
    pv.m_path = path;
    pv.m_rawData.resize(static_cast<size_t>(fileSize));
    file.read(reinterpret_cast<char*>(pv.m_rawData.data()), fileSize);

    if (!file) {
        ICCTEST_ERROR("Failed to read file: %s", path.c_str());
        return std::nullopt;
    }

    pv.parseHeader();
    pv.parseRawTagTable();
    pv.runUBPreScan();
    pv.loadLibrary(skipLibraryOnUB);

    ICCTEST_INFO("ProfileView opened: %s (%zu bytes, %zu tags, lib=%s, ub=%s)",
        path.c_str(), pv.m_rawData.size(), pv.m_rawTags.size(),
        pv.m_profile ? "yes" : "no",
        pv.m_ubPatternsDetected ? "detected" : "clean");

    return pv;
}

std::optional<ProfileView> ProfileView::open(const uint8_t* data, size_t len,
                                             bool skipLibraryOnUB) {
    ::ForceIccDevSafeOverrides();
    ICCTEST_DEBUG("ProfileView::open(buffer, %zu bytes)", len);

    if (len < 128) {
        auto fmt = detectContainerFormat(data, len);
        if (fmt == ImageFormat::UNKNOWN || fmt == ImageFormat::ICC) {
            ICCTEST_WARN("Buffer too small for ICC header: %zu bytes", len);
            return std::nullopt;
        }
    }
    if (len > 256 * 1024 * 1024) {
        ICCTEST_WARN("Buffer exceeds 256MB safety limit: %zu bytes", len);
        return std::nullopt;
    }

    ProfileView pv;
    pv.m_rawData.assign(data, data + len);
    pv.parseHeader();
    pv.parseRawTagTable();
    pv.runUBPreScan();
    pv.loadLibrary(skipLibraryOnUB);

    return pv;
}

// ── Header parsing ──

static uint32_t readU32BE(const uint8_t* p) {
    return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) |
           (uint32_t(p[2]) <<  8) |  uint32_t(p[3]);
}

static uint16_t readU16BE(const uint8_t* p) {
    return (uint16_t(p[0]) << 8) | uint16_t(p[1]);
}

static int32_t readS32BE(const uint8_t* p) {
    return static_cast<int32_t>(readU32BE(p));
}

struct HalfFloatUBScanResult {
    int hitCount = 0;
    std::vector<std::string> examples;
};

static std::string sigStrLocal(uint32_t sig) {
    char buf[5];
    buf[0] = static_cast<char>((sig >> 24) & 0xFF);
    buf[1] = static_cast<char>((sig >> 16) & 0xFF);
    buf[2] = static_cast<char>((sig >> 8) & 0xFF);
    buf[3] = static_cast<char>(sig & 0xFF);
    buf[4] = '\0';
    for (int i = 0; i < 4; i++) {
        unsigned char c = static_cast<unsigned char>(buf[i]);
        if (c < 0x20 || c > 0x7E) buf[i] = '?';
    }
    return std::string(buf);
}

static bool halfFloatTriggersIccUtilUB(uint16_t raw) {
    uint16_t mag = static_cast<uint16_t>(raw & 0x7FFFu);
    uint16_t exp = static_cast<uint16_t>((mag >> 10) & 0x1Fu);
    return mag != 0 && exp < 15;
}

static void recordHalfFloatUBHit(HalfFloatUBScanResult& result, std::string example) {
    result.hitCount++;
    if (result.examples.size() < 4) {
        result.examples.push_back(std::move(example));
    }
}

static HalfFloatUBScanResult scanHalfFloatIccUtilUB(const uint8_t* data,
                                                    size_t len,
                                                    const std::vector<RawTagEntry>& tags) {
    HalfFloatUBScanResult result;
    if (!data || len < 132) return result;

    for (const auto& tag : tags) {
        if (tag.size < 8 || static_cast<uint64_t>(tag.offset) + tag.size > len) continue;

        size_t scanSize = tag.size;
        if (scanSize > 4096) scanSize = 4096;
        if (static_cast<uint64_t>(tag.offset) + scanSize > len) {
            scanSize = len - tag.offset;
        }
        if (scanSize < 8) continue;

        uint32_t typeSig = readU32BE(data + tag.offset);
        std::string tagName = sigStrLocal(tag.signature);

        if (typeSig == 0x666C3136 && scanSize >= 10) { // 'fl16'
            for (size_t off = 8; off + 1 < scanSize; off += 2) {
                uint16_t raw = readU16BE(data + tag.offset + off);
                if (!halfFloatTriggersIccUtilUB(raw)) continue;
                char msg[256];
                std::snprintf(msg, sizeof(msg),
                              "tag '%s' float16ArrayType value raw=0x%04X at tag+0x%zX",
                              tagName.c_str(), raw, off);
                recordHalfFloatUBHit(result, msg);
            }
        }
    }

    return result;
}

void ProfileView::parseHeader() {
    if (m_rawData.size() < 128) return;
    const uint8_t* h = m_rawData.data();

    m_header.size            = readU32BE(h + 0);
    m_header.cmmType         = readU32BE(h + 4);
    m_header.version         = readU32BE(h + 8);
    m_header.deviceClass     = readU32BE(h + 12);
    m_header.colorSpace      = readU32BE(h + 16);
    m_header.pcs             = readU32BE(h + 20);
    m_header.year            = readU16BE(h + 24);
    m_header.month           = readU16BE(h + 26);
    m_header.day             = readU16BE(h + 28);
    m_header.hour            = readU16BE(h + 30);
    m_header.minute          = readU16BE(h + 32);
    m_header.second          = readU16BE(h + 34);
    m_header.magic           = readU32BE(h + 36);
    m_header.platform        = readU32BE(h + 40);
    m_header.flags           = readU32BE(h + 44);
    m_header.manufacturer    = readU32BE(h + 48);
    m_header.model           = readU32BE(h + 52);
    m_header.attributes      = (uint64_t(readU32BE(h + 56)) << 32) | readU32BE(h + 60);
    m_header.renderingIntent = readU32BE(h + 64);
    m_header.illuminantX     = readS32BE(h + 68);
    m_header.illuminantY     = readS32BE(h + 72);
    m_header.illuminantZ     = readS32BE(h + 76);
    m_header.creator         = readU32BE(h + 80);
    std::memcpy(m_header.profileId.data(), h + 84, 16);
    std::memcpy(m_header.reserved.data(), h + 100, 28);
}

// ── Raw tag table parsing ──

void ProfileView::parseRawTagTable() {
    if (m_rawData.size() < 132) return;  // 128 header + 4 tag count
    const uint8_t* base = m_rawData.data();

    uint32_t tagCount = readU32BE(base + 128);
    // Sanity: tag count cannot exceed what fits in file
    size_t maxTags = (m_rawData.size() - 132) / 12;
    if (tagCount > maxTags) {
        ICCTEST_WARN("Tag count %u exceeds file capacity (%zu max), clamping",
                     tagCount, maxTags);
        tagCount = static_cast<uint32_t>(maxTags);
    }
    // Hard limit to prevent pathological allocation
    if (tagCount > 10000) {
        ICCTEST_WARN("Tag count %u exceeds 10000 safety limit, clamping", tagCount);
        tagCount = 10000;
    }

    m_rawTags.reserve(tagCount);
    for (uint32_t i = 0; i < tagCount; i++) {
        size_t entryOffset = 132 + i * 12;
        if (entryOffset + 12 > m_rawData.size()) break;

        RawTagEntry entry;
        entry.signature = readU32BE(base + entryOffset);
        entry.offset    = readU32BE(base + entryOffset + 4);
        entry.size      = readU32BE(base + entryOffset + 8);
        m_rawTags.push_back(entry);
    }
}

// ── UB pre-scan ──
// Checks raw bytes for known patterns that trigger UB in iccDEV library.
// This is extensible: add new pattern checks as lambdas.

void ProfileView::runUBPreScan() {
    if (!m_header.size || m_rawData.size() < 132) return;

    // Pattern 0: Embedded ICC5 tag with ICCp type triggers the unpatched
    // CIccEmbedIO constructor sentinel UB on library parse.
    for (const auto& tag : m_rawTags) {
        if (tag.signature != static_cast<uint32_t>(icSigEmbeddedV5ProfileTag)) {
            continue;
        }
        if (tag.offset + 8 > m_rawData.size() || tag.size < 8) {
            continue;
        }

        uint32_t typeSig = readU32BE(m_rawData.data() + tag.offset);
        if (typeSig == static_cast<uint32_t>(icSigEmbeddedProfileType)) {
            m_ubPatternsDetected = true;
            char desc[192];
            std::snprintf(desc, sizeof(desc),
                "Embedded ICC5 tag at 0x%X with ICCp type will hit CIccEmbedIO constructor UB (IccIO.cpp:569)",
                tag.offset);
            m_ubDescriptions.emplace_back(desc);
            ICCTEST_WARN("UB pre-scan: %s", desc);
        }
        break;
    }

    // Pattern 1: GBD nTriangles overflow (CWE-190)
    // GBD tag layout: [type:4][reserved:4][nPCSChannels:2][nDeviceChannels:2]
    //                 [nVertices:4][nTriangles:4]
    // nTriangles at tag offset+16. If nTriangles*3 overflows int → UBSAN.
    for (const auto& tag : m_rawTags) {
        // 'gbd ' = 0x67626420
        if (tag.signature == 0x67626420) {
            if (tag.offset + 20 <= m_rawData.size() && tag.size >= 20) {
                uint32_t nTriangles = readU32BE(m_rawData.data() + tag.offset + 16);
                if (nTriangles > 715827882u) {  // INT_MAX/3
                    m_ubPatternsDetected = true;
                    char desc[128];
                    std::snprintf(desc, sizeof(desc),
                        "GBD nTriangles=%u would overflow int (nTriangles*3)",
                        nTriangles);
                    m_ubDescriptions.emplace_back(desc);
                    ICCTEST_WARN("UB pre-scan: %s", desc);
                }
            }
        }

        // Pattern 2: NamedColor2 nDeviceCoords > 15 (ICC spec max)
        // 'ncl2' = 0x6E636C32
        if (tag.signature == 0x6E636C32) {
            if (tag.offset + 12 <= m_rawData.size() && tag.size >= 12) {
                uint32_t nDevCoords = readU32BE(m_rawData.data() + tag.offset + 8);
                if (nDevCoords > 15) {
                    m_ubPatternsDetected = true;
                    char desc[128];
                    std::snprintf(desc, sizeof(desc),
                        "NamedColor2 nDeviceCoords=%u exceeds ICC max 15", nDevCoords);
                    m_ubDescriptions.emplace_back(desc);
                }
            }
        }

        // Pattern 3: CLUT grid dimension overflow
        // Check for tags containing CLUTs where grid^ndim could overflow
        // Type signatures: 'mft1', 'mft2', 'mAB ', 'mBA '
        uint32_t typeSig = 0;
        if (tag.offset + 4 <= m_rawData.size()) {
            typeSig = readU32BE(m_rawData.data() + tag.offset);
        }
        if (typeSig == 0x6D667431 || typeSig == 0x6D667432) {  // mft1/mft2
            // LUT8/LUT16: grid size at tag+10 for each input channel
            if (tag.offset + 12 <= m_rawData.size()) {
                uint8_t nInput = m_rawData[tag.offset + 8];
                uint8_t gridSize = m_rawData[tag.offset + 10];
                if (nInput > 0 && gridSize > 0) {
                    uint64_t gridPoints = 1;
                    for (int d = 0; d < nInput && d < 16; d++) {
                        gridPoints *= gridSize;
                        if (gridPoints > 100000000ULL) {
                            m_ubPatternsDetected = true;
                            char desc[128];
                            std::snprintf(desc, sizeof(desc),
                                "CLUT grid^dim overflow: %u^%u > 100M",
                                gridSize, nInput);
                            m_ubDescriptions.emplace_back(desc);
                            break;
                        }
                    }
                }
            }
        }
    }

    HalfFloatUBScanResult halfFloatResult =
        scanHalfFloatIccUtilUB(m_rawData.data(), m_rawData.size(), m_rawTags);
    if (halfFloatResult.hitCount > 0) {
        m_ubPatternsDetected = true;
        for (const auto& example : halfFloatResult.examples) {
            std::string desc =
                "Half-float value triggers icF16toF unsigned-wrap UB (IccUtil.cpp:665/677): " +
                example;
            m_ubDescriptions.push_back(desc);
            ICCTEST_WARN("UB pre-scan: %s", desc.c_str());
        }
    }
}

// ── Library loading ──

bool ProfileView::loadLibrary(bool skipLibraryOnUB) {
    if (skipLibraryOnUB && m_ubPatternsDetected) {
        ICCTEST_WARN("Skipping CIccProfile::Read due to known UB trigger patterns");
        return false;
    }

    try {
        auto* profile = new CIccProfile();
        CIccFileIO io;
        if (!m_path.empty()) {
            if (!io.Open(m_path.c_str(), "rb")) {
                ICCTEST_WARN("CIccFileIO::Open failed: %s", m_path.c_str());
                delete profile;
                return false;
            }
        } else {
            // Memory buffer: use CIccMemIO
            CIccMemIO memIo;
            memIo.Attach(const_cast<icUInt8Number*>(m_rawData.data()),
                         static_cast<icUInt32Number>(m_rawData.size()));
            if (!profile->Read(&memIo)) {
                ICCTEST_WARN("CIccProfile::Read failed (memory buffer)");
                delete profile;
                return false;
            }
            m_profile.reset(profile);
            return true;
        }

        if (!profile->Read(&io)) {
            ICCTEST_WARN("CIccProfile::Read failed: %s", m_path.c_str());
            delete profile;
            return false;
        }
        m_profile.reset(profile);
        return true;
    } catch (const std::exception& e) {
        ICCTEST_ERROR("Library load exception: %s", e.what());
        return false;
    } catch (...) {
        ICCTEST_ERROR("Library load unknown exception");
        return false;
    }
}

// ── Public tag access ──

std::optional<TagView> ProfileView::tag(icTagSignature sig) const {
    if (!m_profile) return std::nullopt;
    try {
        CIccTag* pTag = m_profile->FindTag(sig);
        if (!pTag) return std::nullopt;

        // Find size/offset from raw tag table
        uint32_t tSize = 0, tOffset = 0;
        for (const auto& rt : m_rawTags) {
            if (rt.signature == static_cast<uint32_t>(sig)) {
                tSize = rt.size;
                tOffset = rt.offset;
                break;
            }
        }

        return TagView(pTag, tSize, tOffset, sig);
    } catch (...) {
        ICCTEST_WARN("ProfileView::tag() threw for sig=0x%08X", sig);
        return std::nullopt;
    }
}

bool ProfileView::hasTag(icTagSignature sig) const {
    if (!m_profile) return false;
    try {
        return m_profile->FindTag(sig) != nullptr;
    } catch (...) {
        return false;
    }
}

std::vector<icTagSignature> ProfileView::tagSignatures() const {
    std::vector<icTagSignature> sigs;
    // Use the raw tag table (safe, no library dependency)
    for (const auto& rt : m_rawTags) {
        sigs.push_back(static_cast<icTagSignature>(rt.signature));
    }
    return sigs;
}

size_t ProfileView::tagCount() const {
    return m_rawTags.size();
}

std::optional<RawTagEntry> ProfileView::rawTag(uint32_t sig) const {
    for (const auto& rt : m_rawTags) {
        if (rt.signature == sig) return rt;
    }
    return std::nullopt;
}

// ── Image detection ──

bool ProfileView::isImage() const {
    auto fmt = imageFormat();
    return fmt != ImageFormat::UNKNOWN && fmt != ImageFormat::ICC;
}

ImageFormat ProfileView::imageFormat() const {
    return detectContainerFormat(m_rawData.data(), m_rawData.size());
}

// ── Metadata ──

ProfileMetadata ProfileView::metadata() const {
    ProfileMetadata md{};
    md.version         = m_header.version;
    md.profileClass    = m_header.deviceClass;
    md.colorSpace      = m_header.colorSpace;
    md.pcs             = m_header.pcs;
    md.flags           = m_header.flags;
    md.headerSize      = m_header.size;
    md.fileSize        = m_rawData.size();
    md.renderingIntent = m_header.renderingIntent;
    md.manufacturer    = m_header.manufacturer;
    md.model           = m_header.model;
    md.profileId       = m_header.profileId;
    std::memcpy(md.magic.data(), &m_header.magic, 4);
    // illuminant (12 bytes: 3 × s15Fixed16)
    uint8_t illum[12];
    const uint8_t* raw = m_rawData.data();
    if (m_rawData.size() >= 80) {
        std::memcpy(illum, raw + 68, 12);
    }
    std::memcpy(md.illuminant.data(), illum, 12);
    // Creator as string
    char cr[5];
    cr[0] = static_cast<char>((m_header.creator >> 24) & 0xFF);
    cr[1] = static_cast<char>((m_header.creator >> 16) & 0xFF);
    cr[2] = static_cast<char>((m_header.creator >>  8) & 0xFF);
    cr[3] = static_cast<char>( m_header.creator        & 0xFF);
    cr[4] = '\0';
    md.creator = cr;
    return md;
}

} // namespace icctest
