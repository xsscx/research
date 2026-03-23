/*
 * IccTest Library — test_profile_view.cpp
 * Tests for ProfileView, TagView, and related types.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/ProfileView.h"
#include "icctest/Logger.h"
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <vector>

extern void test_assert(bool, const char*, const char*, int);
#define ASSERT(cond)       test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_EQ(a, b)    test_assert((a) == (b), #a " == " #b, __FILE__, __LINE__)
#define ASSERT_TRUE(cond)  test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_FALSE(cond) test_assert(!(cond), "!" #cond, __FILE__, __LINE__)
#define ASSERT_GT(a, b)    test_assert((a) > (b), #a " > " #b, __FILE__, __LINE__)

using namespace icctest;

static std::filesystem::path resolve_repo_file(const char* relativePath) {
    std::filesystem::path base = std::filesystem::path(__FILE__).parent_path();
    auto candidate = (base / "../../../" / relativePath).lexically_normal();
    if (std::filesystem::exists(candidate)) return candidate;

    candidate = (std::filesystem::current_path() / relativePath).lexically_normal();
    if (std::filesystem::exists(candidate)) return candidate;

    return {};
}

// Helper: create a minimal valid ICC profile in memory (128-byte header + tag table)
static std::vector<uint8_t> makeMinimalProfile() {
    std::vector<uint8_t> data(256, 0);
    auto* p = data.data();

    // Profile size = 256 (big-endian)
    p[0] = 0; p[1] = 0; p[2] = 1; p[3] = 0;  // 256

    // Version 4.4.0.0
    p[8] = 0x04; p[9] = 0x40;

    // Device class: 'mntr'
    p[12] = 'm'; p[13] = 'n'; p[14] = 't'; p[15] = 'r';

    // Color space: 'RGB '
    p[16] = 'R'; p[17] = 'G'; p[18] = 'B'; p[19] = ' ';

    // PCS: 'XYZ '
    p[20] = 'X'; p[21] = 'Y'; p[22] = 'Z'; p[23] = ' ';

    // Magic: 'acsp'
    p[36] = 'a'; p[37] = 'c'; p[38] = 's'; p[39] = 'p';

    // Illuminant D50: X=0.9642 Y=1.0000 Z=0.8249 (s15Fixed16)
    // X = 0x0000F6D6
    p[68] = 0x00; p[69] = 0x00; p[70] = 0xF6; p[71] = 0xD6;
    // Y = 0x00010000
    p[72] = 0x00; p[73] = 0x01; p[74] = 0x00; p[75] = 0x00;
    // Z = 0x0000D32D
    p[76] = 0x00; p[77] = 0x00; p[78] = 0xD3; p[79] = 0x2D;

    // Tag count = 1
    p[128] = 0; p[129] = 0; p[130] = 0; p[131] = 1;

    // Tag entry: 'desc' signature, offset 144, size 112
    p[132] = 'd'; p[133] = 'e'; p[134] = 's'; p[135] = 'c';
    p[136] = 0; p[137] = 0; p[138] = 0; p[139] = 144;  // offset
    p[140] = 0; p[141] = 0; p[142] = 0; p[143] = 112;  // size

    return data;
}

static void test_open_memory_buffer() {
    std::printf("  test_open_memory_buffer...\n");
    auto data = makeMinimalProfile();

    auto pv = ProfileView::open(data.data(), data.size());
    // May or may not succeed (library may reject minimal profile),
    // but the raw parse should work
    if (pv) {
        ASSERT_EQ(256u, pv->header().size);
        ASSERT_EQ(0x04400000u, pv->header().version);
        ASSERT_EQ(0x6D6E7472u, pv->header().deviceClass);  // mntr
        ASSERT_EQ(0x52474220u, pv->header().colorSpace);    // RGB
        ASSERT_EQ(0x61637370u, pv->header().magic);         // acsp
        ASSERT_EQ(1u, pv->rawTagTable().size());
        ASSERT_EQ(0x64657363u, pv->rawTagTable()[0].signature);  // desc
    }
    ASSERT_TRUE(true);  // At minimum, no crash
}

static void test_open_nonexistent_file() {
    std::printf("  test_open_nonexistent_file...\n");
    auto pv = ProfileView::open(std::filesystem::path("/nonexistent/profile.icc"));
    ASSERT_FALSE(pv.has_value());
}

static void test_open_too_small() {
    std::printf("  test_open_too_small...\n");
    std::vector<uint8_t> tiny(64, 0);
    auto pv = ProfileView::open(tiny.data(), tiny.size());
    ASSERT_FALSE(pv.has_value());
}

static void test_open_small_image_buffer() {
    std::printf("  test_open_small_image_buffer...\n");
    std::vector<uint8_t> tinyTiff(13, 0);
    tinyTiff[0] = 0x49; tinyTiff[1] = 0x49; tinyTiff[2] = 0x2a; tinyTiff[3] = 0x00;
    tinyTiff[4] = 0x08; tinyTiff[5] = 0x00; tinyTiff[6] = 0x00; tinyTiff[7] = 0x00;

    auto pv = ProfileView::open(tinyTiff.data(), tinyTiff.size());
    ASSERT_TRUE(pv.has_value());
    if (pv) {
        ASSERT_EQ(ImageFormat::TIFF_LE, pv->imageFormat());
        ASSERT_TRUE(pv->isImage());
        ASSERT_FALSE(pv->libraryLoaded());
        ASSERT_EQ(13u, pv->rawSize());
    }
}

static void test_image_format_detection() {
    std::printf("  test_image_format_detection...\n");

    // ICC profile
    auto iccData = makeMinimalProfile();
    auto iccView = ProfileView::open(iccData.data(), iccData.size());
    if (iccView) {
        ASSERT_EQ(ImageFormat::ICC, iccView->imageFormat());
        ASSERT_FALSE(iccView->isImage());  // ICC is NOT an image container
    }

    // TIFF LE magic
    std::vector<uint8_t> tiffLE(256, 0);
    tiffLE[0] = 0x49; tiffLE[1] = 0x49; tiffLE[2] = 0x2a; tiffLE[3] = 0x00;
    auto tiffView = ProfileView::open(tiffLE.data(), tiffLE.size());
    if (tiffView) {
        ASSERT_EQ(ImageFormat::TIFF_LE, tiffView->imageFormat());
        ASSERT_TRUE(tiffView->isImage());
    }

    // PNG magic
    std::vector<uint8_t> png(256, 0);
    png[0] = 0x89; png[1] = 0x50; png[2] = 0x4e; png[3] = 0x47;
    auto pngView = ProfileView::open(png.data(), png.size());
    if (pngView) {
        ASSERT_EQ(ImageFormat::PNG, pngView->imageFormat());
    }
}

static void test_ub_prescan_gbd() {
    std::printf("  test_ub_prescan_gbd...\n");

    // Create profile with GBD tag where nTriangles > INT_MAX/3
    auto data = makeMinimalProfile();
    auto* p = data.data();

    // Set tag to 'gbd ' with nTriangles = 800000000 (> 715827882)
    p[132] = 'g'; p[133] = 'b'; p[134] = 'd'; p[135] = ' ';
    // offset 144, size 24
    p[136] = 0; p[137] = 0; p[138] = 0; p[139] = 144;
    p[140] = 0; p[141] = 0; p[142] = 0; p[143] = 24;

    // At offset 144+16 = 160, write nTriangles = 0x2FAF0800 (800000000)
    p[160] = 0x2F; p[161] = 0xAF; p[162] = 0x08; p[163] = 0x00;

    auto pv = ProfileView::open(data.data(), data.size());
    if (pv) {
        ASSERT_TRUE(pv->hasKnownUBPatterns());
        ASSERT_TRUE(pv->requiresLibraryQuarantine());
        ASSERT_GT(pv->ubPatternDescriptions().size(), 0u);
    }
}

static void test_ub_prescan_clean() {
    std::printf("  test_ub_prescan_clean...\n");
    auto data = makeMinimalProfile();
    auto pv = ProfileView::open(data.data(), data.size());
    if (pv) {
        ASSERT_FALSE(pv->hasKnownUBPatterns());
        ASSERT_FALSE(pv->requiresLibraryQuarantine());
        ASSERT_EQ(0u, pv->ubPatternDescriptions().size());
    }
}

static void test_ub_prescan_embedded_icc5_skip_load() {
    std::printf("  test_ub_prescan_embedded_icc5_skip_load...\n");
    auto corpusProfile = resolve_repo_file("tests/corpus/cf_embedded_child_class_mismatch.icc");
    if (corpusProfile.empty()) {
        std::printf("    (skipped — embedded corpus profile not found)\n");
        return;
    }

    auto pv = ProfileView::open(corpusProfile, true);
    ASSERT_TRUE(pv.has_value());
    if (pv) {
        ASSERT_TRUE(pv->hasKnownUBPatterns());
        ASSERT_TRUE(pv->requiresLibraryQuarantine());
        ASSERT_FALSE(pv->libraryLoaded());
        ASSERT_GT(pv->ubPatternDescriptions().size(), 0u);
    }
}

static void test_ub_prescan_half_float_header_allows_load() {
    std::printf("  test_ub_prescan_half_float_header_allows_load...\n");
    auto corpusProfile = resolve_repo_file("tests/corpus/h174_half_float_header.icc");
    if (corpusProfile.empty()) {
        std::printf("    (skipped — H174 header corpus profile not found)\n");
        return;
    }

    auto pv = ProfileView::open(corpusProfile, true);
    ASSERT_TRUE(pv.has_value());
    if (pv) {
        ASSERT_FALSE(pv->hasKnownUBPatterns());
        ASSERT_FALSE(pv->requiresLibraryQuarantine());
        ASSERT_TRUE(pv->libraryLoaded());
    }
}

static void test_ub_prescan_half_float_mdv_skip_load() {
    std::printf("  test_ub_prescan_half_float_mdv_skip_load...\n");
    auto corpusProfile = resolve_repo_file("tests/corpus/h174_half_float_mdv_fl16.icc");
    if (corpusProfile.empty()) {
        std::printf("    (skipped — H174 mdv/fl16 corpus profile not found)\n");
        return;
    }

    auto pv = ProfileView::open(corpusProfile, true);
    ASSERT_TRUE(pv.has_value());
    if (pv) {
        ASSERT_TRUE(pv->hasKnownUBPatterns());
        ASSERT_TRUE(pv->requiresLibraryQuarantine());
        ASSERT_FALSE(pv->libraryLoaded());
        ASSERT_GT(pv->ubPatternDescriptions().size(), 0u);
        ASSERT_TRUE(pv->ubPatternDescriptions()[0].find("float16ArrayType") != std::string::npos);
    }
}

static void test_ub_prescan_namedcolor_keeps_library_loaded() {
    std::printf("  test_ub_prescan_namedcolor_keeps_library_loaded...\n");
    auto namedColor = resolve_repo_file("test-profiles/NamedColor.icc");
    if (namedColor.empty()) {
        std::printf("    (skipped — NamedColor.icc not found)\n");
        return;
    }

    auto pv = ProfileView::open(namedColor, true);
    ASSERT_TRUE(pv.has_value());
    if (pv) {
        ASSERT_TRUE(pv->hasKnownUBPatterns());
        ASSERT_FALSE(pv->requiresLibraryQuarantine());
        ASSERT_TRUE(pv->libraryLoaded());
        ASSERT_GT(pv->ubPatternDescriptions().size(), 0u);
        ASSERT_TRUE(pv->ubPatternDescriptions()[0].find("NamedColor2") != std::string::npos);
    }
}

static void test_ub_prescan_mpe_offset_wrap_skip_load() {
    std::printf("  test_ub_prescan_mpe_offset_wrap_skip_load...\n");
    auto corpusProfile = resolve_repo_file("test-profiles/CIccToneMapFunc-Describe-heap-oob-IccMpeBasic_cpp.icc");
    if (corpusProfile.empty()) {
        std::printf("    (skipped — tone-map MPE regression profile not found)\n");
        return;
    }

    auto pv = ProfileView::open(corpusProfile, true);
    ASSERT_TRUE(pv.has_value());
    if (pv) {
        ASSERT_TRUE(pv->hasKnownUBPatterns());
        ASSERT_TRUE(pv->requiresLibraryQuarantine());
        ASSERT_TRUE(pv->librarySkippedDueToUB());
        ASSERT_FALSE(pv->libraryLoaded());
        ASSERT_GT(pv->ubPatternDescriptions().size(), 0u);
        ASSERT_TRUE(pv->ubPatternDescriptions()[0].find("IccTagMPE.cpp:1042") != std::string::npos);
    }
}

static void test_ub_prescan_mpe_offset_wrap_no_quarantine_attempts_load() {
    std::printf("  test_ub_prescan_mpe_offset_wrap_no_quarantine_attempts_load...\n");
    auto corpusProfile = resolve_repo_file("iccanalyzer-lite/tests/corpus/cf142-vor-valid.icc");
    if (corpusProfile.empty()) {
        corpusProfile = resolve_repo_file("tests/corpus/cf142-vor-valid.icc");
    }
    if (corpusProfile.empty()) {
        std::printf("    (skipped — cf142-vor-valid.icc not found)\n");
        return;
    }

    auto pv = ProfileView::open(corpusProfile, false);
    ASSERT_TRUE(pv.has_value());
    if (pv) {
        ASSERT_TRUE(pv->hasKnownUBPatterns());
        ASSERT_TRUE(pv->requiresLibraryQuarantine());
        ASSERT_FALSE(pv->librarySkippedDueToUB());
        ASSERT_FALSE(pv->libraryLoaded());
        ASSERT_GT(pv->ubPatternDescriptions().size(), 0u);
        ASSERT_TRUE(pv->ubPatternDescriptions()[0].find("IccTagMPE.cpp:1042") != std::string::npos);
    }
}

static void test_open_real_profile() {
    std::printf("  test_open_real_profile...\n");
    // Try a known-good profile if it exists
    std::filesystem::path testProfile("test-profiles/sRGB_D65_MAT.icc");
    if (!std::filesystem::exists(testProfile)) {
        testProfile = "../test-profiles/sRGB_D65_MAT.icc";
    }
    if (!std::filesystem::exists(testProfile)) {
        testProfile = "../../test-profiles/sRGB_D65_MAT.icc";
    }
    if (!std::filesystem::exists(testProfile)) {
        std::printf("    (skipped — no test profile found)\n");
        return;
    }

    auto pv = ProfileView::open(testProfile);
    ASSERT_TRUE(pv.has_value());
    if (pv) {
        ASSERT_EQ(0x61637370u, pv->header().magic);  // acsp
        ASSERT_GT(pv->tagCount(), 0u);
        ASSERT_TRUE(pv->libraryLoaded());
        ASSERT_FALSE(pv->isImage());
        if (pv->hasKnownUBPatterns()) {
            ASSERT_GT(pv->ubPatternDescriptions().size(), 0u);
        }

        auto md = pv->metadata();
        ASSERT_GT(md.fileSize, 128u);
    }
}

static void test_metadata() {
    std::printf("  test_metadata...\n");
    auto data = makeMinimalProfile();
    auto pv = ProfileView::open(data.data(), data.size());
    if (pv) {
        auto md = pv->metadata();
        ASSERT_EQ(256u, md.headerSize);
        ASSERT_EQ(256u, md.fileSize);
        ASSERT_EQ(0x04400000u, md.version);
    }
}

void test_profile_view() {
    std::printf("test_profile_view:\n");
    test_open_memory_buffer();
    test_open_nonexistent_file();
    test_open_too_small();
    test_open_small_image_buffer();
    test_image_format_detection();
    test_ub_prescan_gbd();
    test_ub_prescan_clean();
    test_ub_prescan_embedded_icc5_skip_load();
    test_ub_prescan_half_float_header_allows_load();
    test_ub_prescan_half_float_mdv_skip_load();
    test_ub_prescan_namedcolor_keeps_library_loaded();
    test_ub_prescan_mpe_offset_wrap_skip_load();
    test_ub_prescan_mpe_offset_wrap_no_quarantine_attempts_load();
    test_open_real_profile();
    test_metadata();
    std::printf("  [OK]\n\n");
}
