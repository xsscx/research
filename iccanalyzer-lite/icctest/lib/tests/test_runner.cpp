/*
 * IccTest Library — test_runner.cpp
 * Tests for IccTestRunner orchestration.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/IccTest.h"
#include "IccProfile.h"
#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <set>
#include <string_view>
#include <vector>

extern void test_assert(bool, const char*, const char*, int);
#define ASSERT(cond)       test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_EQ(a, b)    test_assert((a) == (b), #a " == " #b, __FILE__, __LINE__)
#define ASSERT_TRUE(cond)  test_assert((cond), #cond, __FILE__, __LINE__)
#define ASSERT_FALSE(cond) test_assert(!(cond), "!" #cond, __FILE__, __LINE__)
#define ASSERT_GT(a, b)    test_assert((a) > (b), #a " > " #b, __FILE__, __LINE__)

using namespace icctest;

static std::filesystem::path find_named_ancestor(std::filesystem::path start,
                                                 std::string_view name) {
    while (!start.empty()) {
        if (start.filename() == name) {
            return start;
        }
        auto parent = start.parent_path();
        if (parent == start) {
            break;
        }
        start = parent;
    }

    return {};
}

static std::filesystem::path find_repo_root(std::filesystem::path start) {
    while (!start.empty()) {
        if (std::filesystem::exists(start / ".git")) {
            return start;
        }
        auto parent = start.parent_path();
        if (parent == start) {
            break;
        }
        start = parent;
    }

    return {};
}

static std::filesystem::path resolve_repo_file(const char* relativePath) {
    std::filesystem::path srcPath(__FILE__);
    std::filesystem::path sourceDir = srcPath.parent_path();
    std::filesystem::path iccaRoot = find_named_ancestor(sourceDir, "iccanalyzer-lite");
    std::filesystem::path repoRoot = find_repo_root(sourceDir);

    if (std::strncmp(relativePath, "tests/", 6) == 0 && !iccaRoot.empty()) {
        std::filesystem::path combined = iccaRoot / relativePath;
        std::filesystem::path candidate = combined.lexically_normal();
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
    }

    if (!repoRoot.empty()) {
        std::filesystem::path combined = repoRoot / relativePath;
        std::filesystem::path candidate = combined.lexically_normal();
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
    }

    if (!iccaRoot.empty()) {
        std::filesystem::path combined = iccaRoot / relativePath;
        std::filesystem::path candidate = combined.lexically_normal();
        if (std::filesystem::exists(candidate)) {
            return candidate;
        }
    }

    std::filesystem::path cwd = std::filesystem::current_path();
    std::filesystem::path combined = cwd / relativePath;
    std::filesystem::path candidate = combined.lexically_normal();
    if (std::filesystem::exists(candidate)) {
        return candidate;
    }

    return {};
}

static std::filesystem::path write_temp_profile(const std::vector<uint8_t>& data,
                                                const char* fileName) {
    std::filesystem::path out = std::filesystem::temp_directory_path() / fileName;
    std::FILE* fp = std::fopen(out.string().c_str(), "wb");
    if (!fp) {
        return {};
    }

    if (!data.empty()) {
        std::fwrite(data.data(), 1, data.size(), fp);
    }
    std::fclose(fp);
    return out;
}

static std::vector<uint8_t> read_file_bytes(const std::filesystem::path& path) {
    std::vector<uint8_t> data;
    std::FILE* fp = std::fopen(path.string().c_str(), "rb");
    if (!fp) {
        return data;
    }

    std::fseek(fp, 0, SEEK_END);
    long size = std::ftell(fp);
    std::rewind(fp);
    if (size > 0) {
        data.resize(static_cast<size_t>(size));
        std::fread(data.data(), 1, data.size(), fp);
    }
    std::fclose(fp);
    return data;
}

static const PerCheckResult* find_per_check(const AnalysisResult& result,
                                            CheckID::Kind kind,
                                            int number) {
    for (const auto& entry : result.perCheck) {
        if (entry.id.kind == kind && entry.id.number == number) {
            return &entry;
        }
    }
    return nullptr;
}

static AnalysisResult analyze_corpus_checks(const std::filesystem::path& profilePath,
                                            const std::vector<int>& checks) {
    AnalysisOptions opts;
    opts.phases = {CheckPhase::CONFORMANCE};
    opts.skipLibraryOnUB = false;
    for (int check : checks) {
        opts.specificChecks.push_back({CheckID::Kind::Conformance, check});
    }

    IccTestRunner runner;
    return runner.analyze(profilePath, opts);
}

static AnalysisResult analyze_corpus_heuristics(const std::filesystem::path& profilePath,
                                                const std::vector<int>& checks) {
    AnalysisOptions opts;
    opts.phases = {
        CheckPhase::HEADER,
        CheckPhase::TAG_TABLE,
        CheckPhase::RAW_SCAN,
        CheckPhase::LIBRARY,
    };
    opts.skipLibraryOnUB = false;
    for (int check : checks) {
        opts.specificChecks.push_back({CheckID::Kind::Heuristic, check});
    }

    IccTestRunner runner;
    return runner.analyze(profilePath, opts);
}

static AnalysisResult analyze_image_checks(const std::filesystem::path& imagePath,
                                           const std::vector<int>& checks) {
    AnalysisOptions opts;
    opts.phases = {CheckPhase::IMAGE};
    for (int check : checks) {
        opts.specificChecks.push_back({CheckID::Kind::Heuristic, check});
    }

    IccTestRunner runner;
    return runner.analyze(imagePath, opts);
}

static std::vector<uint8_t> make_h161_deep_apply_profile() {
    std::vector<uint8_t> data(192, 0);

    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    auto put_u16 = [&](size_t off, uint16_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 1] = static_cast<uint8_t>(value & 0xFF);
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x04400000);   // v4.4
    put_u32(12, 0x6D6E7472);  // 'mntr'
    put_u32(16, 0x3132434C);  // '12CL'
    put_u32(20, 0x4C616220);  // 'Lab '
    put_u32(36, 0x61637370);  // 'acsp'

    put_u32(128, 2);          // tag count
    put_u32(132, 0x41324230); // 'A2B0'
    put_u32(136, 160);
    put_u32(140, 16);
    put_u32(144, 0x42324130); // 'B2A0'
    put_u32(148, 176);
    put_u32(152, 16);

    put_u32(160, 0x6D706574); // 'mpet'
    put_u16(168, 12);
    put_u16(170, 12);
    put_u32(172, 5);

    put_u32(176, 0x6D706574); // 'mpet'
    put_u16(184, 12);
    put_u16(186, 12);
    put_u32(188, 5);

    return data;
}

static std::vector<uint8_t> make_h169_dict_bounds_profile() {
    std::vector<uint8_t> data(160, 0);

    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x04400000);   // v4.4
    put_u32(12, 0x6D6E7472);  // 'mntr'
    put_u32(16, 0x52474220);  // 'RGB '
    put_u32(20, 0x58595A20);  // 'XYZ '
    put_u32(36, 0x61637370);  // 'acsp'

    put_u32(128, 1);          // tag count
    put_u32(132, 0x6D657461); // 'meta'
    put_u32(136, 144);
    put_u32(140, 16);

    put_u32(144, 0x64696374); // 'dict'
    put_u32(152, 3);          // count
    put_u32(156, 8);          // recLen

    return data;
}

static std::vector<uint8_t> make_h97_profile_sequence_id_profile(bool malformed) {
    auto make_mluc = [](const char* text) {
        std::vector<uint8_t> out;
        out.insert(out.end(), {'m','l','u','c', 0,0,0,0});
        auto len = std::strlen(text);
        std::vector<uint8_t> utf16;
        utf16.reserve(len * 2);
        for (size_t i = 0; i < len; i++) {
            utf16.push_back(0);
            utf16.push_back(static_cast<uint8_t>(text[i]));
        }
        uint32_t recordSize = 12;
        uint32_t stringOffset = 28;
        auto put_u32 = [&](uint32_t value) {
            out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(value & 0xFF));
        };
        put_u32(1);
        put_u32(recordSize);
        out.insert(out.end(), {'e','n','U','S'});
        put_u32(static_cast<uint32_t>(utf16.size()));
        put_u32(stringOffset);
        out.insert(out.end(), utf16.begin(), utf16.end());
        while (out.size() % 4) out.push_back(0);
        return out;
    };

    auto make_entry = [&](const std::array<uint8_t, 16>& profileId, const char* text) {
        std::vector<uint8_t> out;
        out.insert(out.end(), profileId.begin(), profileId.end());
        auto mluc = make_mluc(text);
        out.insert(out.end(), mluc.begin(), mluc.end());
        return out;
    };

    std::array<uint8_t, 16> zeroId{};
    std::array<uint8_t, 16> dupId{
        0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
        0x18,0x19,0x1A,0x1B,0x1C,0x1D,0x1E,0x1F
    };
    std::array<uint8_t, 16> cleanIdA{
        0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,
        0x28,0x29,0x2A,0x2B,0x2C,0x2D,0x2E,0x2F
    };
    std::array<uint8_t, 16> cleanIdB{
        0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,
        0x38,0x39,0x3A,0x3B,0x3C,0x3D,0x3E,0x3F
    };

    std::vector<std::vector<uint8_t>> entries;
    if (malformed) {
        entries.push_back(make_entry(zeroId, "Zero"));
        entries.push_back(make_entry(dupId, "DupA"));
        entries.push_back(make_entry(dupId, "DupB"));
    } else {
        entries.push_back(make_entry(cleanIdA, "CleanA"));
        entries.push_back(make_entry(cleanIdB, "CleanB"));
    }

    std::vector<uint8_t> psid;
    psid.insert(psid.end(), {'p','s','i','d', 0,0,0,0});
    uint32_t count = static_cast<uint32_t>(entries.size());
    auto append_u32 = [&](uint32_t value) {
        psid.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        psid.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        psid.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        psid.push_back(static_cast<uint8_t>(value & 0xFF));
    };
    append_u32(count);

    uint32_t dirOffset = 12 + count * 8;
    uint32_t curOffset = dirOffset;
    for (const auto& entry : entries) {
        append_u32(curOffset);
        append_u32(static_cast<uint32_t>(entry.size()));
        curOffset += static_cast<uint32_t>(entry.size());
    }
    for (const auto& entry : entries) {
        psid.insert(psid.end(), entry.begin(), entry.end());
    }
    while (psid.size() % 4) psid.push_back(0);

    std::vector<uint8_t> data(128 + 4 + 12 + psid.size(), 0);
    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x04400000);
    put_u32(12, 0x6D6E7472);
    put_u32(16, 0x52474220);
    put_u32(20, 0x58595A20);
    put_u32(36, 0x61637370);
    put_u32(128, 1);
    put_u32(132, 0x70736964);
    put_u32(136, 144);
    put_u32(140, static_cast<uint32_t>(psid.size()));
    std::memcpy(data.data() + 144, psid.data(), psid.size());
    return data;
}

static std::vector<uint8_t> make_h102_profile_size_profile(uint32_t declaredSize,
                                                           uint32_t descOffset,
                                                           uint32_t descSize) {
    auto corpusPath = resolve_repo_file("tests/corpus/valid_srgb.icc");
    auto data = read_file_bytes(corpusPath);
    if (data.size() < 144) {
        return {};
    }

    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    put_u32(0, declaredSize);
    put_u32(136, descOffset);
    put_u32(140, descSize);
    return data;
}

static std::vector<uint8_t> make_h165_lut_data_sufficiency_profile() {
    std::vector<uint8_t> data(160, 0);

    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x04400000);   // v4.4
    put_u32(12, 0x6D6E7472);  // 'mntr'
    put_u32(16, 0x52474220);  // 'RGB '
    put_u32(20, 0x58595A20);  // 'XYZ '
    put_u32(36, 0x61637370);  // 'acsp'

    put_u32(128, 1);          // tag count
    put_u32(132, 0x41324230); // 'A2B0'
    put_u32(136, 144);
    put_u32(140, 16);

    put_u32(144, 0x6D667431); // 'mft1'
    data[152] = 3;            // nIn
    data[153] = 3;            // nOut
    data[154] = 2;            // grid

    return data;
}

static std::vector<uint8_t> make_h170_null_pcs_profile() {
    std::vector<uint8_t> data(132, 0);

    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x04400000);   // v4.4
    put_u32(12, 0x6D6E7472);  // 'mntr'
    put_u32(16, 0x52474220);  // 'RGB '
    put_u32(20, 0x00000000);  // null PCS
    put_u32(36, 0x61637370);  // 'acsp'
    put_u32(128, 0);          // 0 tags

    return data;
}

static std::vector<uint8_t> make_h172_lut_matrix_profile(bool malformed) {
    std::vector<uint8_t> data(260, 0);

    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    auto put_s32 = [&](size_t off, int32_t value) {
        put_u32(off, static_cast<uint32_t>(value));
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x04400000);   // v4.4
    put_u32(12, 0x70727472);  // 'prtr'
    put_u32(16, 0x52474220);  // 'RGB '
    put_u32(20, 0x4C616220);  // 'Lab '
    put_u32(36, 0x61637370);  // 'acsp'

    put_u32(128, 1);          // tag count
    put_u32(132, 0x41324230); // 'A2B0'
    put_u32(136, 144);
    put_u32(140, 116);

    put_u32(144, 0x6D414220); // 'mAB '
    data[152] = 3;
    data[153] = 3;
    put_u32(156, 32);         // B curves
    put_u32(160, 68);         // Matrix
    put_u32(164, 0);          // M curves
    put_u32(168, 0);          // CLUT
    put_u32(172, 0);          // A curves

    for (int curve = 0; curve < 3; curve++) {
        size_t off = 176 + (curve * 12);
        put_u32(off, 0x63757276);      // 'curv'
        put_u32(off + 4, 0);
        put_u32(off + 8, 0);           // count = 0 (identity)
    }

    const int32_t identity = 1 << 16;
    size_t matrixOff = 212;
    if (malformed) {
        put_s32(matrixOff + 0, 0);
        put_s32(matrixOff + 4, 0);
        put_s32(matrixOff + 8, 0);
        put_s32(matrixOff + 12, 0);
        put_s32(matrixOff + 16, identity);
        put_s32(matrixOff + 20, 0);
        put_s32(matrixOff + 24, 0);
        put_s32(matrixOff + 28, 0);
        put_s32(matrixOff + 32, 200 << 16);
        put_s32(matrixOff + 36, 20 << 16);
        put_s32(matrixOff + 40, 0);
        put_s32(matrixOff + 44, 0);
    } else {
        put_s32(matrixOff + 0, identity);
        put_s32(matrixOff + 4, 0);
        put_s32(matrixOff + 8, 0);
        put_s32(matrixOff + 12, 0);
        put_s32(matrixOff + 16, identity);
        put_s32(matrixOff + 20, 0);
        put_s32(matrixOff + 24, 0);
        put_s32(matrixOff + 28, 0);
        put_s32(matrixOff + 32, identity);
        put_s32(matrixOff + 36, 0);
        put_s32(matrixOff + 40, 0);
        put_s32(matrixOff + 44, 0);
    }

    return data;
}

static void expect_conformance_result(const AnalysisResult& result,
                                      int number,
                                      CheckResult::Status status,
                                      int issueCount) {
    const auto* check = find_per_check(result, CheckID::Kind::Conformance, number);
    ASSERT_TRUE(check != nullptr);
    if (!check) {
        return;
    }
    ASSERT_EQ(status, check->result.status);
    ASSERT_EQ(issueCount, check->result.issueCount());
}

static void expect_heuristic_result(const AnalysisResult& result,
                                    int number,
                                    CheckResult::Status status,
                                    int issueCount) {
    const auto* check = find_per_check(result, CheckID::Kind::Heuristic, number);
    ASSERT_TRUE(check != nullptr);
    if (!check) {
        return;
    }
    ASSERT_EQ(status, check->result.status);
    ASSERT_EQ(issueCount, check->result.issueCount());
}

// Example check: validates magic is 'acsp'
static CheckResult check_magic(const ProfileView& pv) {
    if (pv.header().magic != 0x61637370) {
        CheckResult r;
        r.status = CheckResult::Status::FINDINGS;
        r.summary = "Invalid magic";
        r.findings.push_back(Finding{
            {CheckID::Kind::Heuristic, 1},
            Severity::CRITICAL,
            "Magic is not 'acsp'", "", "CWE-20"});
        return r;
    }
    return CheckResult::ok("Magic valid");
}

// Example check: validates version
static CheckResult check_version(const ProfileView& pv) {
    uint8_t major = (pv.header().version >> 24) & 0xFF;
    if (major < 2 || major > 5) {
        CheckResult r;
        r.status = CheckResult::Status::FINDINGS;
        r.summary = "Unusual version";
        r.findings.push_back(Finding{
            {CheckID::Kind::Heuristic, 2},
            Severity::LOW,
            "Version major byte is outside 2-5 range", "", ""});
        return r;
    }
    return CheckResult::ok("Version OK");
}

static void setup_registry() {
    auto& reg = CheckRegistry::instance();
    reg.clear();

    reg.add(RegisteredCheck{
        {CheckID::Kind::Heuristic, 1},
        CheckMeta{"Magic Validation", "ICC.1 §7.2.9", "ICC.1-2022-05",
                  "CWE-20", "", Severity::CRITICAL, CheckPhase::HEADER},
        check_magic
    });

    reg.add(RegisteredCheck{
        {CheckID::Kind::Heuristic, 2},
        CheckMeta{"Version Validation", "ICC.1 §7.2.4", "ICC.1-2022-05",
                  "", "", Severity::LOW, CheckPhase::HEADER},
        check_version
    });
}

static void test_version_string() {
    std::printf("  test_version_string...\n");
    const char* ver = IccTestRunner::version();
    ASSERT_TRUE(ver != nullptr);
    ASSERT_TRUE(std::strstr(ver, "2.0") != nullptr);
}

static void test_check_count() {
    std::printf("  test_check_count...\n");
    // Do NOT call setup_registry() here — we want the auto-registered checks
    // from static initializers (REGISTER_HEURISTIC macros in check .cpp files).
    auto count = CheckRegistry::instance().size();
    std::printf("    Registered checks: %zu\n", count);
    ASSERT_TRUE(count >= 517u);  // 178 heuristics + 339 conformance
}

static void test_analyze_minimal_profile() {
    std::printf("  test_analyze_minimal_profile...\n");
    setup_registry();

    // Create a minimal ICC profile buffer
    std::vector<uint8_t> data(256, 0);
    auto* p = data.data();
    p[0] = 0; p[1] = 0; p[2] = 1; p[3] = 0;  // size=256
    p[8] = 0x04; p[9] = 0x40;                   // v4.4
    p[12] = 'm'; p[13] = 'n'; p[14] = 't'; p[15] = 'r';
    p[16] = 'R'; p[17] = 'G'; p[18] = 'B'; p[19] = ' ';
    p[20] = 'X'; p[21] = 'Y'; p[22] = 'Z'; p[23] = ' ';
    p[36] = 'a'; p[37] = 'c'; p[38] = 's'; p[39] = 'p';
    p[128] = 0; p[129] = 0; p[130] = 0; p[131] = 0;  // 0 tags

    IccTestRunner runner;
    auto result = runner.analyze(
        data.data(), data.size());

    // Both checks should have run
    ASSERT_EQ(2, result.stats.checksRun);
    // Magic is valid → H1 OK, version is v4 → H2 OK
    // (Findings depend on library parse success)
    ASSERT_GT(result.stats.checksRun, 0);
}

static void test_analyze_bad_magic() {
    std::printf("  test_analyze_bad_magic...\n");
    setup_registry();

    // Create profile with wrong magic
    std::vector<uint8_t> data(256, 0);
    auto* p = data.data();
    p[0] = 0; p[1] = 0; p[2] = 1; p[3] = 0;
    p[8] = 0x04; p[9] = 0x40;
    p[12] = 'm'; p[13] = 'n'; p[14] = 't'; p[15] = 'r';
    p[36] = 'B'; p[37] = 'A'; p[38] = 'D'; p[39] = '!';  // Wrong magic

    IccTestRunner runner;
    auto result = runner.analyze(data.data(), data.size());

    // H1 should find the bad magic
    ASSERT_TRUE(result.hasCritical());
    ASSERT_GT(result.stats.findingsTotal, 0);
    ASSERT_EQ(2u, result.perCheck.size());
    ASSERT_EQ(CheckID::Kind::Heuristic, result.perCheck[0].id.kind);
    ASSERT_EQ(1, result.perCheck[0].id.number);
    ASSERT_EQ(std::string("Magic Validation"),
              std::string(result.perCheck[0].meta.name));
    ASSERT_EQ(CheckResult::Status::FINDINGS, result.perCheck[0].result.status);
    ASSERT_EQ(1, result.perCheck[0].result.issueCount());
    ASSERT_EQ(std::string("Magic is not 'acsp'"),
              result.perCheck[0].result.findings[0].message);
}

static void test_analyze_nonexistent_file() {
    std::printf("  test_analyze_nonexistent_file...\n");
    setup_registry();

    IccTestRunner runner;
    auto result = runner.analyze(
        std::filesystem::path("/nonexistent.icc"));

    // Should get a CRITICAL finding for file open failure
    ASSERT_TRUE(result.hasCritical());
}

static void test_severity_filter() {
    std::printf("  test_severity_filter...\n");
    setup_registry();

    // Profile with bad magic → CRITICAL finding
    std::vector<uint8_t> data(256, 0);
    auto* p = data.data();
    p[0] = 0; p[1] = 0; p[2] = 1; p[3] = 0;
    p[8] = 0x04; p[9] = 0x40;
    p[12] = 'm'; p[13] = 'n'; p[14] = 't'; p[15] = 'r';
    p[36] = 'X'; p[37] = 'X'; p[38] = 'X'; p[39] = 'X';

    AnalysisOptions opts;
    opts.minSeverity = Severity::CRITICAL;

    IccTestRunner runner;
    auto result = runner.analyze(data.data(), data.size(), opts);

    // Only CRITICAL findings should be in results
    for (const auto& f : result.findings) {
        ASSERT_EQ(Severity::CRITICAL, f.level);
    }
}

static void test_analyze_real_profile() {
    std::printf("  test_analyze_real_profile...\n");
    setup_registry();

    auto testProfile = resolve_repo_file("test-profiles/sRGB_D65_MAT.icc");
    if (testProfile.empty()) {
        std::printf("    (skipped — no test profile found)\n");
        return;
    }

    IccTestRunner runner;
    auto result = runner.analyze(testProfile);

    ASSERT_EQ(2, result.stats.checksRun);
    // sRGB should pass both magic and version checks
    ASSERT_FALSE(result.hasCritical());
    // sRGB is class 'mntr' (Display) = 0x6D6E7472
    ASSERT_EQ(0x6D6E7472u, result.metadata.profileClass);
    ASSERT_GT(result.metadata.fileSize, 128u);
}

static void test_heuristic_coverage() {
    std::printf("  test_heuristic_coverage...\n");
    // Do NOT call setup_registry() — use auto-registered checks.

    auto& reg = CheckRegistry::instance();
    const auto& all = reg.all();

    // Verify every H-number from 1..174 is registered
    std::set<int> registered;
    for (auto& c : all) {
        if (c.id.kind == CheckID::Kind::Heuristic)
            registered.insert(c.id.number);
    }

    int missing = 0;
    for (int h = 1; h <= 174; h++) {
        if (registered.find(h) == registered.end()) {
            std::printf("    MISSING: H%d\n", h);
            missing++;
        }
    }
    ASSERT_EQ(0, missing);
    std::printf("    All 174 heuristic IDs present\n");
}

static void test_conformance_coverage() {
    std::printf("  test_conformance_coverage...\n");
    // Do NOT call setup_registry() — use auto-registered checks.

    auto& reg = CheckRegistry::instance();
    const auto& all = reg.all();

    // Collect all registered conformance CF numbers
    std::set<int> registered;
    for (auto& c : all) {
        if (c.id.kind == CheckID::Kind::Conformance)
            registered.insert(c.id.number);
    }

    // All 339 CF IDs are registered (CF-001..CF-339, complete range)
    int missing = 0;
    for (int cf = 1; cf <= 339; cf++) {
        if (registered.find(cf) == registered.end()) {
            std::printf("    MISSING: CF-%03d\n", cf);
            missing++;
        }
    }

    std::printf("    Registered conformance checks: %zu\n", registered.size());
    ASSERT_EQ(0, missing);
    std::printf("    All 339 conformance IDs present\n");
}

static void test_conformance_private_tag_documentation_regression() {
    std::printf("  test_conformance_private_tag_documentation_regression...\n");

    auto corpusPath = resolve_repo_file("tests/corpus/private_tags.icc");
    if (corpusPath.empty()) {
        std::printf("    (skipped — private_tags.icc not found)\n");
        return;
    }

    AnalysisOptions opts;
    opts.phases = {CheckPhase::CONFORMANCE};
    opts.specificChecks = {{CheckID::Kind::Conformance, 97}};

    IccTestRunner runner;
    auto result = runner.analyze(corpusPath, opts);

    ASSERT_EQ(1, result.stats.checksRun);
    const auto* cf97 = find_per_check(result, CheckID::Kind::Conformance, 97);
    ASSERT_TRUE(cf97 != nullptr);
    ASSERT_EQ(CheckResult::Status::FINDINGS, cf97->result.status);
    ASSERT_EQ(2, cf97->result.issueCount());
    ASSERT_TRUE(cf97->result.findings[0].message.find("Undocumented private tag") != std::string::npos);
}

static void test_conformance_adgc_regression() {
    std::printf("  test_conformance_adgc_regression...\n");

    auto corpusPath = resolve_repo_file("tests/corpus/cf_adgc_bad_curve_range.icc");
    if (corpusPath.empty()) {
        std::printf("    (skipped — cf_adgc_bad_curve_range.icc not found)\n");
        return;
    }

    AnalysisOptions opts;
    opts.phases = {CheckPhase::CONFORMANCE};
    opts.specificChecks = {
        {CheckID::Kind::Conformance, 128},
        {CheckID::Kind::Conformance, 134},
        {CheckID::Kind::Conformance, 135},
    };

    IccTestRunner runner;
    auto result = runner.analyze(corpusPath, opts);

    ASSERT_EQ(3, result.stats.checksRun);

    const auto* cf128 = find_per_check(result, CheckID::Kind::Conformance, 128);
    const auto* cf134 = find_per_check(result, CheckID::Kind::Conformance, 134);
    const auto* cf135 = find_per_check(result, CheckID::Kind::Conformance, 135);

    ASSERT_TRUE(cf128 != nullptr);
    ASSERT_TRUE(cf134 != nullptr);
    ASSERT_TRUE(cf135 != nullptr);

    ASSERT_EQ(CheckResult::Status::OK, cf128->result.status);
    ASSERT_EQ(CheckResult::Status::OK, cf134->result.status);
    ASSERT_EQ(CheckResult::Status::FINDINGS, cf135->result.status);
    ASSERT_EQ(0, cf128->result.issueCount());
    ASSERT_EQ(0, cf134->result.issueCount());
    ASSERT_EQ(6, cf135->result.issueCount());
    ASSERT_EQ(6, result.stats.findingsTotal);
}

static void test_sampleicc_legibility_regression() {
    std::printf("  test_sampleicc_legibility_regression...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "valid_srgb.icc", {188, 189, 190});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_conformance_result(result, 188, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 189, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 190, CheckResult::Status::OK, 0);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "zero_tags.icc", {190});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 190, CheckResult::Status::FINDINGS, 1);

        const auto* cf190 = find_per_check(result, CheckID::Kind::Conformance, 190);
        ASSERT_TRUE(cf190 != nullptr);
        ASSERT_TRUE(cf190->result.summary.find("Legibility") != std::string::npos);
        ASSERT_TRUE(cf190->result.findings[0].message.find("0 tags") != std::string::npos);
    }
}

static void test_conformance_parity_regressions() {
    std::printf("  test_conformance_parity_regressions...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_mluc_bad_record_size.icc", {30});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 30, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_mluc_zero_name_placeholder.icc", {223});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 223, CheckResult::Status::FINDINGS, 1);

        const auto* cf223 = find_per_check(result, CheckID::Kind::Conformance, 223);
        ASSERT_TRUE(cf223 != nullptr);
        ASSERT_TRUE(cf223->result.findings[0].message.find("12-byte") != std::string::npos);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_reserved_bytes_nonzero_tag.icc", {224});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 224, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "odd_utf16_mluc.icc", {225});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 225, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "valid_srgb.icc", {223, 224, 225, 226});
        ASSERT_EQ(4, result.stats.checksRun);
        expect_conformance_result(result, 223, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 224, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 225, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 226, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_adgc_nan_weights.icc", {123, 128});
        ASSERT_EQ(2, result.stats.checksRun);
        expect_conformance_result(result, 123, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 128, CheckResult::Status::SKIP, 0);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_devicelink_no_atob.icc", {221});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 221, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "calc_trunc_operator.icc", {229});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 229, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf143-meas-valid.icc", {33, 34, 302});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_conformance_result(result, 33, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 34, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 302, CheckResult::Status::FINDINGS, 5);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf137-mdv-invalid-type.icc", {303});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 303, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_htos_bad_type.icc", {319});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 319, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "xyz_out_of_range.icc", {112, 170, 172, 273, 280});
        ASSERT_EQ(5, result.stats.checksRun);
        expect_conformance_result(result, 112, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 170, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 172, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 273, CheckResult::Status::FINDINGS, 2);
        expect_conformance_result(result, 280, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_sf32_bad_size.icc", {278});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 278, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "cf_adgc_cmyk_violation.icc", {123});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 123, CheckResult::Status::FINDINGS, 2);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "named_color2_excessive_coords.icc", {28});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 28, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "wrong_d50_illuminant.icc", {8});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 8, CheckResult::Status::FINDINGS, 3);
    }
    {
        auto result = analyze_corpus_checks(corpusDir / "zero_tags.icc", {93});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 93, CheckResult::Status::OK, 0);
    }
}

static void test_pawg_s1_matrix_trc_regression() {
    std::printf("  test_pawg_s1_matrix_trc_regression...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "valid_srgb.icc", {60, 61});
        ASSERT_EQ(2, result.stats.checksRun);
        expect_conformance_result(result, 60, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 61, CheckResult::Status::OK, 0);
    }

    auto namedColorPath = resolve_repo_file("test-profiles/NamedColor.icc");
    if (namedColorPath.empty()) {
        std::printf("    (skipped — test-profiles/NamedColor.icc not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_checks(namedColorPath, {60, 61});
        ASSERT_EQ(2, result.stats.checksRun);
        expect_conformance_result(result, 60, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 61, CheckResult::Status::OK, 0);

        const auto* cf60 = find_per_check(result, CheckID::Kind::Conformance, 60);
        const auto* cf61 = find_per_check(result, CheckID::Kind::Conformance, 61);
        ASSERT_TRUE(cf60 != nullptr);
        ASSERT_TRUE(cf61 != nullptr);
        ASSERT_TRUE(cf60->result.summary.rfind("N/A:", 0) == 0);
        ASSERT_TRUE(cf61->result.summary.rfind("N/A:", 0) == 0);
    }

    {
        AnalysisOptions opts;
        opts.phases = {CheckPhase::CONFORMANCE};
        opts.specificChecks.push_back({CheckID::Kind::Conformance, 60});
        opts.specificChecks.push_back({CheckID::Kind::Conformance, 61});

        IccTestRunner runner;
        auto result = runner.analyze(namedColorPath, opts);
        ASSERT_EQ(2, result.stats.checksRun);
        expect_conformance_result(result, 60, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 61, CheckResult::Status::OK, 0);
    }
}

static void test_pawg_quality_regressions() {
    std::printf("  test_pawg_quality_regressions...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "valid_srgb.icc", {99, 100, 101, 102});
        ASSERT_EQ(4, result.stats.checksRun);
        expect_conformance_result(result, 99, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 100, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 101, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 102, CheckResult::Status::OK, 0);

        const auto* cf102 = find_per_check(result, CheckID::Kind::Conformance, 102);
        ASSERT_TRUE(cf102 != nullptr);
        ASSERT_TRUE(cf102->result.summary.rfind("N/A:", 0) == 0);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "lut8_atob_btoa.icc", {99, 100, 101});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_conformance_result(result, 99, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 100, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 101, CheckResult::Status::OK, 0);

        const auto* cf99 = find_per_check(result, CheckID::Kind::Conformance, 99);
        ASSERT_TRUE(cf99 != nullptr);
        ASSERT_TRUE(cf99->result.summary.find("samples=") != std::string::npos);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "lut8_atob2_btoa2.icc", {99, 100, 101});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_conformance_result(result, 99, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 100, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 101, CheckResult::Status::OK, 0);

        const auto* cf99 = find_per_check(result, CheckID::Kind::Conformance, 99);
        const auto* cf100 = find_per_check(result, CheckID::Kind::Conformance, 100);
        const auto* cf101 = find_per_check(result, CheckID::Kind::Conformance, 101);
        ASSERT_TRUE(cf99 != nullptr);
        ASSERT_TRUE(cf100 != nullptr);
        ASSERT_TRUE(cf101 != nullptr);
        ASSERT_TRUE(cf99->result.summary.find("A2B2/B2A2") != std::string::npos);
        ASSERT_TRUE(cf100->result.summary.find("curve(s) checked") != std::string::npos);
        ASSERT_TRUE(cf101->result.summary.find("A2B2") != std::string::npos);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "non_monotonic_curve.icc", {100});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 100, CheckResult::Status::FINDINGS, 1);

        const auto* cf100 = find_per_check(result, CheckID::Kind::Conformance, 100);
        ASSERT_TRUE(cf100 != nullptr);
        ASSERT_TRUE(cf100->result.findings[0].message.find("non-monotonic") != std::string::npos);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "targ_tag_profile.icc", {102});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 102, CheckResult::Status::OK, 0);

        const auto* cf102 = find_per_check(result, CheckID::Kind::Conformance, 102);
        ASSERT_TRUE(cf102 != nullptr);
        ASSERT_TRUE(cf102->result.summary.rfind("GAP:", 0) == 0);
        ASSERT_TRUE(cf102->result.summary.find("measurement rows were parsed") != std::string::npos);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "targ_quality_profile.icc", {99, 100, 101, 102});
        ASSERT_EQ(4, result.stats.checksRun);
        expect_conformance_result(result, 99, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 100, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 101, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 102, CheckResult::Status::OK, 0);

        const auto* cf102 = find_per_check(result, CheckID::Kind::Conformance, 102);
        ASSERT_TRUE(cf102 != nullptr);
        ASSERT_TRUE(cf102->result.summary.find("usableRows=") != std::string::npos);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "targ_cmyk_quality_profile.icc", {99, 100, 101, 102});
        ASSERT_EQ(4, result.stats.checksRun);
        expect_conformance_result(result, 99, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 100, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 101, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 102, CheckResult::Status::OK, 0);

        const auto* cf99 = find_per_check(result, CheckID::Kind::Conformance, 99);
        const auto* cf100 = find_per_check(result, CheckID::Kind::Conformance, 100);
        const auto* cf101 = find_per_check(result, CheckID::Kind::Conformance, 101);
        const auto* cf102 = find_per_check(result, CheckID::Kind::Conformance, 102);
        ASSERT_TRUE(cf99 != nullptr);
        ASSERT_TRUE(cf100 != nullptr);
        ASSERT_TRUE(cf101 != nullptr);
        ASSERT_TRUE(cf102 != nullptr);
        ASSERT_TRUE(cf99->result.summary.find("samples=") != std::string::npos);
        ASSERT_TRUE(cf100->result.summary.find("curve(s) checked") != std::string::npos);
        ASSERT_TRUE(cf101->result.summary.find("model=") != std::string::npos);
        ASSERT_TRUE(cf102->result.summary.find("usableRows=") != std::string::npos);
    }
}

static void test_embedding_tech_note_regressions() {
    std::printf("  test_embedding_tech_note_regressions...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_checks(
            corpusDir / "cf_embedded_clean.icc",
            {153, 154, 155, 156, 157, 158, 175, 176, 177});
        ASSERT_EQ(9, result.stats.checksRun);
        expect_conformance_result(result, 153, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 154, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 155, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 156, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 157, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 158, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 175, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 176, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 177, CheckResult::Status::OK, 0);

        const auto* cf154 = find_per_check(result, CheckID::Kind::Conformance, 154);
        ASSERT_TRUE(cf154 != nullptr);
        if (!cf154) {
            return;
        }
        ASSERT_TRUE(cf154->result.findings[0].message.find("already v5") != std::string::npos);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_embedded_wrong_type.icc", {153, 154, 157, 158, 187});
        ASSERT_EQ(5, result.stats.checksRun);
        expect_conformance_result(result, 153, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 154, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 157, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 158, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 187, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_embedded_child_class_mismatch.icc", {155});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 155, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "cf_embedded_child_class_mismatch.icc", {96});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 96, CheckResult::Status::FINDINGS, 1);
        const auto* h96 = find_per_check(result, CheckID::Kind::Heuristic, 96);
        ASSERT_TRUE(h96 != nullptr);
        ASSERT_TRUE(h96->result.findings[0].message.find("CIccEmbedIO constructor sentinel UB") != std::string::npos);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "cf_embedded_wrong_type.icc", {96});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 96, CheckResult::Status::FINDINGS, 1);
        const auto* h96 = find_per_check(result, CheckID::Kind::Heuristic, 96);
        ASSERT_TRUE(h96 != nullptr);
        ASSERT_TRUE(h96->result.findings[0].message.find("wrong runtime type") != std::string::npos);
    }

    {
        AnalysisOptions opts;
        opts.phases = {CheckPhase::RAW_SCAN, CheckPhase::LIBRARY, CheckPhase::CONFORMANCE};
        opts.specificChecks = {
            {CheckID::Kind::Heuristic, 96},
            {CheckID::Kind::Conformance, 155},
        };

        IccTestRunner runner;
        auto result = runner.analyze(corpusDir / "cf_embedded_child_class_mismatch.icc", opts);

        const auto* h96 = find_per_check(result, CheckID::Kind::Heuristic, 96);
        ASSERT_TRUE(h96 != nullptr);
        ASSERT_EQ(CheckResult::Status::FINDINGS, h96->result.status);
        ASSERT_TRUE(h96->result.findings[0].message.find("CIccEmbedIO constructor sentinel UB") != std::string::npos);
        ASSERT_TRUE(find_per_check(result, CheckID::Kind::Conformance, 155) == nullptr);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {173});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 173, CheckResult::Status::FINDINGS, 1);
        const auto* h173 = find_per_check(result, CheckID::Kind::Heuristic, 173);
        ASSERT_TRUE(h173 != nullptr);
        ASSERT_TRUE(h173->result.findings[0].message.find("IccUtil.cpp:1088,1130,1167,1187,1228,1253") != std::string::npos);
    }

    {
        AnalysisOptions opts;
        opts.phases = {CheckPhase::RAW_SCAN, CheckPhase::LIBRARY, CheckPhase::CONFORMANCE};
        opts.specificChecks = {
            {CheckID::Kind::Heuristic, 174},
            {CheckID::Kind::Conformance, 81},
        };

        IccTestRunner runner;
        auto result = runner.analyze(corpusDir / "h174_half_float_mdv_fl16.icc", opts);

        const auto* h174 = find_per_check(result, CheckID::Kind::Heuristic, 174);
        ASSERT_TRUE(h174 != nullptr);
        ASSERT_EQ(CheckResult::Status::FINDINGS, h174->result.status);
        ASSERT_TRUE(h174->result.findings[0].message.find("IccUtil.cpp:665,677") != std::string::npos);
        ASSERT_TRUE(find_per_check(result, CheckID::Kind::Conformance, 81) == nullptr);
    }

    {
        AnalysisOptions opts;
        opts.phases = {CheckPhase::RAW_SCAN, CheckPhase::CONFORMANCE};
        opts.skipLibraryOnUB = false;
        opts.specificChecks = {
            {CheckID::Kind::Heuristic, 174},
            {CheckID::Kind::Conformance, 81},
        };

        IccTestRunner runner;
        auto result = runner.analyze(corpusDir / "h174_half_float_header.icc", opts);

        expect_heuristic_result(result, 174, CheckResult::Status::FINDINGS, 2);
        const auto* h174 = find_per_check(result, CheckID::Kind::Heuristic, 174);
        ASSERT_TRUE(h174 != nullptr);
        ASSERT_TRUE(h174->result.findings[0].message.find("IccUtil.cpp:665,677") != std::string::npos);
        expect_conformance_result(result, 81, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_embedded_child_flags_bad.icc", {156});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 156, CheckResult::Status::FINDINGS, 2);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_embedded_child_pcs_mismatch.icc", {175});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 175, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_embedded_reserved_nonzero.icc", {176});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 176, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "cf_embedded_devicelink_flagged.icc", {214});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 214, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "valid_srgb.icc", {214, 215, 216, 217, 218, 219});
        ASSERT_EQ(6, result.stats.checksRun);
        expect_conformance_result(result, 214, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 215, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 216, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 217, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 218, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 219, CheckResult::Status::OK, 0);
    }

    {
        auto result = analyze_corpus_checks(corpusDir / "v5_spac_basic.icc", {216, 217, 218, 219});
        ASSERT_EQ(4, result.stats.checksRun);
        expect_conformance_result(result, 216, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 217, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 218, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 219, CheckResult::Status::OK, 0);

        const auto* cf216 = find_per_check(result, CheckID::Kind::Conformance, 216);
        ASSERT_TRUE(cf216 != nullptr);
        ASSERT_TRUE(cf216->result.summary.rfind("NOT RUN:", 0) == 0);
    }
}

static void test_heuristic_parity_regressions() {
    std::printf("  test_heuristic_parity_regressions...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "calc_trunc_operator.icc", {151});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 151, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "reserved_bytes_nonzero.icc", {111, 142});
        ASSERT_EQ(2, result.stats.checksRun);
        expect_heuristic_result(result, 111, CheckResult::Status::FINDINGS, 1);
        expect_heuristic_result(result, 142, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "bad_magic.icc", {111, 142, 164});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_heuristic_result(result, 111, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 142, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 164, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "cf137-mdv-invalid-type.icc", {15, 153});
        ASSERT_EQ(2, result.stats.checksRun);
        expect_heuristic_result(result, 15, CheckResult::Status::FINDINGS, 3);
        expect_heuristic_result(result, 153, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "named_color2_large_nsize.icc", {154, 155});
        ASSERT_EQ(2, result.stats.checksRun);
        expect_heuristic_result(result, 154, CheckResult::Status::FINDINGS, 1);
        expect_heuristic_result(result, 155, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "cf138-ehim-valid.icc", {99});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 99, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "cf139-enim-valid.icc", {99});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 99, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {99});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 99, CheckResult::Status::SKIP, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "just_header.icc", {154, 155, 156, 158, 162, 163});
        ASSERT_EQ(6, result.stats.checksRun);
        expect_heuristic_result(result, 154, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 155, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 156, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 158, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 162, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 163, CheckResult::Status::SKIP, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "invalid_rendering_intent.icc", {158});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 158, CheckResult::Status::OK, 0);
    }
}

static void test_pcc_illuminant_overflow_regression() {
    std::printf("  test_pcc_illuminant_overflow_regression...\n");

    const std::vector<const char*> profiles = {
        "test-profiles/76558f2fb46ff50ff77237856adfde8ff74c3793",
        "test-profiles/8541e466f7def17ed6d5e8fa355bfcb3dc855ce1",
    };

    for (const char* relativePath : profiles) {
        auto profilePath = resolve_repo_file(relativePath);
        if (profilePath.empty()) {
            std::printf("    (skipped — %s not found)\n", relativePath);
            continue;
        }

        auto opened = ProfileView::open(profilePath, false);
        ASSERT_TRUE(opened.has_value());
        ASSERT_TRUE(opened->libraryLoaded());

        CIccProfile* pIcc = opened->unsafeLibraryHandle();
        ASSERT_TRUE(pIcc != nullptr);
        ASSERT_EQ(icIlluminantUnknown, pIcc->getPccIlluminant());
        ASSERT_EQ(0.0f, pIcc->getPccCCT());
        ASSERT_EQ(icStdObsUnknown, pIcc->getPccObserver());

        AnalysisOptions opts;
        opts.phases = {CheckPhase::HEADER, CheckPhase::RAW_SCAN, CheckPhase::LIBRARY};
        opts.skipLibraryOnUB = false;
        opts.specificChecks = {
            {CheckID::Kind::Heuristic, 8},
            {CheckID::Kind::Heuristic, 112},
        };

        IccTestRunner runner;
        auto result = runner.analyze(profilePath, opts);
        ASSERT_EQ(2, result.stats.checksRun);
        ASSERT_TRUE(find_per_check(result, CheckID::Kind::Heuristic, 8) != nullptr);
        ASSERT_TRUE(find_per_check(result, CheckID::Kind::Heuristic, 112) != nullptr);
        ASSERT_TRUE(result.stats.findingsTotal >= 1);
    }
}

static void test_tonemap_describe_overflow_regression() {
    std::printf("  test_tonemap_describe_overflow_regression...\n");

    auto profilePath = resolve_repo_file("test-profiles/CIccToneMapFunc-Describe-heap-oob-IccMpeBasic_cpp.icc");
    if (profilePath.empty()) {
        std::printf("    (skipped — tone-map regression profile not found)\n");
        return;
    }

    AnalysisOptions heuristicOpts;
    heuristicOpts.phases = {CheckPhase::LIBRARY};
    heuristicOpts.specificChecks = {
        {CheckID::Kind::Heuristic, 101},
    };

    IccTestRunner runner;
    auto heuristicResult = runner.analyze(profilePath, heuristicOpts);
    ASSERT_EQ(1, heuristicResult.stats.checksRun);
    const auto* h101 = find_per_check(heuristicResult, CheckID::Kind::Heuristic, 101);
    ASSERT_TRUE(h101 != nullptr);
    if (!h101) {
        return;
    }
    ASSERT_EQ(CheckResult::Status::FINDINGS, h101->result.status);
    ASSERT_TRUE(h101->result.issueCount() >= 1);

    bool sawRawMpeFinding = false;
    for (const auto& finding : h101->result.findings) {
        if (finding.message.find("mpet element table entry") != std::string::npos &&
            finding.cweNote.find("IccTagMPE.cpp:1042") != std::string::npos) {
            sawRawMpeFinding = true;
            break;
        }
    }
    ASSERT_TRUE(sawRawMpeFinding);

    AnalysisOptions conformanceOpts;
    conformanceOpts.phases = {CheckPhase::CONFORMANCE};
    conformanceOpts.skipLibraryOnUB = true;
    conformanceOpts.specificChecks = {
        {CheckID::Kind::Conformance, 115},
    };

    auto conformanceResult = runner.analyze(profilePath, conformanceOpts);
    ASSERT_EQ(1, conformanceResult.stats.checksRun);
    const auto* cf115 = find_per_check(conformanceResult, CheckID::Kind::Conformance, 115);
    ASSERT_TRUE(cf115 != nullptr);
    if (!cf115) {
        return;
    }
    ASSERT_EQ(CheckResult::Status::FINDINGS, cf115->result.status);
    ASSERT_TRUE(cf115->result.issueCount() >= 1);

    bool sawCfMpeFinding = false;
    for (const auto& finding : cf115->result.findings) {
        if (finding.message.find("MPE element table structurally invalid") != std::string::npos &&
            finding.detail.find("mpet element table entry") != std::string::npos) {
            sawCfMpeFinding = true;
            break;
        }
    }
    ASSERT_TRUE(sawCfMpeFinding);
}

static void test_curve_element_oom_regression() {
    std::printf("  test_curve_element_oom_regression...\n");

    const char* triggerNames[] = {
        "test-profiles/oom-CIccSingleSampledCurve-SetSize-IccProfLib-IccMpeBasic_cpp-Line1496.icc",
        "test-profiles/cwe-400/oom-CIccSampledCurveSegment-SetSize-IccMpeBasic_cpp-Line986.icc",
    };

    for (const char* name : triggerNames) {
        auto profilePath = resolve_repo_file(name);
        if (profilePath.empty()) {
            std::printf("    (skipped — %s not found)\n", name);
            continue;
        }

        AnalysisOptions heuristicOpts;
        heuristicOpts.phases = {CheckPhase::RAW_SCAN};
        heuristicOpts.specificChecks = {
            {CheckID::Kind::Heuristic, 152},
        };

        IccTestRunner runner;
        auto heuristicResult = runner.analyze(profilePath, heuristicOpts);
        ASSERT_EQ(1, heuristicResult.stats.checksRun);
        const auto* h152 = find_per_check(heuristicResult, CheckID::Kind::Heuristic, 152);
        ASSERT_TRUE(h152 != nullptr);
        if (!h152) {
            continue;
        }

        ASSERT_EQ(CheckResult::Status::FINDINGS, h152->result.status);
        ASSERT_TRUE(h152->result.issueCount() >= 1);

        bool sawCurveIssue = false;
        for (const auto& finding : h152->result.findings) {
            if ((finding.message.find("SingleSampledCurve") != std::string::npos ||
                 finding.message.find("SampledCurveSegment") != std::string::npos) &&
                finding.cweNote.find("CWE-770") != std::string::npos) {
                sawCurveIssue = true;
                break;
            }
        }
        ASSERT_TRUE(sawCurveIssue);

        auto pv = ProfileView::open(profilePath, true);
        ASSERT_TRUE(pv.has_value());
        if (pv) {
            ASSERT_TRUE(pv->requiresLibraryQuarantine());
            ASSERT_TRUE(pv->librarySkippedDueToUB());
            ASSERT_FALSE(pv->libraryLoaded());
        }
    }
}

static void test_null_mpe_clut_curve_guard_regression() {
    std::printf("  test_null_mpe_clut_curve_guard_regression...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        AnalysisOptions heuristicOpts;
        heuristicOpts.phases = {CheckPhase::RAW_SCAN};
        heuristicOpts.specificChecks = {
            {CheckID::Kind::Heuristic, 167},
        };

        IccTestRunner runner;
        auto heuristicResult = runner.analyze(corpusDir / "lut_null_clut.icc", heuristicOpts);
        ASSERT_EQ(1, heuristicResult.stats.checksRun);
        const auto* h167 = find_per_check(heuristicResult, CheckID::Kind::Heuristic, 167);
        ASSERT_TRUE(h167 != nullptr);
        if (!h167) return;

        ASSERT_EQ(CheckResult::Status::FINDINGS, h167->result.status);
        ASSERT_TRUE(h167->result.issueCount() >= 1);

        bool sawNullClutIssue = false;
        for (const auto& finding : h167->result.findings) {
            if (finding.message.find("CLUT offset=0 but active curves") != std::string::npos &&
                finding.cweNote.find("CWE-476") != std::string::npos) {
                sawNullClutIssue = true;
                break;
            }
        }
        ASSERT_TRUE(sawNullClutIssue);
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {167});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 167, CheckResult::Status::OK, 0);
    }
}

static void test_null_pointer_after_tag_read_regression() {
    std::printf("  test_null_pointer_after_tag_read_regression...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "lut_null_clut.icc", {147});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 147, CheckResult::Status::FINDINGS, 1);

        const auto* h147 = find_per_check(result, CheckID::Kind::Heuristic, 147);
        ASSERT_TRUE(h147 != nullptr);
        if (!h147) return;

        bool sawNullClut = false;
        for (const auto& finding : h147->result.findings) {
            if (finding.message.find("null CLUT") != std::string::npos &&
                finding.cweNote.find("CWE-476") != std::string::npos) {
                sawNullClut = true;
                break;
            }
        }
        ASSERT_TRUE(sawNullClut);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "lut_degenerate_clut.icc", {147});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 147, CheckResult::Status::FINDINGS, 1);

        const auto* h147 = find_per_check(result, CheckID::Kind::Heuristic, 147);
        ASSERT_TRUE(h147 != nullptr);
        if (!h147) return;

        bool sawDegenerateClut = false;
        for (const auto& finding : h147->result.findings) {
            if ((finding.message.find("CLUT has") != std::string::npos ||
                 finding.message.find("pTag pointer is null") != std::string::npos) &&
                finding.cweNote.find("CWE-476") != std::string::npos) {
                sawDegenerateClut = true;
                break;
            }
        }
        ASSERT_TRUE(sawDegenerateClut);
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {147});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 147, CheckResult::Status::OK, 0);
    }
}

static void test_memory_copy_bounds_overlap_regression() {
    std::printf("  test_memory_copy_bounds_overlap_regression...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "named_color2_excessive_coords.icc", {148});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 148, CheckResult::Status::FINDINGS, 1);

        const auto* h148 = find_per_check(result, CheckID::Kind::Heuristic, 148);
        ASSERT_TRUE(h148 != nullptr);
        if (!h148) return;

        bool sawNamedColorOverflow = false;
        for (const auto& finding : h148->result.findings) {
            if (finding.message.find("NamedColor2 deviceCoords=20 exceeds ICC max (15)") != std::string::npos &&
                finding.cweNote.find("CWE-119") != std::string::npos) {
                sawNamedColorOverflow = true;
                break;
            }
        }
        ASSERT_TRUE(sawNamedColorOverflow);
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {148});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 148, CheckResult::Status::OK, 0);
    }
}

static void test_profile_sequence_id_validation_regression() {
    std::printf("  test_profile_sequence_id_validation_regression...\n");

    {
        auto malformed = make_h97_profile_sequence_id_profile(true);
        auto profilePath = write_temp_profile(malformed, "h97-psid-malformed.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {97});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 97, CheckResult::Status::FINDINGS, 3);

        const auto* h97 = find_per_check(result, CheckID::Kind::Heuristic, 97);
        ASSERT_TRUE(h97 != nullptr);
        if (!h97) return;

        bool sawEntryCount = false;
        bool sawNullId = false;
        bool sawDupId = false;
        for (const auto& finding : h97->result.findings) {
            if (finding.message.find("Profile sequence: 3 entries") != std::string::npos) {
                sawEntryCount = true;
            }
            if (finding.message.find("Null profile ID (all zeros) in sequence") != std::string::npos) {
                sawNullId = true;
            }
            if (finding.message.find("Duplicate profile IDs in sequence") != std::string::npos) {
                sawDupId = true;
            }
        }
        ASSERT_TRUE(sawEntryCount);
        ASSERT_TRUE(sawNullId);
        ASSERT_TRUE(sawDupId);

        std::filesystem::remove(profilePath);
    }

    {
        auto clean = make_h97_profile_sequence_id_profile(false);
        auto profilePath = write_temp_profile(clean, "h97-psid-clean.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {97});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 97, CheckResult::Status::OK, 0);

        const auto* h97 = find_per_check(result, CheckID::Kind::Heuristic, 97);
        ASSERT_TRUE(h97 != nullptr);
        if (h97) {
            ASSERT_TRUE(h97->result.summary.find("Profile sequence identifiers valid") != std::string::npos);
        }

        std::filesystem::remove(profilePath);
    }

    {
        auto corpusPath = resolve_repo_file("tests/corpus/suspicious_profile_id.icc");
        if (!corpusPath.empty()) {
            auto result = analyze_corpus_heuristics(corpusPath, {97});
            ASSERT_EQ(1, result.stats.checksRun);
            expect_heuristic_result(result, 97, CheckResult::Status::SKIP, 0);
        }
    }
}

static void test_tag_size_profile_size_cross_check_regression() {
    std::printf("  test_tag_size_profile_size_cross_check_regression...\n");

    {
        auto malformed = make_h102_profile_size_profile(140, 240, 64);
        auto profilePath = write_temp_profile(malformed, "h102-small-header.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {102});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 102, CheckResult::Status::FINDINGS, 11);

        const auto* h102 = find_per_check(result, CheckID::Kind::Heuristic, 102);
        ASSERT_TRUE(h102 != nullptr);
        if (h102) {
            bool sawHeader = false;
            bool sawOffset = false;
            for (const auto& finding : h102->result.findings) {
                if (finding.message.find("Profile size 140 too small for 9 tags") != std::string::npos) {
                    sawHeader = true;
                }
                if (finding.message.find("offset 240 exceeds profile size 140") != std::string::npos) {
                    sawOffset = true;
                }
            }
            ASSERT_TRUE(sawHeader);
            ASSERT_TRUE(sawOffset);
        }
        std::filesystem::remove(profilePath);
    }

    {
        auto malformed = make_h102_profile_size_profile(500, 1000, 64);
        auto profilePath = write_temp_profile(malformed, "h102-bad-offset.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {102});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 102, CheckResult::Status::FINDINGS, 2);

        const auto* h102 = find_per_check(result, CheckID::Kind::Heuristic, 102);
        ASSERT_TRUE(h102 != nullptr);
        if (h102 && !h102->result.findings.empty()) {
            ASSERT_TRUE(h102->result.findings[0].message.find("offset 1000 exceeds profile size 500") != std::string::npos ||
                        h102->result.findings[1].message.find("offset 1000 exceeds profile size 500") != std::string::npos);
        }
        std::filesystem::remove(profilePath);
    }

    {
        auto malformed = make_h102_profile_size_profile(500, 240, 1000);
        auto profilePath = write_temp_profile(malformed, "h102-bad-size.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {102});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 102, CheckResult::Status::FINDINGS, 2);

        const auto* h102 = find_per_check(result, CheckID::Kind::Heuristic, 102);
        ASSERT_TRUE(h102 != nullptr);
        if (h102 && !h102->result.findings.empty()) {
            ASSERT_TRUE(h102->result.findings[0].message.find("extends past profile end") != std::string::npos ||
                        h102->result.findings[1].message.find("extends past profile end") != std::string::npos);
        }
        std::filesystem::remove(profilePath);
    }

    {
        auto corpusPath = resolve_repo_file("tests/corpus/valid_srgb.icc");
        ASSERT_FALSE(corpusPath.empty());
        if (!corpusPath.empty()) {
            auto result = analyze_corpus_heuristics(corpusPath, {102});
            ASSERT_EQ(1, result.stats.checksRun);
            expect_heuristic_result(result, 102, CheckResult::Status::OK, 0);
        }
    }

    {
        auto corpusPath = resolve_repo_file("tests/corpus/just_header.icc");
        ASSERT_FALSE(corpusPath.empty());
        if (!corpusPath.empty()) {
            auto result = analyze_corpus_heuristics(corpusPath, {102});
            ASSERT_EQ(1, result.stats.checksRun);
            expect_heuristic_result(result, 102, CheckResult::Status::SKIP, 0);
        }
    }
}

static void test_unchecked_allocation_size_overflow_regression() {
    std::printf("  test_unchecked_allocation_size_overflow_regression...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "named_color2_large_nsize.icc", {168});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 168, CheckResult::Status::FINDINGS, 1);

        const auto* h168 = find_per_check(result, CheckID::Kind::Heuristic, 168);
        ASSERT_TRUE(h168 != nullptr);
        if (!h168) return;

        bool sawNamedColor = false;
        for (const auto& finding : h168->result.findings) {
            if (finding.message.find("NamedColor2 has 70000 entries") != std::string::npos &&
                finding.cweNote.find("CWE-789") != std::string::npos) {
                sawNamedColor = true;
                break;
            }
        }
        ASSERT_TRUE(sawNamedColor);
    }

    {
        auto gbdPath = resolve_repo_file(
            "test-profiles/oom-CIccTagGamutBoundaryDesc-Read-1024G-IccTagLut_cpp-Line5631.icc");
        if (gbdPath.empty()) {
            std::printf("    (skipped — GamutBoundaryDesc overflow fixture not found)\n");
        } else {
            auto result = analyze_corpus_heuristics(gbdPath, {168});
            ASSERT_EQ(1, result.stats.checksRun);
            expect_heuristic_result(result, 168, CheckResult::Status::FINDINGS, 1);

            const auto* h168 = find_per_check(result, CheckID::Kind::Heuristic, 168);
            ASSERT_TRUE(h168 != nullptr);
            if (!h168) return;

            bool sawGbd = false;
            for (const auto& finding : h168->result.findings) {
                if (finding.message.find("GamutBoundaryDesc") != std::string::npos &&
                    finding.cweNote.find("CWE-190") != std::string::npos) {
                    sawGbd = true;
                    break;
                }
            }
            ASSERT_TRUE(sawGbd);
        }
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {168});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 168, CheckResult::Status::OK, 0);
    }
}

static void test_alloc_dealloc_and_uaf_ownership_regressions() {
    std::printf("  test_alloc_dealloc_and_uaf_ownership_regressions...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "named_color2_large_nsize.icc", {157, 159});
        ASSERT_EQ(2, result.stats.checksRun);
        expect_heuristic_result(result, 157, CheckResult::Status::FINDINGS, 1);
        expect_heuristic_result(result, 159, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto taryPath = resolve_repo_file("test-profiles/cfl-003-roundtrip-segv-tary.icc");
        if (taryPath.empty()) {
            std::printf("    (skipped — TagArray CFL-003 fixture not found)\n");
        } else {
            auto result = analyze_corpus_heuristics(taryPath, {157, 159});
            ASSERT_EQ(2, result.stats.checksRun);
            expect_heuristic_result(result, 157, CheckResult::Status::FINDINGS, 1);
            expect_heuristic_result(result, 159, CheckResult::Status::FINDINGS, 1);

            const auto* h157 = find_per_check(result, CheckID::Kind::Heuristic, 157);
            ASSERT_TRUE(h157 != nullptr);
            if (!h157) return;
            ASSERT_TRUE(h157->result.findings[0].message.find("TagArray ('tary')") != std::string::npos);
            ASSERT_TRUE(h157->result.findings[0].cweNote.find("CWE-762") != std::string::npos);

            const auto* h159 = find_per_check(result, CheckID::Kind::Heuristic, 159);
            ASSERT_TRUE(h159 != nullptr);
            if (!h159) return;
            ASSERT_TRUE(h159->result.findings[0].message.find("CFL-003 UAF path") != std::string::npos);
            ASSERT_TRUE(h159->result.findings[0].cweNote.find("CWE-416") != std::string::npos);
        }
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {157, 159});
        ASSERT_EQ(2, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 157, CheckResult::Status::OK, 0);
        expect_heuristic_result(cleanResult, 159, CheckResult::Status::OK, 0);
    }
}

static void test_deep_apply_stack_escape_regression() {
    std::printf("  test_deep_apply_stack_escape_regression...\n");

    {
        AnalysisOptions opts;
        opts.phases = {CheckPhase::RAW_SCAN};
        opts.specificChecks = {
            {CheckID::Kind::Heuristic, 161},
        };

        auto data = make_h161_deep_apply_profile();
        IccTestRunner runner;
        auto result = runner.analyze(data.data(), data.size(), opts);
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 161, CheckResult::Status::FINDINGS, 3);

        const auto* h161 = find_per_check(result, CheckID::Kind::Heuristic, 161);
        ASSERT_TRUE(h161 != nullptr);
        if (!h161) {
            return;
        }

        bool sawA2B0Risk = false;
        bool sawB2A0Risk = false;
        bool sawProfileWideRisk = false;
        for (const auto& finding : h161->result.findings) {
            if (finding.message.find("Tag 'A2B0' MPE chain: 5 elements x 12->12 channels") != std::string::npos &&
                finding.cweNote.find("CWE-121") != std::string::npos) {
                sawA2B0Risk = true;
            }
            if (finding.message.find("Tag 'B2A0' MPE chain: 5 elements x 12->12 channels") != std::string::npos &&
                finding.cweNote.find("CWE-121") != std::string::npos) {
                sawB2A0Risk = true;
            }
            if (finding.message.find("12-channel profile with 2 MPE tags") != std::string::npos &&
                finding.cweNote.find("High channel count") != std::string::npos) {
                sawProfileWideRisk = true;
            }
        }
        ASSERT_TRUE(sawA2B0Risk);
        ASSERT_TRUE(sawB2A0Risk);
        ASSERT_TRUE(sawProfileWideRisk);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped clean check — tests/corpus not found)\n");
        return;
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {161});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 161, CheckResult::Status::OK, 0);

        const auto* h161 = find_per_check(cleanResult, CheckID::Kind::Heuristic, 161);
        ASSERT_TRUE(h161 != nullptr);
        if (!h161) {
            return;
        }
        ASSERT_TRUE(h161->result.summary.find("No deep Apply() chain stack-escape risk patterns") != std::string::npos);
    }
}

static void test_dictionary_tag_element_bounds_regression() {
    std::printf("  test_dictionary_tag_element_bounds_regression...\n");

    {
        AnalysisOptions opts;
        opts.phases = {CheckPhase::RAW_SCAN};
        opts.specificChecks = {
            {CheckID::Kind::Heuristic, 169},
        };

        auto data = make_h169_dict_bounds_profile();
        IccTestRunner runner;
        auto result = runner.analyze(data.data(), data.size(), opts);
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 169, CheckResult::Status::FINDINGS, 2);

        const auto* h169 = find_per_check(result, CheckID::Kind::Heuristic, 169);
        ASSERT_TRUE(h169 != nullptr);
        if (!h169) {
            return;
        }

        bool sawRecLenFinding = false;
        bool sawBoundsFinding = false;
        for (const auto& finding : h169->result.findings) {
            if (finding.message.find("dict recLen = 8") != std::string::npos &&
                finding.cweNote.find("CWE-20") != std::string::npos) {
                sawRecLenFinding = true;
            }
            if (finding.message.find("3 entries × 8 bytes/rec = 24 bytes exceeds 16-byte tag") != std::string::npos &&
                finding.cweNote.find("CWE-789") != std::string::npos) {
                sawBoundsFinding = true;
            }
        }
        ASSERT_TRUE(sawRecLenFinding);
        ASSERT_TRUE(sawBoundsFinding);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped clean check — tests/corpus not found)\n");
        return;
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {169});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 169, CheckResult::Status::OK, 0);

        const auto* h169 = find_per_check(cleanResult, CheckID::Kind::Heuristic, 169);
        ASSERT_TRUE(h169 != nullptr);
        if (!h169) {
            return;
        }
        ASSERT_TRUE(h169->result.summary.find("No dictionary tag bounds issues detected") != std::string::npos);
    }
}

static void test_lut_data_sufficiency_regression() {
    std::printf("  test_lut_data_sufficiency_regression...\n");

    {
        AnalysisOptions opts;
        opts.phases = {CheckPhase::RAW_SCAN};
        opts.specificChecks = {
            {CheckID::Kind::Heuristic, 165},
        };

        auto data = make_h165_lut_data_sufficiency_profile();
        IccTestRunner runner;
        auto result = runner.analyze(data.data(), data.size(), opts);
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 165, CheckResult::Status::FINDINGS, 1);

        const auto* h165 = find_per_check(result, CheckID::Kind::Heuristic, 165);
        ASSERT_TRUE(h165 != nullptr);
        if (!h165) {
            return;
        }

        ASSERT_TRUE(h165->result.findings[0].message.find("Tag 'A2B0' (lut8): n_in=3 n_out=3 grid=2") != std::string::npos);
        ASSERT_TRUE(h165->result.findings[0].message.find("min 1608 bytes but tag size is 16") != std::string::npos);
        ASSERT_TRUE(h165->result.findings[0].cweNote.find("CWE-125/CWE-122") != std::string::npos);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped clean check — tests/corpus not found)\n");
        return;
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {165});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 165, CheckResult::Status::OK, 0);

        const auto* h165 = find_per_check(cleanResult, CheckID::Kind::Heuristic, 165);
        ASSERT_TRUE(h165 != nullptr);
        if (!h165) {
            return;
        }
        ASSERT_TRUE(h165->result.summary.find("All LUT tags have sufficient data for declared contents") != std::string::npos);
    }
}

static void test_copy_constructor_null_pcs_regression() {
    std::printf("  test_copy_constructor_null_pcs_regression...\n");

    {
        AnalysisOptions opts;
        opts.phases = {CheckPhase::RAW_SCAN};
        opts.specificChecks = {
            {CheckID::Kind::Heuristic, 170},
        };

        auto data = make_h170_null_pcs_profile();
        IccTestRunner runner;
        auto result = runner.analyze(data.data(), data.size(), opts);
        ASSERT_EQ(1, result.stats.checksRun);

        const auto* h170 = find_per_check(result, CheckID::Kind::Heuristic, 170);
        ASSERT_TRUE(h170 != nullptr);
        if (!h170) {
            return;
        }

        ASSERT_EQ(CheckResult::Status::FINDINGS, h170->result.status);
        ASSERT_TRUE(h170->result.issueCount() >= 3);

        bool sawNullPcs = false;
        bool sawTypeConfusion = false;
        bool sawAffectedTools = false;
        for (const auto& finding : h170->result.findings) {
            if (finding.message.find("PCS is null (0x00000000)") != std::string::npos &&
                finding.message.find("profile class 'mntr'") != std::string::npos) {
                sawNullPcs = true;
            }
            if (finding.cweNote.find("CWE-843") != std::string::npos &&
                finding.cweNote.find("invalid vptr") != std::string::npos) {
                sawTypeConfusion = true;
            }
            if (finding.message.find("Affected tools: iccApplySearch, iccRoundTrip") != std::string::npos) {
                sawAffectedTools = true;
            }
        }
        ASSERT_TRUE(sawNullPcs);
        ASSERT_TRUE(sawTypeConfusion);
        ASSERT_TRUE(sawAffectedTools);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped clean check — tests/corpus not found)\n");
        return;
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {170});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 170, CheckResult::Status::OK, 0);

        const auto* h170 = find_per_check(cleanResult, CheckID::Kind::Heuristic, 170);
        ASSERT_TRUE(h170 != nullptr);
        if (!h170) {
            return;
        }
        ASSERT_TRUE(h170->result.summary.find("PCS signature valid for copy-constructor safety") != std::string::npos);
    }
}

static void test_lut_matrix_coefficient_validation_regression() {
    std::printf("  test_lut_matrix_coefficient_validation_regression...\n");

    {
        AnalysisOptions opts;
        opts.phases = {CheckPhase::LIBRARY};
        opts.specificChecks = {
            {CheckID::Kind::Heuristic, 172},
        };

        auto data = make_h172_lut_matrix_profile(true);
        auto path = write_temp_profile(data, "icctest-h172-lut-matrix.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        IccTestRunner runner;
        auto result = runner.analyze(path, opts);
        ASSERT_EQ(1, result.stats.checksRun);

        const auto* h172 = find_per_check(result, CheckID::Kind::Heuristic, 172);
        ASSERT_TRUE(h172 != nullptr);
        if (!h172) {
            return;
        }

        ASSERT_EQ(CheckResult::Status::FINDINGS, h172->result.status);
        ASSERT_TRUE(h172->result.issueCount() >= 3);

        ASSERT_EQ(4, static_cast<int>(h172->result.findings.size()));
        ASSERT_TRUE(h172->result.summary.find("Checked 1 LUT matrices") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    {
        AnalysisOptions opts;
        opts.phases = {CheckPhase::LIBRARY};
        opts.specificChecks = {
            {CheckID::Kind::Heuristic, 172},
        };

        auto cleanData = make_h172_lut_matrix_profile(false);
        auto cleanPath = write_temp_profile(cleanData, "icctest-h172-lut-matrix-clean.icc");
        ASSERT_FALSE(cleanPath.empty());
        if (cleanPath.empty()) {
            return;
        }

        IccTestRunner runner;
        auto cleanResult = runner.analyze(cleanPath, opts);
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 172, CheckResult::Status::OK, 0);

        const auto* h172 = find_per_check(cleanResult, CheckID::Kind::Heuristic, 172);
        ASSERT_TRUE(h172 != nullptr);
        if (!h172) {
            return;
        }
        ASSERT_TRUE(h172->result.summary.find("Validated 1 LUT matrix/matrices") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(cleanPath, ignored);
    }
}

static void test_spectral_mpe_h98_gap_fixture() {
    std::printf("  test_spectral_mpe_h98_gap_fixture...\n");

    auto spectralPath = resolve_repo_file(
        "test-profiles/heap-buffer-overflow-CIccMpeSpectralMatrix-Describe-IccMpeSpectral_cpp-Line352.icc");
    if (spectralPath.empty()) {
        std::printf("    (skipped — spectral H98 regression profile not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_heuristics(spectralPath, {98});
        ASSERT_EQ(1, result.stats.checksRun);

        const auto* h98 = find_per_check(result, CheckID::Kind::Heuristic, 98);
        ASSERT_TRUE(h98 != nullptr);
        if (!h98) return;

        ASSERT_EQ(CheckResult::Status::FINDINGS, h98->result.status);
        ASSERT_TRUE(h98->result.issueCount() >= 2);

        bool sawRowOverflow = false;
        bool sawStrideMismatch = false;
        for (const auto& finding : h98->result.findings) {
            if (finding.message.find("EmissionMatrix out(") != std::string::npos &&
                finding.cweNote.find("CWE-122") != std::string::npos) {
                sawRowOverflow = true;
            }
            if (finding.message.find("pointer advance mismatch") != std::string::npos &&
                finding.cweNote.find("CWE-125") != std::string::npos) {
                sawStrideMismatch = true;
            }
        }

        ASSERT_TRUE(sawRowOverflow);
        ASSERT_TRUE(sawStrideMismatch);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped clean check — tests/corpus not found)\n");
        return;
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {98});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 98, CheckResult::Status::SKIP, 0);
    }
}

static void test_cf115_only_emits_raw_findings_when_quarantined() {
    std::printf("  test_cf115_only_emits_raw_findings_when_quarantined...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    for (const char* name : {"cf142-vor-valid.icc", "cf142-vor-misaligned.icc"}) {
        auto result = analyze_corpus_checks(corpusDir / name, {115});
        ASSERT_EQ(1, result.stats.checksRun);

        const auto* cf115 = find_per_check(result, CheckID::Kind::Conformance, 115);
        ASSERT_TRUE(cf115 != nullptr);
        if (!cf115) {
            return;
        }

        ASSERT_EQ(CheckResult::Status::SKIP, cf115->result.status);
        ASSERT_EQ(0, cf115->result.issueCount());
        ASSERT_TRUE(cf115->result.summary.rfind("NOT RUN: Profile failed to load", 0) == 0);
    }
}

static void test_conformance_v5_only_skip_regression() {
    std::printf("  test_conformance_v5_only_skip_regression...\n");

    auto corpusPath = resolve_repo_file("tests/corpus/bad_wtpt.icc");
    if (corpusPath.empty()) {
        std::printf("    (skipped — bad_wtpt.icc not found)\n");
        return;
    }

    auto result = analyze_corpus_checks(corpusPath, {157, 158, 159, 160, 161, 162, 180, 181, 295});
    ASSERT_EQ(9, result.stats.checksRun);
    expect_conformance_result(result, 157, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 158, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 159, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 160, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 161, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 162, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 180, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 181, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 295, CheckResult::Status::SKIP, 0);
}

static void test_conformance_v5_gate_regression() {
    std::printf("  test_conformance_v5_gate_regression...\n");

    auto reservedBytesPath = resolve_repo_file("tests/corpus/reserved_bytes_nonzero.icc");
    if (reservedBytesPath.empty()) {
        std::printf("    (skipped — reserved_bytes_nonzero.icc not found)\n");
        return;
    }

    auto spectralResult = analyze_corpus_checks(reservedBytesPath, {113, 114, 257});
    ASSERT_EQ(3, spectralResult.stats.checksRun);
    expect_conformance_result(spectralResult, 113, CheckResult::Status::SKIP, 0);
    expect_conformance_result(spectralResult, 114, CheckResult::Status::SKIP, 0);
    expect_conformance_result(spectralResult, 257, CheckResult::Status::SKIP, 0);

    auto flagsPath = resolve_repo_file("tests/corpus/flags_reserved_bits.icc");
    if (flagsPath.empty()) {
        std::printf("    (skipped — flags_reserved_bits.icc not found)\n");
        return;
    }

    auto extendedRangeResult = analyze_corpus_checks(flagsPath, {147});
    ASSERT_EQ(1, extendedRangeResult.stats.checksRun);
    expect_conformance_result(extendedRangeResult, 147, CheckResult::Status::SKIP, 0);
}

static void test_conformance_adgc_skip_regression() {
    std::printf("  test_conformance_adgc_skip_regression...\n");

    auto corpusPath = resolve_repo_file("tests/corpus/bad_wtpt.icc");
    if (corpusPath.empty()) {
        std::printf("    (skipped — bad_wtpt.icc not found)\n");
        return;
    }

    auto result = analyze_corpus_checks(corpusPath, {133, 134, 135, 136});
    ASSERT_EQ(4, result.stats.checksRun);
    expect_conformance_result(result, 133, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 134, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 135, CheckResult::Status::SKIP, 0);
    expect_conformance_result(result, 136, CheckResult::Status::SKIP, 0);

    const auto* cf133 = find_per_check(result, CheckID::Kind::Conformance, 133);
    ASSERT_TRUE(cf133 != nullptr);
    ASSERT_EQ(std::string("No ADGC tag or read failed"), cf133->result.summary);
}

static void test_image_tiff_with_embedded_icc_regression() {
    std::printf("  test_image_tiff_with_embedded_icc_regression...\n");

    auto imagePath = resolve_repo_file("tests/corpus/test_tiff_with_icc.tif");
    if (imagePath.empty()) {
        std::printf("    (skipped — test_tiff_with_icc.tif not found)\n");
        return;
    }

    auto result = analyze_image_checks(imagePath, {139, 140, 141, 149, 150});
    ASSERT_EQ(5, result.stats.checksRun);
    expect_heuristic_result(result, 139, CheckResult::Status::OK, 0);
    expect_heuristic_result(result, 140, CheckResult::Status::OK, 0);
    expect_heuristic_result(result, 141, CheckResult::Status::OK, 0);
    expect_heuristic_result(result, 149, CheckResult::Status::OK, 0);
    expect_heuristic_result(result, 150, CheckResult::Status::OK, 0);

    const auto* h150 = find_per_check(result, CheckID::Kind::Heuristic, 150);
    ASSERT_TRUE(h150 != nullptr);
    ASSERT_EQ(std::string("Strip-based image - tile geometry N/A"), h150->result.summary);
}

static void test_image_truncated_tiff_regression() {
    std::printf("  test_image_truncated_tiff_regression...\n");

    auto imagePath = resolve_repo_file("tests/corpus/corrupt_truncated.tif");
    if (imagePath.empty()) {
        std::printf("    (skipped — corrupt_truncated.tif not found)\n");
        return;
    }

    auto result = analyze_image_checks(imagePath, {139, 140, 141, 149, 150});
    ASSERT_EQ(5, result.stats.checksRun);
    expect_heuristic_result(result, 139, CheckResult::Status::SKIP, 0);
    expect_heuristic_result(result, 140, CheckResult::Status::SKIP, 0);
    expect_heuristic_result(result, 141, CheckResult::Status::SKIP, 0);
    expect_heuristic_result(result, 149, CheckResult::Status::OK, 0);
    expect_heuristic_result(result, 150, CheckResult::Status::SKIP, 0);
}

void test_runner() {
    std::printf("test_runner:\n");
    test_version_string();
    // Run auto-registration tests FIRST (before setup_registry clears them)
    test_check_count();
    test_heuristic_coverage();
    test_conformance_coverage();
    test_conformance_private_tag_documentation_regression();
    test_conformance_adgc_regression();
    test_sampleicc_legibility_regression();
    test_conformance_parity_regressions();
    test_pawg_s1_matrix_trc_regression();
    test_pawg_quality_regressions();
    test_embedding_tech_note_regressions();
    test_conformance_v5_only_skip_regression();
    test_conformance_v5_gate_regression();
    test_conformance_adgc_skip_regression();
    test_heuristic_parity_regressions();
    test_pcc_illuminant_overflow_regression();
    test_tonemap_describe_overflow_regression();
    test_curve_element_oom_regression();
    test_null_mpe_clut_curve_guard_regression();
    test_null_pointer_after_tag_read_regression();
    test_memory_copy_bounds_overlap_regression();
    test_profile_sequence_id_validation_regression();
    test_tag_size_profile_size_cross_check_regression();
    test_unchecked_allocation_size_overflow_regression();
    test_alloc_dealloc_and_uaf_ownership_regressions();
    test_deep_apply_stack_escape_regression();
    test_dictionary_tag_element_bounds_regression();
    test_lut_data_sufficiency_regression();
    test_copy_constructor_null_pcs_regression();
    test_lut_matrix_coefficient_validation_regression();
    test_spectral_mpe_h98_gap_fixture();
    test_cf115_only_emits_raw_findings_when_quarantined();
    test_image_tiff_with_embedded_icc_regression();
    test_image_truncated_tiff_regression();
    // Analysis tests use setup_registry() which clears auto-registrations
    test_analyze_minimal_profile();
    test_analyze_bad_magic();
    test_analyze_nonexistent_file();
    test_severity_filter();
    test_analyze_real_profile();
    std::printf("  [OK]\n\n");

    // Clean up registry
    CheckRegistry::instance().clear();
}
