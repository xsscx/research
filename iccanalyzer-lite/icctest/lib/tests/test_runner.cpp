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
#include <algorithm>
#include <array>
#include <cctype>
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

static std::filesystem::path configured_project_root() {
#ifdef ICCTEST_PROJECT_SOURCE_ROOT
    return std::filesystem::path(ICCTEST_PROJECT_SOURCE_ROOT).lexically_normal();
#else
    return {};
#endif
}

static std::filesystem::path configured_analyzer_root() {
#ifdef ICCTEST_ANALYZER_SOURCE_ROOT
    return std::filesystem::path(ICCTEST_ANALYZER_SOURCE_ROOT).lexically_normal();
#else
    return {};
#endif
}

static std::filesystem::path configured_monorepo_root() {
#ifdef ICCTEST_MONOREPO_SOURCE_ROOT
    return std::filesystem::path(ICCTEST_MONOREPO_SOURCE_ROOT).lexically_normal();
#else
    return {};
#endif
}

static bool path_exists(const std::filesystem::path& path) {
    if (path.empty()) {
        return false;
    }

    std::error_code ec;
    return std::filesystem::exists(path, ec) && !ec;
}

static void append_unique_path(std::vector<std::filesystem::path>& roots,
                               const std::filesystem::path& candidate) {
    if (candidate.empty()) {
        return;
    }

    std::filesystem::path normalized = candidate.lexically_normal();
    if (std::find(roots.begin(), roots.end(), normalized) == roots.end()) {
        roots.push_back(normalized);
    }
}

static std::vector<std::filesystem::path> resolve_repo_roots() {
    std::vector<std::filesystem::path> roots;
    std::filesystem::path analyzerRoot = configured_analyzer_root();
    std::filesystem::path repoRoot = configured_monorepo_root();
    std::filesystem::path projectRoot = configured_project_root();
    std::filesystem::path sourceFile(__FILE__);
    std::filesystem::path sourceDir = sourceFile.parent_path();
    std::filesystem::path iccaRoot = find_named_ancestor(sourceDir, "iccanalyzer-lite");

    append_unique_path(roots, repoRoot);
    std::filesystem::path analyzerParent = analyzerRoot.parent_path();
    append_unique_path(roots, analyzerParent);
    append_unique_path(roots, analyzerRoot);
    append_unique_path(roots, projectRoot);
    std::filesystem::path repoFromSource = find_repo_root(sourceDir);
    append_unique_path(roots, repoFromSource);
    std::filesystem::path iccaParent = iccaRoot.parent_path();
    append_unique_path(roots, iccaParent);
    append_unique_path(roots, iccaRoot);

    std::filesystem::path cwd = std::filesystem::current_path();
    std::filesystem::path repoFromCwd = find_repo_root(cwd);
    append_unique_path(roots, repoFromCwd);
    std::filesystem::path cwdIcca = find_named_ancestor(cwd, "iccanalyzer-lite");
    std::filesystem::path cwdIccaParent = cwdIcca.parent_path();
    append_unique_path(roots, cwdIccaParent);
    append_unique_path(roots, cwdIcca);
    append_unique_path(roots, cwd);

    return roots;
}

static std::filesystem::path resolve_repo_file(const char* relativePath) {
    std::filesystem::path analyzerRoot = configured_analyzer_root();
    if (std::strncmp(relativePath, "tests/", 6) == 0 && !analyzerRoot.empty()) {
        std::filesystem::path joined = analyzerRoot / relativePath;
        std::filesystem::path candidate = joined.lexically_normal();
        if (path_exists(candidate)) {
            return candidate;
        }
    }

    for (const auto& root : resolve_repo_roots()) {
        std::filesystem::path joined = root / relativePath;
        std::filesystem::path candidate = joined.lexically_normal();
        if (path_exists(candidate)) {
            return candidate;
        }
    }

    return {};
}

class ScopedCurrentPath {
public:
    explicit ScopedCurrentPath(const std::filesystem::path& next) {
        previous_ = std::filesystem::current_path();
        std::filesystem::current_path(next);
    }

    ~ScopedCurrentPath() {
        std::error_code ignored;
        if (!previous_.empty()) {
            std::filesystem::current_path(previous_, ignored);
        }
    }

    ScopedCurrentPath(const ScopedCurrentPath&) = delete;
    ScopedCurrentPath& operator=(const ScopedCurrentPath&) = delete;

private:
    std::filesystem::path previous_;
};

static std::filesystem::path write_temp_profile(const std::vector<uint8_t>& data,
                                                const char* fileName) {
    std::filesystem::path out = std::filesystem::temp_directory_path() / fileName;
    std::FILE* fp = std::fopen(out.string().c_str(), "wb");
    if (!fp) {
        return {};
    }

    if (!data.empty()) {
        size_t written = std::fwrite(data.data(), 1, data.size(), fp);
        if (written != data.size()) {
            std::fclose(fp);
            return {};
        }
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
        size_t bytesRead = std::fread(data.data(), 1, data.size(), fp);
        if (bytesRead != data.size()) {
            data.resize(bytesRead);
        }
    }
    std::fclose(fp);
    return data;
}

static std::vector<uint8_t> bytes_from_hex(std::string_view hex) {
    auto hex_value = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };

    std::vector<uint8_t> out;
    int high = -1;
    for (char c : hex) {
        if (std::isspace(static_cast<unsigned char>(c))) {
            continue;
        }
        int value = hex_value(c);
        if (value < 0) {
            continue;
        }
        if (high < 0) {
            high = value;
        } else {
            out.push_back(static_cast<uint8_t>((high << 4) | value));
            high = -1;
        }
    }
    return out;
}

static std::vector<uint8_t> make_h21_tag_struct_profile() {
    static constexpr std::string_view kHex =
        "000002d0000000000500000063656e63524742200000000000000000000000000000000061637370000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000372666e6d000000a80000001463736e6d000000bc0000001063657074000000cc00000204757466380000000049534f2032323032382d3100757466380000000062672d73524742007473747200000000636570740000000f7258595a000000c4000000146758595a000000d8000000146258595a000000ec0000001466756e630000010000000070776c756d000001700000000c7758595a0000017c0000001065526e670000018c00000010626974730000019c0000000b696d7374000001a80000000c69626b67000001b40000000c73726e64000001c00000000c61696c6d000001cc0000000c6d77706c000001d80000000c6d777063000001e4000000106d627063000001f400000010666c3332000000003f23d70a3ea8f5c33cf5c28f666c3332000000003e99999a3f19999a3dcccccd666c3332000000003e19999a3d75c28f3f4a3d71637572660000000000030000bb4d2e1c3b4d2e1c70617266000000000003000043d55555bf870a3dbf80000000000000000000007061726600000000000000003f800000414eb85200000000000000007061726600000000000300003ed555553f870a3d3f8000000000000000000000666c33320000000042a00000666c3332000000003e870a3d3f8000000000000000000000666c33320000000042a00000666c3332000000003ea01a373ea872b0666c333200000000bf07ae143fd70a3d75693038000000000a0c10007369672000000000646f7263666c33320000000042a00000666c3332000000003ea01a373ea872b0666c3332000000003ea01a373ea872b0";
    return bytes_from_hex(kHex);
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

static std::vector<uint8_t> make_h20_tag_type_signature_profile(uint32_t typeSig) {
    auto corpusPath = resolve_repo_file("tests/corpus/valid_srgb.icc");
    auto data = read_file_bytes(corpusPath);
    if (data.size() < 144) {
        return {};
    }

    uint32_t tagCount = (static_cast<uint32_t>(data[128]) << 24) |
                        (static_cast<uint32_t>(data[129]) << 16) |
                        (static_cast<uint32_t>(data[130]) << 8) |
                        static_cast<uint32_t>(data[131]);
    if (tagCount == 0 || data.size() < 144) {
        return {};
    }

    uint32_t firstTagOffset = (static_cast<uint32_t>(data[136]) << 24) |
                              (static_cast<uint32_t>(data[137]) << 16) |
                              (static_cast<uint32_t>(data[138]) << 8) |
                              static_cast<uint32_t>(data[139]);
    if (firstTagOffset + 4 > data.size()) {
        return {};
    }

    data[firstTagOffset + 0] = static_cast<uint8_t>((typeSig >> 24) & 0xFF);
    data[firstTagOffset + 1] = static_cast<uint8_t>((typeSig >> 16) & 0xFF);
    data[firstTagOffset + 2] = static_cast<uint8_t>((typeSig >> 8) & 0xFF);
    data[firstTagOffset + 3] = static_cast<uint8_t>(typeSig & 0xFF);
    return data;
}

static std::vector<uint8_t> make_h18_technology_signature_profile(uint32_t techSig) {
    std::vector<uint8_t> data(156, 0);

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
    put_u32(128, 1);
    put_u32(132, 0x74656368); // 'tech'
    put_u32(136, 144);
    put_u32(140, 12);
    put_u32(144, 0x73696720); // 'sig '
    put_u32(152, techSig);
    return data;
}

static std::vector<uint8_t> make_h38_curve_degenerate_profile() {
    std::vector<uint8_t> data(164, 0);

    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x04400000);   // v4.4
    put_u32(12, 0x6D6E7472);  // 'mntr'
    put_u32(16, 0x47524159);  // 'GRAY'
    put_u32(20, 0x58595A20);  // 'XYZ '
    put_u32(36, 0x61637370);  // 'acsp'
    put_u32(128, 1);
    put_u32(132, 0x6B545243); // 'kTRC'
    put_u32(136, 144);
    put_u32(140, 20);
    put_u32(144, 0x63757276); // 'curv'
    put_u32(152, 4);          // count
    // entries remain zero
    return data;
}

static std::vector<uint8_t> make_h39_shared_tag_alias_profile() {
    std::vector<uint8_t> data(180, 0);

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
    put_u32(128, 2);
    put_u32(132, 0x63707274); // 'cprt'
    put_u32(136, 168);
    put_u32(140, 12);
    put_u32(144, 0x64657363); // 'desc'
    put_u32(148, 168);
    put_u32(152, 8);
    put_u32(168, 0x74657874); // 'text'
    put_u32(172, 0);          // reserved
    put_u32(176, 0x4142);     // "AB"
    return data;
}

static std::vector<uint8_t> make_h25_tag_offset_oob_profile() {
    auto data = read_file_bytes(resolve_repo_file("tests/corpus/valid_srgb.icc"));
    if (data.size() < 144) {
        return data;
    }

    uint32_t badOff = static_cast<uint32_t>(data.size() + 0x20);
    data[136] = static_cast<uint8_t>((badOff >> 24) & 0xFF);
    data[137] = static_cast<uint8_t>((badOff >> 16) & 0xFF);
    data[138] = static_cast<uint8_t>((badOff >> 8) & 0xFF);
    data[139] = static_cast<uint8_t>(badOff & 0xFF);
    return data;
}

static std::vector<uint8_t> make_h26_named_color2_string_profile(bool unterminated) {
    std::vector<uint8_t> data(228, 0);

    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x04400000);
    put_u32(12, 0x6D6E7472);  // 'mntr'
    put_u32(16, 0x52474220);  // 'RGB '
    put_u32(20, 0x58595A20);  // 'XYZ '
    put_u32(36, 0x61637370);  // 'acsp'
    put_u32(128, 1);
    put_u32(132, 0x6E636C32); // 'ncl2'
    put_u32(136, 144);
    put_u32(140, 84);
    put_u32(144, 0x6E636C32); // 'ncl2'
    put_u32(152, 0);          // vendorFlags
    put_u32(156, 1);          // count
    put_u32(160, 3);          // nDevCoords

    uint8_t fill = unterminated ? static_cast<uint8_t>('A') : 0;
    std::memset(data.data() + 164, fill, 32);
    std::memset(data.data() + 196, fill, 32);
    if (!unterminated) {
        data[164] = 'O';
        data[165] = 'K';
        data[196] = 'O';
        data[197] = 'K';
    }
    return data;
}

static std::vector<uint8_t> make_h27_mpe_matrix_output_profile(uint16_t outputChannels) {
    std::vector<uint8_t> data(188, 0);

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
    auto put_f32 = [&](size_t off, float value) {
        uint32_t bits = 0;
        std::memcpy(&bits, &value, sizeof(bits));
        put_u32(off, bits);
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x04400000);
    put_u32(12, 0x6D6E7472);  // 'mntr'
    put_u32(16, 0x52474220);  // 'RGB '
    put_u32(20, 0x58595A20);  // 'XYZ '
    put_u32(36, 0x61637370);  // 'acsp'
    put_u32(128, 1);
    put_u32(132, 0x41324230); // 'A2B0'
    put_u32(136, 144);
    put_u32(140, 44);

    put_u32(144, 0x6D706574); // 'mpet'
    put_u16(152, 1);
    put_u16(154, outputChannels);
    put_u32(156, 1);
    put_u32(160, 24);
    put_u32(164, 20);

    put_u32(168, 0x6D617466); // 'matf'
    put_u16(176, 1);
    put_u16(178, outputChannels);
    if (outputChannels >= 1) put_f32(180, 1.0f);
    if (outputChannels >= 2) put_f32(184, 0.0f);
    return data;
}

static std::vector<uint8_t> make_h28_lut_dimension_profile(uint8_t nInput,
                                                           uint8_t nOutput,
                                                           uint8_t nGrid) {
    std::vector<uint8_t> data(155, 0);

    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x04400000);
    put_u32(12, 0x6D6E7472);  // 'mntr'
    put_u32(16, 0x52474220);  // 'RGB '
    put_u32(20, 0x58595A20);  // 'XYZ '
    put_u32(36, 0x61637370);  // 'acsp'
    put_u32(128, 1);
    put_u32(132, 0x41324230); // 'A2B0'
    put_u32(136, 144);
    put_u32(140, 11);
    put_u32(144, 0x6D667431); // 'mft1'
    data[152] = nInput;
    data[153] = nOutput;
    data[154] = nGrid;
    return data;
}

static std::vector<uint8_t> make_h29_colorant_table_profile(bool unterminated) {
    std::vector<uint8_t> data(232, 0);

    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x04400000);
    put_u32(12, 0x6D6E7472);  // 'mntr'
    put_u32(16, 0x52474220);  // 'RGB '
    put_u32(20, 0x58595A20);  // 'XYZ '
    put_u32(36, 0x61637370);  // 'acsp'
    put_u32(128, 1);
    put_u32(132, 0x636C7274); // 'clrt'
    put_u32(136, 144);
    put_u32(140, 88);
    put_u32(144, 0x636C7274); // 'clrt'
    put_u32(152, 2);          // count

    uint8_t fill = unterminated ? static_cast<uint8_t>('B') : 0;
    std::memset(data.data() + 156, fill, 32);
    std::memset(data.data() + 194, fill, 32);
    if (!unterminated) {
        data[156] = 'R';
        data[157] = 0;
        data[194] = 'G';
        data[195] = 0;
    }
    return data;
}

static std::vector<uint8_t> make_h31_mpe_channel_count_profile(uint16_t channels) {
    std::vector<uint8_t> data(160, 0);

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
    put_u32(8, 0x04400000);
    put_u32(12, 0x6D6E7472);  // 'mntr'
    put_u32(16, 0x52474220);  // 'RGB '
    put_u32(20, 0x58595A20);  // 'XYZ '
    put_u32(36, 0x61637370);  // 'acsp'
    put_u32(128, 1);
    put_u32(132, 0x41324230); // 'A2B0'
    put_u32(136, 144);
    put_u32(140, 16);
    put_u32(144, 0x6D706574); // 'mpet'
    put_u16(152, channels);
    put_u16(154, channels);
    put_u32(156, 0);
    return data;
}

static std::vector<uint8_t> make_h32_unknown_type_profile(uint32_t typeSig) {
    return make_h20_tag_type_signature_profile(typeSig);
}

static std::vector<uint8_t> make_h100_profile_sequence_desc_profile(size_t entryCount) {
    auto make_mluc = [](const std::string& text) {
        std::vector<uint8_t> out;
        out.insert(out.end(), {'m','l','u','c', 0,0,0,0});

        auto put_u32 = [&](uint32_t value) {
            out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(value & 0xFF));
        };

        std::vector<uint8_t> utf16;
        utf16.reserve(text.size() * 2);
        for (char ch : text) {
            utf16.push_back(0);
            utf16.push_back(static_cast<uint8_t>(ch));
        }

        put_u32(1);
        put_u32(12);
        out.insert(out.end(), {'e','n','U','S'});
        put_u32(static_cast<uint32_t>(utf16.size()));
        put_u32(28);
        out.insert(out.end(), utf16.begin(), utf16.end());
        while (out.size() % 4 != 0) {
            out.push_back(0);
        }
        return out;
    };

    auto put_u32 = [](std::vector<uint8_t>& out, uint32_t value) {
        out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
        out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
        out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
        out.push_back(static_cast<uint8_t>(value & 0xFF));
    };

    auto put_u64 = [](std::vector<uint8_t>& out, uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            out.push_back(static_cast<uint8_t>((value >> shift) & 0xFF));
        }
    };

    std::vector<uint8_t> pseq;
    pseq.insert(pseq.end(), {'p','s','e','q', 0,0,0,0});
    put_u32(pseq, static_cast<uint32_t>(entryCount));

    for (size_t idx = 0; idx < entryCount; ++idx) {
        pseq.insert(pseq.end(), {'A','P','P','L'});
        pseq.insert(pseq.end(), {'M','D','L',' '});
        put_u64(pseq, 0);
        pseq.insert(pseq.end(), {'f','s','c','n'});
        auto mfg = make_mluc("Mfg" + std::to_string(idx));
        auto mdl = make_mluc("Model" + std::to_string(idx));
        pseq.insert(pseq.end(), mfg.begin(), mfg.end());
        pseq.insert(pseq.end(), mdl.begin(), mdl.end());
    }
    while (pseq.size() % 4 != 0) {
        pseq.push_back(0);
    }

    size_t size = 128 + 4 + 12 + pseq.size();
    std::vector<uint8_t> data(size, 0);
    auto put_hdr_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };
    auto put_hdr_s32 = [&](size_t off, int32_t value) {
        put_hdr_u32(off, static_cast<uint32_t>(value));
    };

    put_hdr_u32(0, static_cast<uint32_t>(size));
    put_hdr_u32(8, 0x04400000);
    data[12] = 'm'; data[13] = 'n'; data[14] = 't'; data[15] = 'r';
    data[16] = 'R'; data[17] = 'G'; data[18] = 'B'; data[19] = ' ';
    data[20] = 'X'; data[21] = 'Y'; data[22] = 'Z'; data[23] = ' ';
    data[36] = 'a'; data[37] = 'c'; data[38] = 's'; data[39] = 'p';
    data[40] = 'A'; data[41] = 'P'; data[42] = 'P'; data[43] = 'L';
    data[80] = 't'; data[81] = 'e'; data[82] = 's'; data[83] = 't';
    put_hdr_s32(68, static_cast<int32_t>(0.9642 * 65536));
    put_hdr_s32(72, static_cast<int32_t>(1.0 * 65536));
    put_hdr_s32(76, static_cast<int32_t>(0.8249 * 65536));
    put_hdr_u32(128, 1);
    data[132] = 'p'; data[133] = 's'; data[134] = 'e'; data[135] = 'q';
    put_hdr_u32(136, 144);
    put_hdr_u32(140, static_cast<uint32_t>(pseq.size()));
    std::copy(pseq.begin(), pseq.end(), data.begin() + 144);
    return data;
}

static std::vector<uint8_t> make_h91_colorant_order_profile(bool duplicate) {
    std::vector<uint8_t> clro;
    clro.insert(clro.end(), {'c','l','r','o', 0,0,0,0, 0,0,0,2});
    clro.push_back(0);
    clro.push_back(duplicate ? 0 : 1);
    while (clro.size() % 4 != 0) {
        clro.push_back(0);
    }

    size_t size = 128 + 4 + 12 + clro.size();
    std::vector<uint8_t> data(size, 0);
    auto put_hdr_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };
    auto put_hdr_s32 = [&](size_t off, int32_t value) {
        put_hdr_u32(off, static_cast<uint32_t>(value));
    };

    put_hdr_u32(0, static_cast<uint32_t>(size));
    put_hdr_u32(8, 0x04400000);
    data[12] = 'm'; data[13] = 'n'; data[14] = 't'; data[15] = 'r';
    data[16] = 'R'; data[17] = 'G'; data[18] = 'B'; data[19] = ' ';
    data[20] = 'X'; data[21] = 'Y'; data[22] = 'Z'; data[23] = ' ';
    data[36] = 'a'; data[37] = 'c'; data[38] = 's'; data[39] = 'p';
    data[40] = 'A'; data[41] = 'P'; data[42] = 'P'; data[43] = 'L';
    data[80] = 't'; data[81] = 'e'; data[82] = 's'; data[83] = 't';
    put_hdr_s32(68, static_cast<int32_t>(0.9642 * 65536));
    put_hdr_s32(72, static_cast<int32_t>(1.0 * 65536));
    put_hdr_s32(76, static_cast<int32_t>(0.8249 * 65536));
    put_hdr_u32(128, 1);
    data[132] = 'c'; data[133] = 'l'; data[134] = 'r'; data[135] = 'o';
    put_hdr_u32(136, 144);
    put_hdr_u32(140, static_cast<uint32_t>(clro.size()));
    std::copy(clro.begin(), clro.end(), data.begin() + 144);
    return data;
}

static std::vector<uint8_t> make_h90_preview_profile(uint8_t inputChannels,
                                                     uint8_t outputChannels) {
    std::vector<uint8_t> data(160, 0);

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
    data[12] = 'm'; data[13] = 'n'; data[14] = 't'; data[15] = 'r';
    data[16] = 'R'; data[17] = 'G'; data[18] = 'B'; data[19] = ' ';
    data[20] = 'X'; data[21] = 'Y'; data[22] = 'Z'; data[23] = ' ';
    data[36] = 'a'; data[37] = 'c'; data[38] = 's'; data[39] = 'p';
    data[40] = 'A'; data[41] = 'P'; data[42] = 'P'; data[43] = 'L';
    data[80] = 't'; data[81] = 'e'; data[82] = 's'; data[83] = 't';
    put_s32(68, static_cast<int32_t>(0.9642 * 65536));
    put_s32(72, static_cast<int32_t>(1.0 * 65536));
    put_s32(76, static_cast<int32_t>(0.8249 * 65536));

    put_u32(128, 1);          // tag count
    data[132] = 'p'; data[133] = 'r'; data[134] = 'e'; data[135] = '0';
    put_u32(136, 144);
    put_u32(140, 16);

    data[144] = 'm'; data[145] = 'f'; data[146] = 't'; data[147] = '1';
    data[152] = inputChannels;
    data[153] = outputChannels;
    data[154] = 2; // CLUT points

    return data;
}

static std::vector<uint8_t> make_h88_chad_profile_singular() {
    std::vector<uint8_t> sf32;
    sf32.insert(sf32.end(), {'s','f','3','2', 0,0,0,0});
    for (int i = 0; i < 9; i++) {
        sf32.insert(sf32.end(), {0,0,0,0});
    }

    size_t size = 128 + 4 + 12 + sf32.size();
    std::vector<uint8_t> data(size, 0);
    auto put_hdr_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };
    auto put_hdr_s32 = [&](size_t off, int32_t value) {
        put_hdr_u32(off, static_cast<uint32_t>(value));
    };

    put_hdr_u32(0, static_cast<uint32_t>(size));
    put_hdr_u32(8, 0x04400000);
    data[12] = 'm'; data[13] = 'n'; data[14] = 't'; data[15] = 'r';
    data[16] = 'R'; data[17] = 'G'; data[18] = 'B'; data[19] = ' ';
    data[20] = 'X'; data[21] = 'Y'; data[22] = 'Z'; data[23] = ' ';
    data[36] = 'a'; data[37] = 'c'; data[38] = 's'; data[39] = 'p';
    data[40] = 'A'; data[41] = 'P'; data[42] = 'P'; data[43] = 'L';
    data[80] = 't'; data[81] = 'e'; data[82] = 's'; data[83] = 't';
    put_hdr_s32(68, static_cast<int32_t>(0.9642 * 65536));
    put_hdr_s32(72, static_cast<int32_t>(1.0 * 65536));
    put_hdr_s32(76, static_cast<int32_t>(0.8249 * 65536));
    put_hdr_u32(128, 1);
    data[132] = 'c'; data[133] = 'h'; data[134] = 'a'; data[135] = 'd';
    put_hdr_u32(136, 144);
    put_hdr_u32(140, static_cast<uint32_t>(sf32.size()));
    std::copy(sf32.begin(), sf32.end(), data.begin() + 144);
    return data;
}

static std::vector<uint8_t> make_h87_trc_curve_profile_all_zero() {
    std::vector<uint8_t> curv;
    curv.insert(curv.end(), {'c','u','r','v', 0,0,0,0, 0,0,0,3});
    curv.insert(curv.end(), {0,0, 0,0, 0,0});
    while (curv.size() % 4 != 0) {
        curv.push_back(0);
    }

    size_t size = 128 + 4 + 12 + curv.size();
    std::vector<uint8_t> data(size, 0);
    auto put_hdr_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };
    auto put_hdr_s32 = [&](size_t off, int32_t value) {
        put_hdr_u32(off, static_cast<uint32_t>(value));
    };

    put_hdr_u32(0, static_cast<uint32_t>(size));
    put_hdr_u32(8, 0x04400000);
    data[12] = 'm'; data[13] = 'n'; data[14] = 't'; data[15] = 'r';
    data[16] = 'R'; data[17] = 'G'; data[18] = 'B'; data[19] = ' ';
    data[20] = 'X'; data[21] = 'Y'; data[22] = 'Z'; data[23] = ' ';
    data[36] = 'a'; data[37] = 'c'; data[38] = 's'; data[39] = 'p';
    data[40] = 'A'; data[41] = 'P'; data[42] = 'P'; data[43] = 'L';
    data[80] = 't'; data[81] = 'e'; data[82] = 's'; data[83] = 't';
    put_hdr_s32(68, static_cast<int32_t>(0.9642 * 65536));
    put_hdr_s32(72, static_cast<int32_t>(1.0 * 65536));
    put_hdr_s32(76, static_cast<int32_t>(0.8249 * 65536));
    put_hdr_u32(128, 1);
    data[132] = 'r'; data[133] = 'T'; data[134] = 'R'; data[135] = 'C';
    put_hdr_u32(136, 144);
    put_hdr_u32(140, static_cast<uint32_t>(curv.size()));
    std::copy(curv.begin(), curv.end(), data.begin() + 144);
    return data;
}

static std::vector<uint8_t> make_h93_flags_profile(uint32_t flags, uint64_t attributes) {
    std::vector<uint8_t> data(132, 0);

    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };
    auto put_u64 = [&](size_t off, uint64_t value) {
        for (int shift = 56; shift >= 0; shift -= 8) {
            data[off++] = static_cast<uint8_t>((value >> shift) & 0xFF);
        }
    };
    auto put_s32 = [&](size_t off, int32_t value) {
        put_u32(off, static_cast<uint32_t>(value));
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x04400000);
    data[12] = 'm'; data[13] = 'n'; data[14] = 't'; data[15] = 'r';
    data[16] = 'R'; data[17] = 'G'; data[18] = 'B'; data[19] = ' ';
    data[20] = 'X'; data[21] = 'Y'; data[22] = 'Z'; data[23] = ' ';
    data[36] = 'a'; data[37] = 'c'; data[38] = 's'; data[39] = 'p';
    put_u32(44, flags);
    data[80] = 't'; data[81] = 'e'; data[82] = 's'; data[83] = 't';
    put_u64(56, attributes);
    put_s32(68, static_cast<int32_t>(0.9642 * 65536));
    put_s32(72, static_cast<int32_t>(1.0 * 65536));
    put_s32(76, static_cast<int32_t>(0.8249 * 65536));
    put_u32(128, 0);
    return data;
}

static std::vector<uint8_t> make_h94_matrix_trc_profile_bad_columns() {
    auto append_xyz = [](std::vector<uint8_t>& out, int32_t x, int32_t y, int32_t z) {
        out.insert(out.end(), {'X','Y','Z',' ', 0,0,0,0});
        auto put_s32 = [&](int32_t value) {
            out.push_back(static_cast<uint8_t>((static_cast<uint32_t>(value) >> 24) & 0xFF));
            out.push_back(static_cast<uint8_t>((static_cast<uint32_t>(value) >> 16) & 0xFF));
            out.push_back(static_cast<uint8_t>((static_cast<uint32_t>(value) >> 8) & 0xFF));
            out.push_back(static_cast<uint8_t>(static_cast<uint32_t>(value) & 0xFF));
        };
        put_s32(x);
        put_s32(y);
        put_s32(z);
    };

    std::vector<uint8_t> r, g, b;
    append_xyz(r, 0, 0, 0);
    append_xyz(g, 0, 0, 0);
    append_xyz(b, 0, 0, 0);

    size_t size = 128 + 4 + 12 * 3 + r.size() + g.size() + b.size();
    std::vector<uint8_t> data(size, 0);
    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };
    auto put_s32 = [&](size_t off, int32_t value) {
        put_u32(off, static_cast<uint32_t>(value));
    };

    put_u32(0, static_cast<uint32_t>(size));
    put_u32(8, 0x04400000);
    data[12] = 'm'; data[13] = 'n'; data[14] = 't'; data[15] = 'r';
    data[16] = 'R'; data[17] = 'G'; data[18] = 'B'; data[19] = ' ';
    data[20] = 'X'; data[21] = 'Y'; data[22] = 'Z'; data[23] = ' ';
    data[36] = 'a'; data[37] = 'c'; data[38] = 's'; data[39] = 'p';
    data[40] = 'A'; data[41] = 'P'; data[42] = 'P'; data[43] = 'L';
    data[80] = 't'; data[81] = 'e'; data[82] = 's'; data[83] = 't';
    put_s32(68, static_cast<int32_t>(0.9642 * 65536));
    put_s32(72, static_cast<int32_t>(1.0 * 65536));
    put_s32(76, static_cast<int32_t>(0.8249 * 65536));
    put_u32(128, 3);
    data[132] = 'r'; data[133] = 'X'; data[134] = 'Y'; data[135] = 'Z';
    put_u32(136, 168);
    put_u32(140, static_cast<uint32_t>(r.size()));
    data[144] = 'g'; data[145] = 'X'; data[146] = 'Y'; data[147] = 'Z';
    put_u32(148, 168 + static_cast<uint32_t>(r.size()));
    put_u32(152, static_cast<uint32_t>(g.size()));
    data[156] = 'b'; data[157] = 'X'; data[158] = 'Y'; data[159] = 'Z';
    put_u32(160, 168 + static_cast<uint32_t>(r.size() + g.size()));
    put_u32(164, static_cast<uint32_t>(b.size()));
    std::copy(r.begin(), r.end(), data.begin() + 168);
    std::copy(g.begin(), g.end(), data.begin() + 168 + r.size());
    std::copy(b.begin(), b.end(), data.begin() + 168 + r.size() + g.size());
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

static std::vector<uint8_t> make_h41_version_type_profile(uint32_t typeSig) {
    auto data = read_file_bytes(resolve_repo_file("tests/corpus/valid_srgb.icc"));
    if (data.size() < 144) {
        return {};
    }

    data[8] = 0x04;  // v4.x
    data[9] = 0x40;
    data[10] = 0x00;
    data[11] = 0x00;

    uint32_t firstTagOffset = (static_cast<uint32_t>(data[136]) << 24) |
                              (static_cast<uint32_t>(data[137]) << 16) |
                              (static_cast<uint32_t>(data[138]) << 8) |
                              static_cast<uint32_t>(data[139]);
    if (firstTagOffset + 4 > data.size()) {
        return {};
    }

    data[firstTagOffset + 0] = static_cast<uint8_t>((typeSig >> 24) & 0xFF);
    data[firstTagOffset + 1] = static_cast<uint8_t>((typeSig >> 16) & 0xFF);
    data[firstTagOffset + 2] = static_cast<uint8_t>((typeSig >> 8) & 0xFF);
    data[firstTagOffset + 3] = static_cast<uint8_t>(typeSig & 0xFF);
    return data;
}

static std::vector<uint8_t> make_h42_matrix_singularity_profile() {
    std::vector<uint8_t> data(192, 0);

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

    put_u32(128, 1);
    put_u32(132, 0x41324230); // 'A2B0'
    put_u32(136, 144);
    put_u32(140, 48);

    put_u32(144, 0x6D667431); // 'mft1'
    // matrix bytes at 156..191 remain zero -> singular/all-zero
    return data;
}

static std::vector<uint8_t> make_h50_zero_size_tag_profile() {
    auto data = read_file_bytes(resolve_repo_file("tests/corpus/valid_srgb.icc"));
    if (data.size() < 144) {
        return {};
    }

    data[140] = 0;
    data[141] = 0;
    data[142] = 0;
    data[143] = 0;
    return data;
}

static std::vector<uint8_t> make_h43_spectral_brdf_profile() {
    std::vector<uint8_t> data(164, 0);

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
    put_u32(8, 0x05000000);   // v5
    put_u32(12, 0x6D6E7472);  // 'mntr'
    put_u32(16, 0x52474220);  // 'RGB '
    put_u32(20, 0x58595A20);  // 'XYZ '
    put_u32(36, 0x61637370);  // 'acsp'
    put_u32(128, 1);
    put_u32(132, 0x7376636Eu); // 'svcn'
    put_u32(136, 144);
    put_u32(140, 20);
    put_u32(144, 0x73767763u); // 'svwc'
    put_u16(152, 780);
    put_u16(154, 380);
    put_u16(156, 0);
    return data;
}

static std::vector<uint8_t> make_h44_embedded_image_profile() {
    std::vector<uint8_t> data(160, 0);

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
    put_u32(132, 0x70726530); // 'pre0'
    put_u32(136, 144);
    put_u32(140, 0x01000001u); // >16MB
    put_u32(144, 0x74657874);  // 'text'
    return data;
}

static std::vector<uint8_t> make_h45_sparse_matrix_profile() {
    std::vector<uint8_t> data(176, 0);

    auto put_u32 = [&](size_t off, uint32_t value) {
        data[off + 0] = static_cast<uint8_t>((value >> 24) & 0xFF);
        data[off + 1] = static_cast<uint8_t>((value >> 16) & 0xFF);
        data[off + 2] = static_cast<uint8_t>((value >> 8) & 0xFF);
        data[off + 3] = static_cast<uint8_t>(value & 0xFF);
    };

    put_u32(0, static_cast<uint32_t>(data.size()));
    put_u32(8, 0x05000000);
    put_u32(12, 0x6D6E7472);
    put_u32(16, 0x52474220);
    put_u32(20, 0x58595A20);
    put_u32(36, 0x61637370);
    put_u32(128, 1);
    put_u32(132, 0x41324230); // 'A2B0'
    put_u32(136, 144);
    put_u32(140, 32);
    put_u32(144, 0x6D706574); // 'mpet'
    put_u32(152, 0x736D7478); // 'smtx'
    put_u32(160, 5000);
    put_u32(164, 5000);
    return data;
}

static std::vector<uint8_t> make_h46_text_desc_profile() {
    std::vector<uint8_t> data(164, 0);

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
    put_u32(132, 0x64657363); // 'desc'
    put_u32(136, 144);
    put_u32(140, 20);
    put_u32(144, 0x64657363); // 'desc'
    put_u32(152, 64);         // ascii len exceeds tag data
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
    if (status != check->result.status || issueCount != check->result.issueCount()) {
        std::fprintf(stderr,
                     "heuristic mismatch H%d: expected status=%d findings=%d actual status=%d findings=%d summary=%s\n",
                     number,
                     static_cast<int>(status),
                     issueCount,
                     static_cast<int>(check->result.status),
                     check->result.issueCount(),
                     check->result.summary.c_str());
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

static void test_repo_fixture_resolution_stability() {
    std::printf("  test_repo_fixture_resolution_stability...\n");

    const std::filesystem::path repoRoot = configured_monorepo_root();
    const std::filesystem::path analyzerRoot = configured_analyzer_root();
    const std::filesystem::path buildRoot = configured_project_root() / "build";

    ASSERT_TRUE(path_exists(repoRoot));
    ASSERT_TRUE(path_exists(analyzerRoot));
    ASSERT_TRUE(path_exists(buildRoot));

    const std::vector<const char*> fixtures = {
        "test-profiles/sRGB_D65_MAT.icc",
        "test-profiles/NamedColor.icc",
        "test-profiles/CIccToneMapFunc-Describe-heap-oob-IccMpeBasic_cpp.icc",
        "test-profiles/oom-CIccSingleSampledCurve-SetSize-IccProfLib-IccMpeBasic_cpp-Line1496.icc",
        "test-profiles/heap-buffer-overflow-CIccMpeSpectralMatrix-Describe-IccMpeSpectral_cpp-Line352.icc",
        "tests/corpus/valid_srgb.icc",
        "tests/corpus/gbd_tary_signed_channel_wrap.icc",
    };

    const std::vector<std::filesystem::path> workingDirs = {
        repoRoot,
        analyzerRoot,
        buildRoot,
    };

    for (const auto& workingDir : workingDirs) {
        ScopedCurrentPath scoped(workingDir);
        for (const char* relativePath : fixtures) {
            auto resolved = resolve_repo_file(relativePath);
            ASSERT_FALSE(resolved.empty());
            ASSERT_TRUE(path_exists(resolved));

            std::filesystem::path expected =
                std::strncmp(relativePath, "tests/", 6) == 0
                    ? (analyzerRoot / relativePath).lexically_normal()
                    : (repoRoot / relativePath).lexically_normal();
            ASSERT_EQ(expected, resolved.lexically_normal());
        }
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

    {
        auto result = analyze_corpus_checks(corpusDir / "v5_spac_basic.icc", {190});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_conformance_result(result, 190, CheckResult::Status::FINDINGS, 1);

        const auto* cf190 = find_per_check(result, CheckID::Kind::Conformance, 190);
        ASSERT_TRUE(cf190 != nullptr);
        ASSERT_TRUE(cf190->result.summary.find("Legibility") != std::string::npos);
        ASSERT_TRUE(
            cf190->result.findings[0].message.find("Library failed to load profile") !=
            std::string::npos);
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
    ASSERT_EQ(CheckResult::Status::OK, cf115->result.status);
    ASSERT_EQ(0, cf115->result.issueCount());
    ASSERT_TRUE(cf115->result.summary == "NOT RUN: Library quarantined");

    AnalysisOptions loadedConformanceOpts;
    loadedConformanceOpts.phases = {CheckPhase::CONFORMANCE};
    loadedConformanceOpts.skipLibraryOnUB = false;
    loadedConformanceOpts.specificChecks = {
        {CheckID::Kind::Conformance, 115},
    };

    auto loadedConformanceResult = runner.analyze(profilePath, loadedConformanceOpts);
    ASSERT_EQ(1, loadedConformanceResult.stats.checksRun);
    const auto* loadedCf115 = find_per_check(loadedConformanceResult, CheckID::Kind::Conformance, 115);
    ASSERT_TRUE(loadedCf115 != nullptr);
    if (!loadedCf115) {
        return;
    }
    ASSERT_EQ(CheckResult::Status::FINDINGS, loadedCf115->result.status);
    ASSERT_TRUE(loadedCf115->result.issueCount() >= 1);

    bool sawCfToneMapFinding = false;
    for (const auto& finding : loadedCf115->result.findings) {
        if (finding.message.find("tone map element") != std::string::npos &&
            finding.detail.find("Tone mapping function has invalid parameters") != std::string::npos) {
            sawCfToneMapFinding = true;
            break;
        }
    }
    ASSERT_TRUE(sawCfToneMapFinding);
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

static void test_localized_unicode_bounds_regression() {
    std::printf("  test_localized_unicode_bounds_regression...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "mluc_control_chars.icc", {86});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 86, CheckResult::Status::FINDINGS, 1);

        const auto* h86 = find_per_check(result, CheckID::Kind::Heuristic, 86);
        ASSERT_TRUE(h86 != nullptr);
        if (!h86) return;

        bool sawControlChars = false;
        for (const auto& finding : h86->result.findings) {
            if (finding.message.find("non-printable control characters") != std::string::npos &&
                finding.cweNote.find("CWE-116") != std::string::npos) {
                sawControlChars = true;
                break;
            }
        }
        ASSERT_TRUE(sawControlChars);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "mluc_bidi_override.icc", {86});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 86, CheckResult::Status::FINDINGS, 2);

        const auto* h86 = find_per_check(result, CheckID::Kind::Heuristic, 86);
        ASSERT_TRUE(h86 != nullptr);
        if (!h86) return;

        bool sawBidiOverride = false;
        bool sawMixedScripts = false;
        for (const auto& finding : h86->result.findings) {
            if (finding.message.find("bidi override/formatting characters") != std::string::npos &&
                finding.cweNote.find("CWE-116") != std::string::npos) {
                sawBidiOverride = true;
            }
            if (finding.message.find("mixes Latin + non-Latin scripts") != std::string::npos &&
                finding.cweNote.find("CWE-116") != std::string::npos) {
                sawMixedScripts = true;
            }
        }
        ASSERT_TRUE(sawBidiOverride);
        ASSERT_TRUE(sawMixedScripts);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "mluc_embedded_nulls.icc", {86});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 86, CheckResult::Status::FINDINGS, 1);

        const auto* h86 = find_per_check(result, CheckID::Kind::Heuristic, 86);
        ASSERT_TRUE(h86 != nullptr);
        if (!h86) return;

        bool sawEmbeddedNulls = false;
        for (const auto& finding : h86->result.findings) {
            if (finding.message.find("embedded null characters") != std::string::npos &&
                finding.cweNote.find("CWE-170") != std::string::npos) {
                sawEmbeddedNulls = true;
                break;
            }
        }
        ASSERT_TRUE(sawEmbeddedNulls);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "mluc_mixed_scripts.icc", {86});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 86, CheckResult::Status::FINDINGS, 1);

        const auto* h86 = find_per_check(result, CheckID::Kind::Heuristic, 86);
        ASSERT_TRUE(h86 != nullptr);
        if (!h86) return;

        bool sawMixedScripts = false;
        for (const auto& finding : h86->result.findings) {
            if (finding.message.find("mixes Latin + non-Latin scripts") != std::string::npos &&
                finding.cweNote.find("CWE-116") != std::string::npos) {
                sawMixedScripts = true;
                break;
            }
        }
        ASSERT_TRUE(sawMixedScripts);
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {86});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 86, CheckResult::Status::OK, 0);
    }
}

static void test_gbd_tary_signed_channel_wrap_regression() {
    std::printf("  test_gbd_tary_signed_channel_wrap_regression...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    auto profilePath = corpusDir / "gbd_tary_signed_channel_wrap.icc";
    if (!std::filesystem::exists(profilePath)) {
        std::printf("    (skipped — gbd_tary_signed_channel_wrap.icc not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_heuristics(profilePath, {30, 68, 137});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_heuristic_result(result, 30, CheckResult::Status::FINDINGS, 2);
        expect_heuristic_result(result, 68, CheckResult::Status::FINDINGS, 1);
        expect_heuristic_result(result, 137, CheckResult::Status::FINDINGS, 1);

        const auto* h30 = find_per_check(result, CheckID::Kind::Heuristic, 30);
        ASSERT_TRUE(h30 != nullptr);
        if (!h30) return;

        bool sawAlloc = false;
        bool sawChannels = false;
        for (const auto& finding : h30->result.findings) {
            if (finding.message.find("vertices") != std::string::npos &&
                finding.cweNote.find("Allocation:") != std::string::npos) {
                sawAlloc = true;
            }
            if (finding.message.find("PCS channels=65535, Device channels=65534") != std::string::npos &&
                finding.cweNote.find("Signed/unsigned confusion") != std::string::npos) {
                sawChannels = true;
            }
        }
        ASSERT_TRUE(sawAlloc);
        ASSERT_TRUE(sawChannels);

        const auto* h68 = find_per_check(result, CheckID::Kind::Heuristic, 68);
        ASSERT_TRUE(h68 != nullptr);
        if (h68) {
            ASSERT_TRUE(!h68->result.findings.empty());
            ASSERT_TRUE(h68->result.findings.front().message.find("nTriangles=1947472916") != std::string::npos);
        }

        const auto* h137 = find_per_check(result, CheckID::Kind::Heuristic, 137);
        ASSERT_TRUE(h137 != nullptr);
        if (h137) {
            ASSERT_TRUE(!h137->result.findings.empty());
            ASSERT_TRUE(h137->result.findings.front().message.find("nTriangles=1947472916") != std::string::npos);
        }
    }

    {
        auto result = analyze_corpus_checks(profilePath, {140, 286, 287});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_conformance_result(result, 140, CheckResult::Status::OK, 0);
        expect_conformance_result(result, 286, CheckResult::Status::FINDINGS, 1);
        expect_conformance_result(result, 287, CheckResult::Status::FINDINGS, 2);

        const auto* cf140 = find_per_check(result, CheckID::Kind::Conformance, 140);
        ASSERT_TRUE(cf140 != nullptr);
        if (cf140) {
            ASSERT_TRUE(cf140->result.summary.find("vertex count field") != std::string::npos);
            ASSERT_TRUE(cf140->result.summary.find("NOT RUN") == std::string::npos);
        }

        const auto* cf286 = find_per_check(result, CheckID::Kind::Conformance, 286);
        ASSERT_TRUE(cf286 != nullptr);
        if (cf286 && !cf286->result.findings.empty()) {
            ASSERT_TRUE(cf286->result.findings[0].message.find("max distinct triangles") != std::string::npos);
        }

        const auto* cf287 = find_per_check(result, CheckID::Kind::Conformance, 287);
        ASSERT_TRUE(cf287 != nullptr);
        if (cf287) {
            bool sawPcs = false;
            bool sawDev = false;
            for (const auto& finding : cf287->result.findings) {
                if (finding.message.find("PCS channels=65535") != std::string::npos) {
                    sawPcs = true;
                }
                if (finding.message.find("device channels=65534") != std::string::npos) {
                    sawDev = true;
                }
            }
            ASSERT_TRUE(sawPcs);
            ASSERT_TRUE(sawDev);
        }
    }

    {
        auto result = analyze_corpus_heuristics(profilePath, {74, 107, 110, 116, 117});
        ASSERT_EQ(5, result.stats.checksRun);
        expect_heuristic_result(result, 74, CheckResult::Status::FINDINGS, 1);
        expect_heuristic_result(result, 107, CheckResult::Status::FINDINGS, 1);
        expect_heuristic_result(result, 110, CheckResult::Status::FINDINGS, 4);
        expect_heuristic_result(result, 116, CheckResult::Status::FINDINGS, 1);
        expect_heuristic_result(result, 117, CheckResult::Status::FINDINGS, 1);

        const auto* h74 = find_per_check(result, CheckID::Kind::Heuristic, 74);
        ASSERT_TRUE(h74 != nullptr);
        if (h74) {
            ASSERT_EQ(1u, h74->result.findings.size());
            if (h74->result.findings.size() == 1u) {
                ASSERT_TRUE(h74->result.findings[0].message.find("unexpected type") != std::string::npos);
                ASSERT_TRUE(h74->result.findings[0].message.find("rf") != std::string::npos);
            }
        }

        const auto* h107 = find_per_check(result, CheckID::Kind::Heuristic, 107);
        ASSERT_TRUE(h107 != nullptr);
        if (h107) {
            ASSERT_EQ(1u, h107->result.findings.size());
            if (h107->result.findings.size() == 1u) {
                ASSERT_TRUE(h107->result.findings[0].message.find("Cannot determine channel counts") != std::string::npos);
            }
        }

        const auto* h110 = find_per_check(result, CheckID::Kind::Heuristic, 110);
        ASSERT_TRUE(h110 != nullptr);
        if (h110) {
            bool sawMissingDesc = false;
            bool sawMissingWtpt = false;
            bool sawUnknownClass = false;
            bool sawInvalidPcs = false;
            for (const auto& finding : h110->result.findings) {
                if (finding.message.find("Missing required tag 'desc'") != std::string::npos) {
                    sawMissingDesc = true;
                }
                if (finding.message.find("Missing required tag 'wtpt'") != std::string::npos) {
                    sawMissingWtpt = true;
                }
                if (finding.message.find("Unknown profile class") != std::string::npos) {
                    sawUnknownClass = true;
                }
                if (finding.message.find("Non-DeviceLink PCS is not Lab/XYZ/spectral") != std::string::npos) {
                    sawInvalidPcs = true;
                }
            }
            ASSERT_TRUE(sawMissingDesc);
            ASSERT_TRUE(sawMissingWtpt);
            ASSERT_TRUE(sawUnknownClass);
            ASSERT_TRUE(sawInvalidPcs);
        }

        const auto* h116 = find_per_check(result, CheckID::Kind::Heuristic, 116);
        ASSERT_TRUE(h116 != nullptr);
        if (h116) {
            ASSERT_EQ(1u, h116->result.findings.size());
            if (h116->result.findings.size() == 1u) {
                ASSERT_TRUE(h116->result.findings[0].message.find("cprt") != std::string::npos);
                ASSERT_TRUE(h116->result.findings[0].message.find("multiLocalizedUnicodeType") != std::string::npos);
            }
        }

        const auto* h117 = find_per_check(result, CheckID::Kind::Heuristic, 117);
        ASSERT_TRUE(h117 != nullptr);
        if (h117) {
            ASSERT_EQ(1u, h117->result.findings.size());
            if (h117->result.findings.size() == 1u) {
                ASSERT_TRUE(h117->result.findings[0].message.find("'cprt'") != std::string::npos);
                ASSERT_TRUE(h117->result.findings[0].message.find("not in allowed set") != std::string::npos);
            }
        }
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
        expect_heuristic_result(result, 102, CheckResult::Status::FINDINGS, 10);

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
        expect_heuristic_result(result, 102, CheckResult::Status::FINDINGS, 1);

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
        expect_heuristic_result(result, 102, CheckResult::Status::FINDINGS, 1);

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

static void test_profile_sequence_desc_validation_regression() {
    std::printf("  test_profile_sequence_desc_validation_regression...\n");

    {
        auto one = make_h100_profile_sequence_desc_profile(1);
        auto profilePath = write_temp_profile(one, "h100-pseq-one.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {100});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 100, CheckResult::Status::OK, 0);
        std::filesystem::remove(profilePath);
    }

    {
        auto many = make_h100_profile_sequence_desc_profile(101);
        auto profilePath = write_temp_profile(many, "h100-pseq-many.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {100});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 100, CheckResult::Status::FINDINGS, 3);

        const auto* h100 = find_per_check(result, CheckID::Kind::Heuristic, 100);
        ASSERT_TRUE(h100 != nullptr);
        if (h100) {
            bool sawFound = false;
            bool sawCount = false;
            bool sawWarn = false;
            for (const auto& finding : h100->result.findings) {
                if (finding.message.find("Found ProfileSequenceDesc tag") != std::string::npos) {
                    sawFound = true;
                }
                if (finding.message.find("Sequence description entries: ~101") != std::string::npos) {
                    sawCount = true;
                }
                if (finding.message.find("Excessive sequence entries (101)") != std::string::npos &&
                    finding.message.find("DoS risk") != std::string::npos) {
                    sawWarn = true;
                }
            }
            ASSERT_TRUE(sawFound);
            ASSERT_TRUE(sawCount);
            ASSERT_TRUE(sawWarn);
        }
        std::filesystem::remove(profilePath);
    }

    {
        auto corpusPath = resolve_repo_file("tests/corpus/valid_srgb.icc");
        ASSERT_FALSE(corpusPath.empty());
        if (!corpusPath.empty()) {
            auto result = analyze_corpus_heuristics(corpusPath, {100});
            ASSERT_EQ(1, result.stats.checksRun);
            expect_heuristic_result(result, 100, CheckResult::Status::SKIP, 0);
        }
    }
}

static void test_chromatic_adaptation_matrix_regression() {
    std::printf("  test_chromatic_adaptation_matrix_regression...\n");

    {
        auto singular = make_h88_chad_profile_singular();
        auto profilePath = write_temp_profile(singular, "h88-chad-singular.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {88});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 88, CheckResult::Status::FINDINGS, 1);

        const auto* h88 = find_per_check(result, CheckID::Kind::Heuristic, 88);
        ASSERT_TRUE(h88 != nullptr);
        if (h88) {
            bool sawWarn = false;
            for (const auto& finding : h88->result.findings) {
                if (finding.message.find("chad matrix near-singular (det=") != std::string::npos) {
                    sawWarn = true;
                }
            }
            ASSERT_TRUE(sawWarn);
        }
        std::filesystem::remove(profilePath);
    }

    {
        auto corpusPath = resolve_repo_file("tests/corpus/valid_srgb.icc");
        ASSERT_FALSE(corpusPath.empty());
        if (!corpusPath.empty()) {
            auto result = analyze_corpus_heuristics(corpusPath, {88});
            ASSERT_EQ(1, result.stats.checksRun);
            expect_heuristic_result(result, 88, CheckResult::Status::OK, 0);
        }
    }
}

static void test_trc_curve_anomaly_regression() {
    std::printf("  test_trc_curve_anomaly_regression...\n");

    {
        auto zeroCurve = make_h87_trc_curve_profile_all_zero();
        auto profilePath = write_temp_profile(zeroCurve, "h87-trc-zero.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {87});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 87, CheckResult::Status::FINDINGS, 1);

        const auto* h87 = find_per_check(result, CheckID::Kind::Heuristic, 87);
        ASSERT_TRUE(h87 != nullptr);
        if (h87) {
            bool sawWarn = false;
            for (const auto& finding : h87->result.findings) {
                if (finding.message.find("Tag 'redTRCTag': TRC curve all-zero (3 points)") != std::string::npos &&
                    finding.message.find("clipped output") != std::string::npos) {
                    sawWarn = true;
                }
            }
            ASSERT_TRUE(sawWarn);
        }
        std::filesystem::remove(profilePath);
    }

    {
        auto corpusPath = resolve_repo_file("tests/corpus/valid_srgb.icc");
        ASSERT_FALSE(corpusPath.empty());
        if (!corpusPath.empty()) {
            auto result = analyze_corpus_heuristics(corpusPath, {87});
            ASSERT_EQ(1, result.stats.checksRun);
            expect_heuristic_result(result, 87, CheckResult::Status::OK, 0);
        }
    }
}

static void test_embedded_profile_flag_regression() {
    std::printf("  test_embedded_profile_flag_regression...\n");

    {
        auto flagged = make_h93_flags_profile(0x00000004u, 0x0000000000000010ULL);
        auto profilePath = write_temp_profile(flagged, "h93-flags-bad.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {93});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 93, CheckResult::Status::FINDINGS, 2);

        const auto* h93 = find_per_check(result, CheckID::Kind::Heuristic, 93);
        ASSERT_TRUE(h93 != nullptr);
        if (h93) {
            bool sawFlags = false;
            bool sawAttrs = false;
            for (const auto& finding : h93->result.findings) {
                if (finding.message.find("Profile flags=0x00000004: reserved bits set (mask=0x00000004)") != std::string::npos) {
                    sawFlags = true;
                }
                if (finding.message.find("Attributes=0x0000000000000010: reserved bits set") != std::string::npos) {
                    sawAttrs = true;
                }
            }
            ASSERT_TRUE(sawFlags);
            ASSERT_TRUE(sawAttrs);
        }
        std::filesystem::remove(profilePath);
    }

    {
        auto corpusPath = resolve_repo_file("tests/corpus/zero_tags.icc");
        ASSERT_FALSE(corpusPath.empty());
        if (!corpusPath.empty()) {
            auto result = analyze_corpus_heuristics(corpusPath, {93});
            ASSERT_EQ(1, result.stats.checksRun);
            expect_heuristic_result(result, 93, CheckResult::Status::OK, 0);
        }
    }
}

static void test_matrix_trc_colorant_consistency_regression() {
    std::printf("  test_matrix_trc_colorant_consistency_regression...\n");

    {
        auto bad = make_h94_matrix_trc_profile_bad_columns();
        auto profilePath = write_temp_profile(bad, "h94-matrix-bad.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {94});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 94, CheckResult::Status::FINDINGS, 2);

        const auto* h94 = find_per_check(result, CheckID::Kind::Heuristic, 94);
        ASSERT_TRUE(h94 != nullptr);
        if (h94) {
            bool sawWarn = false;
            bool sawInfo = false;
            for (const auto& finding : h94->result.findings) {
                if (finding.message.find("Matrix column sum (0.0000, 0.0000, 0.0000) deviates from D50") != std::string::npos) {
                    sawWarn = true;
                }
                if (finding.message.find("Expected") != std::string::npos &&
                    finding.message.find("deviation (0.9505, 1.0000, 1.0890)") != std::string::npos) {
                    sawInfo = true;
                }
            }
            ASSERT_TRUE(sawWarn);
            ASSERT_TRUE(sawInfo);
        }
        std::filesystem::remove(profilePath);
    }

    {
        auto corpusPath = resolve_repo_file("tests/corpus/valid_srgb.icc");
        ASSERT_FALSE(corpusPath.empty());
        if (!corpusPath.empty()) {
            auto result = analyze_corpus_heuristics(corpusPath, {94});
            ASSERT_EQ(1, result.stats.checksRun);
            expect_heuristic_result(result, 94, CheckResult::Status::OK, 0);
        }
    }
}

static void test_profile_sequence_description_regression() {
    std::printf("  test_profile_sequence_description_regression...\n");

    {
        auto many = make_h100_profile_sequence_desc_profile(257);
        auto profilePath = write_temp_profile(many, "h89-pseq-many.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {89});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 89, CheckResult::Status::FINDINGS, 1);

        const auto* h89 = find_per_check(result, CheckID::Kind::Heuristic, 89);
        ASSERT_TRUE(h89 != nullptr);
        if (h89) {
            bool sawWarn = false;
            for (const auto& finding : h89->result.findings) {
                if (finding.message.find("Profile sequence has 257 descriptions (>256)") != std::string::npos &&
                    finding.message.find("OOM risk") != std::string::npos) {
                    sawWarn = true;
                }
            }
            ASSERT_TRUE(sawWarn);
        }
        std::filesystem::remove(profilePath);
    }

    {
        auto corpusPath = resolve_repo_file("tests/corpus/valid_srgb.icc");
        ASSERT_FALSE(corpusPath.empty());
        if (!corpusPath.empty()) {
            auto result = analyze_corpus_heuristics(corpusPath, {89});
            ASSERT_EQ(1, result.stats.checksRun);
            expect_heuristic_result(result, 89, CheckResult::Status::OK, 0);
        }
    }
}

static void test_colorant_order_validation_regression() {
    std::printf("  test_colorant_order_validation_regression...\n");

    {
        auto dup = make_h91_colorant_order_profile(true);
        auto profilePath = write_temp_profile(dup, "h91-clro-dup.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {91});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 91, CheckResult::Status::FINDINGS, 1);

        const auto* h91 = find_per_check(result, CheckID::Kind::Heuristic, 91);
        ASSERT_TRUE(h91 != nullptr);
        if (h91) {
            bool sawDup = false;
            for (const auto& finding : h91->result.findings) {
                if (finding.message.find("ColorantOrder has duplicate index 0") != std::string::npos) {
                    sawDup = true;
                }
            }
            ASSERT_TRUE(sawDup);
        }
        std::filesystem::remove(profilePath);
    }

    {
        auto clean = make_h91_colorant_order_profile(false);
        auto profilePath = write_temp_profile(clean, "h91-clro-ok.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {91});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 91, CheckResult::Status::OK, 0);
        std::filesystem::remove(profilePath);
    }
}

static void test_preview_tag_channel_consistency_regression() {
    std::printf("  test_preview_tag_channel_consistency_regression...\n");

    {
        auto clean = make_h90_preview_profile(3, 3);
        auto profilePath = write_temp_profile(clean, "h90-preview-ok.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {90});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 90, CheckResult::Status::OK, 0);
        std::filesystem::remove(profilePath);
    }

    {
        auto bad = make_h90_preview_profile(4, 2);
        auto profilePath = write_temp_profile(bad, "h90-preview-bad.icc");
        ASSERT_FALSE(profilePath.empty());
        if (profilePath.empty()) return;

        auto result = analyze_corpus_heuristics(profilePath, {90});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 90, CheckResult::Status::FINDINGS, 2);

        const auto* h90 = find_per_check(result, CheckID::Kind::Heuristic, 90);
        ASSERT_TRUE(h90 != nullptr);
        if (h90) {
            bool sawInput = false;
            bool sawOutput = false;
            for (const auto& finding : h90->result.findings) {
                if (finding.message.find("Tag 'pre0': input channels=4 != PCS channels=3") != std::string::npos) {
                    sawInput = true;
                }
                if (finding.message.find("Tag 'pre0': output channels=2 != PCS channels=3") != std::string::npos) {
                    sawOutput = true;
                }
            }
            ASSERT_TRUE(sawInput);
            ASSERT_TRUE(sawOutput);
        }
        std::filesystem::remove(profilePath);
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

static void test_h20_tag_type_signature_regression() {
    std::printf("  test_h20_tag_type_signature_regression...\n");

    {
        auto data = make_h20_tag_type_signature_profile(0x00000000u);
        auto path = write_temp_profile(data, "icctest-h20-null-type.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {20});
        ASSERT_EQ(1, result.stats.checksRun);

        const auto* h20 = find_per_check(result, CheckID::Kind::Heuristic, 20);
        ASSERT_TRUE(h20 != nullptr);
        if (!h20) {
            return;
        }

        ASSERT_EQ(CheckResult::Status::FINDINGS, h20->result.status);
        ASSERT_EQ(1, h20->result.issueCount());
        ASSERT_TRUE(h20->result.findings[0].message.find("null type signature") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped clean check — tests/corpus not found)\n");
        return;
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {20});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 20, CheckResult::Status::OK, 0);

        const auto* h20 = find_per_check(cleanResult, CheckID::Kind::Heuristic, 20);
        ASSERT_TRUE(h20 != nullptr);
        if (!h20) {
            return;
        }
        ASSERT_TRUE(h20->result.summary.find("All tag type signatures are valid ASCII") != std::string::npos);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "cf_misaligned_tag.icc", {20});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 20, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "gbd_tary_signed_channel_wrap.icc", {20});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 20, CheckResult::Status::FINDINGS, 1);
    }
}

static void test_h18_technology_signature_regression() {
    std::printf("  test_h18_technology_signature_regression...\n");

    {
        auto data = make_h18_technology_signature_profile(0xFFFFFFFFu);
        auto path = write_temp_profile(data, "icctest-h18-tech-invalid.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {18});
        ASSERT_EQ(1, result.stats.checksRun);

        const auto* h18 = find_per_check(result, CheckID::Kind::Heuristic, 18);
        ASSERT_TRUE(h18 != nullptr);
        if (!h18) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h18->result.status);
        ASSERT_TRUE(h18->result.findings[0].message.find("Unknown technology signature") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped clean check — tests/corpus not found)\n");
        return;
    }

    auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {18});
    ASSERT_EQ(1, cleanResult.stats.checksRun);
    expect_heuristic_result(cleanResult, 18, CheckResult::Status::OK, 0);
    const auto* h18 = find_per_check(cleanResult, CheckID::Kind::Heuristic, 18);
    ASSERT_TRUE(h18 != nullptr);
    if (h18) {
        ASSERT_TRUE(h18->result.summary.find("No technology tag present") != std::string::npos);
    }
}

static void test_h25_tag_offset_oob_regression() {
    std::printf("  test_h25_tag_offset_oob_regression...\n");

    {
        auto data = make_h25_tag_offset_oob_profile();
        auto path = write_temp_profile(data, "icctest-h25-offset-oob.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {25});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h25 = find_per_check(result, CheckID::Kind::Heuristic, 25);
        ASSERT_TRUE(h25 != nullptr);
        if (!h25) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h25->result.status);
        ASSERT_TRUE(h25->result.findings[0].message.find("beyond file/profile bounds") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) return;
    auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {25});
    ASSERT_EQ(1, cleanResult.stats.checksRun);
    expect_heuristic_result(cleanResult, 25, CheckResult::Status::OK, 0);
}

static void test_h21_h24_tag_struct_regressions() {
    std::printf("  test_h21_h24_tag_struct_regressions...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) return;
    auto structFixture = write_temp_profile(make_h21_tag_struct_profile(),
                                            "icctest-h21-tagstruct.icc");
    ASSERT_FALSE(structFixture.empty());
    if (structFixture.empty()) return;

    {
        auto result = analyze_corpus_heuristics(structFixture, {21, 22, 23, 24});
        ASSERT_EQ(4, result.stats.checksRun);
        expect_heuristic_result(result, 21, CheckResult::Status::FINDINGS, 4);
        expect_heuristic_result(result, 22, CheckResult::Status::FINDINGS, 1);
        expect_heuristic_result(result, 23, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 24, CheckResult::Status::OK, 0);

        const auto* h21 = find_per_check(result, CheckID::Kind::Heuristic, 21);
        ASSERT_TRUE(h21 != nullptr);
        if (h21) {
            ASSERT_TRUE(h21->result.findings[0].message.find("null type") != std::string::npos ||
                        h21->result.findings[0].message.find("non-ASCII type") != std::string::npos);
        }

        const auto* h22 = find_per_check(result, CheckID::Kind::Heuristic, 22);
        ASSERT_TRUE(h22 != nullptr);
        if (h22) {
            ASSERT_TRUE(h22->result.findings[0].message.find("ViewingSurround") != std::string::npos);
        }

        const auto* h24 = find_per_check(result, CheckID::Kind::Heuristic, 24);
        ASSERT_TRUE(h24 != nullptr);
        if (h24) {
            ASSERT_TRUE(h24->result.summary.find("Max nesting depth: 1") != std::string::npos);
        }
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "cf143-meas-valid.icc", {21, 22, 23, 24});
        ASSERT_EQ(4, result.stats.checksRun);
        expect_heuristic_result(result, 21, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 22, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 23, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 24, CheckResult::Status::OK, 0);

        const auto* h21 = find_per_check(result, CheckID::Kind::Heuristic, 21);
        ASSERT_TRUE(h21 != nullptr);
        if (h21) {
            ASSERT_TRUE(h21->result.summary.find("tagStruct members appear well-formed") != std::string::npos);
        }

        const auto* h22 = find_per_check(result, CheckID::Kind::Heuristic, 22);
        ASSERT_TRUE(h22 != nullptr);
        if (h22) {
            ASSERT_TRUE(h22->result.summary.find("No cept") != std::string::npos);
        }

        const auto* h24 = find_per_check(result, CheckID::Kind::Heuristic, 24);
        ASSERT_TRUE(h24 != nullptr);
        if (h24) {
            ASSERT_TRUE(h24->result.summary.find("Max nesting depth: 0") != std::string::npos);
        }
    }

    std::error_code ignored;
    std::filesystem::remove(structFixture, ignored);
}

static void test_h26_named_color2_string_regression() {
    std::printf("  test_h26_named_color2_string_regression...\n");

    {
        auto data = make_h26_named_color2_string_profile(true);
        auto path = write_temp_profile(data, "icctest-h26-ncl2-bad.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {26});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h26 = find_per_check(result, CheckID::Kind::Heuristic, 26);
        ASSERT_TRUE(h26 != nullptr);
        if (!h26) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h26->result.status);
        bool sawPrefix = false;
        bool sawSuffix = false;
        for (const auto& finding : h26->result.findings) {
            if (finding.message.find("Prefix not null-terminated") != std::string::npos) sawPrefix = true;
            if (finding.message.find("Suffix not null-terminated") != std::string::npos) sawSuffix = true;
        }
        ASSERT_TRUE(sawPrefix);
        ASSERT_TRUE(sawSuffix);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    {
        auto data = make_h26_named_color2_string_profile(false);
        auto path = write_temp_profile(data, "icctest-h26-ncl2-ok.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {26});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 26, CheckResult::Status::OK, 0);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }
}

static void test_h27_mpe_matrix_output_regression() {
    std::printf("  test_h27_mpe_matrix_output_regression...\n");

    {
        auto data = make_h27_mpe_matrix_output_profile(2);
        auto path = write_temp_profile(data, "icctest-h27-matrix-out2.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {27});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h27 = find_per_check(result, CheckID::Kind::Heuristic, 27);
        ASSERT_TRUE(h27 != nullptr);
        if (!h27) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h27->result.status);
        ASSERT_TRUE(h27->result.findings[0].message.find("Matrix has 2 output channels") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) return;
    auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {27});
    ASSERT_EQ(1, cleanResult.stats.checksRun);
    expect_heuristic_result(cleanResult, 27, CheckResult::Status::OK, 0);
}

static void test_h28_lut_dimension_regression() {
    std::printf("  test_h28_lut_dimension_regression...\n");

    {
        auto data = make_h28_lut_dimension_profile(17, 3, 2);
        auto path = write_temp_profile(data, "icctest-h28-lut-bad.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {28});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h28 = find_per_check(result, CheckID::Kind::Heuristic, 28);
        ASSERT_TRUE(h28 != nullptr);
        if (!h28) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h28->result.status);
        ASSERT_TRUE(h28->result.findings[0].message.find("exceeds spec max (16)") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    {
        auto data = make_h28_lut_dimension_profile(3, 3, 2);
        auto path = write_temp_profile(data, "icctest-h28-lut-ok.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {28});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 28, CheckResult::Status::OK, 0);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }
}

static void test_h29_colorant_table_string_regression() {
    std::printf("  test_h29_colorant_table_string_regression...\n");

    {
        auto data = make_h29_colorant_table_profile(true);
        auto path = write_temp_profile(data, "icctest-h29-clrt-bad.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {29});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h29 = find_per_check(result, CheckID::Kind::Heuristic, 29);
        ASSERT_TRUE(h29 != nullptr);
        if (!h29) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h29->result.status);
        ASSERT_TRUE(h29->result.issueCount() >= 2);
        ASSERT_TRUE(h29->result.findings[0].message.find("Colorant[0] name not null-terminated") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    {
        auto data = make_h29_colorant_table_profile(false);
        auto path = write_temp_profile(data, "icctest-h29-clrt-ok.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {29});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 29, CheckResult::Status::OK, 0);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }
}

static void test_h31_mpe_channel_count_regression() {
    std::printf("  test_h31_mpe_channel_count_regression...\n");

    {
        auto data = make_h31_mpe_channel_count_profile(33);
        auto path = write_temp_profile(data, "icctest-h31-mpet-bad.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {31});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h31 = find_per_check(result, CheckID::Kind::Heuristic, 31);
        ASSERT_TRUE(h31 != nullptr);
        if (!h31) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h31->result.status);
        ASSERT_TRUE(h31->result.findings[0].message.find("MPE channels in=33 out=33 (>32)") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) return;
    auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {31});
    ASSERT_EQ(1, cleanResult.stats.checksRun);
    expect_heuristic_result(cleanResult, 31, CheckResult::Status::OK, 0);
}

static void test_h32_tag_data_type_confusion_regression() {
    std::printf("  test_h32_tag_data_type_confusion_regression...\n");

    {
        auto data = make_h32_unknown_type_profile(0x7A7A7A7Au); // 'zzzz'
        auto path = write_temp_profile(data, "icctest-h32-unknown-type.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {32});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h32 = find_per_check(result, CheckID::Kind::Heuristic, 32);
        ASSERT_TRUE(h32 != nullptr);
        if (!h32) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h32->result.status);
        ASSERT_TRUE(h32->result.findings[0].message.find("unknown type signature 'zzzz'") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) return;
    auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {32});
    ASSERT_EQ(1, cleanResult.stats.checksRun);
    expect_heuristic_result(cleanResult, 32, CheckResult::Status::OK, 0);

    {
        auto result = analyze_corpus_heuristics(corpusDir / "huge_tag_count.icc", {32});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 32, CheckResult::Status::FINDINGS, 10);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "gbd_tary_signed_channel_wrap.icc", {32});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 32, CheckResult::Status::FINDINGS, 1);
    }
}

static void test_h52_tag_size_underflow_regression() {
    std::printf("  test_h52_tag_size_underflow_regression...\n");

    auto pocPath = resolve_repo_file("test-profiles/cfl065-nEnd-underflow-v4.icc");
    if (pocPath.empty()) {
        std::printf("    (skipped — cfl065-nEnd-underflow-v4.icc not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_heuristics(pocPath, {52});
        ASSERT_EQ(1, result.stats.checksRun);

        const auto* h52 = find_per_check(result, CheckID::Kind::Heuristic, 52);
        ASSERT_TRUE(h52 != nullptr);
        if (!h52) {
            return;
        }

        ASSERT_EQ(CheckResult::Status::FINDINGS, h52->result.status);
        ASSERT_TRUE(h52->result.issueCount() >= 1);

        bool sawOffsetOverflow = false;
        for (const auto& finding : h52->result.findings) {
            if (finding.message.find("B-curves offset") != std::string::npos &&
                finding.message.find("underflows to ~4GB") != std::string::npos &&
                finding.cweNote.find("CFL-065") != std::string::npos) {
                sawOffsetOverflow = true;
                break;
            }
        }
        ASSERT_TRUE(sawOffsetOverflow);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped clean check — tests/corpus not found)\n");
        return;
    }

    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {52});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 52, CheckResult::Status::OK, 0);

        const auto* h52 = find_per_check(cleanResult, CheckID::Kind::Heuristic, 52);
        ASSERT_TRUE(h52 != nullptr);
        if (!h52) {
            return;
        }
        ASSERT_TRUE(h52->result.summary.find("No integer underflow in tag sizes") != std::string::npos);
    }
}

static void test_h41_h42_h50_raw_scan_regressions() {
    std::printf("  test_h41_h42_h50_raw_scan_regressions...\n");

    {
        auto data = make_h41_version_type_profile(0x64657363u); // 'desc'
        auto path = write_temp_profile(data, "icctest-h41-version-type.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {41});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h41 = find_per_check(result, CheckID::Kind::Heuristic, 41);
        ASSERT_TRUE(h41 != nullptr);
        if (!h41) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h41->result.status);
        ASSERT_EQ(1, h41->result.issueCount());
        ASSERT_TRUE(h41->result.findings[0].message.find("v2-only textDescription type") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    {
        auto data = make_h42_matrix_singularity_profile();
        auto path = write_temp_profile(data, "icctest-h42-singular-matrix.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {42});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h42 = find_per_check(result, CheckID::Kind::Heuristic, 42);
        ASSERT_TRUE(h42 != nullptr);
        if (!h42) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h42->result.status);
        ASSERT_TRUE(h42->result.issueCount() >= 2);
        bool sawSingular = false;
        bool sawAllZero = false;
        for (const auto& finding : h42->result.findings) {
            if (finding.message.find("near-singular 3x3 matrix") != std::string::npos) {
                sawSingular = true;
            }
            if (finding.message.find("matrix is all zeros") != std::string::npos) {
                sawAllZero = true;
            }
        }
        ASSERT_TRUE(sawSingular);
        ASSERT_TRUE(sawAllZero);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    {
        auto data = make_h50_zero_size_tag_profile();
        auto path = write_temp_profile(data, "icctest-h50-zero-size.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {50});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h50 = find_per_check(result, CheckID::Kind::Heuristic, 50);
        ASSERT_TRUE(h50 != nullptr);
        if (!h50) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h50->result.status);
        ASSERT_EQ(1, h50->result.issueCount());
        ASSERT_TRUE(h50->result.findings[0].message.find("zero size") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        return;
    }

    {
        auto clean = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {41, 42, 50});
        ASSERT_EQ(3, clean.stats.checksRun);
        expect_heuristic_result(clean, 41, CheckResult::Status::OK, 0);
        expect_heuristic_result(clean, 42, CheckResult::Status::OK, 0);
        expect_heuristic_result(clean, 50, CheckResult::Status::OK, 0);
    }
}

static void test_h38_h39_raw_scan_regressions() {
    std::printf("  test_h38_h39_raw_scan_regressions...\n");

    {
        auto data = make_h38_curve_degenerate_profile();
        auto path = write_temp_profile(data, "icctest-h38-curve-degenerate.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {38});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h38 = find_per_check(result, CheckID::Kind::Heuristic, 38);
        ASSERT_TRUE(h38 != nullptr);
        if (!h38) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h38->result.status);
        ASSERT_EQ(1, h38->result.issueCount());
        ASSERT_TRUE(h38->result.findings[0].message.find("all 4 entries are zero") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    {
        auto data = make_h39_shared_tag_alias_profile();
        auto path = write_temp_profile(data, "icctest-h39-shared-alias.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }

        auto result = analyze_corpus_heuristics(path, {39});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h39 = find_per_check(result, CheckID::Kind::Heuristic, 39);
        ASSERT_TRUE(h39 != nullptr);
        if (!h39) {
            return;
        }
        ASSERT_EQ(CheckResult::Status::FINDINGS, h39->result.status);
        ASSERT_EQ(1, h39->result.issueCount());
        ASSERT_TRUE(h39->result.findings[0].message.find("share offset") != std::string::npos);

        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        return;
    }

    {
        auto clean = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {38, 39});
        ASSERT_EQ(2, clean.stats.checksRun);
        expect_heuristic_result(clean, 38, CheckResult::Status::OK, 0);
        expect_heuristic_result(clean, 39, CheckResult::Status::OK, 0);
    }
}

static void test_h43_h46_raw_scan_regressions() {
    std::printf("  test_h43_h46_raw_scan_regressions...\n");

    {
        auto data = make_h43_spectral_brdf_profile();
        auto path = write_temp_profile(data, "icctest-h43-svwc.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }
        auto result = analyze_corpus_heuristics(path, {43});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h43 = find_per_check(result, CheckID::Kind::Heuristic, 43);
        ASSERT_TRUE(h43 != nullptr);
        if (!h43) return;
        ASSERT_EQ(CheckResult::Status::FINDINGS, h43->result.status);
        ASSERT_TRUE(h43->result.issueCount() >= 2);
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    {
        auto data = make_h44_embedded_image_profile();
        auto path = write_temp_profile(data, "icctest-h44-embedded-image.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }
        auto result = analyze_corpus_heuristics(path, {44});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h44 = find_per_check(result, CheckID::Kind::Heuristic, 44);
        ASSERT_TRUE(h44 != nullptr);
        if (!h44) return;
        ASSERT_EQ(CheckResult::Status::FINDINGS, h44->result.status);
        ASSERT_TRUE(h44->result.findings[0].message.find("oversized embedded data") != std::string::npos);
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    {
        auto data = make_h45_sparse_matrix_profile();
        auto path = write_temp_profile(data, "icctest-h45-sparse-matrix.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }
        auto result = analyze_corpus_heuristics(path, {45});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h45 = find_per_check(result, CheckID::Kind::Heuristic, 45);
        ASSERT_TRUE(h45 != nullptr);
        if (!h45) return;
        ASSERT_EQ(CheckResult::Status::FINDINGS, h45->result.status);
        ASSERT_TRUE(h45->result.findings[0].message.find("sparse matrix 5000x5000") != std::string::npos);
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    {
        auto data = make_h46_text_desc_profile();
        auto path = write_temp_profile(data, "icctest-h46-text-desc.icc");
        ASSERT_FALSE(path.empty());
        if (path.empty()) {
            return;
        }
        auto result = analyze_corpus_heuristics(path, {46});
        ASSERT_EQ(1, result.stats.checksRun);
        const auto* h46 = find_per_check(result, CheckID::Kind::Heuristic, 46);
        ASSERT_TRUE(h46 != nullptr);
        if (!h46) return;
        ASSERT_EQ(CheckResult::Status::FINDINGS, h46->result.status);
        ASSERT_TRUE(h46->result.findings[0].message.find("ASCII length 64 exceeds available tag data") != std::string::npos);
        std::error_code ignored;
        std::filesystem::remove(path, ignored);
    }

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        return;
    }

    {
        auto clean = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {43, 44, 45, 46});
        ASSERT_EQ(4, clean.stats.checksRun);
        expect_heuristic_result(clean, 43, CheckResult::Status::OK, 0);
        expect_heuristic_result(clean, 44, CheckResult::Status::OK, 0);
        expect_heuristic_result(clean, 45, CheckResult::Status::OK, 0);
        expect_heuristic_result(clean, 46, CheckResult::Status::OK, 0);
    }
}

static void test_integrity_heuristic_regressions() {
    std::printf("  test_integrity_heuristic_regressions...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "version_bcd_invalid.icc", {128});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 128, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {128});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 128, CheckResult::Status::OK, 0);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "wrong_d50_illuminant.icc", {129});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 129, CheckResult::Status::FINDINGS, 4);
    }
    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {129});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 129, CheckResult::Status::OK, 0);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "tag_misaligned.icc", {130});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 130, CheckResult::Status::FINDINGS, 4);
    }
    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {130});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 130, CheckResult::Status::OK, 0);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "cf_md5_mismatch.icc", {131});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 131, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {131});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 131, CheckResult::Status::OK, 0);
    }

    {
        auto singular = make_h88_chad_profile_singular();
        auto profilePath = write_temp_profile(singular, "h132-chad-singular.icc");
        ASSERT_FALSE(profilePath.empty());
        if (!profilePath.empty()) {
            auto result = analyze_corpus_heuristics(profilePath, {132});
            ASSERT_EQ(1, result.stats.checksRun);
            expect_heuristic_result(result, 132, CheckResult::Status::FINDINGS, 1);

            std::error_code ignored;
            std::filesystem::remove(profilePath, ignored);
        }
    }
    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {132});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 132, CheckResult::Status::OK, 0);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "flags_reserved_bits.icc", {133});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 133, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {133});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 133, CheckResult::Status::OK, 0);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "cf_reserved_bytes_nonzero_tag.icc", {134});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 134, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {134});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 134, CheckResult::Status::OK, 0);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "duplicate_tags.icc", {135});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 135, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {135});
        ASSERT_EQ(1, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 135, CheckResult::Status::OK, 0);
    }

    {
        auto result = analyze_corpus_heuristics(corpusDir / "private_tags.icc", {123, 126, 127});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_heuristic_result(result, 123, CheckResult::Status::FINDINGS, 3);
        expect_heuristic_result(result, 126, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 127, CheckResult::Status::FINDINGS, 3);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "malware_private_tag.icc", {123, 126, 127});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_heuristic_result(result, 123, CheckResult::Status::FINDINGS, 2);
        expect_heuristic_result(result, 126, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 127, CheckResult::Status::FINDINGS, 2);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "v5_tags_on_v4.icc", {124, 126, 127});
        ASSERT_EQ(3, result.stats.checksRun);
        expect_heuristic_result(result, 124, CheckResult::Status::FINDINGS, 1);
        expect_heuristic_result(result, 126, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 127, CheckResult::Status::OK, 0);
    }
    {
        auto result = analyze_corpus_heuristics(corpusDir / "targ_cmyk_quality_profile.icc", {125});
        ASSERT_EQ(1, result.stats.checksRun);
        expect_heuristic_result(result, 125, CheckResult::Status::FINDINGS, 1);
    }
    {
        auto cleanResult = analyze_corpus_heuristics(corpusDir / "valid_srgb.icc", {123, 124, 125, 126, 127});
        ASSERT_EQ(5, cleanResult.stats.checksRun);
        expect_heuristic_result(cleanResult, 123, CheckResult::Status::OK, 0);
        expect_heuristic_result(cleanResult, 124, CheckResult::Status::OK, 0);
        expect_heuristic_result(cleanResult, 125, CheckResult::Status::OK, 0);
        expect_heuristic_result(cleanResult, 126, CheckResult::Status::OK, 0);
        expect_heuristic_result(cleanResult, 127, CheckResult::Status::OK, 0);
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

static void test_failed_load_heuristic_parity_regression_cluster() {
    std::printf("  test_failed_load_heuristic_parity_regression_cluster...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    const char* names[] = {
        "calculator_deep_nesting.icc",
        "cf138-ehim-short.icc",
        "cf139-enim-short.icc",
        "cf140-gbd-short.icc",
        "cf140-gbd-valid.icc",
    };

    for (const char* name : names) {
        auto result = analyze_corpus_heuristics(corpusDir / name, {97, 99, 100, 147, 172});
        ASSERT_EQ(5, result.stats.checksRun);

        expect_heuristic_result(result, 97, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 99, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 100, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 172, CheckResult::Status::SKIP, 0);
        expect_heuristic_result(result, 147, CheckResult::Status::FINDINGS, 1);

        const auto* h147 = find_per_check(result, CheckID::Kind::Heuristic, 147);
        ASSERT_TRUE(h147 != nullptr);
        if (!h147) return;

        bool sawNullTag = false;
        for (const auto& finding : h147->result.findings) {
            if (finding.message.find("pTag pointer is null") != std::string::npos &&
                finding.cweNote.find("CWE-476") != std::string::npos) {
                sawNullTag = true;
                break;
            }
        }
        ASSERT_TRUE(sawNullTag);
    }
}

static void test_failed_load_library_only_ok_regression_cluster() {
    std::printf("  test_failed_load_library_only_ok_regression_cluster...\n");

    auto corpusDir = resolve_repo_file("tests/corpus");
    if (corpusDir.empty()) {
        std::printf("    (skipped — tests/corpus not found)\n");
        return;
    }

    {
        auto result = analyze_corpus_heuristics(
            corpusDir / "calculator_deep_nesting.icc",
            {18, 21, 22, 23, 24, 27, 31, 147});
        ASSERT_EQ(8, result.stats.checksRun);
        expect_heuristic_result(result, 18, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 21, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 22, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 23, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 24, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 27, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 31, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 147, CheckResult::Status::FINDINGS, 1);
    }

    {
        auto result = analyze_corpus_heuristics(
            corpusDir / "v5_spac_basic.icc",
            {18, 21, 22, 23, 24, 27, 31, 147});
        ASSERT_EQ(8, result.stats.checksRun);
        expect_heuristic_result(result, 18, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 21, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 22, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 23, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 24, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 27, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 31, CheckResult::Status::OK, 0);
        expect_heuristic_result(result, 147, CheckResult::Status::FINDINGS, 1);
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

        ASSERT_EQ(CheckResult::Status::OK, cf115->result.status);
        ASSERT_EQ(0, cf115->result.issueCount());
        ASSERT_TRUE(cf115->result.summary == "NOT RUN: Library quarantined");
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
    test_repo_fixture_resolution_stability();
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
    test_localized_unicode_bounds_regression();
    test_gbd_tary_signed_channel_wrap_regression();
    test_profile_sequence_id_validation_regression();
    test_tag_size_profile_size_cross_check_regression();
    test_trc_curve_anomaly_regression();
    test_chromatic_adaptation_matrix_regression();
    test_embedded_profile_flag_regression();
    test_matrix_trc_colorant_consistency_regression();
    test_profile_sequence_description_regression();
    test_profile_sequence_desc_validation_regression();
    test_colorant_order_validation_regression();
    test_preview_tag_channel_consistency_regression();
    test_unchecked_allocation_size_overflow_regression();
    test_alloc_dealloc_and_uaf_ownership_regressions();
    test_deep_apply_stack_escape_regression();
    test_dictionary_tag_element_bounds_regression();
    test_lut_data_sufficiency_regression();
    test_copy_constructor_null_pcs_regression();
    test_h18_technology_signature_regression();
    test_h20_tag_type_signature_regression();
    test_h21_h24_tag_struct_regressions();
    test_h25_tag_offset_oob_regression();
    test_h26_named_color2_string_regression();
    test_h27_mpe_matrix_output_regression();
    test_h28_lut_dimension_regression();
    test_h29_colorant_table_string_regression();
    test_h31_mpe_channel_count_regression();
    test_h32_tag_data_type_confusion_regression();
    test_h38_h39_raw_scan_regressions();
    test_h41_h42_h50_raw_scan_regressions();
    test_h43_h46_raw_scan_regressions();
    test_h52_tag_size_underflow_regression();
    test_integrity_heuristic_regressions();
    test_lut_matrix_coefficient_validation_regression();
    test_spectral_mpe_h98_gap_fixture();
    test_failed_load_heuristic_parity_regression_cluster();
    test_failed_load_library_only_ok_regression_cluster();
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
