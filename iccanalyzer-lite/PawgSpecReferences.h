#ifndef ICCANALYZER_PAWG_SPEC_REFERENCES_H
#define ICCANALYZER_PAWG_SPEC_REFERENCES_H

#include <algorithm>
#include <array>
#include <filesystem>
#include <string>
#include <vector>

#if defined(__linux__)
#include <unistd.h>
#endif

namespace iccanalyzer::pawg {

inline constexpr const char* kChecklistUrl =
    "https://www.color.org/profiles/assessment/index.xalter";

inline bool shouldIncludeSpecReferenceName(const std::string& name) {
    return name != "ICC.1_Adaptive_Gain_Curve.pdf";
}

inline std::vector<std::string> fallbackSpecReferencePaths() {
    static constexpr std::array<const char*, 26> kFiles{{
        "Embedding_an_ICC.2_profile_in_an_ICC.1_profile.pdf",
        "Guidelines_on_the_use_of_negative_PCSXYZ_values.pdf",
        "ICC-Technote-PartialAdaptation.pdf",
        "ICC-Technote-ProfileEmbedding.pdf",
        "ICC.1-2022-05.pdf",
        "ICC.1_Adaptive_Gain_Curve.pdf",
        "ICC.2-2019.pdf",
        "ICC.2-2019_Cumulative_Errata_List_2021-03-08.pdf",
        "ICC.2-2019_Cumulative_Errata_List_2021-09-09.pdf",
        "ICC.2-2023.pdf",
        "ICCSpecRevision_25-02-10_dictType-1.pdf",
        "ICCSpecRevision_25-02-10_dictType.pdf",
        "ICC_TN-06-2025_Recommendations_on_calculation_of_tristimulus_values.pdf",
        "ICC_White_Paper_54_Introduction_to_ICS.pdf",
        "ICC_White_Paper_57_Introduction_to_core_ICS_specifications.pdf",
        "ICC_white_paper_21-SampleICCProfileCompliance.pdf",
        "ICS-ExtendedOutput-Part1.pdf",
        "ICS-ExtendedRange-Part1.pdf",
        "ICS-ExtendedRange-Part2.pdf",
        "ICS-ExtendedRange-Part3.pdf",
        "PSD_TechNote.pdf",
        "README.md",
        "icc-individual-cla.pdf",
        "rfc1321.txt",
        "v2profiles_v4.pdf",
        "v4_matrix_entries.pdf",
    }};

    std::vector<std::string> refs;
    refs.reserve(kFiles.size());
    for (const char* name : kFiles) {
        if (!shouldIncludeSpecReferenceName(name)) {
            continue;
        }
        refs.emplace_back("docs/iccDEV/specifications/" + std::string(name));
    }
    return refs;
}

inline void appendUniqueRoot(std::vector<std::filesystem::path>& roots,
                             const std::filesystem::path& root) {
    if (root.empty()) {
        return;
    }

    std::error_code ec;
    auto normalized = std::filesystem::absolute(root, ec);
    if (ec) {
        normalized = root.lexically_normal();
    }

    if (std::find(roots.begin(), roots.end(), normalized) == roots.end()) {
        roots.push_back(normalized);
    }
}

inline std::filesystem::path resolveExecutableDir() {
#if defined(__linux__)
    std::array<char, 4096> buf{};
    const ssize_t len = ::readlink("/proc/self/exe", buf.data(), buf.size() - 1);
    if (len > 0) {
        buf[static_cast<size_t>(len)] = '\0';
        return std::filesystem::path(buf.data()).parent_path();
    }
#endif
    return {};
}

inline std::filesystem::path findSpecsFromRoot(const std::filesystem::path& start) {
    if (start.empty()) {
        return {};
    }

    std::error_code ec;
    auto cursor = std::filesystem::absolute(start, ec);
    if (ec) {
        cursor = start.lexically_normal();
    }

    while (!cursor.empty()) {
        auto candidate = cursor / "docs" / "iccDEV" / "specifications";
        if (std::filesystem::is_directory(candidate, ec) && !ec) {
            return candidate.lexically_normal();
        }

        const auto parent = cursor.parent_path();
        if (parent == cursor) {
            break;
        }
        cursor = parent;
    }

    return {};
}

inline std::filesystem::path locateSpecDirectory(
        const std::filesystem::path& inputFile = std::filesystem::path()) {
    std::vector<std::filesystem::path> roots;

    std::error_code ec;
    appendUniqueRoot(roots, std::filesystem::current_path(ec));
    if (!inputFile.empty()) {
        appendUniqueRoot(roots, inputFile.parent_path());
    }
    appendUniqueRoot(roots, resolveExecutableDir());
    appendUniqueRoot(roots, std::filesystem::path(__FILE__).parent_path());

    for (const auto& root : roots) {
        auto found = findSpecsFromRoot(root);
        if (!found.empty()) {
            return found;
        }
    }

    return {};
}

inline std::vector<std::string> listSpecReferencePaths(
        const std::filesystem::path& inputFile = std::filesystem::path()) {
    std::vector<std::string> refs;
    auto dir = locateSpecDirectory(inputFile);
    if (dir.empty()) {
        return fallbackSpecReferencePaths();
    }

    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        if (ec) {
            break;
        }
        if (!entry.is_regular_file(ec) || ec) {
            continue;
        }
        const auto name = entry.path().filename().string();
        if (!shouldIncludeSpecReferenceName(name)) {
            continue;
        }
        refs.emplace_back("docs/iccDEV/specifications/" + name);
    }

    if (refs.empty()) {
        return fallbackSpecReferencePaths();
    }

    std::sort(refs.begin(), refs.end());
    return refs;
}

}  // namespace iccanalyzer::pawg

#endif  // ICCANALYZER_PAWG_SPEC_REFERENCES_H
