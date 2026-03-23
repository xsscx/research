/*
 * IccTest Tools — icctestParity.cpp
 * Parity-oriented JSON driver exposing per-check execution details.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include <icctest/IccTest.h>
#include <icctest/CoverageEnv.h>

#include <jpeglib.h>
#include <png.h>
#include <tiffio.h>

#include <algorithm>
#include <cctype>
#include <csetjmp>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

extern "C" const char* __asan_default_options() {
    return "halt_on_error=0:detect_leaks=0:print_stats=0:log_path=stderr";
}

extern "C" const char* __ubsan_default_options() {
    return "halt_on_error=0:print_stacktrace=1:silence_unsigned_overflow=1";
}

namespace icctest {
namespace {

enum class Lane : uint8_t {
    All,
    Heuristic,
    Conformance,
    Image,
};

struct ParsedArgs {
    std::filesystem::path inputPath;
    AnalysisOptions opts;
    Lane lane = Lane::All;
    bool pretty = false;
    bool emitEmbeddedProfileBase64 = false;
};

struct EmbeddedProfileInfo {
    bool imageInspected = false;
    bool containerParseable = false;
    std::string containerParseError;
    bool present = false;
    std::string source;
    std::vector<uint8_t> bytes;
};

std::string toUpper(std::string s) {
    for (char& c : s) {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return s;
}

std::vector<std::string> splitList(std::string_view input) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start <= input.size()) {
        size_t pos = input.find(',', start);
        if (pos == std::string_view::npos) {
            pos = input.size();
        }
        auto piece = std::string(input.substr(start, pos - start));
        if (!piece.empty()) {
            out.push_back(piece);
        }
        if (pos == input.size()) {
            break;
        }
        start = pos + 1;
    }
    return out;
}

std::optional<Severity> parseSeverity(const std::string& token) {
    auto upper = toUpper(token);
    if (upper == "INFO") return Severity::INFO;
    if (upper == "LOW") return Severity::LOW;
    if (upper == "MEDIUM") return Severity::MEDIUM;
    if (upper == "HIGH") return Severity::HIGH;
    if (upper == "CRITICAL") return Severity::CRITICAL;
    return std::nullopt;
}

std::optional<CheckPhase> parsePhase(const std::string& token) {
    auto upper = toUpper(token);
    if (upper == "HEADER") return CheckPhase::HEADER;
    if (upper == "TAG_TABLE") return CheckPhase::TAG_TABLE;
    if (upper == "RAW_SCAN") return CheckPhase::RAW_SCAN;
    if (upper == "LIBRARY") return CheckPhase::LIBRARY;
    if (upper == "CONFORMANCE") return CheckPhase::CONFORMANCE;
    if (upper == "IMAGE") return CheckPhase::IMAGE;
    return std::nullopt;
}

std::optional<Lane> parseLane(const std::string& token) {
    auto upper = toUpper(token);
    if (upper == "ALL") return Lane::All;
    if (upper == "HEURISTIC") return Lane::Heuristic;
    if (upper == "CONFORMANCE") return Lane::Conformance;
    if (upper == "IMAGE") return Lane::Image;
    return std::nullopt;
}

std::optional<CheckID> parseCheckId(const std::string& token) {
    auto upper = toUpper(token);
    if (upper.size() >= 2 && upper[0] == 'H') {
        char* end = nullptr;
        long number = std::strtol(upper.c_str() + 1, &end, 10);
        if (end && *end == '\0' && number > 0) {
            return CheckID{CheckID::Kind::Heuristic, static_cast<int>(number)};
        }
        return std::nullopt;
    }
    if (upper.rfind("CF-", 0) == 0) {
        char* end = nullptr;
        long number = std::strtol(upper.c_str() + 3, &end, 10);
        if (end && *end == '\0' && number > 0) {
            return CheckID{CheckID::Kind::Conformance, static_cast<int>(number)};
        }
        return std::nullopt;
    }
    return std::nullopt;
}

void appendLanePhases(Lane lane, std::vector<CheckPhase>& phases) {
    switch (lane) {
        case Lane::All:
            break;
        case Lane::Heuristic:
            phases.push_back(CheckPhase::HEADER);
            phases.push_back(CheckPhase::TAG_TABLE);
            phases.push_back(CheckPhase::RAW_SCAN);
            phases.push_back(CheckPhase::LIBRARY);
            break;
        case Lane::Conformance:
            phases.push_back(CheckPhase::CONFORMANCE);
            break;
        case Lane::Image:
            phases.push_back(CheckPhase::IMAGE);
            break;
    }
}

void dedupePhases(std::vector<CheckPhase>& phases) {
    std::sort(phases.begin(), phases.end(),
        [](CheckPhase a, CheckPhase b) {
            return static_cast<uint8_t>(a) < static_cast<uint8_t>(b);
        });
    phases.erase(std::unique(phases.begin(), phases.end()), phases.end());
}

void dedupeChecks(std::vector<CheckID>& checks) {
    std::sort(checks.begin(), checks.end());
    checks.erase(std::unique(checks.begin(), checks.end()), checks.end());
}

std::string jsonEscape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x",
                                  static_cast<unsigned char>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

const char* normalizedStatusName(CheckResult::Status status) {
    switch (status) {
        case CheckResult::Status::OK:              return "ok";
        case CheckResult::Status::SKIP:            return "skip";
        case CheckResult::Status::FINDINGS:        return "finding";
        case CheckResult::Status::NEEDS_ISOLATION: return "needs_isolation";
        case CheckResult::Status::ERROR:           return "error";
    }
    return "unknown";
}

const char* imageFormatName(ImageFormat fmt) {
    switch (fmt) {
        case ImageFormat::UNKNOWN:    return "UNKNOWN";
        case ImageFormat::ICC:        return "ICC";
        case ImageFormat::TIFF_LE:    return "TIFF_LE";
        case ImageFormat::TIFF_BE:    return "TIFF_BE";
        case ImageFormat::BIGTIFF_LE: return "BIGTIFF_LE";
        case ImageFormat::BIGTIFF_BE: return "BIGTIFF_BE";
        case ImageFormat::PNG:        return "PNG";
        case ImageFormat::JPEG:       return "JPEG";
    }
    return "UNKNOWN";
}

const char* laneName(Lane lane) {
    switch (lane) {
        case Lane::All:         return "all";
        case Lane::Heuristic:   return "heuristic";
        case Lane::Conformance: return "conformance";
        case Lane::Image:       return "image";
    }
    return "all";
}

void configureCoverageOutput(const char* prefix) {
    icctest::configureUniqueCoverageOutput(prefix);
}

std::optional<Severity> maxFindingSeverity(const CheckResult& result) {
    if (result.findings.empty()) {
        return std::nullopt;
    }
    Severity maxLevel = result.findings.front().level;
    for (const auto& f : result.findings) {
        if (f.level > maxLevel) {
            maxLevel = f.level;
        }
    }
    return maxLevel;
}

std::string base64Encode(const uint8_t* data, size_t len) {
    static constexpr char kBase64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    if (!data || len == 0) {
        return {};
    }

    std::string out;
    out.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    while (i + 3 <= len) {
        uint32_t chunk = (static_cast<uint32_t>(data[i]) << 16) |
                         (static_cast<uint32_t>(data[i + 1]) << 8) |
                         static_cast<uint32_t>(data[i + 2]);
        out.push_back(kBase64[(chunk >> 18) & 0x3F]);
        out.push_back(kBase64[(chunk >> 12) & 0x3F]);
        out.push_back(kBase64[(chunk >> 6) & 0x3F]);
        out.push_back(kBase64[chunk & 0x3F]);
        i += 3;
    }

    size_t tail = len - i;
    if (tail == 1) {
        uint32_t chunk = static_cast<uint32_t>(data[i]) << 16;
        out.push_back(kBase64[(chunk >> 18) & 0x3F]);
        out.push_back(kBase64[(chunk >> 12) & 0x3F]);
        out.push_back('=');
        out.push_back('=');
    } else if (tail == 2) {
        uint32_t chunk = (static_cast<uint32_t>(data[i]) << 16) |
                         (static_cast<uint32_t>(data[i + 1]) << 8);
        out.push_back(kBase64[(chunk >> 18) & 0x3F]);
        out.push_back(kBase64[(chunk >> 12) & 0x3F]);
        out.push_back(kBase64[(chunk >> 6) & 0x3F]);
        out.push_back('=');
    }

    return out;
}

bool isTiffFormat(ImageFormat fmt) {
    return fmt == ImageFormat::TIFF_LE || fmt == ImageFormat::TIFF_BE ||
           fmt == ImageFormat::BIGTIFF_LE || fmt == ImageFormat::BIGTIFF_BE;
}

static void tiffSilentWarning(const char*, const char*, va_list) {}
static void tiffSilentError(const char*, const char*, va_list) {}

class ScopedTiffSilence {
public:
    ScopedTiffSilence()
        : m_oldWarn(TIFFSetWarningHandler(tiffSilentWarning)),
          m_oldErr(TIFFSetErrorHandler(tiffSilentError)) {}

    ~ScopedTiffSilence() {
        TIFFSetWarningHandler(m_oldWarn);
        TIFFSetErrorHandler(m_oldErr);
    }

private:
    TIFFErrorHandler m_oldWarn;
    TIFFErrorHandler m_oldErr;
};

EmbeddedProfileInfo inspectTiffEmbeddedProfile(const std::filesystem::path& path) {
    EmbeddedProfileInfo info;
    info.imageInspected = true;

    ScopedTiffSilence silence;
    TIFF* tif = TIFFOpen(path.c_str(), "r");
    if (!tif) {
        info.containerParseError = "TIFFOpen failed";
        return info;
    }

    info.containerParseable = true;
    uint32_t iccLen = 0;
    void* iccData = nullptr;
    if (TIFFGetField(tif, TIFFTAG_ICCPROFILE, &iccLen, &iccData) &&
        iccData && iccLen > 0) {
        info.present = true;
        info.source = "TIFFTAG_ICCPROFILE";
        auto* begin = static_cast<const uint8_t*>(iccData);
        info.bytes.assign(begin, begin + iccLen);
    }

    TIFFClose(tif);
    return info;
}

EmbeddedProfileInfo inspectPngEmbeddedProfile(const std::filesystem::path& path) {
    EmbeddedProfileInfo info;
    info.imageInspected = true;

    std::FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp) {
        info.containerParseError = "Cannot open PNG file";
        return info;
    }

    uint8_t sig[8];
    if (std::fread(sig, 1, sizeof(sig), fp) != sizeof(sig) ||
        png_sig_cmp(sig, 0, sizeof(sig)) != 0) {
        std::fclose(fp);
        info.containerParseError = "Invalid PNG signature";
        return info;
    }

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (!png) {
        std::fclose(fp);
        info.containerParseError = "png_create_read_struct failed";
        return info;
    }

    png_infop meta = png_create_info_struct(png);
    if (!meta) {
        png_destroy_read_struct(&png, nullptr, nullptr);
        std::fclose(fp);
        info.containerParseError = "png_create_info_struct failed";
        return info;
    }

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_read_struct(&png, &meta, nullptr);
        std::fclose(fp);
        info.containerParseError = "libpng read error";
        info.containerParseable = false;
        return info;
    }

    png_init_io(png, fp);
    png_set_sig_bytes(png, 8);
    png_read_info(png, meta);
    info.containerParseable = true;

    png_charp profileName = nullptr;
    int compression = 0;
    png_bytep profileData = nullptr;
    png_uint_32 profileLen = 0;
    if (png_get_iCCP(png, meta, &profileName, &compression, &profileData, &profileLen) &&
        profileData && profileLen > 0) {
        info.present = true;
        info.source = "iCCP";
        info.bytes.assign(profileData, profileData + profileLen);
    }

    png_destroy_read_struct(&png, &meta, nullptr);
    std::fclose(fp);
    return info;
}

struct JpegErrorMgr {
    jpeg_error_mgr pub;
    jmp_buf setjmp_buffer;
};

static void jpegErrorExit(j_common_ptr cinfo) {
    auto* err = reinterpret_cast<JpegErrorMgr*>(cinfo->err);
    longjmp(err->setjmp_buffer, 1);
}

static void jpegEmitMessage(j_common_ptr, int) {}

EmbeddedProfileInfo inspectJpegEmbeddedProfile(const std::filesystem::path& path) {
    EmbeddedProfileInfo info;
    info.imageInspected = true;

    std::FILE* fp = std::fopen(path.c_str(), "rb");
    if (!fp) {
        info.containerParseError = "Cannot open JPEG file";
        return info;
    }

    jpeg_decompress_struct cinfo{};
    JpegErrorMgr jerr{};
    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = jpegErrorExit;
    jerr.pub.emit_message = jpegEmitMessage;

    if (setjmp(jerr.setjmp_buffer)) {
        jpeg_destroy_decompress(&cinfo);
        std::fclose(fp);
        info.containerParseError = "libjpeg read error";
        info.containerParseable = false;
        return info;
    }

    jpeg_create_decompress(&cinfo);
    jpeg_save_markers(&cinfo, JPEG_APP0 + 2, 0xFFFF);
    jpeg_stdio_src(&cinfo, fp);
    jpeg_read_header(&cinfo, TRUE);
    info.containerParseable = true;

    static const uint8_t kIccProfileTag[] = {
        'I','C','C','_','P','R','O','F','I','L','E','\0'
    };
    static constexpr size_t kIccProfileTagLen = 12;
    static constexpr size_t kIccProfileHeaderLen = 14;

    int numIccMarkers = 0;
    int expectedTotal = 0;
    size_t totalIccSize = 0;

    for (jpeg_saved_marker_ptr m = cinfo.marker_list; m; m = m->next) {
        if (m->marker != JPEG_APP0 + 2) continue;
        if (m->data_length < kIccProfileHeaderLen) continue;
        if (std::memcmp(m->data, kIccProfileTag, kIccProfileTagLen) != 0) continue;

        int total = m->data[13];
        if (expectedTotal == 0) {
            expectedTotal = total;
        }
        totalIccSize += (m->data_length - kIccProfileHeaderLen);
        ++numIccMarkers;
    }

    if (numIccMarkers > 0 && totalIccSize > 0 && numIccMarkers == expectedTotal) {
        std::vector<uint8_t> iccBuf(totalIccSize);
        size_t offset = 0;
        bool orderValid = true;

        for (int seq = 1; seq <= expectedTotal; ++seq) {
            bool found = false;
            for (jpeg_saved_marker_ptr m = cinfo.marker_list; m; m = m->next) {
                if (m->marker != JPEG_APP0 + 2) continue;
                if (m->data_length < kIccProfileHeaderLen) continue;
                if (std::memcmp(m->data, kIccProfileTag, kIccProfileTagLen) != 0) continue;
                if (m->data[12] != seq) continue;

                size_t dataLen = m->data_length - kIccProfileHeaderLen;
                if (offset + dataLen <= totalIccSize) {
                    std::memcpy(iccBuf.data() + offset, m->data + kIccProfileHeaderLen,
                                dataLen);
                    offset += dataLen;
                }
                found = true;
                break;
            }
            if (!found) {
                orderValid = false;
                break;
            }
        }

        if (orderValid && offset == totalIccSize) {
            info.present = true;
            info.source = "APP2 ICC_PROFILE";
            info.bytes = std::move(iccBuf);
        }
    }

    jpeg_destroy_decompress(&cinfo);
    std::fclose(fp);
    return info;
}

EmbeddedProfileInfo inspectEmbeddedProfile(const std::filesystem::path& path, ImageFormat fmt) {
    if (isTiffFormat(fmt)) return inspectTiffEmbeddedProfile(path);
    if (fmt == ImageFormat::PNG) return inspectPngEmbeddedProfile(path);
    if (fmt == ImageFormat::JPEG) return inspectJpegEmbeddedProfile(path);
    return {};
}

void printUsage(const char* progName) {
    std::fprintf(stderr,
        "Usage: %s [OPTIONS] <file>\n"
        "\n"
        "Parity-oriented JSON driver for libIccTest.\n"
        "\n"
        "Options:\n"
        "  --lane <heuristic|conformance|image|all>\n"
        "  --phase <PHASE[,PHASE...]>\n"
        "  --check <ID[,ID...]>\n"
        "  --min-severity <INFO|LOW|MEDIUM|HIGH|CRITICAL>\n"
        "  --max-findings <N>\n"
        "  --skip-isolation\n"
        "  --no-skip-library-on-ub\n"
        "  --emit-embedded-profile-base64\n"
        "  --pretty\n"
        "  --help\n"
        "\n"
        "Examples:\n"
        "  %s --lane conformance tests/corpus/valid_srgb.icc\n"
        "  %s --lane heuristic --check H1,H9 tests/corpus/bad_magic.icc\n",
        progName, progName, progName);
}

std::optional<ParsedArgs> parseArgs(int argc, char** argv) {
    ParsedArgs args;
    bool explicitPhases = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);

        if (arg == "--help" || arg == "-h") {
            printUsage(argv[0]);
            return std::nullopt;
        }
        if (arg == "--pretty") {
            args.pretty = true;
            continue;
        }
        if (arg == "--skip-isolation") {
            args.opts.skipIsolation = true;
            continue;
        }
        if (arg == "--no-skip-library-on-ub") {
            args.opts.skipLibraryOnUB = false;
            continue;
        }
        if (arg == "--emit-embedded-profile-base64") {
            args.emitEmbeddedProfileBase64 = true;
            continue;
        }

        auto needValue = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "Error: %s requires a value\n", name);
                return nullptr;
            }
            return argv[++i];
        };

        if (arg == "--lane") {
            const char* value = needValue("--lane");
            if (!value) return std::nullopt;
            auto parsed = parseLane(value);
            if (!parsed) {
                std::fprintf(stderr, "Error: invalid lane '%s'\n", value);
                return std::nullopt;
            }
            args.lane = *parsed;
            continue;
        }
        if (arg == "--phase") {
            const char* value = needValue("--phase");
            if (!value) return std::nullopt;
            explicitPhases = true;
            for (const auto& token : splitList(value)) {
                auto parsed = parsePhase(token);
                if (!parsed) {
                    std::fprintf(stderr, "Error: invalid phase '%s'\n", token.c_str());
                    return std::nullopt;
                }
                args.opts.phases.push_back(*parsed);
            }
            continue;
        }
        if (arg == "--check") {
            const char* value = needValue("--check");
            if (!value) return std::nullopt;
            for (const auto& token : splitList(value)) {
                auto parsed = parseCheckId(token);
                if (!parsed) {
                    std::fprintf(stderr, "Error: invalid check ID '%s'\n",
                                 token.c_str());
                    return std::nullopt;
                }
                args.opts.specificChecks.push_back(*parsed);
            }
            continue;
        }
        if (arg == "--min-severity") {
            const char* value = needValue("--min-severity");
            if (!value) return std::nullopt;
            auto parsed = parseSeverity(value);
            if (!parsed) {
                std::fprintf(stderr, "Error: invalid severity '%s'\n", value);
                return std::nullopt;
            }
            args.opts.minSeverity = *parsed;
            continue;
        }
        if (arg == "--max-findings") {
            const char* value = needValue("--max-findings");
            if (!value) return std::nullopt;
            char* end = nullptr;
            long parsed = std::strtol(value, &end, 10);
            if (!end || *end != '\0' || parsed < 0) {
                std::fprintf(stderr, "Error: invalid max findings '%s'\n", value);
                return std::nullopt;
            }
            args.opts.maxFindings = static_cast<int>(parsed);
            continue;
        }
        if (!arg.empty() && arg[0] == '-') {
            std::fprintf(stderr, "Error: unknown option '%s'\n", arg.c_str());
            return std::nullopt;
        }
        if (!args.inputPath.empty()) {
            std::fprintf(stderr, "Error: unexpected extra path '%s'\n", arg.c_str());
            return std::nullopt;
        }
        args.inputPath = arg;
    }

    if (args.inputPath.empty()) {
        printUsage(argv[0]);
        return std::nullopt;
    }

    if (!explicitPhases) {
        appendLanePhases(args.lane, args.opts.phases);
    }

    dedupePhases(args.opts.phases);
    dedupeChecks(args.opts.specificChecks);
    args.opts.ubPreScan = true;

    return args;
}

std::filesystem::path canonicalize(const std::filesystem::path& path,
                                   std::error_code& ec) {
    auto canonical = std::filesystem::canonical(path, ec);
    if (!ec) {
        return canonical;
    }
    ec.clear();
    return std::filesystem::absolute(path, ec);
}

void printFinding(std::ostream& out, const Finding& f, const RegisteredCheck* reg,
                  bool trailingComma) {
    out << "    {\n";
    out << "      \"id\": \"" << jsonEscape(f.id.str()) << "\",\n";
    out << "      \"kind\": \"" << kindName(f.id.kind) << "\",\n";
    out << "      \"severity\": \"" << severityName(f.level) << "\",\n";
    if (reg) {
        out << "      \"name\": \"" << jsonEscape(std::string(reg->meta.name)) << "\",\n";
        out << "      \"phase\": \"" << phaseName(reg->meta.phase) << "\",\n";
    } else {
        out << "      \"name\": \"\",\n";
        out << "      \"phase\": \"\",\n";
    }
    out << "      \"message\": \"" << jsonEscape(f.message) << "\",\n";
    out << "      \"detail\": \"" << jsonEscape(f.detail) << "\",\n";
    out << "      \"cwe\": \"" << jsonEscape(f.cweNote) << "\"\n";
    out << "    }" << (trailingComma ? "," : "") << "\n";
}

void printJson(std::ostream& out,
               const ParsedArgs& args,
               const std::filesystem::path& resolvedPath,
               const ProfileView& pv,
               const AnalysisResult& result,
               const EmbeddedProfileInfo& embeddedProfile) {
    out << "{\n";
    out << "  \"tool\": \"icctest-parity\",\n";
    out << "  \"version\": \"" << jsonEscape(IccTestRunner::version()) << "\",\n";
    out << "  \"inputFile\": \"" << jsonEscape(resolvedPath.string()) << "\",\n";
    out << "  \"lane\": \"" << laneName(args.lane) << "\",\n";

    out << "  \"options\": {\n";
    out << "    \"minSeverity\": \"" << severityName(args.opts.minSeverity) << "\",\n";
    out << "    \"maxFindings\": " << args.opts.maxFindings << ",\n";
    out << "    \"skipIsolation\": " << (args.opts.skipIsolation ? "true" : "false") << ",\n";
    out << "    \"skipLibraryOnUB\": " << (args.opts.skipLibraryOnUB ? "true" : "false") << ",\n";
    out << "    \"phases\": [";
    for (size_t i = 0; i < args.opts.phases.size(); ++i) {
        if (i > 0) out << ", ";
        out << "\"" << phaseName(args.opts.phases[i]) << "\"";
    }
    out << "],\n";
    out << "    \"specificChecks\": [";
    for (size_t i = 0; i < args.opts.specificChecks.size(); ++i) {
        if (i > 0) out << ", ";
        out << "\"" << args.opts.specificChecks[i].str() << "\"";
    }
    out << "]\n";
    out << "  },\n";

    out << "  \"profile\": {\n";
    out << "    \"libraryLoaded\": " << (pv.libraryLoaded() ? "true" : "false") << ",\n";
    out << "    \"isImage\": " << (pv.isImage() ? "true" : "false") << ",\n";
    out << "    \"imageFormat\": \"" << imageFormatName(pv.imageFormat()) << "\",\n";
    out << "    \"rawSize\": " << pv.rawSize() << ",\n";
    if (pv.isImage()) {
        out << "    \"imageParseable\": "
            << (embeddedProfile.containerParseable ? "true" : "false") << ",\n";
        out << "    \"imageParseError\": \""
            << jsonEscape(embeddedProfile.containerParseError) << "\",\n";
        out << "    \"embeddedProfilePresent\": "
            << (embeddedProfile.present ? "true" : "false") << ",\n";
        out << "    \"embeddedProfileSource\": \""
            << jsonEscape(embeddedProfile.source) << "\",\n";
        out << "    \"embeddedProfileSize\": "
            << embeddedProfile.bytes.size() << ",\n";
        if (args.emitEmbeddedProfileBase64 && embeddedProfile.present) {
            out << "    \"embeddedProfileBase64\": \""
                << jsonEscape(base64Encode(embeddedProfile.bytes.data(),
                                           embeddedProfile.bytes.size()))
                << "\",\n";
        }
    } else {
        out << "    \"imageParseable\": null,\n";
        out << "    \"imageParseError\": \"\",\n";
        out << "    \"embeddedProfilePresent\": false,\n";
        out << "    \"embeddedProfileSource\": \"\",\n";
        out << "    \"embeddedProfileSize\": 0,\n";
    }
    out << "    \"ubPatternsDetected\": "
        << (pv.hasKnownUBPatterns() ? "true" : "false") << ",\n";
    out << "    \"ubPatternDescriptions\": [";
    for (size_t i = 0; i < pv.ubPatternDescriptions().size(); ++i) {
        if (i > 0) out << ", ";
        out << "\"" << jsonEscape(pv.ubPatternDescriptions()[i]) << "\"";
    }
    out << "]\n";
    out << "  },\n";

    out << "  \"metadata\": {\n";
    out << "    \"version\": \"" << ((result.metadata.version >> 24) & 0xFF) << "."
        << ((result.metadata.version >> 20) & 0xF) << "."
        << ((result.metadata.version >> 16) & 0xF) << "\",\n";

    auto sigStr = [](uint32_t sig) -> std::string {
        char buf[5];
        buf[0] = static_cast<char>((sig >> 24) & 0xFF);
        buf[1] = static_cast<char>((sig >> 16) & 0xFF);
        buf[2] = static_cast<char>((sig >> 8) & 0xFF);
        buf[3] = static_cast<char>(sig & 0xFF);
        buf[4] = '\0';
        bool printable = true;
        for (int i = 0; i < 4; ++i) {
            unsigned char c = static_cast<unsigned char>(buf[i]);
            if (c < 0x20 || c > 0x7E) {
                printable = false;
                break;
            }
        }
        if (printable) {
            return buf;
        }
        char hexBuf[11];
        std::snprintf(hexBuf, sizeof(hexBuf), "0x%08X", sig);
        return hexBuf;
    };

    out << "    \"profileClass\": \"" << jsonEscape(sigStr(result.metadata.profileClass)) << "\",\n";
    out << "    \"colorSpace\": \"" << jsonEscape(sigStr(result.metadata.colorSpace)) << "\",\n";
    out << "    \"pcs\": \"" << jsonEscape(sigStr(result.metadata.pcs)) << "\",\n";
    out << "    \"flags\": " << result.metadata.flags << ",\n";
    out << "    \"fileSize\": " << result.metadata.fileSize << "\n";
    out << "  },\n";

    out << "  \"stats\": {\n";
    out << "    \"checksRun\": " << result.stats.checksRun << ",\n";
    out << "    \"checksSkipped\": " << result.stats.checksSkipped << ",\n";
    out << "    \"checksRecorded\": " << result.perCheck.size() << ",\n";
    out << "    \"findingsTotal\": " << result.stats.findingsTotal << ",\n";
    out << "    \"totalTimeUs\": " << result.stats.totalTime.count() << ",\n";
    out << "    \"severity\": {\n";
    out << "      \"CRITICAL\": " << result.stats.findingsBySeverity[4] << ",\n";
    out << "      \"HIGH\": " << result.stats.findingsBySeverity[3] << ",\n";
    out << "      \"MEDIUM\": " << result.stats.findingsBySeverity[2] << ",\n";
    out << "      \"LOW\": " << result.stats.findingsBySeverity[1] << ",\n";
    out << "      \"INFO\": " << result.stats.findingsBySeverity[0] << "\n";
    out << "    }\n";
    out << "  },\n";

    out << "  \"findings\": [\n";
    auto& registry = CheckRegistry::instance();
    for (size_t i = 0; i < result.findings.size(); ++i) {
        const auto* reg = registry.find(result.findings[i].id);
        printFinding(out, result.findings[i], reg, i + 1 < result.findings.size());
    }
    out << "  ],\n";

    out << "  \"perCheck\": [\n";
    for (size_t i = 0; i < result.perCheck.size(); ++i) {
        const auto& entry = result.perCheck[i];
        out << "    {\n";
        out << "      \"id\": \"" << entry.id.str() << "\",\n";
        out << "      \"kind\": \"" << kindName(entry.id.kind) << "\",\n";
        out << "      \"number\": " << entry.id.number << ",\n";
        out << "      \"name\": \"" << jsonEscape(std::string(entry.meta.name)) << "\",\n";
        out << "      \"phase\": \"" << phaseName(entry.meta.phase) << "\",\n";
        out << "      \"severity\": \"" << severityName(entry.meta.severity) << "\",\n";
        out << "      \"specRef\": \"" << jsonEscape(std::string(entry.meta.specRef)) << "\",\n";
        out << "      \"specDoc\": \"" << jsonEscape(std::string(entry.meta.specDoc)) << "\",\n";
        out << "      \"cwe\": \"" << jsonEscape(std::string(entry.meta.primaryCWE)) << "\",\n";
        out << "      \"cveRefs\": \"" << jsonEscape(std::string(entry.meta.cveRefs)) << "\",\n";
        out << "      \"status\": \"" << checkStatusName(entry.result.status) << "\",\n";
        out << "      \"normalizedStatus\": \"" << normalizedStatusName(entry.result.status) << "\",\n";
        out << "      \"summary\": \"" << jsonEscape(entry.result.summary) << "\",\n";
        out << "      \"findingCount\": " << entry.result.findings.size() << ",\n";
        auto maxSeverity = maxFindingSeverity(entry.result);
        if (maxSeverity) {
            out << "      \"maxFindingSeverity\": \"" << severityName(*maxSeverity) << "\",\n";
        } else {
            out << "      \"maxFindingSeverity\": null,\n";
        }
        out << "      \"findings\": [\n";
        for (size_t j = 0; j < entry.result.findings.size(); ++j) {
            const auto& f = entry.result.findings[j];
            out << "        {\n";
            out << "          \"id\": \"" << f.id.str() << "\",\n";
            out << "          \"severity\": \"" << severityName(f.level) << "\",\n";
            out << "          \"message\": \"" << jsonEscape(f.message) << "\",\n";
            out << "          \"detail\": \"" << jsonEscape(f.detail) << "\",\n";
            out << "          \"cwe\": \"" << jsonEscape(f.cweNote) << "\"\n";
            out << "        }" << (j + 1 < entry.result.findings.size() ? "," : "") << "\n";
        }
        out << "      ]\n";
        out << "    }" << (i + 1 < result.perCheck.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

void printOpenError(std::ostream& out,
                    const std::filesystem::path& inputPath,
                    std::string_view message) {
    out << "{\n";
    out << "  \"tool\": \"icctest-parity\",\n";
    out << "  \"version\": \"" << jsonEscape(IccTestRunner::version()) << "\",\n";
    out << "  \"inputFile\": \"" << jsonEscape(inputPath.string()) << "\",\n";
    out << "  \"error\": \"" << jsonEscape(message) << "\"\n";
    out << "}\n";
}

} // namespace

} // namespace icctest

int main(int argc, char** argv) {
    using namespace icctest;

    configureCoverageOutput("icctest-gcov-parity");

    auto parsed = parseArgs(argc, argv);
    if (!parsed) {
        return 3;
    }

    std::error_code ec;
    auto resolved = canonicalize(parsed->inputPath, ec);
    if (ec) {
        printOpenError(std::cout, parsed->inputPath,
                       std::string("Failed to resolve path: ") + ec.message());
        return 2;
    }

    auto pv = ProfileView::open(resolved);
    if (!pv) {
        printOpenError(std::cout, resolved, "Failed to open profile");
        return 2;
    }

    EmbeddedProfileInfo embeddedProfile;
    if (pv->isImage()) {
        embeddedProfile = inspectEmbeddedProfile(resolved, pv->imageFormat());
    }

    IccTestRunner runner;
    auto result = runner.analyze(*pv, parsed->opts);
    printJson(std::cout, *parsed, resolved, *pv, result, embeddedProfile);

    return result.hasCritical() ? 1 :
           (result.stats.findingsTotal > 0 ? 1 : 0);
}
