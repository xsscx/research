/*!
 *  @file IccTiffDump_unsafe.cpp
 *  @brief Sandboxed unsafe TIFF reader and embedded ICC profile extractor
 *
 *  Dumps TIFF directories, copies the first embedded ICC profile byte-for-byte,
 *  and then exercises the vanilla iccDEV parser for diagnostic output.
 */

#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include <openssl/sha.h>
#include <tiffio.h>

#include "IccFileUtil.h"
#include "IccProfile.h"
#include "IccProfLibVer.h"
#include "IccUtil.h"
#include "ColorBleedSandbox.h"

static constexpr int kExitUsage = 64;
static constexpr int kExitNoInput = 66;
static constexpr unsigned int kMaxDirectories = 256;
static constexpr uint32_t kMaxEmbeddedProfileBytes = 512U * 1024U * 1024U;
static constexpr unsigned int kMaxLibTiffMessages = 20;

enum class OutputMode {
    Verbose,
    Summary,
    EvidenceJson,
};

struct TiffEvidence {
    unsigned int directories_read;
    unsigned int profile_directories;
    unsigned int selected_directory;
    unsigned int libtiff_warnings;
    unsigned int libtiff_errors;
    uint32_t embedded_bytes;
    int validation_status;
    bool extraction_complete;
    bool icc_opened;
    bool tags_loaded;
    bool profile_too_large;
    uint64_t temporary_device;
    uint64_t temporary_inode;
    char sha256[SHA256_DIGEST_LENGTH * 2 + 1];
    char temporary_path[PATH_MAX];
};

static TiffEvidence *g_tiff_evidence = nullptr;

static uint32_t EmbeddedProfileLimit()
{
    const char *value = getenv("COLORBLEED_MAX_ICC_BYTES");
    if (!value || !value[0]) {
        return kMaxEmbeddedProfileBytes;
    }

    char *end = nullptr;
    errno = 0;
    unsigned long parsed = strtoul(value, &end, 10);
    if (errno || !end || *end || parsed == 0 || parsed > kMaxEmbeddedProfileBytes) {
        fprintf(stderr,
                "[ColorBleed] WARNING: ignoring invalid COLORBLEED_MAX_ICC_BYTES='%s'\n",
                icSanitizeConsoleText(value).c_str());
        return kMaxEmbeddedProfileBytes;
    }
    return static_cast<uint32_t>(parsed);
}

static bool IsHelpFlag(const char *arg)
{
    return arg && (!strcmp(arg, "-h") || !strcmp(arg, "--help"));
}

static const char *ModeName(OutputMode mode)
{
    switch (mode) {
        case OutputMode::Verbose: return "verbose";
        case OutputMode::Summary: return "summary";
        case OutputMode::EvidenceJson: return "evidence-json";
    }
    return "unknown";
}

static void PrintUsage()
{
    printf("iccTiffDump_unsafe built with IccProfLib Version " ICCPROFLIBVER
           " and %s\n", TIFFGetVersion());
    printf("Usage: iccTiffDump_unsafe [--verbose|--summary|--evidence-json] "
           "input.tif [embedded.icc]\n");
    printf("  --verbose       Full escaped TIFF directory and ICC tag dump (default).\n");
    printf("  --summary       Compact human-readable phase and result output.\n");
    printf("  --evidence-json Emit one JSON evidence object on stdout.\n");
    printf("  Optional extraction atomically preserves the original embedded ICC bytes.\n");
}

static std::string JsonEscape(const char *text)
{
    static const char hex[] = "0123456789ABCDEF";
    std::string result;

    if (!text) {
        return result;
    }

    const unsigned char *p = reinterpret_cast<const unsigned char *>(text);
    for (; *p; p++) {
        unsigned char ch = *p;
        switch (ch) {
            case '"': result += "\\\""; break;
            case '\\': result += "\\\\"; break;
            case '\b': result += "\\b"; break;
            case '\f': result += "\\f"; break;
            case '\n': result += "\\n"; break;
            case '\r': result += "\\r"; break;
            case '\t': result += "\\t"; break;
            default:
                if (ch >= 0x20 && ch < 0x7f) {
                    result += static_cast<char>(ch);
                } else {
                    result += "\\u00";
                    result += hex[(ch >> 4) & 0xf];
                    result += hex[ch & 0xf];
                }
        }
    }
    return result;
}

static std::string Sha256Hex(const icUInt8Number *data, size_t size)
{
    static const char hex[] = "0123456789abcdef";
    unsigned char digest[SHA256_DIGEST_LENGTH];
    std::string result;

    if (!data || !SHA256(data, size, digest)) {
        return result;
    }

    result.reserve(SHA256_DIGEST_LENGTH * 2);
    for (unsigned char byte : digest) {
        result += hex[(byte >> 4) & 0xf];
        result += hex[byte & 0xf];
    }
    return result;
}

static void TiffMessage(bool error, const char *module, const char *format, va_list args)
    __attribute__((format(printf, 3, 0)));

static void TiffMessage(bool error, const char *module, const char *format, va_list args)
{
    char message[2048];
    if (format) {
        vsnprintf(message, sizeof(message), format, args);
    } else {
        message[0] = '\0';
    }

    unsigned int count = 0;
    if (g_tiff_evidence) {
        unsigned int *counter = error ? &g_tiff_evidence->libtiff_errors
                                      : &g_tiff_evidence->libtiff_warnings;
        (*counter)++;
        count = *counter;
    }

    if (!g_tiff_evidence || count <= kMaxLibTiffMessages) {
        std::string safe_module = icSanitizeConsoleText(module ? module : "libtiff");
        std::string safe_message = icSanitizeConsoleText(message);
        fprintf(stderr, "[ColorBleed] LIBTIFF_%s: %s: %s\n",
                error ? "ERROR" : "WARNING", safe_module.c_str(), safe_message.c_str());
    } else if (count == kMaxLibTiffMessages + 1) {
        fprintf(stderr, "[ColorBleed] LIBTIFF_%s: further messages suppressed\n",
                error ? "ERROR" : "WARNING");
    }
}

static void TiffErrorHandler(const char *module, const char *format, va_list args)
    __attribute__((format(printf, 2, 0)));

static void TiffErrorHandler(const char *module, const char *format, va_list args)
{
    TiffMessage(true, module, format, args);
}

static void TiffWarningHandler(const char *module, const char *format, va_list args)
    __attribute__((format(printf, 2, 0)));

static void TiffWarningHandler(const char *module, const char *format, va_list args)
{
    TiffMessage(false, module, format, args);
}

static void PrintEscapedTiffDirectory(TIFF *tiff)
{
    uint32_t width = 0;
    uint32_t height = 0;
    uint32_t rows_per_strip = 0;
    uint16_t bits_per_sample = 0;
    uint16_t compression = 0;
    uint16_t photometric = 0;
    uint16_t samples_per_pixel = 0;
    uint16_t planar = 0;
    char *description = nullptr;

    TIFFGetField(tiff, TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tiff, TIFFTAG_IMAGELENGTH, &height);
    TIFFGetFieldDefaulted(tiff, TIFFTAG_BITSPERSAMPLE, &bits_per_sample);
    TIFFGetFieldDefaulted(tiff, TIFFTAG_COMPRESSION, &compression);
    TIFFGetFieldDefaulted(tiff, TIFFTAG_PHOTOMETRIC, &photometric);
    TIFFGetFieldDefaulted(tiff, TIFFTAG_SAMPLESPERPIXEL, &samples_per_pixel);
    TIFFGetFieldDefaulted(tiff, TIFFTAG_ROWSPERSTRIP, &rows_per_strip);
    TIFFGetFieldDefaulted(tiff, TIFFTAG_PLANARCONFIG, &planar);

    printf("TIFF Directory at offset 0x%llx\n",
           static_cast<unsigned long long>(TIFFCurrentDirOffset(tiff)));
    printf("  Image Width: %u Image Length: %u\n", width, height);
    printf("  Bits/Sample: %u\n", bits_per_sample);
    printf("  Compression: %u\n", compression);
    printf("  Photometric: %u\n", photometric);
    printf("  Samples/Pixel: %u\n", samples_per_pixel);
    printf("  Rows/Strip: %u\n", rows_per_strip);
    printf("  Planar Configuration: %u\n", planar);
    if (TIFFGetField(tiff, TIFFTAG_IMAGEDESCRIPTION, &description) == 1 && description) {
        printf("  ImageDescription: %s\n", icSanitizeConsoleText(description).c_str());
    }
}

static bool WriteAtomicNewFile(const char *path,
                               const std::vector<icUInt8Number>& data,
                               TiffEvidence *evidence)
{
    std::string pattern = std::string(path) + ".tmp-XXXXXX";
    if (pattern.size() >= PATH_MAX) {
        fprintf(stderr, "[ColorBleed] ERROR: output path is too long\n");
        return false;
    }

    std::vector<char> temporary(pattern.begin(), pattern.end());
    temporary.push_back('\0');
    int fd = mkstemp(temporary.data());
    if (fd < 0) {
        fprintf(stderr, "[ColorBleed] ERROR: cannot create extraction temporary: %s\n",
                strerror(errno));
        return false;
    }

    if (evidence) {
        snprintf(evidence->temporary_path, sizeof(evidence->temporary_path), "%s",
                 temporary.data());
        struct stat temporary_stat;
        if (fstat(fd, &temporary_stat) == 0) {
            evidence->temporary_device = static_cast<uint64_t>(temporary_stat.st_dev);
            evidence->temporary_inode = static_cast<uint64_t>(temporary_stat.st_ino);
        }
    }

    bool failed = false;
    int failure_errno = 0;
    size_t offset = 0;
    while (offset < data.size()) {
        ssize_t count = write(fd, data.data() + offset, data.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            failed = true;
            failure_errno = count < 0 ? errno : EIO;
            break;
        }
        offset += static_cast<size_t>(count);
    }

    if (!failed && fsync(fd) != 0) {
        failed = true;
        failure_errno = errno;
    }
    if (close(fd) != 0 && !failed) {
        failed = true;
        failure_errno = errno;
    }

    if (failed) {
        fprintf(stderr, "[ColorBleed] ERROR: extraction write failed: %s\n",
                strerror(failure_errno));
        unlink(temporary.data());
        if (evidence) {
            evidence->temporary_path[0] = '\0';
            evidence->temporary_device = 0;
            evidence->temporary_inode = 0;
        }
        return false;
    }

    if (link(temporary.data(), path) != 0) {
        int link_errno = errno;
        fprintf(stderr, "[ColorBleed] ERROR: cannot publish '%s': %s\n",
                icSanitizeConsoleText(path).c_str(), strerror(link_errno));
        unlink(temporary.data());
        if (evidence) {
            evidence->temporary_path[0] = '\0';
            evidence->temporary_device = 0;
            evidence->temporary_inode = 0;
        }
        return false;
    }

    if (unlink(temporary.data()) != 0) {
        fprintf(stderr, "[ColorBleed] WARNING: cannot remove extraction temporary '%s': %s\n",
                icSanitizeConsoleText(temporary.data()).c_str(), strerror(errno));
    } else if (evidence) {
        evidence->temporary_path[0] = '\0';
        evidence->temporary_device = 0;
        evidence->temporary_inode = 0;
    }
    if (evidence) {
        evidence->extraction_complete = true;
    }
    return true;
}

static const char *ValidationName(icValidateStatus status)
{
    switch (status) {
        case icValidateOK: return "valid";
        case icValidateWarning: return "warning";
        case icValidateNonCompliant: return "non-compliant";
        case icValidateCriticalError: return "critical-error";
        default: return "unknown";
    }
}

static void PrintSanitizedReport(const std::string& report)
{
    size_t start = 0;
    while (start < report.size()) {
        size_t end = report.find('\n', start);
        std::string line = report.substr(start, end == std::string::npos
                                                ? std::string::npos : end - start);
        printf("%s\n", icSanitizeConsoleText(line).c_str());
        if (end == std::string::npos) {
            break;
        }
        start = end + 1;
    }
}

static int DumpIccProfile(const std::vector<icUInt8Number>& profile_data,
                          OutputMode mode, TiffEvidence *evidence)
{
    if (mode == OutputMode::Verbose) {
        printf("\n[ICC] Embedded profile: %zu bytes\n", profile_data.size());
        if (profile_data.size() >= 40) {
            std::string magic(reinterpret_cast<const char *>(&profile_data[36]), 4);
            printf("[ICC] Header magic: %02x%02x%02x%02x ('%s')\n",
                   profile_data[36], profile_data[37], profile_data[38], profile_data[39],
                   icSanitizeConsoleText(magic).c_str());
        }
    }

    CIccProfile *profile = OpenIccProfile(profile_data.data(),
                                          static_cast<icUInt32Number>(profile_data.size()));
    if (!profile) {
        fprintf(stderr, "[ColorBleed] ERROR: iccDEV rejected the embedded profile header\n");
        return 4;
    }
    evidence->icc_opened = true;

    if (mode == OutputMode::Verbose) {
        CIccInfo info;
        printf("[ICC] Version: %s\n", info.GetVersionName(profile->m_Header.version));
        printf("[ICC] Class: %s\n", info.GetProfileClassSigName(profile->m_Header.deviceClass));
        printf("[ICC] Color space: %s\n", info.GetColorSpaceSigName(profile->m_Header.colorSpace));
        printf("[ICC] PCS: %s\n", info.GetColorSpaceSigName(profile->m_Header.pcs));
        printf("[ICC] Tag directory entries: %zu\n", profile->m_Tags.size());

        for (const auto& entry : profile->m_Tags) {
            char sig[16];
            printf("[ICC] Tag %s offset=%u size=%u loaded=%s\n",
                   icGetSig(sig, sizeof(sig), entry.TagInfo.sig, false),
                   entry.TagInfo.offset, entry.TagInfo.size,
                   entry.pTag ? "yes" : "no");
        }
    }

    if (mode != OutputMode::EvidenceJson) {
        fprintf(stderr, "[ColorBleed] ICC phase: recursively loading all tags\n");
    }
    if (!profile->ReadTags(profile)) {
        fprintf(stderr, "[ColorBleed] ERROR: iccDEV failed while loading ICC tags\n");
        delete profile;
        return 5;
    }
    evidence->tags_loaded = true;

    std::string report;
    icValidateStatus status = profile->Validate(report);
    evidence->validation_status = static_cast<int>(status);
    if (mode == OutputMode::Verbose) {
        printf("[ICC] Validation: %s (%d)\n", ValidationName(status), status);
        if (!report.empty()) {
            printf("[ICC] Validation report follows:\n");
            PrintSanitizedReport(report);
        }
    }

    delete profile;
    return status > icValidateWarning ? 6 : 0;
}

static int DumpTiff(const char *src_path, const char *dst_path,
                    OutputMode mode, TiffEvidence *evidence)
{
    g_tiff_evidence = evidence;
    TIFFSetErrorHandler(TiffErrorHandler);
    TIFFSetWarningHandler(TiffWarningHandler);

    TIFF *tiff = TIFFOpen(src_path, "r");
    if (!tiff) {
        fprintf(stderr, "[ColorBleed] ERROR: libtiff could not open '%s'\n",
                icSanitizeConsoleText(src_path).c_str());
        return 2;
    }

    std::vector<icUInt8Number> first_profile;
    unsigned int directory = 0;

    for (;;) {
        if (mode == OutputMode::Verbose) {
            printf("\n[TIFF] Directory %u\n", directory);
            PrintEscapedTiffDirectory(tiff);
        }

        uint32_t profile_size = 0;
        void *profile_bytes = nullptr;
        if (TIFFGetField(tiff, TIFFTAG_ICCPROFILE, &profile_size, &profile_bytes) == 1 &&
            profile_bytes && profile_size > 0) {
            evidence->profile_directories++;
            const icUInt8Number *begin = static_cast<const icUInt8Number *>(profile_bytes);
            std::string digest = Sha256Hex(begin, profile_size);
            if (mode == OutputMode::Verbose) {
                printf("[TIFF] Directory %u ICC profile: %u bytes sha256=%s\n",
                       directory, profile_size, digest.c_str());
            }
            if (first_profile.empty()) {
                evidence->selected_directory = directory;
                evidence->embedded_bytes = profile_size;
                snprintf(evidence->sha256, sizeof(evidence->sha256), "%s", digest.c_str());
                uint32_t profile_limit = EmbeddedProfileLimit();
                if (profile_size > profile_limit) {
                    evidence->profile_too_large = true;
                    TIFFClose(tiff);
                    fprintf(stderr,
                            "[ColorBleed] ERROR: embedded ICC profile exceeds %u-byte limit\n",
                            profile_limit);
                    return 9;
                }
                first_profile.assign(begin, begin + profile_size);
            }
        } else if (mode == OutputMode::Verbose) {
            printf("[TIFF] Directory %u ICC profile: none\n", directory);
        }

        directory++;
        evidence->directories_read = directory;
        if (directory == kMaxDirectories) {
            if (!TIFFLastDirectory(tiff)) {
                fprintf(stderr, "[ColorBleed] WARNING: TIFF directory cap reached (%u)\n",
                        kMaxDirectories);
            }
            break;
        }
        if (TIFFLastDirectory(tiff)) {
            break;
        }

        unsigned int errors_before = evidence->libtiff_errors;
        if (TIFFReadDirectory(tiff) != 1) {
            TIFFClose(tiff);
            fprintf(stderr, "[ColorBleed] ERROR: failed to read TIFF directory %u%s\n",
                    directory, evidence->libtiff_errors > errors_before
                                   ? " after a libtiff error" : "");
            return 8;
        }
    }

    TIFFClose(tiff);
    if (mode == OutputMode::Verbose) {
        printf("\n[TIFF] Directories read: %u; directories with ICC: %u\n",
               evidence->directories_read, evidence->profile_directories);
    }

    if (first_profile.empty()) {
        if (dst_path) {
            fprintf(stderr, "[ColorBleed] ERROR: no embedded ICC profile to extract\n");
            return 3;
        }
        return 0;
    }

    if (evidence->profile_directories > 1) {
        fprintf(stderr,
                "[ColorBleed] WARNING: multiple TIFF directories contain ICC profiles; "
                "diagnostics and extraction use directory %u\n",
                evidence->selected_directory);
    }

    if (dst_path) {
        if (!WriteAtomicNewFile(dst_path, first_profile, evidence)) {
            return 7;
        }
        if (mode == OutputMode::Verbose) {
            printf("[ColorBleed] Extracted %zu original ICC bytes to %s sha256=%s\n",
                   first_profile.size(), icSanitizeConsoleText(dst_path).c_str(),
                   evidence->sha256);
        }
    }

    return DumpIccProfile(first_profile, mode, evidence);
}

static const char *OutcomeName(const SandboxResult& result)
{
    if (result.SanitizerFinding()) return "sanitizer-finding";
    if (result.crashed) return result.timed_out ? "timeout" : "crash";
    if (result.exit_code == 0) return "clean";
    return "soft-failure";
}

static void PrintSummary(const SandboxResult& result, const TiffEvidence& evidence)
{
    const char *validation = evidence.validation_status >= 0
        ? ValidationName(static_cast<icValidateStatus>(evidence.validation_status)) : "not-run";
    std::string selected = evidence.selected_directory == UINT_MAX
        ? "none" : std::to_string(evidence.selected_directory);
    printf("[ColorBleed] RESULT outcome=%s exit=%d directories=%u icc_directories=%u "
           "selected=%s bytes=%u sha256=%s extracted=%s opened=%s tags_loaded=%s "
           "validation=%s libtiff_warnings=%u libtiff_errors=%u\n",
           OutcomeName(result), result.exit_code, evidence.directories_read,
           evidence.profile_directories, selected.c_str(), evidence.embedded_bytes,
           evidence.sha256[0] ? evidence.sha256 : "none",
           evidence.extraction_complete ? "yes" : "no",
           evidence.icc_opened ? "yes" : "no", evidence.tags_loaded ? "yes" : "no",
           validation, evidence.libtiff_warnings, evidence.libtiff_errors);
}

static void PrintEvidenceJson(const char *src_path, const char *dst_path,
                              const SandboxResult& result, const TiffEvidence& evidence)
{
    printf("{");
    printf("\"schema\":\"colorbleed-tiff-evidence/v1\",");
    printf("\"tool\":\"iccTiffDump_unsafe\",");
    printf("\"input\":\"%s\",", JsonEscape(src_path).c_str());
    if (dst_path) {
        printf("\"output\":\"%s\",", JsonEscape(dst_path).c_str());
    } else {
        printf("\"output\":null,");
    }
    printf("\"mode\":\"%s\",", ModeName(OutputMode::EvidenceJson));
    printf("\"outcome\":\"%s\",", OutcomeName(result));
    printf("\"tiff\":{");
    printf("\"directoriesRead\":%u,\"iccDirectories\":%u,",
           evidence.directories_read, evidence.profile_directories);
    if (evidence.selected_directory == UINT_MAX) {
        printf("\"selectedDirectory\":null,");
    } else {
        printf("\"selectedDirectory\":%u,", evidence.selected_directory);
    }
    printf("\"warnings\":%u,\"errors\":%u},",
           evidence.libtiff_warnings, evidence.libtiff_errors);
    printf("\"icc\":{");
    printf("\"bytes\":%u,", evidence.embedded_bytes);
    if (evidence.sha256[0]) {
        printf("\"sha256\":\"%s\",", evidence.sha256);
    } else {
        printf("\"sha256\":null,");
    }
    printf("\"extracted\":%s,\"opened\":%s,\"tagsLoaded\":%s,",
           evidence.extraction_complete ? "true" : "false",
           evidence.icc_opened ? "true" : "false",
           evidence.tags_loaded ? "true" : "false");
    if (evidence.validation_status >= 0) {
        printf("\"validation\":\"%s\",",
               ValidationName(static_cast<icValidateStatus>(evidence.validation_status)));
    } else {
        printf("\"validation\":null,");
    }
    printf("\"tooLarge\":%s},", evidence.profile_too_large ? "true" : "false");
    printf("\"sandbox\":{");
    printf("\"exitCode\":%d,\"signal\":%d,\"timedOut\":%s,",
           result.exit_code, result.signal_num, result.timed_out ? "true" : "false");
    printf("\"sanitizerFinding\":%s,\"crashed\":%s}",
           result.SanitizerFinding() ? "true" : "false",
           result.crashed ? "true" : "false");
    printf("}\n");
}

static void PrintPreflightEvidenceJson(const char *src_path, const char *dst_path,
                                       int exit_code)
{
    TiffEvidence evidence = {};
    evidence.selected_directory = UINT_MAX;
    evidence.validation_status = -1;
    SandboxResult result = {};
    result.exit_code = exit_code;
    PrintEvidenceJson(src_path ? src_path : "", dst_path, result, evidence);
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    OutputMode mode = OutputMode::Verbose;
    int arg_index = 1;
    if (argc > 1 && !strcmp(argv[1], "--verbose")) {
        mode = OutputMode::Verbose;
        arg_index++;
    } else if (argc > 1 && !strcmp(argv[1], "--summary")) {
        mode = OutputMode::Summary;
        arg_index++;
    } else if (argc > 1 && !strcmp(argv[1], "--evidence-json")) {
        mode = OutputMode::EvidenceJson;
        arg_index++;
    }

    if (argc == 2 && IsHelpFlag(argv[1])) {
        PrintUsage();
        return 0;
    }
    int remaining = argc - arg_index;
    if (remaining < 1 || remaining > 2 || IsHelpFlag(argv[arg_index])) {
        PrintUsage();
        return remaining == 1 && IsHelpFlag(argv[arg_index]) ? 0 : kExitUsage;
    }

    char resolved_src[PATH_MAX];
    if (!realpath(argv[arg_index], resolved_src)) {
        fprintf(stderr, "[ColorBleed] ERROR: cannot resolve input '%s': %s\n",
                icSanitizeConsoleText(argv[arg_index]).c_str(), strerror(errno));
        if (mode == OutputMode::EvidenceJson) {
            PrintPreflightEvidenceJson(argv[arg_index],
                                       remaining == 2 ? argv[arg_index + 1] : nullptr,
                                       kExitNoInput);
        }
        return kExitNoInput;
    }

    std::string safe_dst;
    if (remaining == 2) {
        safe_dst = ValidateOutputPath(argv[arg_index + 1]);
        if (safe_dst.empty()) {
            if (mode == OutputMode::EvidenceJson) {
                PrintPreflightEvidenceJson(resolved_src, argv[arg_index + 1], kExitUsage);
            }
            return kExitUsage;
        }
    }

    TiffEvidence *evidence = static_cast<TiffEvidence *>(
        mmap(nullptr, sizeof(TiffEvidence), PROT_READ | PROT_WRITE,
             MAP_SHARED | MAP_ANONYMOUS, -1, 0));
    if (evidence == MAP_FAILED) {
        fprintf(stderr, "[ColorBleed] ERROR: cannot allocate shared evidence: %s\n",
                strerror(errno));
        if (mode == OutputMode::EvidenceJson) {
            PrintPreflightEvidenceJson(resolved_src,
                                       safe_dst.empty() ? nullptr : safe_dst.c_str(), 70);
        }
        return 70;
    }
    memset(evidence, 0, sizeof(*evidence));
    evidence->selected_directory = UINT_MAX;
    evidence->validation_status = -1;

    if (mode == OutputMode::Verbose) {
        printf("[ColorBleed] Sandboxed TIFF and embedded ICC dump\n");
        printf("[ColorBleed] Input: %s\n", icSanitizeConsoleText(resolved_src).c_str());
        if (!safe_dst.empty()) {
            printf("[ColorBleed] ICC output: %s (atomic new file, exact embedded bytes)\n",
                   icSanitizeConsoleText(safe_dst).c_str());
        }
    }
    if (mode != OutputMode::EvidenceJson) {
        fprintf(stderr, "[ColorBleed] TIFF phase: opening input with libtiff\n");
    }

    SandboxLimits limits;
    limits.max_mem_mb = 4096;
    limits.max_cpu_sec = 60;
    limits.max_fsize_mb = 512;
    limits.max_wall_sec = 30;

    const char *dst_path = safe_dst.empty() ? nullptr : safe_dst.c_str();
    SandboxResult result = RunSandboxed([&]() -> int {
        return DumpTiff(resolved_src, dst_path, mode, evidence);
    }, limits);

    if (evidence->temporary_path[0]) {
        struct stat temporary_stat;
        bool exact_temporary = evidence->temporary_device && evidence->temporary_inode &&
            lstat(evidence->temporary_path, &temporary_stat) == 0 &&
            static_cast<uint64_t>(temporary_stat.st_dev) == evidence->temporary_device &&
            static_cast<uint64_t>(temporary_stat.st_ino) == evidence->temporary_inode;
        if (exact_temporary) {
            if (unlink(evidence->temporary_path) != 0 && errno != ENOENT) {
                fprintf(stderr,
                        "[ColorBleed] WARNING: cannot clean extraction temporary '%s': %s\n",
                        icSanitizeConsoleText(evidence->temporary_path).c_str(), strerror(errno));
            }
        } else {
            fprintf(stderr,
                    "[ColorBleed] WARNING: extraction temporary identity was not verified; "
                    "cleanup skipped\n");
        }
        evidence->temporary_path[0] = '\0';
    }

    if (mode == OutputMode::Verbose) {
        result.Report("TIFF + embedded ICC dump", resolved_src);
    } else if (mode == OutputMode::Summary) {
        PrintSummary(result, *evidence);
    } else {
        PrintEvidenceJson(resolved_src, dst_path, result, *evidence);
    }

    if (result.SanitizerFinding()) {
        fprintf(stderr, "[ColorBleed] FINDING: TIFF/ICC processing triggered a sanitizer report\n");
    } else if (result.crashed) {
        fprintf(stderr, "[ColorBleed] FINDING: TIFF/ICC processing crashed: %s\n",
                result.SignalName());
    }

    int exit_code = result.exit_code;
    munmap(evidence, sizeof(*evidence));
    return exit_code;
}
