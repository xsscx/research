/*!
 *  @file IccTiffDump_unsafe.cpp
 *  @brief Sandboxed unsafe TIFF reader and embedded ICC profile extractor
 *
 *  Dumps TIFF directories, copies the first embedded ICC profile byte-for-byte,
 *  and then exercises the vanilla iccDEV parser for diagnostic output.
 */

#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

#include <tiffio.h>

#include "IccProfile.h"
#include "IccProfLibVer.h"
#include "IccUtil.h"
#include "ColorBleedSandbox.h"

static constexpr int kExitUsage = 64;
static constexpr int kExitNoInput = 66;
static constexpr unsigned int kMaxDirectories = 256;

static bool IsHelpFlag(const char *arg)
{
    return arg && (!strcmp(arg, "-h") || !strcmp(arg, "--help"));
}

static void PrintUsage()
{
    printf("iccTiffDump_unsafe built with IccProfLib Version " ICCPROFLIBVER
           " and %s\n", TIFFGetVersion());
    printf("Usage: iccTiffDump_unsafe input.tif [embedded.icc]\n");
    printf("  Dumps TIFF directories and ICC diagnostics in a sandbox.\n");
    printf("  Optional extraction preserves the original embedded ICC bytes.\n");
}

static bool WriteNewFile(const char *path, const std::vector<icUInt8Number>& data)
{
    int flags = O_WRONLY | O_CREAT | O_EXCL;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif

    int fd = open(path, flags, 0600);
    if (fd < 0) {
        fprintf(stderr, "[ColorBleed] ERROR: cannot create '%s': %s\n",
                path, strerror(errno));
        return false;
    }

    size_t offset = 0;
    while (offset < data.size()) {
        ssize_t count = write(fd, data.data() + offset, data.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            fprintf(stderr, "[ColorBleed] ERROR: write failed for '%s': %s\n",
                    path, strerror(errno));
            close(fd);
            unlink(path);
            return false;
        }
        offset += static_cast<size_t>(count);
    }

    bool close_failed = fsync(fd) != 0;
    if (close(fd) != 0) {
        close_failed = true;
    }
    if (close_failed) {
        fprintf(stderr, "[ColorBleed] ERROR: flush/close failed for '%s': %s\n",
                path, strerror(errno));
        unlink(path);
        return false;
    }

    return true;
}

static const char *ValidationName(icValidateStatus status)
{
    switch (status) {
        case icValidateOK: return "valid";
        case icValidateWarning: return "warning";
        case icValidateNonCompliant: return "non-compliant";
        case icValidateCriticalError: return "critical error";
        default: return "unknown";
    }
}

static int DumpIccProfile(const std::vector<icUInt8Number>& profile_data)
{
    printf("\n[ICC] Embedded profile: %zu bytes\n", profile_data.size());
    if (profile_data.size() >= 40) {
        printf("[ICC] Header magic: %c%c%c%c\n",
               profile_data[36], profile_data[37], profile_data[38], profile_data[39]);
    }

    CIccProfile *profile = OpenIccProfile(profile_data.data(),
                                          static_cast<icUInt32Number>(profile_data.size()));
    if (!profile) {
        fprintf(stderr, "[ColorBleed] ERROR: iccDEV rejected the embedded profile header\n");
        return 4;
    }

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

    fprintf(stderr, "[ColorBleed] ICC phase: recursively loading all tags\n");
    if (!profile->ReadTags(profile)) {
        fprintf(stderr, "[ColorBleed] ERROR: iccDEV failed while loading ICC tags\n");
        delete profile;
        return 5;
    }

    std::string report;
    icValidateStatus status = profile->Validate(report);
    printf("[ICC] Validation: %s (%d)\n", ValidationName(status), status);
    if (!report.empty()) {
        printf("[ICC] Validation report follows:\n%s", report.c_str());
        if (report.back() != '\n') {
            printf("\n");
        }
    }

    delete profile;
    return status > icValidateWarning ? 6 : 0;
}

static int DumpTiff(const char *src_path, const char *dst_path)
{
    TIFF *tiff = TIFFOpen(src_path, "r");
    if (!tiff) {
        fprintf(stderr, "[ColorBleed] ERROR: libtiff could not open '%s'\n", src_path);
        return 2;
    }

    std::vector<icUInt8Number> first_profile;
    unsigned int profile_directories = 0;
    unsigned int directory = 0;

    do {
        printf("\n[TIFF] Directory %u\n", directory);
        TIFFPrintDirectory(tiff, stdout, 0);

        uint32_t profile_size = 0;
        void *profile_bytes = nullptr;
        if (TIFFGetField(tiff, TIFFTAG_ICCPROFILE, &profile_size, &profile_bytes) == 1 &&
            profile_bytes && profile_size > 0) {
            profile_directories++;
            printf("[TIFF] Directory %u ICC profile: %u bytes\n", directory, profile_size);
            if (first_profile.empty()) {
                const icUInt8Number *begin = static_cast<const icUInt8Number *>(profile_bytes);
                first_profile.assign(begin, begin + profile_size);
            }
        } else {
            printf("[TIFF] Directory %u ICC profile: none\n", directory);
        }

        directory++;
        if (directory == kMaxDirectories) {
            if (!TIFFLastDirectory(tiff)) {
                fprintf(stderr, "[ColorBleed] WARNING: TIFF directory cap reached (%u)\n",
                        kMaxDirectories);
            }
            break;
        }
    } while (TIFFReadDirectory(tiff) == 1);

    TIFFClose(tiff);
    printf("\n[TIFF] Directories read: %u; directories with ICC: %u\n",
           directory, profile_directories);

    if (first_profile.empty()) {
        if (dst_path) {
            fprintf(stderr, "[ColorBleed] ERROR: no embedded ICC profile to extract\n");
            return 3;
        }
        return 0;
    }

    if (profile_directories > 1) {
        fprintf(stderr,
                "[ColorBleed] WARNING: multiple TIFF directories contain ICC profiles; "
                "diagnostics and extraction use the first\n");
    }

    if (dst_path) {
        if (!WriteNewFile(dst_path, first_profile)) {
            return 7;
        }
        printf("[ColorBleed] Extracted %zu original ICC bytes to %s\n",
               first_profile.size(), dst_path);
    }

    return DumpIccProfile(first_profile);
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    if (argc == 2 && IsHelpFlag(argv[1])) {
        PrintUsage();
        return 0;
    }
    if (argc < 2 || argc > 3) {
        PrintUsage();
        return kExitUsage;
    }

    char resolved_src[PATH_MAX];
    if (!realpath(argv[1], resolved_src)) {
        fprintf(stderr, "[ColorBleed] ERROR: cannot resolve input '%s': %s\n",
                argv[1], strerror(errno));
        return kExitNoInput;
    }

    std::string safe_dst;
    if (argc == 3) {
        safe_dst = ValidateOutputPath(argv[2]);
        if (safe_dst.empty()) {
            return kExitUsage;
        }
    }

    printf("[ColorBleed] Sandboxed TIFF and embedded ICC dump\n");
    printf("[ColorBleed] Input: %s\n", resolved_src);
    if (!safe_dst.empty()) {
        printf("[ColorBleed] ICC output: %s (new file, exact embedded bytes)\n",
               safe_dst.c_str());
    }
    fprintf(stderr, "[ColorBleed] TIFF phase: opening input with libtiff\n");

    SandboxLimits limits;
    limits.max_mem_mb = 4096;
    limits.max_cpu_sec = 60;
    limits.max_fsize_mb = 512;
    limits.max_wall_sec = 30;

    const char *dst_path = safe_dst.empty() ? nullptr : safe_dst.c_str();
    SandboxResult result = RunSandboxed([&]() -> int {
        return DumpTiff(resolved_src, dst_path);
    }, limits);

    result.Report("TIFF + embedded ICC dump", resolved_src);
    if (result.SanitizerFinding()) {
        fprintf(stderr, "[ColorBleed] FINDING: TIFF/ICC processing triggered a sanitizer report\n");
    } else if (result.crashed) {
        fprintf(stderr, "[ColorBleed] FINDING: TIFF/ICC processing crashed: %s\n",
                result.SignalName());
    }

    return result.exit_code;
}
