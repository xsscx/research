/*!
 *  @file IccJpegDump_unsafe.cpp
 *  @brief Sandboxed JPEG ICC profile extractor with forensic chunk recovery
 *
 *  Preserves ICC_PROFILE APP2 payload bytes and validates the reconstructed
 *  profile with the vanilla iccDEV IccProfLib parser.
 */

#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

#include "IccFileUtil.h"
#include "IccIO.h"
#include "IccProfile.h"
#include "IccProfLibVer.h"
#include "IccUtil.h"
#include "ColorBleedSandbox.h"

static constexpr int kExitUsage = 64;
static constexpr int kExitNoInput = 66;
static constexpr int kExitRecovered = 10;
static constexpr size_t kMaxInputBytes = 512U * 1024U * 1024U;
static constexpr size_t kMaxProfileBytes = 512U * 1024U * 1024U;

struct IccChunk {
    unsigned int sequence;
    unsigned int total;
    size_t marker_offset;
    std::vector<icUInt8Number> payload;
};

static bool IsHelpFlag(const char *arg)
{
    return arg && (!strcmp(arg, "-h") || !strcmp(arg, "--help"));
}

static void PrintUsage()
{
    printf("iccJpegDump_unsafe built with IccProfLib Version " ICCPROFLIBVER "\n");
    printf("Usage: iccJpegDump_unsafe [--forensic|--strict] input.jpg output.icc\n");
    printf("  --forensic  Recover malformed chunk metadata in physical APP2 order (default).\n");
    printf("  --strict    Reject invalid, duplicate, inconsistent, or missing chunk numbers.\n");
    printf("  The output is atomically published before IccProfLib validation.\n");
}

static bool ReadInput(const char *path, std::vector<icUInt8Number>& data)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "[ColorBleed] ERROR: cannot open JPEG: %s\n", strerror(errno));
        return false;
    }

    struct stat input_stat;
    if (fstat(fd, &input_stat) != 0 || !S_ISREG(input_stat.st_mode) ||
        input_stat.st_size < 0 ||
        static_cast<uint64_t>(input_stat.st_size) > kMaxInputBytes) {
        fprintf(stderr, "[ColorBleed] ERROR: JPEG is not a bounded regular file\n");
        close(fd);
        return false;
    }

    data.resize(static_cast<size_t>(input_stat.st_size));
    size_t offset = 0;
    while (offset < data.size()) {
        ssize_t count = read(fd, data.data() + offset, data.size() - offset);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            fprintf(stderr, "[ColorBleed] ERROR: short JPEG read\n");
            close(fd);
            return false;
        }
        offset += static_cast<size_t>(count);
    }
    close(fd);
    return true;
}

static bool IsStandaloneMarker(unsigned int marker)
{
    return marker == 0x01 || marker == 0xd8 ||
           (marker >= 0xd0 && marker <= 0xd7);
}

static bool ParseIccChunks(const std::vector<icUInt8Number>& jpeg,
                           std::vector<IccChunk>& chunks)
{
    if (jpeg.size() < 4 || jpeg[0] != 0xff || jpeg[1] != 0xd8) {
        fprintf(stderr, "[ColorBleed] ERROR: input does not begin with JPEG SOI\n");
        return false;
    }

    size_t pos = 2;
    while (pos < jpeg.size()) {
        while (pos < jpeg.size() && jpeg[pos] != 0xff) {
            pos++;
        }
        if (pos == jpeg.size()) {
            break;
        }

        size_t marker_offset = pos;
        while (pos < jpeg.size() && jpeg[pos] == 0xff) {
            pos++;
        }
        if (pos == jpeg.size()) {
            fprintf(stderr, "[ColorBleed] ERROR: truncated JPEG marker\n");
            return false;
        }

        unsigned int marker = jpeg[pos++];
        if (marker == 0x00) {
            continue;
        }
        if (marker == 0xd9) {
            break;
        }
        if (IsStandaloneMarker(marker)) {
            continue;
        }
        if (pos + 2 > jpeg.size()) {
            fprintf(stderr, "[ColorBleed] ERROR: truncated JPEG segment length\n");
            return false;
        }

        size_t segment_size = (static_cast<size_t>(jpeg[pos]) << 8) | jpeg[pos + 1];
        if (segment_size < 2 || segment_size > jpeg.size() - pos) {
            fprintf(stderr, "[ColorBleed] ERROR: invalid JPEG segment length at 0x%zx\n",
                    marker_offset);
            return false;
        }

        const icUInt8Number *segment = jpeg.data() + pos + 2;
        size_t payload_size = segment_size - 2;
        if (marker == 0xe2 && payload_size >= 14 &&
            !memcmp(segment, "ICC_PROFILE\0", 12)) {
            IccChunk chunk;
            chunk.sequence = segment[12];
            chunk.total = segment[13];
            chunk.marker_offset = marker_offset;
            chunk.payload.assign(segment + 14, segment + payload_size);
            chunks.push_back(chunk);
            printf("[JPEG] ICC APP2 marker offset=0x%zx sequence=%u total=%u bytes=%zu\n",
                   marker_offset, chunk.sequence, chunk.total, chunk.payload.size());
        }
        pos += segment_size;
    }
    return true;
}

static bool AssembleProfile(const std::vector<IccChunk>& chunks, bool strict,
                            std::vector<icUInt8Number>& profile, bool& recovered)
{
    if (chunks.empty()) {
        return false;
    }

    unsigned int expected = chunks[0].total;
    bool metadata_valid = expected > 0 && expected <= 255 && chunks.size() == expected;
    std::vector<const IccChunk *> ordered(expected ? expected : 1, nullptr);

    for (const IccChunk& chunk : chunks) {
        if (!expected || chunk.total != expected || !chunk.sequence ||
            chunk.sequence > expected) {
            metadata_valid = false;
            continue;
        }
        if (ordered[chunk.sequence - 1]) {
            metadata_valid = false;
            continue;
        }
        ordered[chunk.sequence - 1] = &chunk;
    }
    if (metadata_valid) {
        for (const IccChunk *chunk : ordered) {
            if (!chunk) {
                metadata_valid = false;
                break;
            }
        }
    }

    if (!metadata_valid && strict) {
        fprintf(stderr, "[ColorBleed] ERROR: malformed JPEG ICC chunk metadata\n");
        return false;
    }

    size_t profile_size = 0;
    for (const IccChunk& chunk : chunks) {
        if (chunk.payload.size() > kMaxProfileBytes - profile_size) {
            fprintf(stderr, "[ColorBleed] ERROR: reconstructed ICC exceeds byte limit\n");
            return false;
        }
        profile_size += chunk.payload.size();
    }

    profile.reserve(profile_size);
    if (metadata_valid) {
        for (const IccChunk *chunk : ordered) {
            profile.insert(profile.end(), chunk->payload.begin(), chunk->payload.end());
        }
        recovered = false;
        printf("[JPEG] ICC assembly: strict sequence order\n");
    } else {
        for (const IccChunk& chunk : chunks) {
            profile.insert(profile.end(), chunk.payload.begin(), chunk.payload.end());
        }
        recovered = true;
        fprintf(stderr,
                "[ColorBleed] WARNING: malformed ICC chunk metadata; "
                "recovered payloads in physical APP2 order\n");
        printf("[JPEG] ICC assembly: physical-order forensic recovery\n");
    }
    return true;
}

static bool WriteAtomicProfile(const char *path, std::vector<icUInt8Number>& profile)
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
        fprintf(stderr, "[ColorBleed] ERROR: cannot create output temporary: %s\n",
                strerror(errno));
        return false;
    }

    FILE *stream = fdopen(fd, "wb");
    if (!stream) {
        fprintf(stderr, "[ColorBleed] ERROR: cannot open output temporary: %s\n",
                strerror(errno));
        close(fd);
        unlink(temporary.data());
        return false;
    }

    CIccFileIO output;
    output.Attach(stream);
    bool complete = output.Write8(profile.data(), profile.size()) == profile.size() &&
                    output.Flush() && fsync(fd) == 0 && output.CloseFile();
    if (!complete) {
        fprintf(stderr, "[ColorBleed] ERROR: incomplete ICC output write\n");
        output.CloseFile();
        unlink(temporary.data());
        return false;
    }

    if (link(temporary.data(), path) != 0) {
        fprintf(stderr, "[ColorBleed] ERROR: cannot publish ICC output: %s\n",
                strerror(errno));
        unlink(temporary.data());
        return false;
    }
    unlink(temporary.data());
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

static int InspectProfile(const std::vector<icUInt8Number>& profile_data)
{
    if (profile_data.size() > UINT32_MAX) {
        fprintf(stderr, "[ColorBleed] ERROR: ICC is too large for IccProfLib\n");
        return 9;
    }

    CIccProfile *profile = OpenIccProfile(profile_data.data(),
        static_cast<icUInt32Number>(profile_data.size()));
    if (!profile) {
        fprintf(stderr, "[ColorBleed] ERROR: IccProfLib rejected the recovered ICC header\n");
        return 4;
    }

    CIccInfo info;
    printf("[ICC] Bytes: %zu\n", profile_data.size());
    printf("[ICC] Version: %s\n", info.GetVersionName(profile->m_Header.version));
    printf("[ICC] Class: %s\n", info.GetProfileClassSigName(profile->m_Header.deviceClass));
    printf("[ICC] Color space: %s\n", info.GetColorSpaceSigName(profile->m_Header.colorSpace));
    printf("[ICC] PCS: %s\n", info.GetColorSpaceSigName(profile->m_Header.pcs));
    printf("[ICC] Tag directory entries: %zu\n", profile->m_Tags.size());

    if (!profile->ReadTags(profile)) {
        fprintf(stderr, "[ColorBleed] ERROR: IccProfLib failed while loading ICC tags\n");
        delete profile;
        return 5;
    }

    std::string report;
    icValidateStatus status = profile->Validate(report);
    printf("[ICC] Validation: %s (%d)\n", ValidationName(status), status);
    delete profile;
    return status > icValidateWarning ? 6 : 0;
}

static int ExtractJpegProfile(const char *src_path, const char *dst_path, bool strict)
{
    std::vector<icUInt8Number> jpeg;
    if (!ReadInput(src_path, jpeg)) {
        return 2;
    }

    std::vector<IccChunk> chunks;
    if (!ParseIccChunks(jpeg, chunks)) {
        return 2;
    }
    if (chunks.empty()) {
        fprintf(stderr, "[ColorBleed] ERROR: JPEG has no ICC_PROFILE APP2 markers\n");
        return 3;
    }

    std::vector<icUInt8Number> profile;
    bool recovered = false;
    if (!AssembleProfile(chunks, strict, profile, recovered)) {
        return strict ? 8 : 9;
    }
    if (!WriteAtomicProfile(dst_path, profile)) {
        return 7;
    }
    printf("[ColorBleed] Extracted %zu ICC bytes to %s\n", profile.size(),
           icSanitizeConsoleText(dst_path).c_str());

    int inspect_status = InspectProfile(profile);
    if (inspect_status) {
        return inspect_status;
    }
    return recovered ? kExitRecovered : 0;
}

int main(int argc, char *argv[])
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    bool strict = false;
    int arg_index = 1;
    if (argc > 1 && !strcmp(argv[1], "--strict")) {
        strict = true;
        arg_index++;
    } else if (argc > 1 && !strcmp(argv[1], "--forensic")) {
        arg_index++;
    }

    if (argc == 2 && IsHelpFlag(argv[1])) {
        PrintUsage();
        return 0;
    }
    if (argc - arg_index != 2 || IsHelpFlag(argv[arg_index])) {
        PrintUsage();
        return kExitUsage;
    }

    char resolved_src[PATH_MAX];
    if (!realpath(argv[arg_index], resolved_src)) {
        fprintf(stderr, "[ColorBleed] ERROR: cannot resolve input '%s': %s\n",
                icSanitizeConsoleText(argv[arg_index]).c_str(), strerror(errno));
        return kExitNoInput;
    }
    std::string safe_dst = ValidateOutputPath(argv[arg_index + 1]);
    if (safe_dst.empty()) {
        return kExitUsage;
    }

    printf("[ColorBleed] Sandboxed JPEG ICC extraction\n");
    printf("[ColorBleed] Input: %s\n", icSanitizeConsoleText(resolved_src).c_str());
    printf("[ColorBleed] Output: %s\n", icSanitizeConsoleText(safe_dst).c_str());
    printf("[ColorBleed] Chunk policy: %s\n", strict ? "strict" : "forensic fallback");

    SandboxLimits limits;
    limits.max_mem_mb = 4096;
    limits.max_cpu_sec = 60;
    limits.max_fsize_mb = 512;
    limits.max_wall_sec = 30;

    SandboxResult result = RunSandboxed([&]() -> int {
        return ExtractJpegProfile(resolved_src, safe_dst.c_str(), strict);
    }, limits);
    result.Report("JPEG ICC extraction", resolved_src);
    return result.exit_code;
}
