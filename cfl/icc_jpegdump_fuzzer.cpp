/*
 * Copyright (c) International Color Consortium.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. In the absence of prior written permission, the names "ICC" and "The
 *    International Color Consortium" must not be used to imply that the
 *    ICC organization endorses or promotes products derived from this
 *    software.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE INTERNATIONAL COLOR CONSORTIUM OR
 * ITS CONTRIBUTING MEMBERS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @file
    CFL harness for iccDEV iccJpegDump.

    Modeled command:
      iccJpegDump jpeg_file output_icc_file

    The input JPEG bytes are parsed for ICC_PROFILE APP2 chunks, reassembled in
    command-line order, written to a temporary output path, then loaded through
    CIccProfile to exercise the extracted ICC profile surface.
 */

#include "IccIO.h"
#include "IccProfile.h"
#include "fuzz_utils.h"

#include <stddef.h>
#include <stdint.h>
#include <climits>
#include <cstdio>
#include <cstring>
#include <string>
#include <unistd.h>
#include <vector>

static constexpr size_t kMaxJpegInputSize = 10 * 1024 * 1024;
static constexpr size_t kMaxExtractedIccSize = 8 * 1024 * 1024;

static bool write_temp_file(const uint8_t *data, size_t size, char *path, size_t pathSize,
                            const char *suffix)
{
    if (!fuzz_build_path(path, pathSize, fuzz_tmpdir(), suffix))
        return false;

    int fd = mkstemp(path);
    if (fd < 0)
        return false;

    bool wrote = (write(fd, data, size) == (ssize_t)size);
    close(fd);
    if (!wrote)
        unlink(path);

    return wrote;
}

static bool write_temp_vector(const std::vector<uint8_t> &data, char *path, size_t pathSize)
{
    if (!fuzz_build_path(path, pathSize, fuzz_tmpdir(), "/fuzz_jpegdump_icc_XXXXXX"))
        return false;

    int fd = mkstemp(path);
    if (fd < 0)
        return false;

    bool wrote = data.empty() || (write(fd, data.data(), data.size()) == (ssize_t)data.size());
    close(fd);
    if (!wrote)
        unlink(path);

    return wrote;
}

static bool extract_icc_profile(const uint8_t *data, size_t size, std::vector<uint8_t> &iccData)
{
    if (!data || size < 4 || data[0] != 0xff || data[1] != 0xd8)
        return false;

    static const uint8_t kSig[12] = {
        'I', 'C', 'C', '_', 'P', 'R', 'O', 'F', 'I', 'L', 'E', '\0'
    };

    std::vector<std::vector<uint8_t> > chunks;
    std::vector<bool> seen;
    uint32_t totalChunks = 0;
    size_t pos = 2;

    while (pos < size) {
        if (data[pos] != 0xff) {
            pos++;
            continue;
        }
        while (pos < size && data[pos] == 0xff)
            pos++;
        if (pos >= size)
            break;

        uint8_t marker = data[pos++];
        if (marker == 0xd9 || marker == 0xda)
            break;
        if (marker == 0x01 || (marker >= 0xd0 && marker <= 0xd7))
            continue;
        if (pos + 2 > size)
            break;

        uint32_t segmentLength = ((uint32_t)data[pos] << 8) | (uint32_t)data[pos + 1];
        pos += 2;
        if (segmentLength < 2)
            return false;

        size_t payloadLength = (size_t)segmentLength - 2;
        if (payloadLength > size - pos)
            break;

        const uint8_t *segment = data + pos;
        if (marker == 0xe2 && payloadLength >= 14 && memcmp(segment, kSig, sizeof(kSig)) == 0) {
            uint32_t seq = segment[12];
            uint32_t total = segment[13];
            if (seq == 0 || total == 0 || seq > total)
                return false;
            if (totalChunks == 0) {
                totalChunks = total;
                chunks.resize(total);
                seen.assign(total, false);
            }
            else if (total != totalChunks) {
                return false;
            }
            if (seen[seq - 1])
                return false;

            seen[seq - 1] = true;
            chunks[seq - 1].assign(segment + 14, segment + payloadLength);
        }

        pos += payloadLength;
    }

    if (totalChunks == 0)
        return false;

    size_t totalSize = 0;
    for (uint32_t i = 0; i < totalChunks; i++) {
        if (!seen[i])
            return false;
        if (chunks[i].size() > kMaxExtractedIccSize - totalSize)
            return false;
        totalSize += chunks[i].size();
    }

    iccData.clear();
    iccData.reserve(totalSize);
    for (uint32_t i = 0; i < totalChunks; i++)
        iccData.insert(iccData.end(), chunks[i].begin(), chunks[i].end());

    return !iccData.empty();
}

static void exercise_extracted_profile(const std::vector<uint8_t> &iccData)
{
    char outputPath[PATH_MAX];
    if (!write_temp_vector(iccData, outputPath, sizeof(outputPath)))
        return;

    CIccMemIO mem;
    if (mem.Attach(const_cast<icUInt8Number *>(iccData.data()), iccData.size(), false)) {
        CIccProfile profile;
        if (profile.Read(&mem)) {
            std::string report;
            profile.Validate(report);
        }
    }

    unlink(outputPath);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size < 4 || size > kMaxJpegInputSize)
        return 0;

    char jpegPath[PATH_MAX];
    if (!write_temp_file(data, size, jpegPath, sizeof(jpegPath), "/fuzz_jpegdump_XXXXXX"))
        return 0;

    std::vector<uint8_t> iccData;
    if (extract_icc_profile(data, size, iccData))
        exercise_extracted_profile(iccData);

    unlink(jpegPath);
    return 0;
}
