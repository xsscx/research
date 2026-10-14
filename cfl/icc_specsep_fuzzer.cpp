/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * This software and associated documentation files (the "Software") are the
 * exclusive intellectual property of David H Hoyt LLC.
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
 * 3. The name "David H Hoyt LLC" must not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID H HOYT LLC "AS IS" AND ANY EXPRESSED
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL DAVID H HOYT LLC BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Contact: https://hoyt.net
 */

/*
 * icc_specsep_fuzzer - filesystem-backed coverage for iccSpecSepToTiff.
 *
 * Input formats:
 *
 *   Raw TIFF:
 *     A classic TIFF or BigTIFF is used as one separation. This makes the
 *     repository's ordinary TIFF corpus directly useful.
 *
 *   SSP3 bundle (little-endian lengths):
 *     "SSP3" flags count tile_w tile_h icc_len
 *     file_len[count] TIFF[count] ICC
 *
 *     flags bit 0: LZW output
 *     flags bit 1: separated output planes
 *     flags bit 2: tiled output; tile bytes select 16, 32, 48, or 64
 *     flags bit 3: BigTIFF output
 *
 *   Legacy V2 bundle:
 *     [count control][flags][equal TIFF chunks][optional ICC tail]
 *
 * SSP3 provides stable boundaries for multi-channel and profile-bearing
 * seeds. The legacy decoder remains for existing corpora and crash artifacts.
 */

#include <stddef.h>
#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <vector>

#include <tiffio.h>

#include "IccDefs.h"
#include "IccProfile.h"
#include "IccUtil.h"
#include "TiffImg.h"
#include "fuzz_utils.h"

namespace {

const size_t kMaxSeparations = 16;
const unsigned int kMaxInputTileBandBytes = 256u * 1024u * 1024u;

struct Blob {
    const uint8_t *data;
    size_t size;
};

struct ParsedInput {
    bool compress = false;
    bool separate = false;
    bool big_tiff = false;
    unsigned int tile_width = 0;
    unsigned int tile_height = 0;
    std::vector<Blob> tiffs;
    Blob profile = {nullptr, 0};
};

static void SilentTIFFErrorHandler(const char *, const char *, va_list) {}
static void SilentTIFFWarningHandler(const char *, const char *, va_list) {}

static bool checked_mul_size(size_t a, size_t b, size_t &out)
{
    if (a != 0 && b > std::numeric_limits<size_t>::max() / a)
        return false;
    out = a * b;
    return true;
}

static uint32_t read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static bool looks_like_tiff(const uint8_t *data, size_t size)
{
    if (size < 4)
        return false;

    return (data[0] == 'I' && data[1] == 'I' &&
            ((data[2] == 42 && data[3] == 0) ||
             (data[2] == 43 && data[3] == 0))) ||
           (data[0] == 'M' && data[1] == 'M' &&
            ((data[2] == 0 && data[3] == 42) ||
             (data[2] == 0 && data[3] == 43)));
}

static bool parse_ssp3(const uint8_t *data, size_t size, ParsedInput &parsed)
{
    if (size < 12 || memcmp(data, "SSP3", 4) != 0)
        return false;

    const uint8_t flags = data[4];
    const size_t count = data[5];
    if (!count || count > kMaxSeparations || count > (size - 12) / 4)
        return false;

    parsed.compress = (flags & 1) != 0;
    parsed.separate = (flags & 2) != 0;
    parsed.big_tiff = (flags & 8) != 0;
    if (flags & 4) {
        parsed.tile_width = 16u * ((data[6] & 3u) + 1u);
        parsed.tile_height = 16u * ((data[7] & 3u) + 1u);
    }

    const size_t profile_size = read_le32(data + 8);
    const size_t lengths_offset = 12;
    size_t cursor = lengths_offset + count * 4;
    parsed.tiffs.reserve(count);

    for (size_t i = 0; i < count; i++) {
        const size_t blob_size = read_le32(data + lengths_offset + i * 4);
        if (blob_size < 8 || blob_size > size - cursor)
            return false;
        parsed.tiffs.push_back({data + cursor, blob_size});
        cursor += blob_size;
    }

    if (profile_size != size - cursor)
        return false;
    if (profile_size)
        parsed.profile = {data + cursor, profile_size};

    return true;
}

static bool parse_legacy(const uint8_t *data, size_t size, ParsedInput &parsed)
{
    if (size < 10)
        return false;

    const size_t count = (data[0] % 8) + 1;
    const uint8_t flags = data[1];
    const uint8_t *payload = data + 2;
    size_t payload_size = size - 2;

    parsed.compress = (flags & 1) != 0;
    parsed.separate = (flags & 2) != 0;

    if (flags & 4) {
        size_t profile_size = payload_size / 4;
        if (profile_size < 16)
            profile_size = 16;
        if (profile_size > 256u * 1024u)
            profile_size = 256u * 1024u;
        if (profile_size < payload_size - 8) {
            parsed.profile = {payload + payload_size - profile_size, profile_size};
            payload_size -= profile_size;
        }
    }

    const size_t chunk_size = payload_size / count;
    if (chunk_size < 8)
        return false;

    parsed.tiffs.reserve(count);
    for (size_t i = 0; i < count; i++) {
        const size_t blob_size = i + 1 == count
                                     ? payload_size - i * chunk_size
                                     : chunk_size;
        parsed.tiffs.push_back({payload + i * chunk_size, blob_size});
    }
    return true;
}

static bool parse_input(const uint8_t *data, size_t size, ParsedInput &parsed)
{
    if (looks_like_tiff(data, size)) {
        parsed.tiffs.push_back({data, size});
        return true;
    }
    if (size >= 4 && memcmp(data, "SSP3", 4) == 0)
        return parse_ssp3(data, size, parsed);
    return parse_legacy(data, size, parsed);
}

struct TmpFiles {
    char paths[kMaxSeparations + 2][512];
    size_t count = 0;

    ~TmpFiles()
    {
        for (size_t i = 0; i < count; i++)
            unlink(paths[i]);
    }

    bool add(const char *dir, const char *suffix)
    {
        if (count >= kMaxSeparations + 2)
            return false;
        if (!fuzz_build_path(paths[count], sizeof(paths[count]), dir, suffix))
            return false;
        const int fd = mkstemp(paths[count]);
        if (fd < 0)
            return false;
        close(fd);
        count++;
        return true;
    }

    bool write_last(const uint8_t *buf, size_t len)
    {
        if (!count)
            return false;
        const int fd = open(paths[count - 1], O_WRONLY | O_TRUNC, 0600);
        if (fd < 0)
            return false;
        FILE *fp = fdopen(fd, "wb");
        if (!fp) {
            close(fd);
            return false;
        }
        const size_t written = fwrite(buf, 1, len, fp);
        const int close_status = fclose(fp);
        return written == len && close_status == 0;
    }
};

static bool profile_matches_samples(const uint8_t *data, size_t size,
                                    size_t samples)
{
    if (!data || !size || size > std::numeric_limits<icUInt32Number>::max())
        return false;

    std::string report;
    icValidateStatus status = icValidateOK;
    std::unique_ptr<CIccProfile> profile(
        ValidateIccProfile(data, (icUInt32Number)size, report, status));
    if (!profile || status >= icValidateNonCompliant)
        return false;

    std::unique_ptr<CIccProfile> spectral_profile(
        OpenIccProfile(data, (icUInt32Number)size, true));
    const CIccProfile *candidate = profile.get();
    if (spectral_profile &&
        spectral_profile->m_Header.spectralPCS != icSigNoSpectralData)
        candidate = spectral_profile.get();

    const icHeader &header = candidate->m_Header;
    if (header.deviceClass == icSigLinkClass)
        return false;

    if (header.deviceClass == icSigAbstractClass &&
        header.colorSpace == icSigNoColorData) {
        const icUInt32Number spectral_samples =
            icGetSpaceSamples((icColorSpaceSignature)header.spectralPCS);
        return spectral_samples == samples &&
               header.spectralRange.steps == samples;
    }

    return icGetSpaceSamples((icColorSpaceSignature)header.colorSpace) == samples;
}

} // namespace

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void)argc;
    (void)argv;
    TIFFSetErrorHandler(SilentTIFFErrorHandler);
    TIFFSetWarningHandler(SilentTIFFWarningHandler);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    ParsedInput parsed;
    if (!parse_input(data, size, parsed))
        return 0;

    const size_t count = parsed.tiffs.size();
    const char *tmpdir = fuzz_tmpdir();
    TmpFiles tmp;

    for (size_t i = 0; i < count; i++) {
        char suffix[40];
        snprintf(suffix, sizeof(suffix), "/fuzz_sep_%02zu_XXXXXX", i);
        if (!tmp.add(tmpdir, suffix) ||
            !tmp.write_last(parsed.tiffs[i].data, parsed.tiffs[i].size))
            return 0;
    }

    if (!tmp.add(tmpdir, "/fuzz_out_XXXXXX"))
        return 0;
    const char *out_path = tmp.paths[tmp.count - 1];

    unsigned int remaining_tile_bytes = kMaxInputTileBandBytes;
    std::vector<CTiffImg> inputs(count);
    for (size_t i = 0; i < count; i++) {
        if (!inputs[i].Open(tmp.paths[i], false, 0, remaining_tile_bytes))
            return 0;
        const unsigned int tile_bytes = inputs[i].GetTileBandSize();
        if (tile_bytes > remaining_tile_bytes)
            return 0;
        remaining_tile_bytes -= tile_bytes;

        if (inputs[i].GetSamples() != 1 ||
            inputs[i].GetPhoto() == PHOTO_PALETTE)
            return 0;

        if (i && (inputs[i].GetWidth() != inputs[0].GetWidth() ||
                  inputs[i].GetHeight() != inputs[0].GetHeight() ||
                  inputs[i].GetBitsPerSample() != inputs[0].GetBitsPerSample() ||
                  inputs[i].GetPhoto() != inputs[0].GetPhoto() ||
                  inputs[i].GetXRes() != inputs[0].GetXRes() ||
                  inputs[i].GetYRes() != inputs[0].GetYRes() ||
                  inputs[i].GetResolutionUnit() != inputs[0].GetResolutionUnit()))
            return 0;
    }

    CTiffImg *first = &inputs[0];
    bool invert = false;
    if (first->GetPhoto() == PHOTO_MINISWHITE)
        invert = true;
    else if (first->GetPhoto() != PHOTO_MINISBLACK)
        return 0;

    if (invert && first->GetSampleFormat() == SAMPLEFORMAT_IEEEFP)
        return 0;
    if (!first->GetBitsPerSample() || first->GetBitsPerSample() % 8)
        return 0;

    const size_t bytes_per_line = first->GetBytesPerLine();
    const size_t bytes_per_sample = first->GetBitsPerSample() / 8;
    size_t input_size = 0;
    size_t output_width_size = 0;
    size_t output_size = 0;
    size_t total_output_size = 0;
    if (!bytes_per_line || !bytes_per_sample ||
        !checked_mul_size(bytes_per_line, count, input_size) ||
        !checked_mul_size(first->GetWidth(), bytes_per_sample,
                          output_width_size) ||
        !checked_mul_size(output_width_size, count, output_size) ||
        !checked_mul_size(output_size, first->GetHeight(), total_output_size) ||
        input_size > 2u * 1024u * 1024u ||
        output_size > 2u * 1024u * 1024u ||
        total_output_size > 128u * 1024u * 1024u)
        return 0;

    std::unique_ptr<icUInt8Number[]> input_buffer(
        new (std::nothrow) icUInt8Number[input_size]);
    std::unique_ptr<icUInt8Number[]> output_buffer(
        new (std::nothrow) icUInt8Number[output_size]);
    if (!input_buffer || !output_buffer)
        return 0;

    if (parsed.profile.data &&
        !profile_matches_samples(parsed.profile.data, parsed.profile.size, count))
        return 0;

    std::unique_ptr<unsigned char[]> profile_buffer;
    if (parsed.profile.data) {
        profile_buffer.reset(new (std::nothrow) unsigned char[parsed.profile.size]);
        if (!profile_buffer)
            return 0;
        memcpy(profile_buffer.get(), parsed.profile.data, parsed.profile.size);
    }

    float x_res = first->GetXRes();
    float y_res = first->GetYRes();
    if (x_res < 1)
        x_res = 72;
    if (y_res < 1)
        y_res = 72;

    CTiffImg output;
    const unsigned int extra_samples = count > 1 ? (unsigned int)count - 1 : 0;
    if (!output.Create(out_path, first->GetWidth(), first->GetHeight(),
                       first->GetBitsPerSample(), PHOTO_MINISBLACK,
                       (unsigned int)count, extra_samples, x_res, y_res,
                       parsed.compress, parsed.separate,
                       first->GetResolutionUnit(), parsed.tile_width,
                       parsed.tile_height, parsed.big_tiff))
        return 0;

    if (profile_buffer &&
        !output.SetIccProfile(profile_buffer.get(),
                              (unsigned int)parsed.profile.size))
        return 0;

    icUInt8Number *input_line = input_buffer.get();
    icUInt8Number *output_line = output_buffer.get();
    for (unsigned int row = 0; row < first->GetHeight(); row++) {
        for (size_t channel = 0; channel < count; channel++) {
            icUInt8Number *source = input_line + channel * bytes_per_line;
            if (!inputs[channel].ReadLine(source))
                return 0;
            if (invert) {
                for (size_t i = 0; i < bytes_per_line; i++)
                    source[i] ^= 0xff;
            }
        }

        icUInt8Number *destination = output_line;
        for (unsigned int column = 0; column < first->GetWidth(); column++) {
            for (size_t channel = 0; channel < count; channel++) {
                const icUInt8Number *source =
                    input_line + channel * bytes_per_line +
                    column * bytes_per_sample;
                memcpy(destination, source, bytes_per_sample);
                destination += bytes_per_sample;
            }
        }

        if (!output.WriteLine(output_line))
            return 0;
    }

    if (!output.Close())
        return 0;

    return 0;
}
