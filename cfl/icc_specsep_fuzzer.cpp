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
 * icc_specsep_fuzzer — 1:1 fidelity with iccSpecSepToTiff tool
 *
 * Upstream tool: iccDEV/Tools/CmdLine/IccSpecSepToTiff/iccSpecSepToTiff.cpp
 *
 * What the tool does:
 * Concatenates N single-channel spectral separation TIFF files into one
 * multi-channel TIFF, optionally embedding an ICC profile. This is a pure
 * image format converter — no ICC color management (CIccCmm) is performed.
 *
 * Gate sequence (matches tool main() lines 119-271):
 *   Gate 0:   Input size bounds + parse control header
 *   Gate 1:   Sufficient pixel data for nFiles × width × height × bytesPerSample
 *   Gate 2:   Create nFiles temporary single-channel TIFF files from fuzzer data
 *             (simulates upstream's pre-existing spectral separation files)
 *   Gate 3:   Open all input files (tool lines 162-165)
 *   Gate 4:   Per-file validation: SPP=1, no PALETTE (tool lines 167-175)
 *   Gate 5:   Format consistency across all files (tool lines 177-185)
 *   Gate 6:   Photometric: MINISWHITE or MINISBLACK only (tool lines 196-202)
 *   Gate 7:   Allocate in/out buffers (tool lines 207-210)
 *   Gate 8:   Resolution defaults to 72 if < 1 (tool lines 212-218)
 *   Gate 9:   Create output TIFF: PHOTO_MINISBLACK, nFiles channels (tool lines 220-225)
 *   Gate 10:  Optional ICC profile embedding via raw bytes (tool lines 229-238)
 *   Gate 11:  Scanline loop: read → invert (MINISWHITE) → interleave → write
 *             (tool lines 240-263)
 *
 * Input format:
 *   [0]:     nFiles control (mod 8 + 1 → 1-8 spectral channels)
 *   [1]:     width control (mod 64 + 1 → 1-64 pixels)
 *   [2]:     height control (mod 64 + 1 → 1-64 pixels)
 *   [3]:     bit 0 = MINISWHITE (else MINISBLACK), bit 1 = compress, bit 2 = separate
 *   [4]:     bit 0 = 16-bit samples (else 8-bit)
 *   [5-14]:  reserved
 *   [15..]:  pixel data (nFiles × width × height × bytesPerSample)
 *            + optional trailing ICC profile bytes
 *
 * Upstream's argv[4]/[5]/[6]/[7] (format string, start, end, step) generate
 * N input filenames via snprintf. We pre-expand to nFiles temp files directly.
 *
 * Retired: Old fuzzer at cfl/retired/icc_specsep_fuzzer.cpp.retired-20260311
 */

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <cstring>
#include <cmath>
#include <memory>
#include <vector>
#include <new>
#include <tiffio.h>

#include "IccDefs.h"
#include "TiffImg.h"
#include "fuzz_utils.h"

static void SilentTIFFErrorHandler(const char*, const char*, va_list) {}
static void SilentTIFFWarningHandler(const char*, const char*, va_list) {}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    TIFFSetErrorHandler(SilentTIFFErrorHandler);
    TIFFSetWarningHandler(SilentTIFFWarningHandler);
    return 0;
}

// RAII cleanup for temporary files — stack-allocated paths, no malloc
struct TmpFiles {
    char paths[9][512]; // up to 8 input + 1 output
    int count = 0;
    ~TmpFiles() {
        for (int i = 0; i < count; i++)
            unlink(paths[i]);
    }
    bool add(const char *dir, const char *suffix) {
        if (count >= 9) return false;
        if (!fuzz_build_path(paths[count], sizeof(paths[count]), dir, suffix))
            return false;
        int fd = mkstemp(paths[count]);
        if (fd < 0) return false;
        close(fd);
        count++;
        return true;
    }
    const char *last() const { return paths[count - 1]; }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // --- Gate 0: Size bounds + control header parse ---
    if (size < 16 || size > 1024 * 1024)
        return 0;

    uint8_t nFiles = (data[0] % 8) + 1;       // 1-8 spectral channels
    uint32_t width = (data[1] % 64) + 1;      // 1-64 pixels
    uint32_t height = (data[2] % 64) + 1;     // 1-64 pixels

    // Tool argv[2] = compress, argv[3] = sep (tool lines 127-128)
    unsigned int nPhoto = (data[3] & 1) ? PHOTO_MINISWHITE : PHOTO_MINISBLACK;
    bool bCompress = (data[3] >> 1) & 1;
    bool bSep = (data[3] >> 2) & 1;

    // Tool only processes integer samples — 8 or 16 bit
    uint8_t bitsPerSample = (data[4] & 1) ? 16 : 8;
    size_t bytesPerSample = bitsPerSample / 8;

    // --- Gate 1: Sufficient pixel data ---
    // Tool calculates: nSamples = abs(end - start) / step + 1 (line 146)
    // Each file is width × height single-channel pixels
    size_t minDataSize = (size_t)width * height * bytesPerSample * nFiles;
    if (size < 15 + minDataSize)
        return 0;

    const char *tmpdir = fuzz_tmpdir();
    TmpFiles tmp;

    // --- Gate 2: Create nFiles single-channel input TIFFs ---
    // Simulates spectral separation files the tool expects.
    // Tool generates filenames via snprintf(filename, ..., argv[4], channelNum)
    // where channelNum = i*step + start (line 161).
    for (uint8_t i = 0; i < nFiles; i++) {
        char suffix[64] = "/fuzz_sep_";
        size_t slen = strlen(suffix);
        suffix[slen++] = '0' + (i / 10);
        suffix[slen++] = '0' + (i % 10);
        memcpy(suffix + slen, "_XXXXXX", 8);

        if (!tmp.add(tmpdir, suffix))
            return 0;

        // Create TIFF: 1 SPP (tool requirement: GetSamples() == 1, line 167)
        CTiffImg tiff;
        if (!tiff.Create(tmp.last(), width, height, bitsPerSample,
                         nPhoto, 1, 0, 72, 72, false, false))
            return 0;

        // Write pixel data from fuzzer input
        size_t pixelsPerRow = width * bytesPerSample;
        size_t offset = 15 + (size_t)i * width * height * bytesPerSample;
        const uint8_t *pixelData = data + offset;

        for (uint32_t row = 0; row < height; row++) {
            size_t rowOffset = row * pixelsPerRow;
            if (offset + rowOffset + pixelsPerRow > size)
                return 0;
            tiff.WriteLine((icUInt8Number*)(pixelData + rowOffset));
        }
        tiff.Close();
    }

    // Output temp file
    if (!tmp.add(tmpdir, "/fuzz_out_XXXXXX"))
        return 0;
    const char *outPath = tmp.last();

    // --- Gate 3: Open all input files (tool lines 162-165) ---
    std::vector<CTiffImg> infiles(nFiles);
    for (uint8_t i = 0; i < nFiles; i++) {
        if (!infiles[i].Open(tmp.paths[i]))
            return 0;

        // --- Gate 4: Per-file validation (tool lines 167-175) ---
        if (infiles[i].GetSamples() != 1)
            return 0;
        if (infiles[i].GetPhoto() == PHOTOMETRIC_PALETTE)
            return 0;

        // --- Gate 5: Format consistency (tool lines 177-185) ---
        // Tool uses exact == for all comparisons including float resolution.
        // Integer comparisons for dimensions/format, memcmp for float resolution
        // (values from same TIFF parser — exact bit equality is correct).
        if (i > 0) {
            if (infiles[i].GetWidth() != infiles[0].GetWidth() ||
                infiles[i].GetHeight() != infiles[0].GetHeight() ||
                infiles[i].GetBitsPerSample() != infiles[0].GetBitsPerSample() ||
                infiles[i].GetPhoto() != infiles[0].GetPhoto())
                return 0;
            float xres_i = infiles[i].GetXRes(), xres_0 = infiles[0].GetXRes();
            float yres_i = infiles[i].GetYRes(), yres_0 = infiles[0].GetYRes();
            if (memcmp(&xres_i, &xres_0, sizeof(float)) != 0 ||
                memcmp(&yres_i, &yres_0, sizeof(float)) != 0)
                return 0;
        }
    }

    // --- Gate 6: Photometric validation (tool lines 196-202) ---
    CTiffImg *f = &infiles[0];
    bool invert = false;
    if (f->GetPhoto() == PHOTO_MINISWHITE)
        invert = true;
    else if (f->GetPhoto() != PHOTO_MINISBLACK)
        return 0;

    // --- Gate 7: Buffer allocation (tool lines 207-210) ---
    long bytePerLine = f->GetBytesPerLine();
    long bps_img = f->GetBitsPerSample() / 8;

    std::unique_ptr<icUInt8Number[]> inbuffer(
        new (std::nothrow) icUInt8Number[bytePerLine * nFiles]);
    std::unique_ptr<icUInt8Number[]> outbuffer(
        new (std::nothrow) icUInt8Number[f->GetWidth() * bps_img * nFiles]);
    if (!inbuffer || !outbuffer)
        return 0;

    icUInt8Number *inbuf = inbuffer.get();
    icUInt8Number *outbuf = outbuffer.get();

    // --- Gate 8: Resolution defaults (tool lines 212-218) ---
    float xRes = f->GetXRes();
    float yRes = f->GetYRes();
    if (xRes < 1) xRes = 72;
    if (yRes < 1) yRes = 72;

    // --- Gate 9: Create output TIFF (tool lines 220-225) ---
    // Tool: always PHOTO_MINISBLACK output, nSamples channels, 0 extra samples
    CTiffImg outimg;
    if (!outimg.Create(outPath, f->GetWidth(), f->GetHeight(),
                       f->GetBitsPerSample(), PHOTO_MINISBLACK, nFiles, 0,
                       xRes, yRes, bCompress, bSep))
        return 0;

    // --- Gate 10: Optional ICC profile embedding (tool lines 229-238) ---
    // Tool reads raw bytes via CIccFileIO.Open() + Read8() and passes to
    // SetIccProfile(). We copy raw bytes from the fuzzer input tail.
    size_t profileOffset = 15 + minDataSize;
    std::unique_ptr<unsigned char[]> profileBuf;
    if (size > profileOffset + 128) {
        size_t profileSize = size - profileOffset;
        if (profileSize > 1024 * 1024) profileSize = 1024 * 1024;
        profileBuf.reset(new (std::nothrow) unsigned char[profileSize]);
        if (profileBuf) {
            memcpy(profileBuf.get(), data + profileOffset, profileSize);
            outimg.SetIccProfile(profileBuf.get(), (unsigned int)profileSize);
        }
    }

    // --- Gate 11: Scanline processing (tool lines 240-263) ---
    for (uint32_t i = 0; i < f->GetHeight(); i++) {
        bool readOk = true;
        for (uint8_t j = 0; j < nFiles; j++) {
            icUInt8Number *sptr = inbuf + j * bytePerLine;

            // Tool line 244: ReadLine per file
            if (!infiles[j].ReadLine(sptr)) {
                readOk = false;
                break;
            }

            // Tool lines 248-252: MINISWHITE inversion (inside per-file loop)
            // "NOTE - this will not work for floating point data"
            if (invert) {
                for (long k = 0; k < bytePerLine; k++)
                    sptr[k] ^= 0xff;
            }
        }
        if (!readOk) break;

        // Tool lines 254-261: Interleave planar → pixel-interleaved
        icUInt8Number *tptr = outbuf;
        for (uint32_t k = 0; k < f->GetWidth(); k++) {
            for (uint8_t j = 0; j < nFiles; j++) {
                icUInt8Number *sptr = inbuf + j * bytePerLine + k * bps_img;
                memcpy(tptr, sptr, bps_img);
                tptr += bps_img;
            }
        }

        // Tool line 262: Write interleaved scanline
        outimg.WriteLine(outbuf);
    }

    // Tool line 266: Close output before buffer destruction
    outimg.Close();

    // TmpFiles destructor handles unlink of all temp files
    return 0;
}
