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
 *   Concatenates N single-channel spectral separation TIFF files into one
 *   multi-channel TIFF, optionally embedding an ICC profile. Pure image
 *   format converter — no ICC color management (CIccCmm) is performed.
 *
 * Architecture (V2 — raw TIFF bytes):
 *   V1 created perfect TIFFs internally then re-opened them. LibFuzzer
 *   could only mutate control bytes and pixel values — never the TIFF
 *   structure itself. Coverage stalled at ~3,975 edges after 3 seconds.
 *
 *   V2 feeds raw TIFF bytes from the fuzz input directly to temp files,
 *   then opens them with CTiffImg::Open(). LibFuzzer can now mutate:
 *   - TIFF headers (magic, IFD pointers, byte order)
 *   - IFD entries (dimensions, BPS, photometric, strip offsets/sizes)
 *   - Strip data (pixel bytes, compression artifacts)
 *   - Cross-file structure mismatches (different dimensions, BPS, etc.)
 *
 *   Seed corpus: single-channel spectral TIFFs from xnuimagegenerator
 *   (fuzz/xnuimagegenerator/tiff/spectral/) — SPP=1, MINISBLACK, 8/16-bit.
 *
 * Input format:
 *   [0]:     nFiles control (mod 8 + 1 → 1-8 spectral channels)
 *   [1]:     flags: bit 0 = compress, bit 1 = sep, bit 2 = has ICC profile
 *   [2..]:   divided into nFiles equal chunks — each is raw TIFF bytes
 *            written to a temp file then opened with CTiffImg::Open()
 *            If bit 2 set: last 1/4 of payload is ICC profile data
 *
 * Gate sequence (matches tool main() lines 119-271):
 *   Gate 0:  Input size bounds + parse control
 *   Gate 1:  Write N raw TIFF blobs to temp files
 *   Gate 2:  Open all input files (tool lines 162-165)
 *   Gate 3:  Per-file validation: SPP=1, no PALETTE (tool lines 167-175)
 *   Gate 4:  Format consistency across files (tool lines 177-185)
 *   Gate 5:  Photometric: MINISWHITE or MINISBLACK only (tool lines 196-202)
 *   Gate 6:  Buffer allocation (tool lines 207-210) — OOM-guarded
 *   Gate 7:  Resolution defaults (tool lines 212-218)
 *   Gate 8:  Create output TIFF (tool lines 220-225)
 *   Gate 9:  Optional ICC profile embedding (tool lines 229-238)
 *   Gate 10: Scanline loop: read → invert → interleave → write (lines 240-263)
 *
 * Retired: V1 at cfl/icc_specsep_fuzzer.cpp.retired
 */

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <memory>
#include <vector>
#include <new>
#include <tiffio.h>

#include "IccDefs.h"
#include "IccIO.h"
#include "TiffImg.h"
#include "fuzz_utils.h"

static void SilentTIFFErrorHandler(const char*, const char*, va_list) {}
static void SilentTIFFWarningHandler(const char*, const char*, va_list) {}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    TIFFSetErrorHandler(SilentTIFFErrorHandler);
    TIFFSetWarningHandler(SilentTIFFWarningHandler);
    return 0;
}

// RAII cleanup for temporary files
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
    // Write raw bytes to the last temp file (0600 permissions — not world-writable)
    bool writeLast(const uint8_t *buf, size_t len) {
        int fd = open(paths[count - 1], O_WRONLY | O_TRUNC, 0600);
        if (fd < 0) return false;
        FILE *fp = fdopen(fd, "wb");
        if (!fp) { close(fd); return false; }
        size_t written = fwrite(buf, 1, len, fp);
        fclose(fp);
        return written == len;
    }
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // --- Gate 0: Size bounds + control parse ---
    // Minimum: 2 control bytes + at least 8 bytes of TIFF data per file
    if (size < 10 || size > 2 * 1024 * 1024)
        return 0;

    uint8_t nFiles = (data[0] % 8) + 1;       // 1-8 spectral channels
    bool bCompress = (data[1] >> 0) & 1;       // tool argv[2]
    bool bSep      = (data[1] >> 1) & 1;       // tool argv[3]
    bool hasICC    = (data[1] >> 2) & 1;        // tool argv[8] present

    const uint8_t *payload = data + 2;
    size_t payloadSize = size - 2;

    // If hasICC, reserve the tail of the payload for ICC profile data.
    // Tool lines 229-238: CIccFileIO opens profile, reads length, Read8.
    const uint8_t *iccData = nullptr;
    size_t iccSize = 0;
    if (hasICC) {
        // ICC profile declares its own size at bytes 0-3 (big-endian).
        // Use the last portion of the payload as ICC data.
        // Minimum ICC: 128-byte header + 4-byte tag count = 132 bytes.
        // Split: last 1/4 of payload for ICC, rest for TIFF chunks.
        iccSize = payloadSize / 4;
        if (iccSize < 16) iccSize = 16;
        if (iccSize > 256 * 1024) iccSize = 256 * 1024; // 256K cap
        if (iccSize >= payloadSize - 8) {
            hasICC = false;  // not enough room for TIFF data
        } else {
            iccData = payload + (payloadSize - iccSize);
            payloadSize -= iccSize;
        }
    }

    // Each file gets an equal share of the TIFF payload
    size_t chunkSize = payloadSize / nFiles;
    if (chunkSize < 8) return 0;  // need TIFF magic at minimum

    const char *tmpdir = fuzz_tmpdir();
    TmpFiles tmp;

    // --- Gate 1: Write N raw TIFF blobs to temp files ---
    static const char *const kSuffixes[8] = {
        "/fuzz_sep_00_XXXXXX", "/fuzz_sep_01_XXXXXX",
        "/fuzz_sep_02_XXXXXX", "/fuzz_sep_03_XXXXXX",
        "/fuzz_sep_04_XXXXXX", "/fuzz_sep_05_XXXXXX",
        "/fuzz_sep_06_XXXXXX", "/fuzz_sep_07_XXXXXX",
    };
    for (uint8_t i = 0; i < nFiles; i++) {

        if (!tmp.add(tmpdir, kSuffixes[i]))
            return 0;

        const uint8_t *blob = payload + (size_t)i * chunkSize;
        size_t blobLen = (i == nFiles - 1) ? (payloadSize - (size_t)i * chunkSize) : chunkSize;

        if (!tmp.writeLast(blob, blobLen))
            return 0;
    }

    // Output temp file
    if (!tmp.add(tmpdir, "/fuzz_out_XXXXXX"))
        return 0;
    const char *outPath = tmp.paths[tmp.count - 1];

    // --- Gate 2: Open all input files (tool lines 162-165) ---
    std::vector<CTiffImg> infiles(nFiles);
    for (uint8_t i = 0; i < nFiles; i++) {
        if (!infiles[i].Open(tmp.paths[i]))
            return 0;

        // --- Gate 3: Per-file validation (tool lines 167-175) ---
        if (infiles[i].GetSamples() != 1)
            return 0;
        if (infiles[i].GetPhoto() == PHOTOMETRIC_PALETTE)
            return 0;

        // --- Gate 4: Format consistency (tool lines 177-185) ---
        if (i > 0) {
            if (infiles[i].GetWidth() != infiles[0].GetWidth() ||
                infiles[i].GetHeight() != infiles[0].GetHeight() ||
                infiles[i].GetBitsPerSample() != infiles[0].GetBitsPerSample() ||
                infiles[i].GetPhoto() != infiles[0].GetPhoto() ||
                infiles[i].GetXRes() != infiles[0].GetXRes() ||
                infiles[i].GetYRes() != infiles[0].GetYRes())
                return 0;
        }
    }

    // --- Gate 5: Photometric validation (tool lines 196-202) ---
    CTiffImg *f = &infiles[0];
    bool invert = false;
    if (f->GetPhoto() == PHOTO_MINISWHITE)
        invert = true;
    else if (f->GetPhoto() != PHOTO_MINISBLACK)
        return 0;

    // OOM guard: reject huge dimensions from malformed TIFFs
    if (f->GetWidth() > 4096 || f->GetHeight() > 4096)
        return 0;

    // --- Gate 6: BPS validation + buffer allocation (tool lines 204-210) ---
    // CFL-015: BPS must be byte-aligned; truncation (e.g. 14/8=1) undersizes
    // output buffer → HBO in CTiffImg::WriteLine via TIFFWriteEncodedStrip.
    if (f->GetBitsPerSample() % 8 != 0 || f->GetBitsPerSample() == 0)
        return 0;
    long bytePerLine = f->GetBytesPerLine();
    long bps_img = f->GetBitsPerSample() / 8;
    if (bytePerLine <= 0 || bps_img <= 0)
        return 0;

    // OOM guard: cap buffer allocation at 2MB
    size_t inBufSize = (size_t)bytePerLine * nFiles;
    size_t outBufSize = (size_t)f->GetWidth() * bps_img * nFiles;
    if (inBufSize > 2 * 1024 * 1024 || outBufSize > 2 * 1024 * 1024)
        return 0;

    std::unique_ptr<icUInt8Number[]> inbuffer(
        new (std::nothrow) icUInt8Number[inBufSize]);
    std::unique_ptr<icUInt8Number[]> outbuffer(
        new (std::nothrow) icUInt8Number[outBufSize]);
    if (!inbuffer || !outbuffer)
        return 0;

    icUInt8Number *inbuf = inbuffer.get();
    icUInt8Number *outbuf = outbuffer.get();

    // --- Gate 7: Resolution defaults (tool lines 212-218) ---
    float xRes = f->GetXRes();
    float yRes = f->GetYRes();
    if (xRes < 1) xRes = 72;
    if (yRes < 1) yRes = 72;

    // --- Gate 8: Create output TIFF (tool lines 220-225) ---
    CTiffImg outimg;
    if (!outimg.Create(outPath, f->GetWidth(), f->GetHeight(),
                       f->GetBitsPerSample(), PHOTO_MINISBLACK, nFiles, 0,
                       xRes, yRes, bCompress, bSep))
        return 0;

    // --- Gate 9: Optional ICC profile embedding (tool lines 229-238) ---
    // Tool reads raw ICC bytes via CIccFileIO.Open() + Read8(), then
    // calls outfile.SetIccProfile(). This exercises IccIO.cpp paths.
    std::unique_ptr<unsigned char[]> destProfile;
    if (hasICC && iccData && iccSize > 0) {
        // Write ICC data to a temp file, then read via CIccFileIO
        // (matches tool lines 229-237 exactly)
        if (tmp.add(tmpdir, "/fuzz_icc_XXXXXX") && tmp.writeLast(iccData, iccSize)) {
            CIccFileIO io;
            if (io.Open(tmp.paths[tmp.count - 1], "rb")) {
                size_t length = io.GetLength();
                if (length > 0 && length <= 256 * 1024) {
                    destProfile.reset(new (std::nothrow) unsigned char[length]);
                    if (destProfile) {
                        io.Read8(destProfile.get(), (icInt32Number)length);
                        outimg.SetIccProfile(destProfile.get(), (unsigned int)length);
                    }
                }
                io.Close();
            }
        }
    }

    // --- Gate 10: Scanline loop (tool lines 240-263) ---
    for (unsigned int i = 0; i < f->GetHeight(); i++) {
        bool readOk = true;
        for (uint8_t j = 0; j < nFiles; j++) {
            icUInt8Number *sptr = inbuf + j * bytePerLine;

            // Tool line 244: ReadLine per file
            if (!infiles[j].ReadLine(sptr)) {
                readOk = false;
                break;
            }

            // Tool lines 248-252: MINISWHITE inversion
            if (invert) {
                for (long k = 0; k < bytePerLine; k++)
                    sptr[k] ^= 0xff;
            }
        }
        if (!readOk) break;

        // Tool lines 254-261: Interleave planar → pixel-interleaved
        icUInt8Number *tptr = outbuf;
        for (unsigned int k = 0; k < f->GetWidth(); k++) {
            for (uint8_t j = 0; j < nFiles; j++) {
                icUInt8Number *sptr = inbuf + j * bytePerLine + k * bps_img;
                memcpy(tptr, sptr, bps_img);
                tptr += bps_img;
            }
        }

        // Tool line 262: Write interleaved scanline
        outimg.WriteLine(outbuf);
    }

    // Tool line 266: Close before buffer destruction
    outimg.Close();

    return 0;
}
