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

//
// icc_applysearch_fuzzer — Fuzzer for CIccCmmSearch (Nelder-Mead optimization)
//
// Exercises: CIccCmmSearch::AddXform(), Begin(), Apply(),
//   CIccApplyCmmSearch::costFunc(), boundsCheck(), findMin(),
//   AttachPCC(), SetDstInitProfile(), RemoveAllIO()
//
// Upstream tool: iccDEV/Tools/CmdLine/IccApplySearch/iccApplySearch.cpp
//
// Coverage target: IccCmmSearch.cpp (452 lines, previously 0%)
//
// Input format (2-profile split on ICC declared size):
//   [0..prof1_size-1]:  First ICC profile (source)
//   [prof1_size..N-5]:  Second ICC profile (destination)
//   [N-4]: intent1 (0-3)
//   [N-3]: intent2 (0-3)
//   [N-2]: interp (bit 0), use_bounds (bit 1), use_pcc (bit 2)
//   [N-1]: pixel seed byte
//

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cstdlib>
#include <new>
#include "IccCmmSearch.h"
#include "IccUtil.h"
#include "IccDefs.h"
#include "IccProfile.h"
#include "fuzz_utils.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Gate 0a: minimum size for 2 profiles + 4 control bytes
    if (size < 264 || size > 2 * 1024 * 1024) return 0;

    // Gate 0b: read first profile's declared size to split input
    uint32_t prof1_size = (static_cast<uint32_t>(data[0]) << 24) |
                          (static_cast<uint32_t>(data[1]) << 16) |
                          (static_cast<uint32_t>(data[2]) << 8)  |
                          static_cast<uint32_t>(data[3]);

    if (prof1_size < 132 || prof1_size > size - 136) return 0;

    const uint8_t *prof1_data = data;
    size_t prof1_len = prof1_size;

    const uint8_t *prof2_data = data + prof1_size;
    size_t prof2_len = size - prof1_size - 4;

    if (prof2_len < 132) return 0;

    // Control bytes are the last 4 bytes
    const uint8_t *ctrl = data + size - 4;
    icRenderingIntent intent1 = static_cast<icRenderingIntent>(ctrl[0] % 4);
    icRenderingIntent intent2 = static_cast<icRenderingIntent>(ctrl[1] % 4);
    icXformInterp interp = (ctrl[2] & 0x01) ? icInterpLinear : icInterpTetrahedral;
    bool use_bounds = (ctrl[2] & 0x02) != 0;
    bool use_pcc = (ctrl[2] & 0x04) != 0;
    uint8_t pixel_seed = ctrl[3];

    // Gate 0c: validate both profiles' tag tables
    if (!fuzz_validate_icc_tags(prof1_data, prof1_len)) return 0;
    if (!fuzz_validate_icc_tags(prof2_data, prof2_len)) return 0;

    const char *tmpdir = fuzz_tmpdir();

    // Write profile 1 to temp file
    char tmp_prof1[512];
    if (!fuzz_build_path(tmp_prof1, sizeof(tmp_prof1), tmpdir, "/fuzz_search1_XXXXXX.icc"))
        return 0;
    int fd = mkstemps(tmp_prof1, 4);
    if (fd == -1) return 0;
    write(fd, prof1_data, prof1_len);
    close(fd);

    // Write profile 2 to temp file
    char tmp_prof2[512];
    if (!fuzz_build_path(tmp_prof2, sizeof(tmp_prof2), tmpdir, "/fuzz_search2_XXXXXX.icc")) {
        unlink(tmp_prof1);
        return 0;
    }
    fd = mkstemps(tmp_prof2, 4);
    if (fd == -1) { unlink(tmp_prof1); return 0; }
    write(fd, prof2_data, prof2_len);
    close(fd);

    // Construct CIccCmmSearch (exercises constructor with bounds config)
    CIccCmmSearch cmm(use_bounds);

    // AddXform for source profile (matches tool line 367)
    icStatusCMM stat = cmm.CIccCmm::AddXform(tmp_prof1, intent1, interp,
                                               nullptr, icXformLutColor, true, nullptr);
    if (stat != icCmmStatOk) {
        unlink(tmp_prof1);
        unlink(tmp_prof2);
        return 0;
    }

    // AddXform for destination profile (matches tool line 367)
    stat = cmm.CIccCmm::AddXform(tmp_prof2, intent2, interp,
                                  nullptr, icXformLutColor, true, nullptr);
    if (stat != icCmmStatOk) {
        unlink(tmp_prof1);
        unlink(tmp_prof2);
        return 0;
    }

    // Optional: AttachPCC — use profile 1 as PCC source
    // Exercises IccPcc.cpp code paths
    if (use_pcc) {
        CIccProfile *pPcc = OpenIccProfile(tmp_prof1);
        if (pPcc) {
            if (pPcc->ReadPccTags()) {
                pPcc->Detach();
                cmm.AttachPCC(pPcc, 1.0);
            } else {
                delete pPcc;
            }
        }
    }

    // Begin — builds internal CMM pipeline (the complex part of IccCmmSearch.cpp)
    stat = cmm.Begin();
    if (stat != icCmmStatOk) {
        unlink(tmp_prof1);
        unlink(tmp_prof2);
        return 0;
    }

    // Get color spaces and validate
    icColorSpaceSignature srcSig = cmm.GetSourceSpace();
    icColorSpaceSignature dstSig = cmm.GetDestSpace();
    int nSrc = icGetSpaceSamples(srcSig);
    int nDst = icGetSpaceSamples(dstSig);

    if (nSrc <= 0 || nSrc > 16 || nDst <= 0 || nDst > 16) {
        cmm.RemoveAllIO();
        unlink(tmp_prof1);
        unlink(tmp_prof2);
        return 0;
    }

    // Synthesize test pixels and Apply
    // This triggers costFunc(), boundsCheck(), findMin() via Nelder-Mead
    icFloatNumber srcPixel[16] = {};
    icFloatNumber dstPixel[16] = {};

    // Fill source pixels from seed byte
    for (int i = 0; i < nSrc; i++) {
        srcPixel[i] = static_cast<icFloatNumber>((pixel_seed + i * 37) & 0xFF) / 255.0f;
    }

    cmm.Apply(dstPixel, srcPixel);

    // Second pixel with different values to exercise more optimization paths
    for (int i = 0; i < nSrc; i++) {
        srcPixel[i] = static_cast<icFloatNumber>((pixel_seed + i * 73 + 128) & 0xFF) / 255.0f;
    }
    cmm.Apply(dstPixel, srcPixel);

    // Exercise query methods
    (void)cmm.GetNumXforms();

    // Cleanup (exercises RemoveAllIO)
    cmm.RemoveAllIO();

    unlink(tmp_prof1);
    unlink(tmp_prof2);
    return 0;
}
