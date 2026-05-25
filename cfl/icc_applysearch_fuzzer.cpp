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
// icc_applysearch_fuzzer - Fuzzer for CIccCmmSearch (Nelder-Mead optimization)
//
// Exercises: CIccCmmSearch::AddXform(), Begin(), Apply(),
//   CIccApplyCmmSearch::costFunc(), boundsCheck(), findMin(),
//   AttachPCC(), SetDstInitProfile(), RemoveAllIO()
//
// Upstream tool: iccDEV/Tools/CmdLine/IccApplySearch/iccApplySearch.cpp
//
// Coverage target: IccCmmSearch.cpp (452 lines, previously 0%)
//
// Input format:
//   The complete LibFuzzer input is written as one ICC argv file. Baseline
//   mode uses it as the destination profile with fixed sRGB source. The weight
//   variant uses fixed source/destination profiles and the fuzzed file as PCC.
//   Control values are sampled from input bytes without removing bytes from
//   the argv file, so iccDEV sees the actual file length.
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
    if (size < 132 || size > 2 * 1024 * 1024) return 0;

    const uint8_t *ctrl = data;
    icRenderingIntent intent1 = static_cast<icRenderingIntent>(ctrl[0] % 4);
    icRenderingIntent intent2 = static_cast<icRenderingIntent>((size > 1 ? ctrl[1] : 1) % 4);
    uint8_t flags = (size > 2) ? ctrl[2] : 0;
    icXformInterp interp = (flags & 0x01) ? icInterpLinear : icInterpTetrahedral;
    bool use_bounds = (flags & 0x02) != 0;
#ifdef ICC_APPLYSEARCH_FUZZ_WEIGHTS
    bool use_pcc = true;
#else
    bool use_pcc = (flags & 0x04) != 0;
#endif
    uint8_t pixel_seed = (size > 3) ? ctrl[3] : 0;
#ifdef ICC_APPLYSEARCH_FUZZ_WEIGHTS
    static const icFloatNumber weight_cases[] = {
        1.0f,
        0.0f,
        -1.0f,
        0.5f,
        2.0f,
        static_cast<icFloatNumber>(0.0f / 0.0f)
    };
    icFloatNumber pcc_weight = weight_cases[(ctrl[2] >> 3) % (sizeof(weight_cases) / sizeof(weight_cases[0]))];
#else
    icFloatNumber pcc_weight = 1.0f;
#endif

    if (!fuzz_validate_icc_tags(data, size)) return 0;

    const char *tmpdir = fuzz_tmpdir();
    char fixed_srgb[512];
    if (!fuzz_find_repo_file(fixed_srgb, sizeof(fixed_srgb), __FILE__,
                             "test-profiles/sRGB_D65_MAT.icc"))
        return 0;

    char tmp_profile[512];
    if (!fuzz_build_path(tmp_profile, sizeof(tmp_profile), tmpdir, "/fuzz_search_XXXXXX.icc"))
        return 0;
    int fd = mkstemps(tmp_profile, 4);
    if (fd == -1) return 0;
    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(tmp_profile);
        return 0;
    }
    close(fd);

    // Construct CIccCmmSearch (exercises constructor with bounds config)
    CIccCmmSearch cmm(use_bounds);

    const char *src_profile = fixed_srgb;
    const char *dst_profile = tmp_profile;
#ifdef ICC_APPLYSEARCH_FUZZ_WEIGHTS
    dst_profile = fixed_srgb;
#endif

    // AddXform for source profile (matches tool line 367)
    icStatusCMM stat = cmm.CIccCmm::AddXform(src_profile, intent1, interp,
                                               nullptr, icXformLutColor, true, nullptr);
    if (stat != icCmmStatOk) {
        unlink(tmp_profile);
        return 0;
    }

    // AddXform for destination profile (matches tool line 367)
    stat = cmm.CIccCmm::AddXform(dst_profile, intent2, interp,
                                  nullptr, icXformLutColor, true, nullptr);
    if (stat != icCmmStatOk) {
        unlink(tmp_profile);
        return 0;
    }

    // Optional: AttachPCC - use the fuzzed argv file as PCC source.
    // Exercises IccPcc.cpp code paths
    if (use_pcc) {
        CIccProfile *pPcc = OpenIccProfile(tmp_profile);
        if (pPcc) {
            if (pPcc->ReadPccTags()) {
                pPcc->Detach();
                if (cmm.AttachPCC(pPcc, pcc_weight) != icCmmStatOk) {
                    delete pPcc;
                }
            } else {
                delete pPcc;
            }
        }
    }

    // Begin - builds internal CMM pipeline (the complex part of IccCmmSearch.cpp)
    stat = cmm.Begin();
    if (stat != icCmmStatOk) {
        unlink(tmp_profile);
        return 0;
    }

    // Get color spaces and validate
    icColorSpaceSignature srcSig = cmm.GetSourceSpace();
    icColorSpaceSignature dstSig = cmm.GetDestSpace();
    int nSrc = icGetSpaceSamples(srcSig);
    int nDst = icGetSpaceSamples(dstSig);

    if (nSrc <= 0 || nSrc > 16 || nDst <= 0 || nDst > 16) {
        cmm.RemoveAllIO();
        unlink(tmp_profile);
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

    unlink(tmp_profile);
    return 0;
}
