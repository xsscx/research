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
#include <memory>
#include <new>
#include <string>
#include <vector>
#include "IccConnect.h"
#include "IccCmmConfig.h"
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
#ifndef CFL_APPLYSEARCH_THREADED
    bool use_bounds = (flags & 0x02) != 0;
#endif
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

    const char *tmpdir = fuzz_tmpdir();
    char fixed_srgb[512];
    if (!fuzz_find_repo_file(fixed_srgb, sizeof(fixed_srgb), __FILE__,
                             "test-profiles/sRGB_v4_ICC_preference.icc"))
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

    const char *src_profile = fixed_srgb;
    const char *dst_profile = tmp_profile;
#ifdef ICC_APPLYSEARCH_FUZZ_WEIGHTS
    dst_profile = fixed_srgb;
#endif

#ifdef CFL_APPLYSEARCH_THREADED
    CIccCfgSearchApply search_apply;
    CIccCfgProfilePtr src_cfg(new (std::nothrow) CIccCfgProfile());
    CIccCfgProfilePtr dst_cfg(new (std::nothrow) CIccCfgProfile());
    if (!src_cfg || !dst_cfg) {
        unlink(tmp_profile);
        return 0;
    }

    src_cfg->m_iccFile = src_profile;
    src_cfg->m_intent = intent1;
    src_cfg->m_interpolation = interp;
    src_cfg->m_useD2BxB2Dx = (flags & 0x08) == 0;
    dst_cfg->m_iccFile = dst_profile;
    dst_cfg->m_intent = intent2;
    dst_cfg->m_interpolation = interp;
    dst_cfg->m_useD2BxB2Dx = (flags & 0x10) == 0;
    search_apply.m_profiles.push_back(src_cfg);
    search_apply.m_profiles.push_back(dst_cfg);

    if (use_pcc) {
        CIccCfgPccWeightPtr pcc_cfg(new (std::nothrow) CIccCfgPccWeight());
        if (pcc_cfg) {
            pcc_cfg->m_pccPath = tmp_profile;
            pcc_cfg->m_dWeight = pcc_weight;
            search_apply.m_pccWeights.push_back(pcc_cfg);
        }
    }

    std::string connect_error;
    std::unique_ptr<CIccConnectCmm> connection(
        CIccConnectCmm::CreateSearch(search_apply, &connect_error,
#ifdef CFL_APPLYSEARCH_THREADED
                                     4
#else
                                     1
#endif
        ));
    CIccCmmSearch *cmm = connection ? connection->GetSearchCmm() : nullptr;
    if (!cmm) {
        unlink(tmp_profile);
        return 0;
    }
#else
    std::unique_ptr<CIccCmmSearch> scalar_cmm(new (std::nothrow) CIccCmmSearch(use_bounds));
    if (!scalar_cmm) {
        unlink(tmp_profile);
        return 0;
    }
    icStatusCMM stat = scalar_cmm->CIccCmm::AddXform(
        src_profile, intent1, interp, nullptr, icXformLutColor, true, nullptr);
    if (stat != icCmmStatOk) {
        unlink(tmp_profile);
        return 0;
    }
    stat = scalar_cmm->CIccCmm::AddXform(
        dst_profile, intent2, interp, nullptr, icXformLutColor, true, nullptr);
    if (stat != icCmmStatOk) {
        unlink(tmp_profile);
        return 0;
    }
    if (use_pcc) {
        CIccProfile *pPcc = OpenIccProfile(tmp_profile);
        if (pPcc) {
            if (pPcc->ReadPccTags()) {
                pPcc->Detach();
                if (scalar_cmm->AttachPCC(pPcc, pcc_weight) != icCmmStatOk)
                    delete pPcc;
            } else {
                delete pPcc;
            }
        }
    }
    if (scalar_cmm->Begin() != icCmmStatOk) {
        unlink(tmp_profile);
        return 0;
    }
    CIccCmmSearch *cmm = scalar_cmm.get();
#endif

    // Get color spaces and validate
    icColorSpaceSignature srcSig = cmm->GetSourceSpace();
    icColorSpaceSignature dstSig = cmm->GetDestSpace();
    int nSrc = icGetSpaceSamples(srcSig);
    int nDst = icGetSpaceSamples(dstSig);

    if (nSrc <= 0 || nSrc > 16 || nDst <= 0 || nDst > 16) {
        unlink(tmp_profile);
        return 0;
    }

    // Synthesize test pixels and Apply
    // This triggers costFunc(), boundsCheck(), findMin() via Nelder-Mead
    const icUInt32Number nPixels =
#ifdef CFL_APPLYSEARCH_THREADED
        257;
#else
        1;
#endif
    std::vector<icFloatNumber> srcPixel(nPixels * nSrc, 0.0f);
    std::vector<icFloatNumber> dstPixel(nPixels * nDst, 0.0f);

    for (icUInt32Number p = 0; p < nPixels; ++p) {
        for (int i = 0; i < nSrc; ++i) {
            srcPixel[p * nSrc + i] =
                static_cast<icFloatNumber>((pixel_seed + p * 73 + i * 37) & 0xFF) / 255.0f;
        }
    }

#ifdef CFL_APPLYSEARCH_THREADED
    connection->GetCmm()->Apply(dstPixel.data(), srcPixel.data(), nPixels);
#else
    for (icUInt32Number p = 0; p < nPixels; ++p)
        cmm->Apply(dstPixel.data() + p * nDst, srcPixel.data() + p * nSrc);
#endif

    // Exercise query methods
    (void)cmm->GetNumXforms();

    unlink(tmp_profile);
    return 0;
}
