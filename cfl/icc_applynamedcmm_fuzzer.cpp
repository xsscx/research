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

/** @file
    LibFuzzer harness for the iccApplyNamedCmm profile-application path.

    Input is one unmodified ICC profile. There is no prefix, suffix, or
    reserved-byte control channel. Each parseable profile is exercised through
    a bounded matrix derived from the public positional and JSON controls:
    transform types, rendering intents, interpolation, BPC, PCS luminance,
    D2Bx/B2Dx, v5 subprofiles, named-color overprint, environment variables,
    input direction, encodings, pixel patterns, and a same-profile chain.

    Independent PCC files, JSON parsing/export, legacy data parsing, and the
    calculator debugger require additional inputs or tool-owned I/O. Those are
    intentionally covered by tool QA and the dedicated icc_cfg_fuzzer.
 */

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>

#include <memory>
#include <string>

#include "IccCmm.h"
#include "IccCmmConfig.h"
#include "IccConnect.h"
#include "IccDefs.h"
#include "IccProfile.h"
#include "IccUtil.h"
#include "fuzz_utils.h"

#define IsSpacePCS(x) ((x) == icSigXYZData || (x) == icSigLabData)

static constexpr size_t kMinProfileSize = 132;

class TempProfile {
public:
    TempProfile() {
        m_path[0] = '\0';
    }

    ~TempProfile() {
        if (m_path[0])
            unlink(m_path);
    }

    bool Write(const uint8_t *data, size_t size) {
        if (!fuzz_build_path(m_path, sizeof(m_path), fuzz_tmpdir(),
                             "/fuzz_applynamedcmm_XXXXXX.icc"))
            return false;

        int fd = mkstemps(m_path, 4);
        if (fd < 0) {
            m_path[0] = '\0';
            return false;
        }

        const uint8_t *cursor = data;
        size_t remaining = size;
        while (remaining) {
            ssize_t written = write(fd, cursor, remaining);
            if (written <= 0) {
                close(fd);
                unlink(m_path);
                m_path[0] = '\0';
                return false;
            }
            cursor += written;
            remaining -= static_cast<size_t>(written);
        }
        close(fd);
        return true;
    }

    const char *Path() const {
        return m_path;
    }

private:
    char m_path[512];
};

static void AddQaEnvironment(CIccCfgProfile &cfg, bool pcc_environment) {
    icCmmEnvSigMap &env = pcc_environment ? cfg.m_pccEnvVars : cfg.m_iccEnvVars;
    env[icGetSigVal("bkgX")] = 0.0985f;
    env[icGetSigVal("bkgY")] = 0.159f;
    env[icGetSigVal("bkgZ")] = 0.122f;
    env[icGetSigVal("ambL")] = 20.0f;
}

static CIccCfgProfilePtr MakeConfig(const char *path, int lut_type,
                                    icUInt32Number header_intent) {
    CIccCfgProfilePtr cfg(new CIccCfgProfile());
    if (!cfg)
        return cfg;

    cfg->reset();
    cfg->m_iccFile = path;
    cfg->m_intent = static_cast<int>((header_intent % 4 +
                                      static_cast<icUInt32Number>(lut_type)) % 4);
    cfg->m_interpolation = (lut_type & 1) ? icInterpLinear : icInterpTetrahedral;
    cfg->m_useD2BxB2Dx = lut_type != 1;
    cfg->m_adjustPcsLuminance = (lut_type % 3) == 0;
    cfg->m_useBPC = lut_type == 4;
    cfg->m_useV5SubProfile = lut_type == 10;
    cfg->m_useHToS = lut_type == 9;

    if (lut_type == 1) {
        cfg->m_transform = icXformLutColor;
        cfg->m_useD2BxB2Dx = false;
    }
    else if (lut_type == 3) {
        cfg->m_transform = icXformLutGamut;
    }
    else if (lut_type == 4) {
        cfg->m_transform = icXformLutColor;
    }
    else {
        cfg->m_transform = static_cast<icXformLutType>(lut_type);
    }

    if (cfg->m_transform == icXformLutNamedColor ||
        cfg->m_transform == icXformLutNamedColorimetric ||
        cfg->m_transform == icXformLutNamedSpectral ||
        cfg->m_transform == icXformLutNamedDevice) {
        cfg->m_nOverprint = static_cast<icNamedColorOverprintType>(lut_type % 3);
    }

    if (lut_type == 0)
        AddQaEnvironment(*cfg, false);
    if (lut_type == 10)
        AddQaEnvironment(*cfg, true);

    return cfg;
}

static void FillPixel(icFloatNumber *pixel, int samples, int pattern) {
    for (int i = 0; i < samples; i++) {
        switch (pattern) {
        case 0:
            pixel[i] = 0.0f;
            break;
        case 1:
            pixel[i] = 0.5f;
            break;
        case 2:
            pixel[i] = 1.0f;
            break;
        default:
            pixel[i] = static_cast<icFloatNumber>(i) /
                       static_cast<icFloatNumber>(samples > 1 ? samples - 1 : 1);
            break;
        }
    }
}

static void ExerciseApply(CIccNamedColorCmm *cmm, bool b_input_profile) {
    if (!cmm)
        return;

    icColorSpaceSignature src_space = cmm->GetSourceSpace();
    icColorSpaceSignature dst_space = cmm->GetDestSpace();
    bool clip = true;

    if (b_input_profile && IsSpacePCS(src_space)) {
        if (src_space == icSigXYZPcsData)
            src_space = icSigDevXYZData;
        else if (src_space == icSigLabPcsData)
            src_space = icSigDevLabData;
    }

    const int src_samples = icGetSpaceSamples(src_space);
    const int dst_samples = icGetSpaceSamples(dst_space);
    if ((src_space != icSigNamedData && (src_samples <= 0 || src_samples > 48)) ||
        (dst_space != icSigNamedData && (dst_samples <= 0 || dst_samples > 48)))
        return;

    icFloatNumber pixel[64] = {};
    icFloatNumber src_pixel[64] = {};
    icFloatNumber dst_pixel[64] = {};
    icFloatNumber encoded_pixel[64] = {};
    char dst_name[256] = {};

    if (src_space == icSigNamedData) {
        switch (cmm->GetInterface()) {
        case icApplyNamed2Pixel:
            if (!cmm->Apply(dst_pixel, "FuzzTestColor", 1.0f)) {
                for (int encoding = icEncodeValue; encoding <= icEncode16BitV2; encoding++) {
                    CIccCmm::FromInternalEncoding(dst_space,
                                                  static_cast<icFloatColorEncoding>(encoding),
                                                  encoded_pixel, dst_pixel,
                                                  encoding != icEncodeFloat);
                }
            }
            break;
        case icApplyNamed2Named:
            cmm->Apply(dst_name, "FuzzTestColor", 1.0f);
            break;
        default:
            break;
        }
        return;
    }

    for (int pattern = 0; pattern < 4; pattern++) {
        FillPixel(pixel, src_samples, pattern);
        for (int encoding = icEncodeValue; encoding <= icEncode16BitV2; encoding++) {
            icFloatColorEncoding src_encoding = static_cast<icFloatColorEncoding>(encoding);
            clip = true;
            if (b_input_profile &&
                (src_encoding == icEncodeFloat || src_encoding == icEncodeUnitFloat ||
                 src_encoding == icEncodePercent)) {
                clip = false;
            }
            if (CIccCmm::ToInternalEncoding(src_space, src_encoding, src_pixel, pixel, clip))
                continue;

            switch (cmm->GetInterface()) {
            case icApplyPixel2Pixel:
                if (!cmm->Apply(dst_pixel, src_pixel)) {
                    CIccCmm::FromInternalEncoding(dst_space, src_encoding,
                                                  encoded_pixel, dst_pixel);
                }
                break;
            case icApplyPixel2Named:
                cmm->Apply(dst_name, src_pixel);
                break;
            default:
                break;
            }
        }
    }
}

static void ExerciseConfig(const char *path, const CIccCfgProfilePtr &cfg,
                           icColorSpaceSignature src_space,
                           icColorSpaceSignature profile_color_space,
                           icProfileClassSignature device_class,
                           bool add_second_stage) {
    if (!cfg)
        return;

    CIccCfgProfileSequence sequence;
    sequence.m_profiles.push_back(cfg);
    if (add_second_stage) {
        CIccCfgProfilePtr second = MakeConfig(path, 0, cfg->m_intent);
        if (second)
            sequence.m_profiles.push_back(second);
    }

    bool b_input_profile = !IsSpacePCS(src_space);
    if (!b_input_profile && device_class != icSigAbstractClass &&
        IsSpacePCS(profile_color_space))
        b_input_profile = true;

    std::string error;
    std::unique_ptr<CIccConnectCmm> connection(
        CIccConnectCmm::CreateNamed(sequence, src_space, b_input_profile, &error));
    if (connection)
        ExerciseApply(connection->GetNamedCmm(), b_input_profile);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (!data || size < kMinProfileSize)
        return 0;

    TempProfile profile_file;
    if (!profile_file.Write(data, size))
        return 0;

    std::unique_ptr<CIccProfile> profile(OpenIccProfile(profile_file.Path()));
    if (!profile)
        return 0;

    const icColorSpaceSignature color_space = profile->m_Header.colorSpace;
    const icColorSpaceSignature pcs = profile->m_Header.pcs;
    const icProfileClassSignature device_class = profile->m_Header.deviceClass;
    const icUInt32Number header_intent = profile->m_Header.renderingIntent;
    profile.reset();

    if (icGetSpaceSamples(color_space) == 0 && color_space != icSigNamedData)
        return 0;

    for (int lut_type = icXformLutMinimum; lut_type <= icXformLutMaximum; lut_type++) {
        CIccCfgProfilePtr cfg = MakeConfig(profile_file.Path(), lut_type, header_intent);
        icColorSpaceSignature src_space = color_space;
        if (lut_type >= icXformLutNamedColorimetric)
            src_space = icSigNamedData;
        else if ((lut_type == icXformLutColorimetric || lut_type == icXformLutSpectral) &&
                 IsSpacePCS(pcs))
            src_space = pcs;
        ExerciseConfig(profile_file.Path(), cfg, src_space, color_space,
                       device_class, false);
    }

    CIccCfgProfilePtr chain_cfg = MakeConfig(profile_file.Path(), 0, header_intent);
    ExerciseConfig(profile_file.Path(), chain_cfg, color_space, color_space,
                   device_class, true);
    return 0;
}
