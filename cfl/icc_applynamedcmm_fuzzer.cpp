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
 * icc_applynamedcmm_fuzzer — 1:1 fidelity with iccApplyNamedCmm tool
 *
 * Upstream tool: iccDEV/Tools/CmdLine/IccApplyNamedCmm/iccApplyNamedCmm.cpp
 *
 * Gate sequence (matches tool main() lines 305-563):
 *   Gate 0a: size [132..1MB]
 *   Gate 0b: fuzz_validate_icc_tags() — offset/size/overflow checks
 *   Gate 1:  Write to temp file (CIccFileIO path — matches tool's OpenIccProfile)
 *   Gate 2:  Open profile, extract header fields
 *   Gate 3:  srcSpace = profile.colorSpace (matches what fromLegacy data file declares)
 *   Gate 4:  bInputProfile = !IsSpacePCS(srcSpace) with abstract class exception
 *   Gate 5:  CIccNamedColorCmm(srcSpace, icSigUnknownData, bInputProfile)
 *   Gate 6:  AddXform(path, intent, interp, ...) — path-based overload
 *   Gate 7:  Begin() — validates xform compatibility
 *   Gate 8:  GetInterface() → Apply with synthesized midrange test pixels
 *
 * Input: Entire fuzz input = ICC profile binary (no control header)
 *
 * srcSpace derivation: The upstream tool reads srcSpace from a user-provided
 * data file (fromLegacy line 1: "'RGB '"). A correctly-paired data file would
 * declare the profile's own colorSpace. We use profile.colorSpace directly,
 * which is semantically equivalent and exercises the same AddXform code path.
 *
 * Retired: Old fuzzer at cfl/retired/icc_applynamedcmm_fuzzer.cpp.retired-20260311
 * had srcSpace alignment gap causing crashes on profiles the tool cleanly rejects.
 */

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <string>
#include "IccCmm.h"
#include "IccUtil.h"
#include "IccProfile.h"
#include "IccDefs.h"
#include "IccApplyBPC.h"
#include "IccEnvVar.h"
#include "fuzz_utils.h"

// Match the tool's local macro (iccApplyNamedCmm.cpp line 91)
// Note: IccCmm.cpp internally uses a broader version that also checks spectral PCS.
// We use the tool's simpler version for bInputProfile determination — exactly as
// the tool does at line 327.
#define IsSpacePCS(x) ((x)==icSigXYZData || (x)==icSigLabData)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // --- Gate 0a: Size bounds ---
    if (size < 132 || size > 1024 * 1024)
        return 0;

    // --- Gate 0b: Tag table structural validation ---
    if (!fuzz_validate_icc_tags(data, size))
        return 0;

    // --- Gate 1: Write to temp file (CIccFileIO path) ---
    char tmp_path[512];
    if (!fuzz_build_path(tmp_path, sizeof(tmp_path), fuzz_tmpdir(),
                         "/fuzz_applynamedcmm.icc"))
        return 0;

    int fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return 0;
    ssize_t written = write(fd, data, size);
    close(fd);
    if (written != (ssize_t)size) {
        unlink(tmp_path);
        return 0;
    }

    // --- Gate 2: Read profile to extract header fields ---
    // Open a temporary copy just to read the header — matches tool opening
    // the profile to check deviceClass at line 330 before AddXform.
    CIccProfile *pProf = OpenIccProfile(tmp_path);
    if (!pProf) {
        unlink(tmp_path);
        return 0;
    }

    icColorSpaceSignature colorSpace = pProf->m_Header.colorSpace;
    (void)pProf->m_Header.pcs;  // read but not used — retained for documentation
    icProfileClassSignature deviceClass = pProf->m_Header.deviceClass;
    icRenderingIntent headerIntent =
        (icRenderingIntent)(pProf->m_Header.renderingIntent & 0x3);

    delete pProf;
    pProf = nullptr;

    // --- Gate 3: srcSpace = profile.colorSpace ---
    // Matches tool line 321: SrcspaceSig = cfgData.m_srcSpace
    // A correctly-paired data file declares the profile's own colorSpace.
    icColorSpaceSignature srcSpace = colorSpace;

    // Validate srcSpace yields > 0 samples (or is named data)
    icUInt32Number nSrcSamples = icGetSpaceSamples(srcSpace);
    if (nSrcSamples == 0 && srcSpace != icSigNamedData) {
        unlink(tmp_path);
        return 0;
    }

    // --- Gate 4: bInputProfile (tool lines 327-336) ---
    // "If first profile colorspace is PCS and it matches the source data space
    //  then treat as input profile" — except abstract profiles stay as output.
    bool bInputProfile = !IsSpacePCS(srcSpace);
    if (!bInputProfile) {
        // Tool opens profile again to check deviceClass and colorSpace
        if (deviceClass != icSigAbstractClass && IsSpacePCS(colorSpace))
            bInputProfile = true;
    }

    // --- Gate 5: Construct CIccNamedColorCmm (tool line 339) ---
    CIccNamedColorCmm namedCmm(srcSpace, icSigUnknownData, bInputProfile);

    // --- Gate 6: AddXform — path-based (tool lines 381-388) ---
    // The tool iterates over a profile sequence; we use a single profile.
    // Intent from header (tool gets it from fromArgs → nIntent%10, clamped 0-3).
    // interpolation = icInterpLinear (tool default)
    // xformType = icXformLutColor (tool default when nType=0)
    // useD2BxB2Dx = true (tool default)
    // bUseSubProfile = false (tool default)
    icStatusCMM stat = namedCmm.AddXform(
        tmp_path,
        headerIntent,
        icInterpLinear,
        nullptr,               // pPcc
        icXformLutColor,       // nLutType
        true,                  // bUseD2BxB2DxTags
        nullptr,               // pHintManager — no BPC/luminance for base case
        false                  // bUseSubProfile
    );

    if (stat != icCmmStatOk) {
        unlink(tmp_path);
        return 0;
    }

    // --- Gate 7: Begin() (tool line 397) ---
    stat = namedCmm.Begin();
    if (stat != icCmmStatOk) {
        unlink(tmp_path);
        return 0;
    }

    // --- Gate 8: Apply (tool lines 462-563) ---
    // Get source/dest spaces post-Begin (tool lines 408-413)
    icColorSpaceSignature SrcspaceSig = namedCmm.GetSourceSpace();
    icColorSpaceSignature DestspaceSig = namedCmm.GetDestSpace();

    nSrcSamples = icGetSpaceSamples(SrcspaceSig);
    icUInt32Number nDestSamples = icGetSpaceSamples(DestspaceSig);

    // Gate 8a: MPE Apply copies nSrcSamples/nDestSamples floats into caller buffers.
    // Upstream tool uses CIccPixelBuf (dynamic). We use fixed stack arrays.
    // Skip profiles with channel counts exceeding buffer capacity.
    // Crash ref: crash-4bfc817104995c431c3cc96a8331d149f92cd740 (81-ch spac profile)
    if (nSrcSamples == 0 || nSrcSamples > 48 || nDestSamples == 0 || nDestSamples > 48) {
        unlink(tmp_path);
        return 0;
    }

    // Allocate pixel buffers (tool lines 432-433: CIccPixelBuf with +16 headroom)
    icFloatNumber SrcPixel[48] = {};
    icFloatNumber DestPixel[48] = {};
    char DestNameBuf[256] = {};

    // Synthesize 1 midrange test pixel (0.5 per channel)
    for (icUInt32Number i = 0; i < nSrcSamples && i < 48; i++)
        SrcPixel[i] = 0.5f;

    switch (namedCmm.GetInterface()) {
        case icApplyPixel2Pixel:
            // Tool lines 530-546: ToInternalEncoding → Apply → FromInternalEncoding
            // We skip encoding conversion (use icEncodeFloat equivalent — raw floats)
            namedCmm.Apply(DestPixel, SrcPixel);
            break;

        case icApplyPixel2Named:
            // Tool lines 547-555
            namedCmm.Apply(DestNameBuf, SrcPixel);
            break;

        case icApplyNamed2Pixel:
            // Tool lines 480-504: named color input
            // Synthesize a generic color name — Apply will search named color table
            namedCmm.Apply(DestPixel, "FuzzTestColor", 1.0f);
            break;

        case icApplyNamed2Named:
            // Tool lines 505-517
            namedCmm.Apply(DestNameBuf, "FuzzTestColor", 1.0f);
            break;

        default:
            break;
    }

    unlink(tmp_path);
    return 0;
}
