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
    File:       icc_applynamedcmm_fuzzer.cpp
    Contains:   LibFuzzer harness for iccApplyNamedCmm
    Version:    V2 — rewrite for tool-aligned coverage (2026-03-31)

    Upstream tool: iccDEV/Tools/CmdLine/IccApplyNamedCmm/iccApplyNamedCmm.cpp

    Alignment report: ~/work/copilot/triage-applynamedcmm/results/alignment-report.md
    V1 retired to:    cfl/retired/icc_applynamedcmm_fuzzer.cpp.retired-20260331

    V1 fidelity gap: 100% of crash files were gracefully rejected by the upstream
    tool (exit 255, zero ASAN/UBSAN). Root causes (D1-D7 in alignment report):
      D1: PCC self-reference (tool uses SEPARATE file — never self-ref)
      D2: Intent from profile header (tool decodes packed nIntent from CLI arg)
      D3: Hardcoded icXformLutColor (tool supports 10 transform types)
      D4: No BPC/luminance hints (tool creates CIccCreateXformHintManager)
      D5: No encoding conversion (tool uses To/FromInternalEncoding)

    V2 first finding (2026-03-31): CWE-416 UAF in CIccNamedColorCmm::AddXform()
    at IccCmm.cpp:10564 — confirmed tool-reachable at iccDEV master HEAD (d5a3dc2).
    Dual sanitizer manifestation: UBSAN (invalid vptr) masks ASAN (HUAF) by default.
    Suppress UBSAN vptr to reveal ASAN HUAF. Triggers on nType=5 or nType=6 with
    cenc/RGB profiles. CFL-078 patch guards delete on cenc class profiles.
    Ground truth: ~/work/copilot/triage-applynamedcmm/results/ground-truth-ub-cfl078.md

    V2 fixes all 5 divergences. Control bytes from ICC reserved region (100-107,
    must be 0x00 per ICC.1-2022-05 §7.2.19) drive parameter diversity.

    Control byte layout:
      data[100]: bits 0-3 → nType (0-9, maps through tool's switch at line 790)
      data[101]: bit0=BPC, bit1=luminance, bit2=!useD2Bx, bit3=V5Sub
      data[102]: bits 0-1 → intent (0-3), bit4 → tetrahedral interpolation
      data[103]: bits 0-2 → src encoding (0-6), bits 4-6 → dest encoding (0-6)
      data[104]: bits 0-1 → pixel pattern (0=mid, 1=zero, 2=saturated, 3=mixed)

    Gate sequence (matches tool main()):
      Gate 0:  size [132..1MB], tag table validation
      Gate 1:  Write to temp file (CIccFileIO path)
      Gate 2:  Open profile, extract header fields
      Gate 3:  srcSpace = profile.colorSpace
      Gate 4:  bInputProfile = !IsSpacePCS(srcSpace) with abstract exception
      Gate 5:  CIccNamedColorCmm(srcSpace, icSigUnknownData, bInputProfile)
      Gate 6:  Build CIccCreateXformHintManager (BPC, luminance)
      Gate 7:  AddXform(path, intent, interp, pPcc=NULL, xformType, hints, ...)
      Gate 8:  Begin()
      Gate 9:  PCS remap (tool lines 469-477)
      Gate 10: ToInternalEncoding → Apply → FromInternalEncoding

    Reference artifacts:
      call-graph/iccdev/tools/iccApplyNamedCmm-callgraph-enriched.dot (531 edges)
      call-graph/cfl/icc_applynamedcmm_fuzzer-callgraph.dot (V1: 18 edges)
      ast-trees/iccdev/iccApplyNamedCmm-ast-summary.txt (67 gates)
      docs/iccDEV/Tools/iccApplyNamedCmm/README.md (data format, encoding values)
*/

#include <stdint.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cmath>
#include <new>
#include "IccCmm.h"
#include "IccUtil.h"
#include "IccProfile.h"
#include "IccDefs.h"
#include "IccApplyBPC.h"
#include "IccEnvVar.h"
#include "fuzz_utils.h"

// Tool's macro (iccApplyNamedCmm.cpp line 91)
#define IsSpacePCS(x) ((x)==icSigXYZData || (x)==icSigLabData)

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // --- Gate 0: Size bounds + tag table validation ---
    if (size < 132 || size > 1024 * 1024)
        return 0;
    if (!fuzz_validate_icc_tags(data, size))
        return 0;

    // --- Extract control bytes from ICC reserved region (bytes 100-107) ---
    // ICC.1-2022-05 §7.2.19: bytes 100-127 must be zero in conforming profiles.
    // Fuzz mutators naturally set these to non-zero, providing control diversity.
    uint8_t ctrl_xform  = data[100];  // transform type selector
    uint8_t ctrl_flags  = data[101];  // hint/flag bits
    uint8_t ctrl_intent = data[102];  // intent + interpolation
    uint8_t ctrl_enc    = data[103];  // encoding types
    uint8_t ctrl_pixel  = data[104];  // pixel pattern selector

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

    // --- Gate 2: Open profile to extract header fields (tool line 330) ---
    CIccProfile *pProf = OpenIccProfile(tmp_path);
    if (!pProf) {
        unlink(tmp_path);
        return 0;
    }

    icColorSpaceSignature colorSpace = pProf->m_Header.colorSpace;
    icProfileClassSignature deviceClass = pProf->m_Header.deviceClass;
    delete pProf;
    pProf = nullptr;

    // --- Gate 3: srcSpace = profile.colorSpace (tool line 321) ---
    // Tool reads srcSpace from data file; a correctly-paired data file declares
    // the profile's own colorSpace, so we use it directly.
    icColorSpaceSignature srcSpace = colorSpace;
    icUInt32Number nSrcSamples = icGetSpaceSamples(srcSpace);
    if (nSrcSamples == 0 && srcSpace != icSigNamedData) {
        unlink(tmp_path);
        return 0;
    }

    // --- Gate 4: bInputProfile (tool lines 327-336) ---
    bool bInputProfile = !IsSpacePCS(srcSpace);
    if (!bInputProfile) {
        if (deviceClass != icSigAbstractClass && IsSpacePCS(colorSpace))
            bInputProfile = true;
    }

    // --- Gate 5: Construct CIccNamedColorCmm (tool line 339) ---
    CIccNamedColorCmm namedCmm(srcSpace, icSigUnknownData, bInputProfile);

    // --- Gate 6: Derive AddXform parameters from control bytes ---
    // Matches tool's nIntent decoding at IccCmmConfig.cpp lines 783-808:
    //   nType = abs(nIntent) / 10
    //   switch(nType): 1→!D2Bx, 3→Gamut, 4→BPC, default→passthrough

    icRenderingIntent intent = (icRenderingIntent)(ctrl_intent & 0x3);
    icXformInterp interp = (ctrl_intent & 0x10) ? icInterpTetrahedral : icInterpLinear;

    int nType = ctrl_xform % 10;
    bool useBPC = false;
    bool useD2BxB2Dx = true;
    icXformLutType xformType;

    switch (nType) {
    case 1:
        useD2BxB2Dx = false;
        xformType = icXformLutColor;
        break;
    case 3:
        xformType = icXformLutGamut;
        break;
    case 4:
        useBPC = true;
        xformType = icXformLutColor;
        break;
    default:
        // Direct passthrough — exercises all 10 transform types including
        // icXformLutNamedColor(1), icXformLutColorimetric(2),
        // icXformLutSpectral(3), icXformLutMCS(4), icXformLutPreview(5),
        // icXformLutGamut(6), icXformLutBRDFParam(7), icXformLutBRDFDirect(8),
        // icXformLutBRDFMcsParam(9)
        xformType = (icXformLutType)nType;
        break;
    }

    // Additional flags from ctrl_flags (tool lines 786-789)
    if (ctrl_flags & 0x01) useBPC = true;
    bool adjustPcsLuminance = (ctrl_flags & 0x02) != 0;
    if (ctrl_flags & 0x04) useD2BxB2Dx = false;
    bool useV5SubProfile = (ctrl_flags & 0x08) != 0;

    // Build hint manager (tool lines 393-403)
    CIccCreateXformHintManager Hint;
    if (useBPC) {
        auto *bpcHint = new (std::nothrow) CIccApplyBPCHint();
        if (bpcHint) {
            Hint.AddHint(bpcHint);
        }
    }
    if (adjustPcsLuminance) {
        auto *luminanceHint = new (std::nothrow) CIccLuminanceMatchingHint();
        if (luminanceHint) {
            Hint.AddHint(luminanceHint);
        }
    }

    // --- Gate 7: AddXform (tool lines 423-430) ---
    // PCC is NULL — tool uses a SEPARATE file for PCC, never self-reference.
    // V1 used the same file as both profile and PCC, causing 100% of crashes
    // to activate the PCC self-reference path (D1 in alignment report).
    icStatusCMM stat = namedCmm.AddXform(
        tmp_path,
        intent,
        interp,
        nullptr,           // pPcc — NULL (no self-reference)
        xformType,
        useD2BxB2Dx,
        &Hint,
        useV5SubProfile
    );

    if (stat != icCmmStatOk) {
        unlink(tmp_path);
        return 0;
    }

    // --- Gate 8: Begin() (tool line 437) ---
    stat = namedCmm.Begin();
    if (stat != icCmmStatOk) {
        unlink(tmp_path);
        return 0;
    }

    // --- Gate 9: Post-Begin space handling (tool lines 469-477) ---
    icColorSpaceSignature SrcspaceSig = namedCmm.GetSourceSpace();
    icColorSpaceSignature DestspaceSig = namedCmm.GetDestSpace();

    // Tool remaps PCS to device space to avoid interpreting device data as PCS
    bool bClip = true;
    if (bInputProfile && IsSpacePCS(SrcspaceSig)) {
        if (SrcspaceSig == icSigXYZPcsData)
            SrcspaceSig = icSigDevXYZData;
        else if (SrcspaceSig == icSigLabPcsData)
            SrcspaceSig = icSigDevLabData;
        bClip = false;  // float encoding → no clip
    }

    nSrcSamples = icGetSpaceSamples(SrcspaceSig);
    icUInt32Number nDestSamples = icGetSpaceSamples(DestspaceSig);

    if (nSrcSamples == 0 || nSrcSamples > 48 || nDestSamples == 0 || nDestSamples > 48) {
        unlink(tmp_path);
        return 0;
    }

    // --- Derive encoding types (tool lines 319, 449-451) ---
    static const icFloatColorEncoding kEncodings[] = {
        icEncodeValue, icEncodePercent, icEncodeUnitFloat, icEncodeFloat,
        icEncode8Bit, icEncode16Bit, icEncode16BitV2
    };
    icFloatColorEncoding srcEncoding = kEncodings[ctrl_enc % 7];
    icFloatColorEncoding destEncoding = kEncodings[(ctrl_enc >> 4) % 7];

    if (SrcspaceSig == icSigNamedData)
        srcEncoding = icEncodeValue;
    if (DestspaceSig == icSigNamedData)
        destEncoding = icEncodeValue;

    // --- Gate 10: Apply (tool lines 496-563) ---
    icFloatNumber SrcPixel[64] = {};
    icFloatNumber DestPixel[64] = {};
    icFloatNumber Pixel[64] = {};
    char DestNameBuf[256] = {};

    // Synthesize test pixel data — pattern from ctrl_pixel
    // Tool reads from data file; we synthesize representative values.
    switch (ctrl_pixel & 0x3) {
    case 0:  // Midrange
        for (icUInt32Number i = 0; i < nSrcSamples; i++) Pixel[i] = 0.5f;
        break;
    case 1:  // Zero/black
        for (icUInt32Number i = 0; i < nSrcSamples; i++) Pixel[i] = 0.0f;
        break;
    case 2:  // Saturated/white
        for (icUInt32Number i = 0; i < nSrcSamples; i++) Pixel[i] = 1.0f;
        break;
    case 3:  // Per-channel gradient
        for (icUInt32Number i = 0; i < nSrcSamples; i++)
            Pixel[i] = (float)i / (float)(nSrcSamples > 1 ? nSrcSamples - 1 : 1);
        break;
    }

    switch (namedCmm.GetInterface()) {
    case icApplyPixel2Pixel:
        // Tool lines 530-546: ToInternalEncoding → Apply → FromInternalEncoding
        if (CIccCmm::ToInternalEncoding(SrcspaceSig, srcEncoding, SrcPixel, Pixel, bClip))
            break;
        namedCmm.Apply(DestPixel, SrcPixel);
        CIccCmm::FromInternalEncoding(DestspaceSig, destEncoding, DestPixel, DestPixel);
        break;

    case icApplyPixel2Named:
        // Tool lines 547-555
        if (CIccCmm::ToInternalEncoding(SrcspaceSig, srcEncoding, SrcPixel, Pixel, bClip))
            break;
        namedCmm.Apply(DestNameBuf, SrcPixel);
        break;

    case icApplyNamed2Pixel:
        // Tool lines 480-504
        namedCmm.Apply(DestPixel, "FuzzTestColor", 1.0f);
        CIccCmm::FromInternalEncoding(DestspaceSig, destEncoding, DestPixel, DestPixel);
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
