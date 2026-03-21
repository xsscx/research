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

/**
 * @file IccAnalyzerLUTTextIO.cpp
 * @brief Text-based LUT export/import for round-trip ICC profile editing + .cube support
 *
 * Exports LUT components (curves, CLUTs, matrices) as editable TSV text files.
 * Imports edited TSV files back into ICC profiles with full validation.
 * Also supports .cube 3D LUT export/import.
 *
 * All parsing uses defensive programming: NaN/Inf rejection, overflow-safe
 * arithmetic, value clamping, and ASAN+UBSAN instrumentation.
 */

#include "IccAnalyzerCommon.h"
#include "IccAnalyzerLUT.h"
#include "IccAnalyzerSafeArithmetic.h"
#include "IccAnalyzerSecurity.h"
#include "IccHeuristicsHelpers.h"
#include <cmath>
#include <cstring>
#include <cerrno>
#include <climits>
#include <new>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <libgen.h>
#include <sstream>
#include <algorithm>

// Safety limits
static constexpr size_t kMaxImportFileSize  = 100 * 1024 * 1024;
static constexpr size_t kMaxImportLineCount = 10 * 1000 * 1000;
static constexpr int    kMaxGridDim         = 256;
static constexpr int    kMaxChannels        = 16;
static constexpr int    kMaxCurveSamples    = 65536;
static constexpr size_t kMaxLineLen         = 4096;

// ═══════════════════════════════════════════════════════════════════════════════
// Secure file helpers (shared with IccAnalyzerLUT.cpp via static linkage)
// ═══════════════════════════════════════════════════════════════════════════════

static FILE *SecureFileOpenText(const char *path, const char *mode) {
    if (!path || !path[0]) return nullptr;
    size_t len = strlen(path);
    if (len > 4096 || strstr(path, "..")) return nullptr;

    char pathCopy[PATH_MAX];
    strncpy(pathCopy, path, PATH_MAX - 1);
    pathCopy[PATH_MAX - 1] = '\0';
    char *dir = dirname(pathCopy);
    char resolvedDir[PATH_MAX];
    if (!realpath(dir, resolvedDir)) return nullptr;

    char pathCopy2[PATH_MAX];
    strncpy(pathCopy2, path, PATH_MAX - 1);
    pathCopy2[PATH_MAX - 1] = '\0';
    char *base = basename(pathCopy2);

    char resolvedPath[PATH_MAX];
    int n = snprintf(resolvedPath, PATH_MAX, "%s/%s", resolvedDir, base);
    if (n < 0 || n >= PATH_MAX) return nullptr;

    if (mode[0] == 'r') {
        return fopen(resolvedPath, mode);
    }
    int flags = O_WRONLY | O_CREAT | O_TRUNC;
    int fd = open(resolvedPath, flags, S_IRUSR | S_IWUSR);
    if (fd < 0) return nullptr;
    FILE *f = fdopen(fd, "w");
    if (!f) close(fd);
    return f;
}

static std::string SanitizeTag(const char *raw) {
    std::string out;
    if (!raw) return "unknown";
    for (const char *p = raw; *p; ++p) {
        char c = *p;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') || c == '_' || c == '-')
            out += c;
        else
            out += '_';
    }
    return out.empty() ? "unknown" : out;
}

/// Parse float with NaN/Inf rejection

/// Resolve a tag name string to its icTagSignature
static icTagSignature ResolveTagSig(const char *name) {
    if (!name || !name[0]) return icSigAToB0Tag;
    // Common friendly names
    if (strcmp(name, "A2B0") == 0 || strcmp(name, "AToB0Tag") == 0) return icSigAToB0Tag;
    if (strcmp(name, "A2B1") == 0 || strcmp(name, "AToB1Tag") == 0) return icSigAToB1Tag;
    if (strcmp(name, "A2B2") == 0 || strcmp(name, "AToB2Tag") == 0) return icSigAToB2Tag;
    if (strcmp(name, "B2A0") == 0 || strcmp(name, "BToA0Tag") == 0) return icSigBToA0Tag;
    if (strcmp(name, "B2A1") == 0 || strcmp(name, "BToA1Tag") == 0) return icSigBToA1Tag;
    if (strcmp(name, "B2A2") == 0 || strcmp(name, "BToA2Tag") == 0) return icSigBToA2Tag;
    if (strcmp(name, "DToB0Tag") == 0) return icSigDToB0Tag;
    if (strcmp(name, "DToB1Tag") == 0) return icSigDToB1Tag;
    if (strcmp(name, "DToB2Tag") == 0) return icSigDToB2Tag;
    if (strcmp(name, "DToB3Tag") == 0) return icSigDToB3Tag;
    if (strcmp(name, "BToD0Tag") == 0) return icSigBToD0Tag;
    if (strcmp(name, "BToD1Tag") == 0) return icSigBToD1Tag;
    if (strcmp(name, "BToD2Tag") == 0) return icSigBToD2Tag;
    if (strcmp(name, "BToD3Tag") == 0) return icSigBToD3Tag;
    if (strcmp(name, "customToStandardPccTag") == 0) return icSigCustomToStandardPccTag;
    if (strcmp(name, "standardToCustomPccTag") == 0) return icSigStandardToCustomPccTag;
    // 4-byte raw signature
    if (strlen(name) == 4) {
        return (icTagSignature)(((uint32_t)(unsigned char)name[0] << 24) |
               ((uint32_t)(unsigned char)name[1] << 16) |
               ((uint32_t)(unsigned char)name[2] << 8) |
                (uint32_t)(unsigned char)name[3]);
    }
    return icSigAToB0Tag;
}

/// Parse "# Tag:" header from text file, return resolved signature
static icTagSignature ParseTagFromFile(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return icSigAToB0Tag;
    char line[kMaxLineLen];
    icTagSignature sig = icSigAToB0Tag;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] != '#') break;
        if (strncmp(line, "# Tag:", 6) == 0) {
            char *p = line + 6;
            while (*p == ' ' || *p == '\t') p++;
            // Trim trailing whitespace/newline
            char *end = p + strlen(p) - 1;
            while (end > p && (*end == '\n' || *end == '\r' || *end == ' ')) *end-- = '\0';
            sig = ResolveTagSig(p);
            break;
        }
    }
    fclose(f);
    return sig;
}
static bool SafeFloat(const char *str, float &out, bool clamp01 = true) {
    if (!str || !str[0]) return false;
    char *end = nullptr;
    errno = 0;
    float val = strtof(str, &end);
    if (errno != 0 || end == str || std::isnan(val) || std::isinf(val))
        return false;
    if (clamp01) {
        if (val < 0.0f) val = 0.0f;
        if (val > 1.0f) val = 1.0f;
    }
    out = val;
    return true;
}

/// Parse float without clamping (for matrix values)
static bool SafeFloatUnclamped(const char *str, float &out) {
    if (!str || !str[0]) return false;
    char *end = nullptr;
    errno = 0;
    float val = strtof(str, &end);
    if (errno != 0 || end == str || std::isnan(val) || std::isinf(val))
        return false;
    if (val > 1e6f) val = 1e6f;
    if (val < -1e6f) val = -1e6f;
    out = val;
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEXT EXPORT — CIccMBB (lutAtoB/lutBtoA/lut8/lut16)
// ═══════════════════════════════════════════════════════════════════════════════

/// Export MBB curves (A/B/M) as editable TSV text
static int ExportMBBCurves(CIccMBB *pMBB, const char *tagName,
                           const char *curveSet, LPIccCurve *curves,
                           int nChannels, const char *baseName)
{
    if (!curves || nChannels <= 0) return 0;
    int exported = 0;
    std::string safeTag = SanitizeTag(tagName);

    for (int ch = 0; ch < nChannels && ch < kMaxChannels; ch++) {
        CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve*>(curves[ch]);
        if (!pCurve) continue;

        icUInt32Number nEntries = pCurve->GetSize();
        if (nEntries == 0 || nEntries > kMaxCurveSamples) continue;

        char filename[512];
        snprintf(filename, sizeof(filename), "%s_%s_curve%s_%d.txt",
                 baseName, safeTag.c_str(), curveSet, ch);

        FILE *f = SecureFileOpenText(filename, "w");
        if (!f) continue;

        fprintf(f, "# ICC Profile 1D LUT Export\n");
        fprintf(f, "# Tag: %s\n", tagName);
        fprintf(f, "# Curve: %s curve%s[%d]\n", tagName, curveSet, ch);
        fprintf(f, "# Samples: %u\n", nEntries);
        fprintf(f, "# Format: input(normalized 0-1) <tab> output(normalized 0-1)\n");
        fprintf(f, "#\n");
        fprintf(f, "input\toutput\n");

        for (icUInt32Number j = 0; j < nEntries; j++) {
            float input = (nEntries > 1)
                ? static_cast<float>(j) / static_cast<float>(nEntries - 1)
                : 0.0f;
            float output = (*pCurve)[j];
            if (std::isnan(output) || std::isinf(output)) output = 0.0f;
            fprintf(f, "%.9f\t%.9f\n", input, output);
        }

        fclose(f);
        printf("  Wrote curve %s[%d]: %s (%u samples)\n",
               curveSet, ch, filename, nEntries);
        exported++;
    }
    return exported;
}

/// Export MBB CLUT as editable TSV text
static int ExportMBBCLUT(CIccCLUT *pCLUT, const char *tagName,
                         const char *baseName)
{
    if (!pCLUT) return 0;

    int inputDim = pCLUT->GetInputDim();
    int outCh = pCLUT->GetOutputChannels();
    if (inputDim <= 0 || inputDim > kMaxChannels || outCh <= 0 || outCh > kMaxChannels)
        return 0;

    uint64_t totalEntries = 1;
    for (int d = 0; d < inputDim; d++) {
        icUInt32Number gp = pCLUT->GridPoint(d);
        if (gp == 0 || gp > kMaxGridDim) return 0;
        if (totalEntries > UINT32_MAX / gp) return 0;
        totalEntries *= gp;
    }

    icFloatNumber *data = pCLUT->GetData(0);
    if (!data) return 0;

    std::string safeTag = SanitizeTag(tagName);
    char filename[512];
    snprintf(filename, sizeof(filename), "%s_%s_clut.txt",
             baseName, safeTag.c_str());

    FILE *f = SecureFileOpenText(filename, "w");
    if (!f) return 0;

    fprintf(f, "# ICC Profile CLUT Export\n");
    fprintf(f, "# Tag: %s\n", tagName);
    fprintf(f, "# Input channels: %d\n", inputDim);
    fprintf(f, "# Output channels: %d\n", outCh);
    fprintf(f, "# Grid points:");
    for (int d = 0; d < inputDim; d++)
        fprintf(f, " %u", pCLUT->GridPoint(d));
    fprintf(f, "\n");
    fprintf(f, "# Total grid entries: %llu\n", (unsigned long long)totalEntries);
    fprintf(f, "# Values are normalized floats (0.0 - 1.0)\n");
    fprintf(f, "#\n");

    // Column headers
    for (int d = 0; d < inputDim; d++)
        fprintf(f, "in%d\t", d);
    for (int c = 0; c < outCh; c++) {
        fprintf(f, "out%d", c);
        if (c < outCh - 1) fprintf(f, "\t");
    }
    fprintf(f, "\n");

    // Grid data — iterate all grid positions
    std::vector<int> idx(inputDim, 0);
    std::vector<int> gridSizes(inputDim);
    for (int d = 0; d < inputDim; d++)
        gridSizes[d] = pCLUT->GridPoint(d);

    uint64_t dataIdx = 0;
    for (uint64_t entry = 0; entry < totalEntries; entry++) {
        // Input coordinates (normalized)
        for (int d = 0; d < inputDim; d++) {
            float norm = (gridSizes[d] > 1)
                ? static_cast<float>(idx[d]) / static_cast<float>(gridSizes[d] - 1)
                : 0.0f;
            fprintf(f, "%.9f\t", norm);
        }
        // Output values
        for (int c = 0; c < outCh; c++) {
            float val = data[dataIdx++];
            if (std::isnan(val) || std::isinf(val)) val = 0.0f;
            fprintf(f, "%.9f", val);
            if (c < outCh - 1) fprintf(f, "\t");
        }
        fprintf(f, "\n");

        // Increment multi-dimensional index (innermost first)
        for (int d = inputDim - 1; d >= 0; d--) {
            idx[d]++;
            if (idx[d] < gridSizes[d]) break;
            idx[d] = 0;
        }
    }

    fclose(f);
    printf("  Wrote CLUT: %s (%llu entries × %d outputs)\n",
           filename, (unsigned long long)totalEntries, outCh);
    return 1;
}

/// Export MBB matrix as editable TSV text
static int ExportMBBMatrix(CIccMatrix *pMatrix, const char *tagName,
                           const char *baseName)
{
    if (!pMatrix) return 0;

    std::string safeTag = SanitizeTag(tagName);
    char filename[512];
    snprintf(filename, sizeof(filename), "%s_%s_matrix.txt",
             baseName, safeTag.c_str());

    FILE *f = SecureFileOpenText(filename, "w");
    if (!f) return 0;

    fprintf(f, "# ICC Profile Matrix Export\n");
    fprintf(f, "# Tag: %s\n", tagName);
    fprintf(f, "# Format: 3x4 matrix (3x3 + 3 constants)\n");
    fprintf(f, "# UseConstants: %s\n", pMatrix->m_bUseConstants ? "true" : "false");
    fprintf(f, "#\n");
    fprintf(f, "# e0\te1\te2\toffset\n");

    for (int row = 0; row < 3; row++) {
        for (int col = 0; col < 3; col++) {
            float val = pMatrix->m_e[row * 4 + col];
            if (std::isnan(val) || std::isinf(val)) val = 0.0f;
            fprintf(f, "%.9f\t", val);
        }
        float offset = pMatrix->m_e[row * 4 + 3];
        if (std::isnan(offset) || std::isinf(offset)) offset = 0.0f;
        fprintf(f, "%.9f\n", offset);
    }

    fclose(f);
    printf("  Wrote matrix: %s\n", filename);
    return 1;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEXT EXPORT — MPE (MultiProcessElement)
// ═══════════════════════════════════════════════════════════════════════════════

/// Export MPE CurveSet as editable TSV (all channels in one file)
static int ExportMPECurveSet(CIccMpeCurveSet *pCS, const char *tagName,
                             int elemIdx, const char *baseName)
{
    if (!pCS) return 0;

    int nChannels = pCS->NumInputChannels();
    if (nChannels <= 0 || nChannels > kMaxChannels) return 0;

    const int nSamples = 4096;

    // Begin() must be called before Apply()
    if (!pCS->Begin(icElemInterpLinear, nullptr)) {
        fprintf(stderr, "[WARN] CurveSet Begin() failed — skipping\n");
        return 0;
    }

    std::string safeTag = SanitizeTag(tagName);
    char filename[512];
    snprintf(filename, sizeof(filename), "%s_%s_mpe%d_curves.txt",
             baseName, safeTag.c_str(), elemIdx);

    FILE *f = SecureFileOpenText(filename, "w");
    if (!f) return 0;

    fprintf(f, "# ICC Profile MPE CurveSet Export\n");
    fprintf(f, "# Tag: %s\n", tagName);
    fprintf(f, "# Element: %d\n", elemIdx);
    fprintf(f, "# Channels: %d\n", nChannels);
    fprintf(f, "# Samples: %d\n", nSamples);
    fprintf(f, "# Format: input(normalized 0-1) <tab> ch0_output ... chN_output\n");
    fprintf(f, "#\n");

    // Header row
    fprintf(f, "input");
    for (int ch = 0; ch < nChannels; ch++)
        fprintf(f, "\tch%d", ch);
    fprintf(f, "\n");

    // Evaluate CurveSet at uniform sample points using Apply()
    // Apply() processes all channels simultaneously
    std::vector<icFloatNumber> srcPixel(static_cast<size_t>(nChannels), 0.0f);
    std::vector<icFloatNumber> dstPixel(static_cast<size_t>(nChannels), 0.0f);

    for (int s = 0; s < nSamples; s++) {
        float input = (nSamples > 1)
            ? static_cast<float>(s) / static_cast<float>(nSamples - 1)
            : 0.0f;

        // Set all input channels to the same value (1D curve evaluation)
        for (int ch = 0; ch < nChannels; ch++)
            srcPixel[static_cast<size_t>(ch)] = input;

        pCS->Apply(nullptr, dstPixel.data(), srcPixel.data());

        fprintf(f, "%.9f", input);
        for (int ch = 0; ch < nChannels; ch++) {
            float output = dstPixel[static_cast<size_t>(ch)];
            if (std::isnan(output) || std::isinf(output)) output = 0.0f;
            fprintf(f, "\t%.9f", output);
        }
        fprintf(f, "\n");
    }

    fclose(f);
    printf("  Wrote MPE CurveSet[%d]: %s (%d ch × %d samples)\n",
           elemIdx, filename, nChannels, nSamples);
    return 1;
}

/// Export MPE Matrix as editable TSV text
static int ExportMPEMatrix(CIccMpeMatrix *pMat, const char *tagName,
                           int elemIdx, const char *baseName)
{
    if (!pMat) return 0;

    int inCh = pMat->NumInputChannels();
    int outCh = pMat->NumOutputChannels();
    if (inCh <= 0 || outCh <= 0 || inCh > kMaxChannels || outCh > kMaxChannels)
        return 0;

    const icFloatNumber *pMatrix = pMat->GetMatrix();
    const icFloatNumber *pConst = pMat->GetConstants();
    bool hasConstants = (pConst != nullptr);

    std::string safeTag = SanitizeTag(tagName);
    char filename[512];
    snprintf(filename, sizeof(filename), "%s_%s_mpe%d_matrix.txt",
             baseName, safeTag.c_str(), elemIdx);

    FILE *f = SecureFileOpenText(filename, "w");
    if (!f) return 0;

    fprintf(f, "# ICC Profile MPE Matrix Export\n");
    fprintf(f, "# Tag: %s\n", tagName);
    fprintf(f, "# Element: %d\n", elemIdx);
    fprintf(f, "# Dimensions: %dx%d%s\n", outCh, inCh,
            hasConstants ? " + offsets" : "");
    fprintf(f, "# ApplyConstants: %s\n", hasConstants ? "true" : "false");
    fprintf(f, "#\n");

    // Header row
    for (int c = 0; c < inCh; c++)
        fprintf(f, "m[%d]\t", c);
    if (hasConstants)
        fprintf(f, "offset");
    fprintf(f, "\n");

    // Matrix rows
    for (int r = 0; r < outCh; r++) {
        if (pMatrix) {
            for (int c = 0; c < inCh; c++) {
                float val = pMatrix[r * inCh + c];
                if (std::isnan(val) || std::isinf(val)) val = 0.0f;
                fprintf(f, "%.9f\t", val);
            }
        }
        if (hasConstants) {
            float off = pConst[r];
            if (std::isnan(off) || std::isinf(off)) off = 0.0f;
            fprintf(f, "%.9f", off);
        }
        fprintf(f, "\n");
    }

    fclose(f);
    printf("  Wrote MPE Matrix[%d]: %s (%dx%d)\n",
           elemIdx, filename, outCh, inCh);
    return 1;
}

/// Export MPE CLUT as editable TSV text
static int ExportMPECLUTText(CIccMpeCLUT *pMpeCLUT, const char *tagName,
                             int elemIdx, const char *baseName)
{
    if (!pMpeCLUT) return 0;

    CIccCLUT *pCLUT = pMpeCLUT->GetCLUT();
    if (!pCLUT) return 0;

    std::string safeTag = SanitizeTag(tagName);
    char filename[512];
    snprintf(filename, sizeof(filename), "%s_%s_mpe%d_clut.txt",
             baseName, safeTag.c_str(), elemIdx);

    // Reuse the MBB CLUT export format (identical structure)
    // Just tag it as MPE in the header
    int inputDim = pCLUT->GetInputDim();
    int outCh = pCLUT->GetOutputChannels();
    if (inputDim <= 0 || inputDim > kMaxChannels || outCh <= 0 || outCh > kMaxChannels)
        return 0;

    uint64_t totalEntries = 1;
    for (int d = 0; d < inputDim; d++) {
        icUInt32Number gp = pCLUT->GridPoint(d);
        if (gp == 0 || gp > kMaxGridDim) return 0;
        if (totalEntries > UINT32_MAX / gp) return 0;
        totalEntries *= gp;
    }

    icFloatNumber *data = pCLUT->GetData(0);
    if (!data) return 0;

    FILE *f = SecureFileOpenText(filename, "w");
    if (!f) return 0;

    fprintf(f, "# ICC Profile MPE CLUT Export\n");
    fprintf(f, "# Tag: %s (MPE element %d)\n", tagName, elemIdx);
    fprintf(f, "# Input channels: %d\n", inputDim);
    fprintf(f, "# Output channels: %d\n", outCh);
    fprintf(f, "# Grid points:");
    for (int d = 0; d < inputDim; d++)
        fprintf(f, " %u", pCLUT->GridPoint(d));
    fprintf(f, "\n");
    fprintf(f, "# Total grid entries: %llu\n", (unsigned long long)totalEntries);
    fprintf(f, "# Values are normalized floats (0.0 - 1.0)\n");
    fprintf(f, "#\n");

    for (int d = 0; d < inputDim; d++)
        fprintf(f, "in%d\t", d);
    for (int c = 0; c < outCh; c++) {
        fprintf(f, "out%d", c);
        if (c < outCh - 1) fprintf(f, "\t");
    }
    fprintf(f, "\n");

    std::vector<int> idx(inputDim, 0);
    std::vector<int> gridSizes(inputDim);
    for (int d = 0; d < inputDim; d++)
        gridSizes[d] = pCLUT->GridPoint(d);

    uint64_t dataIdx = 0;
    for (uint64_t entry = 0; entry < totalEntries; entry++) {
        for (int d = 0; d < inputDim; d++) {
            float norm = (gridSizes[d] > 1)
                ? static_cast<float>(idx[d]) / static_cast<float>(gridSizes[d] - 1)
                : 0.0f;
            fprintf(f, "%.9f\t", norm);
        }
        for (int c = 0; c < outCh; c++) {
            float val = data[dataIdx++];
            if (std::isnan(val) || std::isinf(val)) val = 0.0f;
            fprintf(f, "%.9f", val);
            if (c < outCh - 1) fprintf(f, "\t");
        }
        fprintf(f, "\n");

        for (int d = inputDim - 1; d >= 0; d--) {
            idx[d]++;
            if (idx[d] < gridSizes[d]) break;
            idx[d] = 0;
        }
    }

    fclose(f);
    printf("  Wrote MPE CLUT[%d]: %s (%llu entries × %d outputs)\n",
           elemIdx, filename, (unsigned long long)totalEntries, outCh);
    return 1;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC EXPORT — Called from ExtractLutData
// ═══════════════════════════════════════════════════════════════════════════════

int ExtractLutText(const char *filename, const char *baseName)
{
    CIccFileIO io;
    if (!io.Open(filename, "rb")) {
        printf("Error opening file: %s\n", filename);
        return -1;
    }

    CIccProfile *pIcc = new (std::nothrow) CIccProfile;
    if (!pIcc) { printf("Error: allocation failed\n"); return -1; }
    if (!pIcc->Read(&io)) {
        printf("Error reading ICC profile\n");
        delete pIcc;
        return -1;
    }
    io.Close();

    printf("=== Extracting LUT data as text from: %s ===\n", filename);

    CIccInfo info;
    int totalExported = 0;

    TagEntryList::iterator it;
    for (it = pIcc->m_Tags.begin(); it != pIcc->m_Tags.end(); it++) {
        CIccTag *pTag = pIcc->FindTag((*it).TagInfo.sig);
        if (!pTag) continue;

        icTagTypeSignature tagType = pTag->GetType();
        const char *rawTagName = info.GetTagSigName((*it).TagInfo.sig);

        // Handle all CIccMBB subtypes: lut8, lut16, lutAtoB, lutBtoA
        CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pTag);
        if (pMBB) {
            printf("\n--- %s (type: %s) ---\n", rawTagName,
                   info.GetTagTypeSigName(tagType));

            int inCh = pMBB->InputChannels();
            int outCh = pMBB->OutputChannels();
            printf("  Channels: in=%d out=%d\n", inCh, outCh);

            LPIccCurve *curvesA = pMBB->GetCurvesA();
            LPIccCurve *curvesB = pMBB->GetCurvesB();
            LPIccCurve *curvesM = pMBB->GetCurvesM();
            CIccCLUT   *pCLUT   = pMBB->GetCLUT();
            CIccMatrix *pMatrix = pMBB->GetMatrix();

            // For lut8/lut16: B curves are input-side (IsInputB=true), A curves are output-side
            // For lutAtoB/lutBtoA: B curves are output-side
            int curvesA_count = pMBB->IsInputB() ? outCh : inCh;
            int curvesB_count = pMBB->IsInputB() ? inCh  : outCh;
            int curvesM_count = outCh;

            if (curvesA) totalExported += ExportMBBCurves(pMBB, rawTagName, "A", curvesA, curvesA_count, baseName);
            if (pCLUT)   totalExported += ExportMBBCLUT(pCLUT, rawTagName, baseName);
            if (curvesM) totalExported += ExportMBBCurves(pMBB, rawTagName, "M", curvesM, curvesM_count, baseName);
            if (pMatrix) totalExported += ExportMBBMatrix(pMatrix, rawTagName, baseName);
            if (curvesB) totalExported += ExportMBBCurves(pMBB, rawTagName, "B", curvesB, curvesB_count, baseName);
        }

        // Handle MultiProcessElement tags
        if (tagType == icSigMultiProcessElementType) {
            CIccTagMultiProcessElement *pMPE =
                dynamic_cast<CIccTagMultiProcessElement*>(pTag);
            if (!pMPE) continue;

            printf("\n--- %s (MPE: %u elements) ---\n",
                   rawTagName, pMPE->NumElements());
            printf("  Channels: in=%u out=%u\n",
                   pMPE->NumInputChannels(), pMPE->NumOutputChannels());

            for (icUInt32Number e = 0; e < pMPE->NumElements(); e++) {
                CIccMultiProcessElement *pElem = pMPE->GetElement(e);
                if (!pElem) continue;

                icElemTypeSignature eType = pElem->GetType();

                if (eType == icSigCurveSetElemType) {
                    CIccMpeCurveSet *pCS = dynamic_cast<CIccMpeCurveSet*>(pElem);
                    if (pCS) {
                        // Begin() is called inside ExportMPECurveSet
                        totalExported += ExportMPECurveSet(pCS, rawTagName, e, baseName);
                    }
                } else if (eType == icSigMatrixElemType) {
                    CIccMpeMatrix *pMat = dynamic_cast<CIccMpeMatrix*>(pElem);
                    if (pMat)
                        totalExported += ExportMPEMatrix(pMat, rawTagName, e, baseName);
                } else if (eType == icSigCLutElemType) {
                    CIccMpeCLUT *pMC = dynamic_cast<CIccMpeCLUT*>(pElem);
                    if (pMC)
                        totalExported += ExportMPECLUTText(pMC, rawTagName, e, baseName);
                } else {
                    printf("  Element[%u]: %s (skipped)\n", e, pElem->GetClassName());
                }
            }
        }
    }

    printf("\n=== Exported %d LUT component(s) ===\n", totalExported);
    delete pIcc;
    return totalExported > 0 ? 0 : -1;
}

// ═══════════════════════════════════════════════════════════════════════════════
// TEXT IMPORT — Parse TSV files and inject into ICC profiles
// ═══════════════════════════════════════════════════════════════════════════════

/// Detect file type from header comment
static int DetectTextFileType(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;

    char line[kMaxLineLen];
    int type = -1;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] != '#') break;
        if (strstr(line, "1D LUT Export"))          { type = 0; break; } // MBB Curve1D
        if (strstr(line, "MPE CurveSet Export"))     { type = 1; break; } // MPE CurveSet
        if (strstr(line, "MPE CLUT Export"))          { type = 5; break; } // MPE CLUT
        if (strstr(line, "CLUT Export"))              { type = 2; break; } // MBB CLUT
        if (strstr(line, "MPE Matrix Export"))        { type = 4; break; } // MPE Matrix
        if (strstr(line, "Matrix Export"))            { type = 3; break; } // MBB Matrix
    }
    fclose(f);
    return type;
}

/// Parse a 1D curve TSV file, return values in outInput/outOutput
static bool ParseCurve1DText(const char *path, std::vector<float> &outInput,
                             std::vector<float> &outOutput, std::string &error)
{
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size > (off_t)kMaxImportFileSize) {
        error = "File too large or not found";
        return false;
    }

    FILE *f = fopen(path, "r");
    if (!f) { error = "Cannot open file"; return false; }

    char line[kMaxLineLen];
    size_t lineCount = 0;
    bool inData = false;

    while (fgets(line, sizeof(line), f)) {
        if (++lineCount > kMaxImportLineCount) { error = "Too many lines"; fclose(f); return false; }

        // Strip newline
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;

        if (line[0] == '#') continue;

        // Skip header row
        if (!inData && strstr(line, "input")) { inData = true; continue; }
        if (!inData) continue;

        // Parse "input\toutput"
        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';

        float inp = 0.0f, outp = 0.0f;
        if (!SafeFloat(line, inp) || !SafeFloat(tab + 1, outp)) continue;

        outInput.push_back(inp);
        outOutput.push_back(outp);

        if (outInput.size() > kMaxCurveSamples) { error = "Too many samples"; fclose(f); return false; }
    }
    fclose(f);

    if (outInput.empty()) { error = "No data found"; return false; }
    return true;
}

/// Parse a CLUT TSV file
static bool ParseCLUTText(const char *path, int &inputDim, int &outputCh,
                          std::vector<int> &gridPoints,
                          std::vector<float> &outputData, std::string &error)
{
    struct stat st;
    if (stat(path, &st) != 0 || st.st_size > (off_t)kMaxImportFileSize) {
        error = "File too large or not found";
        return false;
    }

    FILE *f = fopen(path, "r");
    if (!f) { error = "Cannot open file"; return false; }

    char line[kMaxLineLen];
    size_t lineCount = 0;
    bool inData = false;
    inputDim = 0;
    outputCh = 0;

    while (fgets(line, sizeof(line), f)) {
        if (++lineCount > kMaxImportLineCount) { error = "Too many lines"; fclose(f); return false; }

        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;

        // Parse header comments
        if (line[0] == '#') {
            if (sscanf(line, "# Input channels: %d", &inputDim) == 1) continue;
            if (sscanf(line, "# Output channels: %d", &outputCh) == 1) continue;
            const char *gp = strstr(line, "# Grid points:");
            if (gp) {
                gp += strlen("# Grid points:");
                std::istringstream iss(gp);
                int val = 0;
                while (iss >> val) {
                    if (val <= 0 || val > kMaxGridDim) { error = "Invalid grid size"; fclose(f); return false; }
                    gridPoints.push_back(val);
                }
            }
            continue;
        }

        // Skip header row (contains "in0" or "out0")
        if (!inData && (strstr(line, "in0") || strstr(line, "out0"))) {
            inData = true;
            continue;
        }
        if (!inData) continue;

        // Parse data row: in0 in1 ... inN out0 out1 ... outN
        // We only need the output values
        std::istringstream iss(line);
        std::string token;
        int col = 0;
        while (std::getline(iss, token, '\t')) {
            float val = 0.0f;
            if (col >= inputDim) {
                if (SafeFloat(token.c_str(), val))
                    outputData.push_back(val);
            }
            col++;
        }
    }
    fclose(f);

    if (outputData.empty()) { error = "No CLUT data found"; return false; }
    if (inputDim <= 0 || outputCh <= 0) { error = "Missing channel info in header"; return false; }

    uint64_t expected = outputCh;
    for (int g : gridPoints) {
        if (expected > UINT32_MAX / (uint64_t)g) { error = "Grid size overflow"; return false; }
        expected *= g;
    }
    if (outputData.size() != expected) {
        error = "CLUT data count mismatch: got " + std::to_string(outputData.size()) +
                ", expected " + std::to_string(expected);
        return false;
    }

    return true;
}

/// Parse a matrix TSV file
static bool ParseMatrixText(const char *path, float e[12], bool &useConstants,
                            std::string &error)
{
    FILE *f = fopen(path, "r");
    if (!f) { error = "Cannot open file"; return false; }

    char line[kMaxLineLen];
    bool inData = false;
    int row = 0;
    useConstants = false;
    memset(e, 0, 12 * sizeof(float));

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;

        if (line[0] == '#') {
            if (strstr(line, "UseConstants: true") || strstr(line, "ApplyConstants: true"))
                useConstants = true;
            continue;
        }

        // Skip header row
        if (!inData && (strstr(line, "e0") || strstr(line, "m[0]"))) {
            inData = true;
            continue;
        }
        if (!inData) continue;
        if (row >= 3) break;

        // Parse "e0\te1\te2\toffset"
        std::istringstream iss(line);
        std::string token;
        int col = 0;
        while (std::getline(iss, token, '\t') && col < 4) {
            float val = 0.0f;
            if (SafeFloatUnclamped(token.c_str(), val))
                e[row * 4 + col] = val;
            col++;
        }
        row++;
    }
    fclose(f);

    if (row < 3) { error = "Incomplete matrix (need 3 rows)"; return false; }
    return true;
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPER — Parse element index from MPE text file header
// ═══════════════════════════════════════════════════════════════════════════════

static int ParseElementIndex(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[kMaxLineLen];
    int idx = 0;
    while (fgets(line, sizeof(line), f)) {
        if (line[0] != '#') break;
        if (strncmp(line, "# Element:", 10) == 0) {
            idx = atoi(line + 10);
            if (idx < 0 || idx > 255) idx = 0;
            break;
        }
    }
    fclose(f);
    return idx;
}

// ═══════════════════════════════════════════════════════════════════════════════
// PUBLIC IMPORT — Modify ICC profile from text files
// ═══════════════════════════════════════════════════════════════════════════════

int ImportTextLutData(const char *profileFile, const char *outputFile,
                      const char *textFile, const char *tagSigStr)
{
    if (IccAnalyzerSecurity::ValidateFilePath(profileFile,
          IccAnalyzerSecurity::PathValidationMode::STRICT, true, {".icc", ".icm"})
          != IccAnalyzerSecurity::PathValidationResult::VALID) {
        printf("Error: invalid profile path\n");
        return -1;
    }
    if (IccAnalyzerSecurity::ValidateFilePath(textFile,
          IccAnalyzerSecurity::PathValidationMode::STRICT, true)
          != IccAnalyzerSecurity::PathValidationResult::VALID) {
        printf("Error: invalid text file path\n");
        return -1;
    }

    int fileType = DetectTextFileType(textFile);
    if (fileType < 0) {
        printf("Error: cannot detect file type from header of %s\n", textFile);
        return -1;
    }

    CIccProfile *pIcc = OpenIccProfile(profileFile);
    if (!pIcc) return -1;

    // Find target tag — use explicit arg, or auto-detect from file header
    icTagSignature targetSig;
    if (tagSigStr && tagSigStr[0]) {
        targetSig = ResolveTagSig(tagSigStr);
    } else {
        targetSig = ParseTagFromFile(textFile);
    }

    CIccTag *pTag = pIcc->FindTag(targetSig);
    if (!pTag) {
        // Format sig for error message
        char sigStr[5] = {0};
        sigStr[0] = (char)((targetSig >> 24) & 0xFF);
        sigStr[1] = (char)((targetSig >> 16) & 0xFF);
        sigStr[2] = (char)((targetSig >> 8) & 0xFF);
        sigStr[3] = (char)(targetSig & 0xFF);
        printf("Error: tag '%s' not found in profile\n", 
               (tagSigStr && tagSigStr[0]) ? tagSigStr : sigStr);
        delete pIcc;
        return -1;
    }

    bool modified = false;
    std::string err;

    // Handle curve import
    if (fileType == 0) { // Curve1D
        CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pTag);
        if (!pMBB) {
            printf("Error: tag is not an MBB type (lut8/16/AtoB/BtoA)\n");
            delete pIcc;
            return -1;
        }

        std::vector<float> inpVals, outVals;
        if (!ParseCurve1DText(textFile, inpVals, outVals, err)) {
            printf("Error parsing curve: %s\n", err.c_str());
            delete pIcc;
            return -1;
        }

        // Detect which curve set and channel from filename
        // Pattern: ..._curveA_0.txt or ..._curveB_1.txt or ..._curveM_2.txt
        const char *base = strrchr(textFile, '/');
        base = base ? base + 1 : textFile;
        char curveSet = 'B';
        int channel = 0;
        const char *cp = strstr(base, "_curve");
        if (cp) {
            curveSet = cp[6]; // A, B, or M
            if (cp[7] == '_') channel = atoi(cp + 8);
        }

        LPIccCurve *curves = nullptr;
        int nCh = 0;
        if (curveSet == 'A') { curves = pMBB->GetCurvesA(); nCh = pMBB->InputChannels(); }
        else if (curveSet == 'M') { curves = pMBB->GetCurvesM(); nCh = pMBB->OutputChannels(); }
        else { curves = pMBB->GetCurvesB(); nCh = pMBB->OutputChannels(); }

        if (!curves || channel >= nCh) {
            printf("Error: curve%c[%d] not found in tag\n", curveSet, channel);
            delete pIcc;
            return -1;
        }

        CIccTagCurve *pCurve = dynamic_cast<CIccTagCurve*>(curves[channel]);
        if (!pCurve) {
            printf("Error: curve is not CIccTagCurve type\n");
            delete pIcc;
            return -1;
        }

        // Validate sample count matches
        if (outVals.size() != pCurve->GetSize()) {
            printf("Resizing curve from %u to %zu samples\n",
                   pCurve->GetSize(), outVals.size());
            pCurve->SetSize(outVals.size());
        }

        for (size_t j = 0; j < outVals.size(); j++)
            (*pCurve)[j] = outVals[j];

        printf("Imported curve%c[%d]: %zu samples\n", curveSet, channel, outVals.size());
        modified = true;
    }

    // Handle CLUT import
    if (fileType == 2) { // CLUT
        CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pTag);
        if (!pMBB) {
            printf("Error: tag is not an MBB type\n");
            delete pIcc;
            return -1;
        }

        int inDim = 0, outCh = 0;
        std::vector<int> grid;
        std::vector<float> clutData;
        if (!ParseCLUTText(textFile, inDim, outCh, grid, clutData, err)) {
            printf("Error parsing CLUT: %s\n", err.c_str());
            delete pIcc;
            return -1;
        }

        CIccCLUT *pCLUT = pMBB->GetCLUT();
        if (!pCLUT) {
            printf("Error: no CLUT in tag\n");
            delete pIcc;
            return -1;
        }

        // Validate dimensions match
        if (pCLUT->GetInputDim() != inDim || pCLUT->GetOutputChannels() != outCh) {
            printf("Error: CLUT dimensions mismatch (profile: %d→%d, file: %d→%d)\n",
                   pCLUT->GetInputDim(), pCLUT->GetOutputChannels(), inDim, outCh);
            delete pIcc;
            return -1;
        }

        for (int d = 0; d < inDim; d++) {
            if ((int)pCLUT->GridPoint(d) != grid[d]) {
                printf("Error: grid size mismatch dim %d (profile: %u, file: %d)\n",
                       d, pCLUT->GridPoint(d), grid[d]);
                delete pIcc;
                return -1;
            }
        }

        icFloatNumber *data = pCLUT->GetData(0);
        if (!data) {
            printf("Error: cannot access CLUT data\n");
            delete pIcc;
            return -1;
        }

        for (size_t j = 0; j < clutData.size(); j++)
            data[j] = clutData[j];

        printf("Imported CLUT: %zu output values\n", clutData.size());
        modified = true;
    }

    // Handle matrix import
    if (fileType == 3) { // Matrix
        CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pTag);
        if (!pMBB) {
            printf("Error: tag is not an MBB type\n");
            delete pIcc;
            return -1;
        }

        float e[12];
        bool useConst = false;
        if (!ParseMatrixText(textFile, e, useConst, err)) {
            printf("Error parsing matrix: %s\n", err.c_str());
            delete pIcc;
            return -1;
        }

        CIccMatrix *pMatrix = pMBB->GetMatrix();
        if (!pMatrix) {
            printf("Error: no matrix in tag\n");
            delete pIcc;
            return -1;
        }

        for (int j = 0; j < 12; j++)
            pMatrix->m_e[j] = e[j];
        pMatrix->m_bUseConstants = useConst;

        printf("Imported 3x4 matrix (constants: %s)\n", useConst ? "yes" : "no");
        modified = true;
    }

    // Handle MPE Matrix import (fileType 4)
    if (fileType == 4) {
        CIccTagMultiProcessElement *pMPE =
            dynamic_cast<CIccTagMultiProcessElement*>(pTag);
        if (!pMPE) {
            printf("Error: tag is not a MultiProcessElement type\n");
            delete pIcc;
            return -1;
        }

        // Parse element index from file header
        int elemIdx = ParseElementIndex(textFile);

        float e[12];
        bool useConst = false;
        if (!ParseMatrixText(textFile, e, useConst, err)) {
            printf("Error parsing MPE matrix: %s\n", err.c_str());
            delete pIcc;
            return -1;
        }

        CIccMultiProcessElement *pElem = nullptr;
        if (elemIdx >= 0 && elemIdx < (int)pMPE->NumElements())
            pElem = pMPE->GetElement(elemIdx);

        CIccMpeMatrix *pMat = pElem ?
            dynamic_cast<CIccMpeMatrix*>(pElem) : nullptr;
        if (!pMat || !pMat->GetMatrix()) {
            printf("Error: MPE element %d is not a matrix or has no data\n", elemIdx);
            delete pIcc;
            return -1;
        }

        // MPE matrices: GetMatrix() returns mutable pointer
        // e[] layout from ParseMatrixText: row-major with offset interleaved
        // e[0..2]=row0 matrix, e[3]=off0, e[4..6]=row1, e[7]=off1, e[8..10]=row2, e[11]=off2
        // mData[] layout: row-major 3x3 without offsets
        icFloatNumber *mData = pMat->GetMatrix();
        for (int row = 0; row < 3; row++)
            for (int col = 0; col < 3; col++)
                mData[row * 3 + col] = e[row * 4 + col];
        icFloatNumber *cData = pMat->GetConstants();
        if (cData && useConst) {
            for (int row = 0; row < 3; row++)
                cData[row] = e[row * 4 + 3];
        }

        printf("Imported MPE matrix[%d] (constants: %s)\n", elemIdx,
               useConst ? "yes" : "no");
        modified = true;
    }

    // Handle MPE CLUT import (fileType 5)
    if (fileType == 5) {
        CIccTagMultiProcessElement *pMPE =
            dynamic_cast<CIccTagMultiProcessElement*>(pTag);
        if (!pMPE) {
            printf("Error: tag is not a MultiProcessElement type\n");
            delete pIcc;
            return -1;
        }

        int elemIdx = ParseElementIndex(textFile);
        int inDim = 0, outCh = 0;
        std::vector<int> grid;
        std::vector<float> clutData;
        if (!ParseCLUTText(textFile, inDim, outCh, grid, clutData, err)) {
            printf("Error parsing MPE CLUT: %s\n", err.c_str());
            delete pIcc;
            return -1;
        }

        CIccMultiProcessElement *pElem = nullptr;
        if (elemIdx >= 0 && elemIdx < (int)pMPE->NumElements())
            pElem = pMPE->GetElement(elemIdx);

        CIccMpeCLUT *pMC = pElem ?
            dynamic_cast<CIccMpeCLUT*>(pElem) : nullptr;
        CIccCLUT *pCLUT = pMC ? pMC->GetCLUT() : nullptr;
        if (!pCLUT) {
            printf("Error: MPE element %d has no CLUT\n", elemIdx);
            delete pIcc;
            return -1;
        }

        icFloatNumber *data = pCLUT->GetData(0);
        if (!data) {
            printf("Error: CLUT has no data array\n");
            delete pIcc;
            return -1;
        }

        size_t totalNeeded = 1;
        for (int d = 0; d < inDim; d++) totalNeeded *= grid[d];
        totalNeeded *= outCh;

        if (clutData.size() != totalNeeded) {
            printf("Error: CLUT data size mismatch (%zu vs %zu expected)\n",
                   clutData.size(), totalNeeded);
            delete pIcc;
            return -1;
        }

        for (size_t j = 0; j < clutData.size(); j++)
            data[j] = clutData[j];

        printf("Imported MPE CLUT[%d]: %dD, %d output channels\n",
               elemIdx, inDim, outCh);
        modified = true;
    }

    // Handle MPE CurveSet import (fileType 1)
    // MPE CurveSets contain all channels in one file — we replace the entire element's data
    if (fileType == 1) {
        CIccTagMultiProcessElement *pMPE =
            dynamic_cast<CIccTagMultiProcessElement*>(pTag);
        if (!pMPE) {
            printf("Error: tag is not a MultiProcessElement type\n");
            delete pIcc;
            return -1;
        }

        // Parse element index (reserved for future per-element replacement)
        (void)ParseElementIndex(textFile);

        // Parse MPE CurveSet: multi-channel samples
        FILE *csvF = fopen(textFile, "r");
        if (!csvF) {
            printf("Error: cannot open %s\n", textFile);
            delete pIcc;
            return -1;
        }

        char line[kMaxLineLen];
        int nChannels = 0, nSamples = 0;
        while (fgets(line, sizeof(line), csvF)) {
            if (line[0] != '#') break;
            if (strncmp(line, "# Channels:", 11) == 0) nChannels = atoi(line + 11);
            if (strncmp(line, "# Samples:", 10) == 0) nSamples = atoi(line + 10);
        }
        // Skip header row (input\tch0\tch1...)
        // line already has the header row from above

        if (nChannels < 1 || nChannels > 16 || nSamples < 2 || nSamples > 65536) {
            printf("Error: invalid MPE CurveSet dimensions (%d ch × %d samples)\n",
                   nChannels, nSamples);
            fclose(csvF);
            delete pIcc;
            return -1;
        }

        // Read all channel output values
        std::vector<std::vector<float>> chData(nChannels);
        for (int c = 0; c < nChannels; c++)
            chData[c].reserve(nSamples);

        while (fgets(line, sizeof(line), csvF)) {
            if (line[0] == '#' || line[0] == '\n') continue;
            char *p = line;
            // Skip input column
            strtof(p, &p);
            for (int c = 0; c < nChannels; c++) {
                while (*p == '\t' || *p == ' ') p++;
                float val;
                char *end = nullptr;
                errno = 0;
                val = strtof(p, &end);
                if (errno != 0 || end == p || std::isnan(val) || std::isinf(val))
                    val = 0.0f;
                if (val < 0.0f) val = 0.0f;
                if (val > 1.0f) val = 1.0f;
                p = end;
                chData[c].push_back(val);
            }
        }
        fclose(csvF);

        if ((int)chData[0].size() < 2) {
            printf("Error: too few samples read (%zu)\n", chData[0].size());
            delete pIcc;
            return -1;
        }

        // We can't replace individual curves in CIccMpeCurveSet (protected m_curve).
        // Instead, verify the sample counts match and report what was parsed.
        // For now: inform the user that MPE CurveSet modification requires
        // creating a new element — this is a read-back verification.
        printf("Parsed MPE CurveSet: %d channels × %zu samples\n",
               nChannels, chData[0].size());
        printf("Note: MPE CurveSet in-place modification requires element replacement\n");
        printf("      (CIccMpeCurveSet internal curves are not directly accessible)\n");
        // Mark as not modified — inform user
        // Future: create new CIccMpeCurveSet with CIccSampledCurve and swap elements
    }

    if (!modified) {
        printf("No modifications applied\n");
        delete pIcc;
        return -1;
    }

    // Write output
    CIccFileIO outIO;
    if (!outIO.Open(outputFile, "wb")) {
        printf("Error opening output: %s\n", outputFile);
        delete pIcc;
        return -1;
    }
    if (!pIcc->Write(&outIO)) {
        printf("Error writing profile\n");
        delete pIcc;
        return -1;
    }
    outIO.Close();
    delete pIcc;

    printf("Modified profile written to: %s\n", outputFile);
    return 0;
}

// ═══════════════════════════════════════════════════════════════════════════════
// .CUBE EXPORT/IMPORT
// ═══════════════════════════════════════════════════════════════════════════════

int ExportCubeFromProfile(const char *profileFile, const char *tagSigStr,
                          const char *cubeFile)
{
    if (IccAnalyzerSecurity::ValidateFilePath(profileFile,
          IccAnalyzerSecurity::PathValidationMode::STRICT, true, {".icc", ".icm"})
          != IccAnalyzerSecurity::PathValidationResult::VALID) {
        printf("Error: invalid profile path\n");
        return -1;
    }

    CIccProfile *pIcc = OpenIccProfile(profileFile);
    if (!pIcc) return -1;

    icTagSignature sig = icSigAToB0Tag;
    if (tagSigStr) {
        if (strcmp(tagSigStr, "A2B1") == 0) sig = icSigAToB1Tag;
        else if (strcmp(tagSigStr, "B2A0") == 0) sig = icSigBToA0Tag;
        else if (strcmp(tagSigStr, "B2A1") == 0) sig = icSigBToA1Tag;
    }

    CIccTag *pTag = pIcc->FindTag(sig);
    if (!pTag) {
        printf("Error: tag %s not found\n", tagSigStr ? tagSigStr : "A2B0");
        delete pIcc;
        return -1;
    }

    CIccCLUT *pCLUT = nullptr;
    int inputDim = 0;
    int outputCh = 0;

    // Try MBB first
    CIccMBB *pMBB = dynamic_cast<CIccMBB*>(pTag);
    if (pMBB) {
        pCLUT = pMBB->GetCLUT();
        if (pCLUT) {
            inputDim = pCLUT->GetInputDim();
            outputCh = pCLUT->GetOutputChannels();
        }
    }

    // Try MPE
    if (!pCLUT) {
        CIccTagMultiProcessElement *pMPE =
            dynamic_cast<CIccTagMultiProcessElement*>(pTag);
        if (pMPE) {
            for (icUInt32Number e = 0; e < pMPE->NumElements(); e++) {
                CIccMultiProcessElement *pElem = pMPE->GetElement(e);
                if (pElem && pElem->GetType() == icSigCLutElemType) {
                    CIccMpeCLUT *pMC = dynamic_cast<CIccMpeCLUT*>(pElem);
                    if (pMC) {
                        pCLUT = pMC->GetCLUT();
                        if (pCLUT) {
                            inputDim = pCLUT->GetInputDim();
                            outputCh = pCLUT->GetOutputChannels();
                        }
                    }
                    break;
                }
            }
        }
    }

    if (!pCLUT || inputDim != 3 || outputCh != 3) {
        printf("Error: .cube requires a 3D→3 channel CLUT (found %dD→%d)\n",
               inputDim, outputCh);
        delete pIcc;
        return -1;
    }

    int gridSize = pCLUT->GridPoint(0);
    for (int d = 1; d < 3; d++) {
        if ((int)pCLUT->GridPoint(d) != gridSize) {
            printf("Error: .cube requires uniform grid (got %u vs %d)\n",
                   pCLUT->GridPoint(d), gridSize);
            delete pIcc;
            return -1;
        }
    }

    icFloatNumber *data = pCLUT->GetData(0);
    if (!data) {
        printf("Error: no CLUT data\n");
        delete pIcc;
        return -1;
    }

    FILE *f = SecureFileOpenText(cubeFile, "w");
    if (!f) {
        printf("Error creating .cube file: %s\n", cubeFile);
        delete pIcc;
        return -1;
    }

    fprintf(f, "# Exported by iccanalyzer-lite\n");
    fprintf(f, "# Source: %s tag %s\n", profileFile, tagSigStr ? tagSigStr : "A2B0");
    fprintf(f, "TITLE \"ICC Profile CLUT\"\n");
    fprintf(f, "LUT_3D_SIZE %d\n", gridSize);
    fprintf(f, "\n");

    uint64_t total = (uint64_t)gridSize * gridSize * gridSize;
    for (uint64_t i = 0; i < total; i++) {
        for (int c = 0; c < 3; c++) {
            float val = data[i * 3 + c];
            if (std::isnan(val) || std::isinf(val)) val = 0.0f;
            if (val < 0.0f) val = 0.0f;
            if (val > 1.0f) val = 1.0f;
            fprintf(f, "%.6f", val);
            if (c < 2) fprintf(f, " ");
        }
        fprintf(f, "\n");
    }

    fclose(f);
    delete pIcc;

    printf("Exported .cube: %s (grid %d³ = %llu entries)\n",
           cubeFile, gridSize, (unsigned long long)total);
    return 0;
}

int ImportCubeToProfile(const char *cubeFile, const char *outputFile)
{
    if (IccAnalyzerSecurity::ValidateFilePath(cubeFile,
          IccAnalyzerSecurity::PathValidationMode::STRICT, true, {".cube"})
          != IccAnalyzerSecurity::PathValidationResult::VALID) {
        printf("Error: invalid .cube file path\n");
        return -1;
    }

    struct stat st;
    if (stat(cubeFile, &st) != 0 || st.st_size > (off_t)kMaxImportFileSize) {
        printf("Error: file too large or not found\n");
        return -1;
    }

    FILE *f = fopen(cubeFile, "r");
    if (!f) { printf("Error opening .cube: %s\n", cubeFile); return -1; }

    char line[kMaxLineLen];
    int gridSize = 0;
    std::string title;
    std::vector<float> data;

    while (fgets(line, sizeof(line), f)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;

        if (line[0] == '#') continue;

        if (strncmp(line, "TITLE", 5) == 0) {
            const char *q1 = strchr(line, '"');
            if (q1) {
                const char *q2 = strchr(q1 + 1, '"');
                if (q2) title.assign(q1 + 1, q2);
            }
            continue;
        }

        if (strncmp(line, "LUT_3D_SIZE", 11) == 0) {
            gridSize = atoi(line + 12);
            if (gridSize < 2 || gridSize > kMaxGridDim) {
                printf("Error: invalid grid size %d\n", gridSize);
                fclose(f);
                return -1;
            }
            continue;
        }

        // Skip LUT_1D_SIZE, DOMAIN_MIN, DOMAIN_MAX
        if (strncmp(line, "LUT_1D", 6) == 0 || strncmp(line, "DOMAIN", 6) == 0)
            continue;

        // Parse RGB triplet
        float r, g, b;
        if (sscanf(line, "%f %f %f", &r, &g, &b) == 3) {
            if (std::isnan(r) || std::isinf(r)) r = 0.0f;
            if (std::isnan(g) || std::isinf(g)) g = 0.0f;
            if (std::isnan(b) || std::isinf(b)) b = 0.0f;
            if (r < 0.0f) r = 0.0f; if (r > 1.0f) r = 1.0f;
            if (g < 0.0f) g = 0.0f; if (g > 1.0f) g = 1.0f;
            if (b < 0.0f) b = 0.0f; if (b > 1.0f) b = 1.0f;
            data.push_back(r);
            data.push_back(g);
            data.push_back(b);
        }
    }
    fclose(f);

    if (gridSize == 0) {
        printf("Error: no LUT_3D_SIZE found in .cube\n");
        return -1;
    }

    uint64_t expected = (uint64_t)gridSize * gridSize * gridSize * 3;
    if (data.size() != expected) {
        printf("Error: expected %llu values, got %zu\n",
               (unsigned long long)expected, data.size());
        return -1;
    }

    // Create ICC DeviceLink profile with MPE CLUT (matches upstream iccFromCube)
    CIccProfile profile;
    profile.InitHeader();
    profile.m_Header.deviceClass = icSigLinkClass;
    profile.m_Header.colorSpace = icSigRgbData;
    profile.m_Header.pcs = icSigRgbData;
    profile.m_Header.version = icVersionNumberV5;
    profile.m_Header.renderingIntent = icPerceptual;

    // A2B0 as MPE with CLUT element
    CIccTagMultiProcessElement *pTag = new (std::nothrow) CIccTagMultiProcessElement(3, 3);
    if (!pTag) { printf("Error: allocation failed\n"); return -1; }

    CIccMpeCLUT *pMpeCLUT = new (std::nothrow) CIccMpeCLUT;
    if (!pMpeCLUT) { printf("Error: allocation failed\n"); delete pTag; return -1; }

    CIccCLUT *pCLUT = new (std::nothrow) CIccCLUT(3, 3);
    if (!pCLUT) { printf("Error: allocation failed\n"); delete pMpeCLUT; delete pTag; return -1; }

    icUInt8Number gridDims[16] = {};
    gridDims[0] = gridDims[1] = gridDims[2] = (icUInt8Number)gridSize;
    if (!pCLUT->Init(gridDims)) {
        printf("Error: CLUT init failed\n");
        delete pCLUT; delete pMpeCLUT; delete pTag;
        return -1;
    }

    icFloatNumber *pData = pCLUT->GetData(0);
    if (!pData) {
        printf("Error: no CLUT data pointer\n");
        delete pCLUT; delete pMpeCLUT; delete pTag;
        return -1;
    }
    for (size_t i = 0; i < data.size(); i++)
        pData[i] = data[i];

    pMpeCLUT->SetCLUT(pCLUT);  // takes ownership
    pTag->Attach(pMpeCLUT);     // takes ownership
    profile.AttachTag(icSigAToB0Tag, pTag);

    // Required tags (use MultiLocalizedUnicode like upstream)
    CIccTagMultiLocalizedUnicode *pDesc = new (std::nothrow) CIccTagMultiLocalizedUnicode;
    if (pDesc) {
        const char *t = title.empty() ? "Imported .cube LUT" : title.c_str();
        pDesc->SetText(t);
        profile.AttachTag(icSigProfileDescriptionTag, pDesc);
    }

    CIccTagMultiLocalizedUnicode *pCopy = new (std::nothrow) CIccTagMultiLocalizedUnicode;
    if (pCopy) {
        pCopy->SetText("Generated by iccanalyzer-lite");
        profile.AttachTag(icSigCopyrightTag, pCopy);
    }

    bool ok = SaveIccProfile(outputFile, &profile);
    if (!ok) {
        printf("Error writing profile: %s\n", outputFile);
        return -1;
    }

    printf("Created ICC DeviceLink from .cube: %s (grid %d³)\n", outputFile, gridSize);
    return 0;
}
