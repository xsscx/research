/*
 * Copyright (c) International Color Consortium.
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
 * 3. In the absence of prior written permission, the names "ICC" and "The
 *    International Color Consortium" must not be used to imply that the
 *    ICC organization endorses or promotes products derived from this
 *    software.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE INTERNATIONAL COLOR CONSORTIUM OR
 * ITS CONTRIBUTING MEMBERS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/** @file
    CFL harness for iccDEV iccPngDump.

    Modeled command:
      iccPngDump png_file output_icc_file

    The input PNG bytes are written to a temporary file, parsed through libpng,
    and any embedded iCCP profile is written to a temporary output path and
    loaded through CIccProfile to exercise the extracted ICC profile surface.
 */

#include "IccCmm.h"
#include "IccCmdLineUtil.h"
#include "IccUtil.h"
#include "fuzz_utils.h"

#include <png.h>
#include <stddef.h>
#include <stdint.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

static constexpr size_t kMaxPngInputSize = 10 * 1024 * 1024;
static constexpr png_uint_32 kMaxIccProfileSize = 8 * 1024 * 1024;

static bool write_temp_file(const uint8_t *data, size_t size, char *path, size_t pathSize,
                            const char *suffix)
{
    if (!fuzz_build_path(path, pathSize, fuzz_tmpdir(), suffix))
        return false;

    int fd = mkstemp(path);
    if (fd < 0)
        return false;

    bool wrote = (write(fd, data, size) == (ssize_t)size);
    close(fd);
    if (!wrote)
        unlink(path);

    return wrote;
}

static bool write_embedded_icc_profile(const char *path, const unsigned char *profileData,
                                       png_uint_32 profileLength)
{
    if (!path || !profileData || !profileLength || profileLength > kMaxIccProfileSize)
        return false;

    FILE *fp = icOpenRegularWriteBinaryFile(path);
    if (!fp)
        return false;

    bool failed = (fwrite(profileData, 1, profileLength, fp) != profileLength);
    if (!icFlushAndClose(fp))
        failed = true;

    return !failed;
}

static void touch_profile_info(CIccProfile *profile)
{
    if (!profile)
        return;

    icHeader *hdr = &profile->m_Header;
    CIccInfo fmt;

    (void)fmt.GetVersionName(hdr->version);
    if (hdr->colorSpace)
        (void)fmt.GetColorSpaceSigName(hdr->colorSpace);
    if (hdr->pcs)
        (void)fmt.GetColorSpaceSigName(hdr->pcs);

    CIccTag *desc = profile->FindTag(icSigProfileDescriptionTag);
    if (desc) {
        if (desc->GetType() == icSigTextDescriptionType) {
            CIccTagTextDescription *text = (CIccTagTextDescription *)desc;
            std::string clean = icSanitizeConsoleText(text->GetText());
            (void)clean.size();
        }
        else if (desc->GetType() == icSigMultiLocalizedUnicodeType) {
            CIccTagMultiLocalizedUnicode *strs = (CIccTagMultiLocalizedUnicode *)desc;
            if (strs->m_Strings) {
                CIccMultiLocalizedUnicode::iterator text = strs->m_Strings->begin();
                if (text != strs->m_Strings->end()) {
                    std::string line;
                    text->GetText(line);
                    std::string clean = icSanitizeConsoleText(line);
                    (void)clean.size();
                }
            }
        }
    }

    CIccTag *embedded = profile->FindTag(icSigEmbeddedV5ProfileTag);
    if (embedded && embedded->GetType() == icSigEmbeddedProfileType) {
        CIccTagEmbeddedProfile *embeddedTag = (CIccTagEmbeddedProfile *)embedded;
        if (embeddedTag->GetProfile())
            touch_profile_info(embeddedTag->GetProfile());
    }
}

static void exercise_icc_profile(const unsigned char *profileData, png_uint_32 profileLength,
                                 const char *exportPath)
{
    if (!profileData || !profileLength || profileLength > kMaxIccProfileSize)
        return;

    CIccProfile *profile = OpenIccProfile(profileData, profileLength);
    if (profile) {
        touch_profile_info(profile);
        if (profile->ReadTags(profile))
            (void)SaveIccProfile(exportPath, profile);
        delete profile;
    }
    else {
        (void)write_embedded_icc_profile(exportPath, profileData, profileLength);
    }
}

static void exercise_png_file(const char *pngPath, const char *exportPath)
{
    FILE *fp = fopen(pngPath, "rb");
    if (!fp)
        return;

    unsigned char header[8];
    if (fread(header, 1, sizeof(header), fp) != sizeof(header) ||
        png_sig_cmp(header, 0, sizeof(header))) {
        fclose(fp);
        return;
    }

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) {
        fclose(fp);
        return;
    }

    png_infop info = png_create_info_struct(png);
    if (!info) {
        png_destroy_read_struct(&png, NULL, NULL);
        fclose(fp);
        return;
    }

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_read_struct(&png, &info, NULL);
        fclose(fp);
        return;
    }

    png_init_io(png, fp);
    png_set_sig_bytes(png, sizeof(header));
    png_read_info(png, info);

    (void)png_get_image_width(png, info);
    (void)png_get_image_height(png, info);
    (void)png_get_bit_depth(png, info);
    (void)png_get_color_type(png, info);
    (void)png_get_interlace_type(png, info);

    png_charp profileName = NULL;
    int compressionType = 0;
    png_bytep profileData = NULL;
    png_uint_32 profileLength = 0;
    if (png_get_iCCP(png, info, &profileName, &compressionType, &profileData,
                     &profileLength)) {
        (void)profileName;
        (void)compressionType;
        exercise_icc_profile(profileData, profileLength, exportPath);
    }

    png_destroy_read_struct(&png, &info, NULL);
    fclose(fp);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size < 8 || size > kMaxPngInputSize)
        return 0;

    char pngPath[PATH_MAX];
    if (!write_temp_file(data, size, pngPath, sizeof(pngPath), "/fuzz_pngdump_XXXXXX"))
        return 0;

    char exportPath[PATH_MAX];
    if (!fuzz_build_path(exportPath, sizeof(exportPath), fuzz_tmpdir(),
                         "/fuzz_pngdump_export_XXXXXX")) {
        unlink(pngPath);
        return 0;
    }
    int exportFd = mkstemp(exportPath);
    if (exportFd < 0) {
        unlink(pngPath);
        return 0;
    }
    close(exportFd);

    exercise_png_file(pngPath, exportPath);

    unlink(exportPath);
    unlink(pngPath);
    return 0;
}
