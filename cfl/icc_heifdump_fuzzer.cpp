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
    CFL harness for iccDEV iccHeifDump.

    The input carrier is parsed through the tool-owned HEIF property reader.
    Embedded prof and rICC payloads are then loaded through IccProfLib. Normal
    builds also validate the carrier through libheif; MSan builds omit that
    uninstrumented dependency while retaining the instrumented parser path.
 */

#include "HeifIccProperties.h"
#include "IccProfile.h"
#include "fuzz_utils.h"

#ifdef CFL_HAVE_LIBHEIF
#include <libheif/heif.h>
#endif

#include <climits>
#include <cstddef>
#include <cstdint>
#include <new>
#include <unistd.h>
#include <vector>

static bool write_temp_file(const std::uint8_t *data, std::size_t size,
                            char *path, std::size_t pathSize)
{
    if (!fuzz_build_path(path, pathSize, fuzz_tmpdir(), "/fuzz_heifdump_XXXXXX"))
        return false;

    int fd = mkstemp(path);
    if (fd < 0)
        return false;

    const bool wrote = write(fd, data, size) == static_cast<ssize_t>(size);
    close(fd);
    if (!wrote)
        unlink(path);

    return wrote;
}

static void exercise_profiles(const std::vector<iccdev_heif::IccProperty> &properties,
                              const std::vector<std::uint8_t> &bytes)
{
    for (const auto &property : properties) {
        if (property.profileOffset > bytes.size() ||
            property.profileSize > bytes.size() - property.profileOffset ||
            property.profileSize == 0)
            continue;

        const std::uint8_t *profileData = bytes.data() + property.profileOffset;
        CIccProfile *profile = ReadIccProfile(
            reinterpret_cast<const icUInt8Number *>(profileData),
            static_cast<icUInt32Number>(property.profileSize));
        delete profile;
    }
}

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    if (!data || size == 0)
        return 0;

    char heifPath[PATH_MAX];
    if (!write_temp_file(data, size, heifPath, sizeof(heifPath)))
        return 0;

    std::vector<iccdev_heif::IccProperty> properties;
    std::vector<std::uint8_t> bytes;
    bool collected = false;
    try {
        collected = iccdev_heif::collectIccProperties(heifPath, properties, bytes);
        if (collected)
            exercise_profiles(properties, bytes);
    }
    catch (const std::bad_alloc &) {
    }

#ifdef CFL_HAVE_LIBHEIF
    if (collected) {
        heif_context *context = heif_context_alloc();
        if (context) {
            (void)heif_context_read_from_file(context, heifPath, nullptr);
            heif_context_free(context);
        }
    }
#endif

    unlink(heifPath);
    return 0;
}
