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
    CFL harness for iccDEV iccProfileVisualize.

    Retired: the iccProfileVisualize tool surface is new and this harness
    depended on processLuts(), which is not currently exposed by refreshed
    upstream iccDEV builds. Keep this source for later repair instead of
    carrying it in the active CFL build.

    Modeled command:
      iccProfileVisualize -silent profile

    The input ICC bytes are written to a temporary profile path, loaded with
    OpenIccProfile(), and passed through processLuts() from the tool source.
    Generated PDF/TIFF outputs are removed before returning to LibFuzzer.
 */

#include "fuzz_utils.h"

#include <stddef.h>
#include <stdint.h>
#include <climits>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <string>
#include <unistd.h>

#define main iccProfileVisualizeMain
#include "iccProfileVisualize.cpp"
#undef main

static constexpr size_t kMaxIccInputSize = 5 * 1024 * 1024;

static bool write_profile_file(const uint8_t *data, size_t size, char *path, size_t pathSize)
{
    if (!fuzz_build_path(path, pathSize, fuzz_tmpdir(),
                         "/fuzz_profilevisualize_XXXXXX.icc"))
        return false;

    int fd = mkstemps(path, 4);
    if (fd < 0)
        return false;

    bool wrote = (write(fd, data, size) == (ssize_t)size);
    close(fd);
    if (!wrote)
        unlink(path);

    return wrote;
}

static bool has_prefix(const std::string &text, const std::string &prefix)
{
    return text.size() >= prefix.size() &&
           memcmp(text.data(), prefix.data(), prefix.size()) == 0;
}

static bool has_suffix(const std::string &text, const char *suffix)
{
    size_t suffixLen = strlen(suffix);
    return text.size() >= suffixLen &&
           memcmp(text.data() + text.size() - suffixLen, suffix, suffixLen) == 0;
}

static void cleanup_visualize_outputs(const std::string &profilePath)
{
    std::string basename = icSanitizeFileName(remove_extension(profilePath));
    unlink((basename + "_luts.pdf").c_str());

    size_t slash = basename.find_last_of('/');
    std::string dir = slash == std::string::npos ? "." : basename.substr(0, slash);
    std::string leaf = slash == std::string::npos ? basename : basename.substr(slash + 1);
    std::string prefix = leaf + "_";

    DIR *dp = opendir(dir.c_str());
    if (!dp)
        return;

    while (dirent *ent = readdir(dp)) {
        std::string name = ent->d_name;
        if (!has_prefix(name, prefix) || !has_suffix(name, ".tif"))
            continue;

        std::string path = dir + "/" + name;
        unlink(path.c_str());
    }

    closedir(dp);
}

static void run_profile_visualize(const char *profilePath)
{
    CIccProfile *profile = OpenIccProfile(profilePath);
    if (!profile)
        return;

    gRunSilent = true;
    gLogErrorsToString = true;
    ClearErrorLogs();

    try {
        (void)processLuts(profile, profilePath);
    }
    catch (const std::exception &) {
    }
    catch (...) {
    }

    ClearErrorLogs();
    delete profile;
    cleanup_visualize_outputs(profilePath);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size < 132 || size > kMaxIccInputSize)
        return 0;

    char profilePath[PATH_MAX];
    if (!write_profile_file(data, size, profilePath, sizeof(profilePath)))
        return 0;

    run_profile_visualize(profilePath);

    unlink(profilePath);
    return 0;
}
