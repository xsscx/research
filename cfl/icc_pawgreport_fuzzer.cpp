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
    CFL harness for iccDEV iccPawgReport.

    Modeled command:
      iccPawgReport --json profile

    The input ICC profile bytes are written to a temporary file and passed
    through DumpPawgReport() with JSON output enabled.
 */

#include "PawgReport.h"
#include "fuzz_utils.h"

#include <stddef.h>
#include <stdint.h>
#include <climits>
#include <cstdio>
#include <exception>
#include <fcntl.h>
#include <unistd.h>

static constexpr size_t kMaxIccInputSize = 5 * 1024 * 1024;

static bool write_profile_file(const uint8_t *data, size_t size, char *path, size_t pathSize)
{
    if (!fuzz_build_path(path, pathSize, fuzz_tmpdir(), "/fuzz_pawgreport_XXXXXX"))
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

static void run_report_quietly(const char *path)
{
    fflush(stdout);
    int savedStdout = dup(STDOUT_FILENO);
    int devNull = open("/dev/null", O_WRONLY);
    if (savedStdout < 0 || devNull < 0) {
        if (savedStdout >= 0)
            close(savedStdout);
        if (devNull >= 0)
            close(devNull);
        (void)DumpPawgReport(path, true);
        return;
    }

    dup2(devNull, STDOUT_FILENO);
    close(devNull);
    (void)DumpPawgReport(path, true);
    fflush(stdout);
    dup2(savedStdout, STDOUT_FILENO);
    close(savedStdout);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!data || size < 132 || size > kMaxIccInputSize)
        return 0;

    char profilePath[PATH_MAX];
    if (!write_profile_file(data, size, profilePath, sizeof(profilePath)))
        return 0;

    try {
        run_report_quietly(profilePath);
    }
    catch (const std::exception &) {
    }
    catch (...) {
    }

    unlink(profilePath);
    return 0;
}
