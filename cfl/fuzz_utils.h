/*
 * fuzz_utils.h - Shared utilities for fuzzer harnesses
 *
 * Provides safe temp-path construction without snprintf format strings.
 */

#ifndef FUZZ_UTILS_H
#define FUZZ_UTILS_H

#include <stdint.h>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

// Get FUZZ_TMPDIR with /tmp fallback
static inline const char *fuzz_tmpdir(void) {
    const char *d = getenv("FUZZ_TMPDIR");
    return d ? d : "/tmp";
}

// Build a temp path (dir + suffix) without format strings.
// Returns total length written, or 0 on overflow.
static inline size_t fuzz_build_path(char *buf, size_t bufsize,
                                     const char *dir, const char *suffix) {
    size_t dlen = strlen(dir);
    size_t slen = strlen(suffix);
    if (dlen + slen >= bufsize) return 0;
    memcpy(buf, dir, dlen);
    memcpy(buf + dlen, suffix, slen + 1);
    return dlen + slen;
}

// Find a repository file from either the current working directory or a source
// file under cfl/. This keeps harnesses tool-shaped without parsing fuzzer
// inputs to synthesize companion argv files.
static inline bool fuzz_find_repo_file(char *buf, size_t bufsize,
                                       const char *source_file,
                                       const char *repo_relative) {
    size_t rlen = strlen(repo_relative);
    if (rlen < bufsize) {
        memcpy(buf, repo_relative, rlen + 1);
        if (access(buf, R_OK) == 0)
            return true;
    }

    static const char up[] = "../";
    if (sizeof(up) - 1 + rlen < bufsize) {
        memcpy(buf, up, sizeof(up) - 1);
        memcpy(buf + sizeof(up) - 1, repo_relative, rlen + 1);
        if (access(buf, R_OK) == 0)
            return true;
    }

    const char *slash = strrchr(source_file, '/');
    if (slash) {
        size_t dlen = (size_t)(slash - source_file + 1);
        if (dlen + sizeof(up) - 1 + rlen < bufsize) {
            memcpy(buf, source_file, dlen);
            memcpy(buf + dlen, up, sizeof(up) - 1);
            memcpy(buf + dlen + sizeof(up) - 1, repo_relative, rlen + 1);
            if (access(buf, R_OK) == 0)
                return true;
        }
    }

    return false;
}

#endif // FUZZ_UTILS_H
