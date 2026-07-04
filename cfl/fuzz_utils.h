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

// Validate ICC profile tag table integrity (Gate 0b/0c).
// Rejects profiles where tag offsets or tag sizes exceed actual file size.
// Header-declared file size mismatches are intentionally allowed up to a hard
// cap because they are a target bug class for these harnesses.
// Returns true if profile passes validation, false to reject.
static inline bool fuzz_validate_icc_tags(const uint8_t *data, size_t size) {
    if (size < 132) return false;
    uint32_t tagCount = ((uint32_t)data[128] << 24) | ((uint32_t)data[129] << 16) |
                        ((uint32_t)data[130] << 8) | (uint32_t)data[131];
    if (tagCount > 200) return false;
    for (uint32_t t = 0; t < tagCount; t++) {
        size_t base = 132 + t * 12;
        if (base + 12 > size) return false;
        uint32_t tOff  = ((uint32_t)data[base+4] << 24) | ((uint32_t)data[base+5] << 16) |
                         ((uint32_t)data[base+6] << 8) | (uint32_t)data[base+7];
        uint32_t tSize = ((uint32_t)data[base+8] << 24) | ((uint32_t)data[base+9] << 16) |
                         ((uint32_t)data[base+10] << 8) | (uint32_t)data[base+11];
        if (tOff > size || tSize > size) return false;
        if (tOff + tSize < tOff) return false;  // overflow
    }
    uint32_t hdrSize = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
                       ((uint32_t)data[2] << 8) | (uint32_t)data[3];
    if (hdrSize > 16U * 1024U * 1024U) return false;
    return true;
}

#endif // FUZZ_UTILS_H
