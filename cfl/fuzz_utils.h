/*
 * fuzz_utils.h — Shared utilities for fuzzer harnesses
 *
 * Provides safe temp-path construction without snprintf format strings.
 */

#ifndef FUZZ_UTILS_H
#define FUZZ_UTILS_H

#include <cstdlib>
#include <cstring>

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

#endif // FUZZ_UTILS_H
