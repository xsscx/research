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

// Validate ICC profile tag table integrity (Gate 0b/0c).
// Rejects profiles where tag offsets, tag sizes, or header-declared size
// exceed actual file size. Prevents CWE-789 amplification OOMs.
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
    if (hdrSize > size) return false;
    return true;
}

#endif // FUZZ_UTILS_H
