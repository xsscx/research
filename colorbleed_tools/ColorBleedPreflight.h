/*!
 *  @file ColorBleedPreflight.h
 *  @brief Pre-flight ICC profile validation before unsafe library calls
 *  @author David Hoyt
 *  @date 28 FEB 2026
 *  @version 1.0.0
 *
 *  Pure binary-read validation of ICC profile headers and tag tables.
 *  Runs BEFORE calling any iccDEV library functions to detect malformed
 *  profiles that would trigger crashes in unpatched code.
 *
 *  Adapted from iccanalyzer-lite heuristics (H1-H19) for use in
 *  colorbleed tools. Unlike iccanalyzer-lite, this does NOT reject
 *  profiles — it logs warnings and returns a risk assessment so the
 *  sandbox can make informed decisions about resource limits.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#ifndef COLORBLEED_PREFLIGHT_H
#define COLORBLEED_PREFLIGHT_H

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <cctype>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// ── Resource limits (aligned with iccanalyzer-lite) ──
static constexpr uint64_t CB_MAX_PROFILE_SIZE   = 1ULL << 30;   // 1 GiB
static constexpr uint64_t CB_MAX_TAG_SIZE       = 64ULL << 20;  // 64 MiB per tag
static constexpr uint32_t CB_MAX_TAG_COUNT      = 200;
static constexpr uint64_t CB_MAX_CLUT_ENTRIES   = 16ULL << 20;  // 16M entries
static constexpr uint32_t CB_MAX_MPE_ELEMENTS   = 1024;

// ── icRealloc OOM guard ──
// iccDEV routes all tag allocations through icRealloc() (IccUtil.cpp:112).
// To override, compile ColorBleedAlloc.cpp as a separate object linked
// BEFORE libIccProfLib2-static.a. See build.sh for link order.
// Cap: 256 MB per single allocation.

// ── Safe arithmetic ──
static inline bool SafeMul64(uint64_t *r, uint64_t a, uint64_t b) {
  if (a == 0 || b == 0) { *r = 0; return true; }
  if (a > UINT64_MAX / b) return false;
  *r = a * b;
  return true;
}

// ── Sanitize a 4-byte ICC signature for safe display ──
static inline void SanitizeSig4(const uint8_t* raw, char out[5]) {
  for (int i = 0; i < 4; i++) {
    uint8_t c = raw[i];
    out[i] = (c >= 0x20 && c <= 0x7E) ? static_cast<char>(c) : '?';
  }
  out[4] = '\0';
}

// ── Big-endian readers ──
static inline uint32_t ReadBE32(const uint8_t *p) {
  return ((uint32_t)p[0]<<24) | ((uint32_t)p[1]<<16) |
         ((uint32_t)p[2]<<8)  |  (uint32_t)p[3];
}

static inline uint16_t ReadBE16(const uint8_t *p) {
  return ((uint16_t)p[0]<<8) | (uint16_t)p[1];
}

// ── Preflight result ──
enum class PreflightSeverity { CLEAN, WARNING, CRITICAL };

struct PreflightWarning {
  std::string heuristic;  // e.g. "H1", "H14"
  std::string message;
  PreflightSeverity severity;
};

struct PreflightResult {
  PreflightSeverity worst = PreflightSeverity::CLEAN;
  std::vector<PreflightWarning> warnings;
  uint32_t profile_size = 0;
  uint32_t tag_count = 0;
  bool has_tag_array = false;

  void AddWarning(const char* id, const char* msg, PreflightSeverity sev) {
    warnings.push_back({id, msg, sev});
    if (sev > worst) worst = sev;
  }

  void Report(const char* filename) const {
    fprintf(stderr, "\n[ColorBleed] Pre-flight scan: %s\n", filename);
    if (worst == PreflightSeverity::CLEAN) {
      fprintf(stderr, "[ColorBleed] Pre-flight: CLEAN (%u tags, %u bytes)\n",
              tag_count, profile_size);
      return;
    }
    for (const auto& w : warnings) {
      const char* sev = (w.severity == PreflightSeverity::CRITICAL) ? "CRITICAL" : "WARNING";
      fprintf(stderr, "[ColorBleed] [%s] %s: %s\n", w.heuristic.c_str(), sev, w.message.c_str());
    }
    fprintf(stderr, "[ColorBleed] Pre-flight: %zu warning(s), worst=%s\n",
            warnings.size(),
            worst == PreflightSeverity::CRITICAL ? "CRITICAL" : "WARNING");
  }
};

// ── Core pre-flight validation ──
// Reads only raw bytes — no iccDEV library calls.
#ifndef COLORBLEED_SKIP_ICC_PREFLIGHT
static PreflightResult PreflightValidateICC(const char* filename) {
  PreflightResult result;

  // Open first, then fstat on the fd to avoid TOCTOU
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    result.AddWarning("H0", "Cannot open file",
                      PreflightSeverity::CRITICAL);
    return result;
  }

  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    result.AddWarning("H0", "Cannot stat file or not a regular file",
                      PreflightSeverity::CRITICAL);
    close(fd);
    return result;
  }
  size_t fileSize = st.st_size;

  if (fileSize < 132) {
    result.AddWarning("H0", "File too small for ICC header + tag count (< 132 bytes)",
                      PreflightSeverity::CRITICAL);
    close(fd);
    return result;
  }

  FILE* fp = fdopen(fd, "rb");
  if (!fp) {
    result.AddWarning("H0", "Cannot open file stream", PreflightSeverity::CRITICAL);
    close(fd);
    return result;
  }

  // Read full header (128 bytes) + tag count (4 bytes)
  uint8_t hdr[132];
  if (fread(hdr, 1, 132, fp) != 132) {
    result.AddWarning("H0", "Cannot read ICC header", PreflightSeverity::CRITICAL);
    fclose(fp);
    return result;
  }

  // ── H1: Profile Size ──
  uint32_t profileSize = ReadBE32(hdr + 0);
  result.profile_size = profileSize;

  if (profileSize == 0) {
    result.AddWarning("H1", "Profile size is ZERO", PreflightSeverity::CRITICAL);
  } else if (profileSize > CB_MAX_PROFILE_SIZE) {
    char buf[128];
    snprintf(buf, sizeof(buf), "Profile claims %u bytes (> 1 GiB limit)", profileSize);
    result.AddWarning("H1", buf, PreflightSeverity::CRITICAL);
  }

  // Size inflation: header claims much more than actual file
  if (profileSize > 0 && profileSize > fileSize * 16 && profileSize > (128u << 20)) {
    char buf[128];
    snprintf(buf, sizeof(buf), "Size inflation: header=%u, file=%zu (%.0fx)",
             profileSize, fileSize, (double)profileSize / fileSize);
    result.AddWarning("H1", buf, PreflightSeverity::CRITICAL);
  }

  // ── H2: Magic Bytes (offset 36 = 0x24) ──
  if (memcmp(hdr + 36, "acsp", 4) != 0) {
    result.AddWarning("H2", "Invalid magic bytes (expected 'acsp' at offset 0x24)",
                      PreflightSeverity::CRITICAL);
  }

  // ── H3: Data ColorSpace (offset 16) ──
  uint32_t colorSpace = ReadBE32(hdr + 16);
  {
    uint8_t cs[4] = {(uint8_t)(colorSpace>>24), (uint8_t)(colorSpace>>16),
                     (uint8_t)(colorSpace>>8),  (uint8_t)colorSpace};
    bool printable = true;
    for (int i = 0; i < 4; i++) {
      if (cs[i] < 0x20 || cs[i] > 0x7E) { printable = false; break; }
    }
    if (!printable) {
      result.AddWarning("H3", "ColorSpace contains non-printable characters",
                        PreflightSeverity::WARNING);
    }
  }

  // ── H4: PCS (offset 20) ──
  uint32_t pcs = ReadBE32(hdr + 20);
  // 'XYZ ' = 0x58595A20, 'Lab ' = 0x4C616220
  if (pcs != 0x58595A20 && pcs != 0x4C616220) {
    // Allow ICC v5 spectral PCS (check version)
    uint32_t version = ReadBE32(hdr + 8);
    uint8_t majorVer = (version >> 24) & 0xFF;
    if (majorVer < 5) {
      result.AddWarning("H4", "PCS is neither XYZ nor Lab (v2/v4 must be one of these)",
                        PreflightSeverity::WARNING);
    }
  }

  // ── H6: Rendering Intent (offset 64) ──
  uint32_t intent = ReadBE32(hdr + 64);
  if (intent > 3) {
    char buf[80];
    snprintf(buf, sizeof(buf), "Rendering intent %u out of range (0-3)", intent);
    result.AddWarning("H6", buf, PreflightSeverity::WARNING);
  }

  // ── H8: Illuminant XYZ (offset 68, 3×4 bytes = s15Fixed16Number) ──
  {
    int32_t illumX = (int32_t)ReadBE32(hdr + 68);
    int32_t illumY = (int32_t)ReadBE32(hdr + 72);
    int32_t illumZ = (int32_t)ReadBE32(hdr + 76);
    if (illumX < 0 || illumY < 0 || illumZ < 0) {
      result.AddWarning("H8", "Illuminant XYZ has negative value(s)",
                        PreflightSeverity::WARNING);
    }
    // Check for NaN-like patterns (all bits set in mantissa, exponent)
    // s15Fixed16 doesn't have NaN, but 0x7FFFFFFF or 0x80000000 are suspicious
    double xVal = illumX / 65536.0;
    double yVal = illumY / 65536.0;
    double zVal = illumZ / 65536.0;
    if (xVal > 5.0 || yVal > 5.0 || zVal > 5.0) {
      result.AddWarning("H8", "Illuminant XYZ value(s) > 5.0 (suspicious range)",
                        PreflightSeverity::WARNING);
    }
  }

  // ── H15: Date Validation (offset 24, 6×2 bytes) ──
  {
    uint16_t year   = ReadBE16(hdr + 24);
    uint16_t month  = ReadBE16(hdr + 26);
    uint16_t day    = ReadBE16(hdr + 28);
    uint16_t hour   = ReadBE16(hdr + 30);
    uint16_t minute = ReadBE16(hdr + 32);
    uint16_t second = ReadBE16(hdr + 34);
    if (month < 1 || month > 12 || day < 1 || day > 31 ||
        hour > 23 || minute > 59 || second > 59 ||
        year < 1900 || year > 2100) {
      result.AddWarning("H15", "Invalid date/time fields in header",
                        PreflightSeverity::WARNING);
    }
  }

  // ── H16: Signature Pattern Analysis ──
  {
    uint32_t devClass = ReadBE32(hdr + 12);
    uint32_t platform = ReadBE32(hdr + 40);
    uint32_t sigs[] = {colorSpace, pcs, devClass, platform};
    for (int i = 0; i < 4; i++) {
      uint8_t b = sigs[i] & 0xFF;
      if (b == ((sigs[i]>>8)&0xFF) && b == ((sigs[i]>>16)&0xFF) && b == ((sigs[i]>>24)&0xFF)) {
        if (sigs[i] != 0x20202020 && sigs[i] != 0) { // spaces and null are valid
          char buf[80];
          snprintf(buf, sizeof(buf), "Repeat-byte pattern 0x%08X (fuzz artifact?)", sigs[i]);
          result.AddWarning("H16", buf, PreflightSeverity::WARNING);
          break; // one warning is enough
        }
      }
    }
  }

  // ── Tag Table Validation ──
  uint32_t tagCount = ReadBE32(hdr + 128);
  result.tag_count = tagCount;

  // ── H10: Tag Count ──
  if (tagCount == 0) {
    result.AddWarning("H10", "Zero tags (invalid profile)", PreflightSeverity::WARNING);
  } else if (tagCount > CB_MAX_TAG_COUNT) {
    char buf[80];
    snprintf(buf, sizeof(buf), "Excessive tag count: %u (limit %u)", tagCount, CB_MAX_TAG_COUNT);
    result.AddWarning("H10", buf, PreflightSeverity::CRITICAL);
  }

  // Read tag table entries (each 12 bytes: sig + offset + size)
  uint32_t safeTagCount = (tagCount > 256) ? 256 : tagCount;
  size_t tagTableSize = (size_t)safeTagCount * 12;

  struct TagEntry { uint32_t sig; uint32_t offset; uint32_t size; };
  std::vector<TagEntry> tags;

  if (tagTableSize > 0 && 132 + tagTableSize <= fileSize) {
    std::vector<uint8_t> tagData(tagTableSize);
    fseek(fp, 132, SEEK_SET);
    if (fread(tagData.data(), 1, tagTableSize, fp) == tagTableSize) {
      tags.reserve(safeTagCount);
      for (uint32_t i = 0; i < safeTagCount; i++) {
        const uint8_t* e = tagData.data() + i * 12;
        TagEntry t;
        t.sig    = ReadBE32(e + 0);
        t.offset = ReadBE32(e + 4);
        t.size   = ReadBE32(e + 8);
        tags.push_back(t);
      }
    }
  }

  // ── H13: Per-Tag Size Check ──
  for (const auto& t : tags) {
    if (t.size > CB_MAX_TAG_SIZE) {
      char buf[128];
      uint8_t raw4[4] = {(uint8_t)(t.sig>>24),(uint8_t)(t.sig>>16),(uint8_t)(t.sig>>8),(uint8_t)t.sig};
      char sig4[5]; SanitizeSig4(raw4, sig4);
      snprintf(buf, sizeof(buf), "Tag '%.4s' size=%u bytes (%.1f MB > 64 MB limit)",
               sig4, t.size, t.size / (1024.0 * 1024.0));
      result.AddWarning("H13", buf, PreflightSeverity::CRITICAL);
    }
  }

  // ── H14: TagArrayType Detection (UAF Risk) ──
  for (const auto& t : tags) {
    if (t.offset >= 128 && t.size >= 4 && t.size <= fileSize &&
        t.offset <= fileSize - t.size) {
      uint8_t typeBytes[4];
      fseek(fp, t.offset, SEEK_SET);
      if (fread(typeBytes, 1, 4, fp) == 4) {
        uint32_t tagType = ReadBE32(typeBytes);
        if (tagType == 0x74617279) { // 'tary' = TagArrayType
          uint8_t raw4[4] = {(uint8_t)(t.sig>>24),(uint8_t)(t.sig>>16),(uint8_t)(t.sig>>8),(uint8_t)t.sig};
          char sig4[5]; SanitizeSig4(raw4, sig4);
          char buf[128];
          snprintf(buf, sizeof(buf),
                   "TagArrayType ('tary') under signature '%.4s' — UAF in CIccTagArray::Cleanup()",
                   sig4);
          result.AddWarning("H14", buf, PreflightSeverity::CRITICAL);
          result.has_tag_array = true;
        }
      }
    }
  }

  // ── H19: Tag Overlap Detection ──
  {
    int overlapCount = 0;
    for (size_t a = 0; a < tags.size(); a++) {
      for (size_t b = a + 1; b < tags.size(); b++) {
        // Shared tag data (same offset+size) is allowed by spec
        if (tags[a].offset == tags[b].offset && tags[a].size == tags[b].size)
          continue;
        uint64_t aEnd = (uint64_t)tags[a].offset + tags[a].size;
        uint64_t bEnd = (uint64_t)tags[b].offset + tags[b].size;
        if (tags[a].offset < bEnd && tags[b].offset < aEnd &&
            tags[a].offset != tags[b].offset) {
          overlapCount++;
          if (overlapCount == 1) { // report first one
            uint8_t ra[4] = {(uint8_t)(tags[a].sig>>24),(uint8_t)(tags[a].sig>>16),(uint8_t)(tags[a].sig>>8),(uint8_t)tags[a].sig};
            uint8_t rb[4] = {(uint8_t)(tags[b].sig>>24),(uint8_t)(tags[b].sig>>16),(uint8_t)(tags[b].sig>>8),(uint8_t)tags[b].sig};
            char s1[5]; SanitizeSig4(ra, s1);
            char s2[5]; SanitizeSig4(rb, s2);
            char buf[128];
            snprintf(buf, sizeof(buf), "Tags '%.4s' and '%.4s' overlap: [%u+%u] vs [%u+%u]",
                     s1, s2, tags[a].offset, tags[a].size, tags[b].offset, tags[b].size);
            result.AddWarning("H19", buf, PreflightSeverity::WARNING);
          }
        }
      }
    }
    if (overlapCount > 1) {
      char buf[64];
      snprintf(buf, sizeof(buf), "%d total tag overlap(s) detected", overlapCount);
      result.AddWarning("H19", buf, PreflightSeverity::WARNING);
    }
  }

  // ── Tag bounds check: offsets within file ──
  for (const auto& t : tags) {
    if (t.offset > 0 && t.size > 0) {
      uint64_t end = (uint64_t)t.offset + t.size;
      if (end > fileSize) {
        uint8_t raw4[4] = {(uint8_t)(t.sig>>24),(uint8_t)(t.sig>>16),(uint8_t)(t.sig>>8),(uint8_t)t.sig};
        char sig4[5]; SanitizeSig4(raw4, sig4);
        char buf[128];
        snprintf(buf, sizeof(buf), "Tag '%.4s' extends past EOF: offset=%u size=%u file=%zu",
                 sig4, t.offset, t.size, fileSize);
        result.AddWarning("H0", buf, PreflightSeverity::WARNING);
      }
    }
  }

  fclose(fp);
  return result;
}
#endif // COLORBLEED_SKIP_ICC_PREFLIGHT

// ── XML pre-flight for IccFromXml ──
#ifndef COLORBLEED_SKIP_XML_PREFLIGHT
static PreflightResult PreflightValidateXML(const char* filename) {
  PreflightResult result;

  // Open first, then fstat on the fd to avoid TOCTOU
  int fd = open(filename, O_RDONLY);
  if (fd < 0) {
    result.AddWarning("X0", "Cannot open XML file",
                      PreflightSeverity::CRITICAL);
    return result;
  }

  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    result.AddWarning("X0", "Cannot stat file or not a regular file",
                      PreflightSeverity::CRITICAL);
    close(fd);
    return result;
  }
  size_t fileSize = st.st_size;

  if (fileSize == 0) {
    result.AddWarning("X0", "Empty XML file", PreflightSeverity::CRITICAL);
    close(fd);
    return result;
  }

  if (fileSize > CB_MAX_PROFILE_SIZE) {
    char buf[128];
    snprintf(buf, sizeof(buf), "XML file %zu bytes exceeds 1 GiB limit", fileSize);
    result.AddWarning("X1", buf, PreflightSeverity::CRITICAL);
    close(fd);
    return result;
  }

  // Check for XXE indicators — scan up to 1MB
  FILE* fp = fdopen(fd, "rb");
  if (!fp) {
    result.AddWarning("X0", "Cannot open file stream", PreflightSeverity::CRITICAL);
    close(fd);
    return result;
  }

  size_t checkSize = (fileSize < (1024*1024)) ? fileSize : (1024*1024);
  std::vector<uint8_t> head(checkSize);
  if (fread(head.data(), 1, checkSize, fp) == checkSize) {
    // Case-insensitive search for XXE patterns
    std::string preview(head.begin(), head.end());
    // Convert to lowercase for case-insensitive matching
    std::string lower = preview;
    for (auto& c : lower) c = (char)tolower((unsigned char)c);

    if (lower.find("<!entity") != std::string::npos) {
      result.AddWarning("X2", "XML contains <!ENTITY declaration (XXE risk)",
                        PreflightSeverity::CRITICAL);
    }
    if (lower.find("system") != std::string::npos &&
        lower.find("<!doctype") != std::string::npos) {
      result.AddWarning("X2", "XML DOCTYPE references SYSTEM entity (XXE risk)",
                        PreflightSeverity::WARNING);
    }
    // XInclude: <xi:include href="file:///etc/passwd"/>
    if (lower.find("<xi:include") != std::string::npos ||
        lower.find("xinclude") != std::string::npos) {
      result.AddWarning("X3", "XML contains XInclude directive (file inclusion risk)",
                        PreflightSeverity::CRITICAL);
    }
    // Parameter entities: <!ENTITY % name "value">
    if (lower.find("<!entity %") != std::string::npos ||
        lower.find("<!entity%") != std::string::npos) {
      result.AddWarning("X4", "XML contains parameter entity (XXE amplification risk)",
                        PreflightSeverity::CRITICAL);
    }
  }

  fclose(fp);
  return result;
}
#endif // COLORBLEED_SKIP_XML_PREFLIGHT

#endif // COLORBLEED_PREFLIGHT_H
