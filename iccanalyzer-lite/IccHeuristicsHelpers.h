/*
 * IccHeuristicsHelpers.h — Shared utility functions for heuristic modules
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

#ifndef ICC_HEURISTICS_HELPERS_H
#define ICC_HEURISTICS_HELPERS_H

#include "IccProfile.h"
#include "IccAnalyzerColors.h"
#include <cstdio>
#include <cstdlib>
#include <cstdint>

// ── ICC Signature Conversion Helpers ──
// UBSAN-safe: uses static_cast<unsigned char> to avoid implicit-conversion warnings
// when byte value > 127.

// Convert a 32-bit ICC signature to a null-terminated 4-char string.
// Usage: char buf[5]; SigToChars(sig, buf);
inline void SigToChars(uint32_t sig, char out[5]) {
  out[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));
  out[1] = static_cast<char>(static_cast<unsigned char>((sig >> 16) & 0xFF));
  out[2] = static_cast<char>(static_cast<unsigned char>((sig >>  8) & 0xFF));
  out[3] = static_cast<char>(static_cast<unsigned char>( sig        & 0xFF));
  out[4] = '\0';
}

// Read a big-endian uint32 from a byte buffer.
// Caller must ensure buf points to at least 4 readable bytes.
inline uint32_t ReadU32BE(const unsigned char *buf) {
  return (static_cast<uint32_t>(buf[0]) << 24) |
         (static_cast<uint32_t>(buf[1]) << 16) |
         (static_cast<uint32_t>(buf[2]) <<  8) |
          static_cast<uint32_t>(buf[3]);
}

// FindAndCast<T> — combines FindTag + dynamic_cast + null check.
// Returns nullptr if tag not found or wrong type.
template <typename T>
T *FindAndCast(CIccProfile *pIcc, icTagSignature sig) {
  CIccTag *tag = pIcc->FindTag(sig);
  if (!tag) return nullptr;
  return dynamic_cast<T *>(tag);
}

// RawFileHandle — RAII wrapper for FILE* with file size.
// Automatically closes file on destruction.
struct RawFileHandle {
  FILE *fp;
  long fileSize;

  RawFileHandle() : fp(nullptr), fileSize(0) {}
  ~RawFileHandle() { if (fp) fclose(fp); }

  RawFileHandle(const RawFileHandle &) = delete;
  RawFileHandle &operator=(const RawFileHandle &) = delete;
  RawFileHandle(RawFileHandle &&other) noexcept : fp(other.fp), fileSize(other.fileSize) {
    other.fp = nullptr;
    other.fileSize = 0;
  }
  RawFileHandle &operator=(RawFileHandle &&other) noexcept {
    if (this != &other) {
      if (fp) fclose(fp);
      fp = other.fp;
      fileSize = other.fileSize;
      other.fp = nullptr;
      other.fileSize = 0;
    }
    return *this;
  }

  explicit operator bool() const { return fp != nullptr; }

  // Read exactly `count` bytes at the current position. Returns true on success.
  bool ReadBytes(void *buf, size_t count) {
    return fp && fread(buf, 1, count, fp) == count;
  }

  // Seek to an absolute offset. Returns true on success.
  bool Seek(long offset) {
    return fp && fseek(fp, offset, SEEK_SET) == 0;
  }

  // Read a big-endian uint32 at the current position. Returns true on success.
  bool ReadU32BE(uint32_t &out) {
    unsigned char buf[4];
    if (!ReadBytes(buf, 4)) return false;
    out = (static_cast<uint32_t>(buf[0]) << 24) |
          (static_cast<uint32_t>(buf[1]) << 16) |
          (static_cast<uint32_t>(buf[2]) <<  8) |
           static_cast<uint32_t>(buf[3]);
    return true;
  }
};

// OpenRawFile — opens a file for binary reading and determines its size.
// Returns a RawFileHandle (RAII). Check with if(handle) before use.
inline RawFileHandle OpenRawFile(const char *filename) {
  RawFileHandle h;
  if (!filename) return h;
  h.fp = fopen(filename, "rb");
  if (!h.fp) return h;
  if (fseek(h.fp, 0, SEEK_END) != 0) {
    fclose(h.fp);
    h.fp = nullptr;
    return h;
  }
  h.fileSize = ftell(h.fp);
  if (h.fileSize < 0) {
    fclose(h.fp);
    h.fp = nullptr;
    return h;
  }
  rewind(h.fp);
  return h;
}

#endif
