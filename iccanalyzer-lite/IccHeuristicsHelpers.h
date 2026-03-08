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
