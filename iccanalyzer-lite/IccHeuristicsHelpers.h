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
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <limits.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

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

inline uint16_t ReadU16BE(const unsigned char *buf) {
  return (static_cast<uint16_t>(buf[0]) << 8) |
          static_cast<uint16_t>(buf[1]);
}

// The upstream iccDEV icF16toF() implementation rebiases the exponent using
// unsigned arithmetic. Any non-zero half-float with exponent < 15 (that is,
// any magnitude below 1.0, including subnormals) trips UBSAN even though the
// numerical result is otherwise representable.
inline bool HalfFloatTriggersIccUtilUB(icFloat16Number raw) {
  icUInt16Number mag = static_cast<icUInt16Number>(raw & 0x7FFFu);
  icUInt16Number exp = static_cast<icUInt16Number>((mag >> 10) & 0x1Fu);
  return mag != 0 && exp < 15;
}

// Analyzer-owned half-float conversion that preserves the upstream semantics
// without the unsigned-wrap UBSAN hit in iccDEV IccUtil.cpp:665/677.
inline icFloatNumber SafeF16ToF(icFloat16Number num) {
  icUInt16Number signBits = static_cast<icUInt16Number>(num & 0x8000u);
  icUInt16Number expBits = static_cast<icUInt16Number>((num >> 10) & 0x1Fu);
  icUInt16Number mantBits = static_cast<icUInt16Number>(num & 0x03FFu);
  icUInt32Number bits = static_cast<icUInt32Number>(signBits) << 16;

  if ((num & 0x7FFFu) == 0) {
    bits = static_cast<icUInt32Number>(num) << 16;
  } else if (expBits == 0) {
    int exp = -14;
    icUInt16Number mant = mantBits;
    while ((mant & 0x0400u) == 0) {
      mant <<= 1;
      --exp;
    }
    mant = static_cast<icUInt16Number>(mant & 0x03FFu);
    bits |= (static_cast<icUInt32Number>(exp + 127) << 23) |
            (static_cast<icUInt32Number>(mant) << 13);
  } else if (expBits == 0x1Fu) {
    bits |= 0x7F800000u | (static_cast<icUInt32Number>(mantBits) << 13);
    if (mantBits) {
      bits |= 0x00400000u; // Quiet NaN bit.
    }
  } else {
    int exp = static_cast<int>(expBits) - 15 + 127;
    bits |= (static_cast<icUInt32Number>(exp) << 23) |
            (static_cast<icUInt32Number>(mantBits) << 13);
  }

  icFloatNumber out = 0.0f;
  std::memcpy(&out, &bits, sizeof(out));
  return out;
}

// Exact float comparison for spec-driven equality checks without direct
// floating-point == / != operators. Treats +0.0 and -0.0 as equal.
inline bool ExactFiniteFloatEqual(icFloatNumber a, icFloatNumber b) {
  if (!std::isfinite(a) || !std::isfinite(b)) {
    return false;
  }

  uint32_t aBits = 0;
  uint32_t bBits = 0;
  std::memcpy(&aBits, &a, sizeof(aBits));
  std::memcpy(&bBits, &b, sizeof(bBits));

  if ((aBits & 0x7FFFFFFFu) == 0u && (bBits & 0x7FFFFFFFu) == 0u) {
    return true;
  }

  return aBits == bBits;
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
  if (!filename[0]) return h;
  if (std::strlen(filename) >= PATH_MAX) return h;

  char resolvedPath[PATH_MAX];
  if (!realpath(filename, resolvedPath)) return h;

  int fd = open(resolvedPath, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return h;

  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return h;
  }

  h.fp = fdopen(fd, "rb");
  if (!h.fp) {
    close(fd);
    return h;
  }
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

// ── Shared Raw Profile Context ──
// Pre-parsed ICC header and tag table for raw-file heuristics.
// Created once per profile, shared across all raw heuristics to
// eliminate redundant fopen/header-parse/tag-table-parse cycles.
// The FILE* remains open for heuristics that need to seek to tag data.

static constexpr uint32_t kMaxContextTags = 256;

struct RawProfileContext {
  RawFileHandle fh;
  uint8_t header[132];
  uint32_t tagCount;

  struct TagEntry {
    uint32_t sig;
    uint32_t offset;
    uint32_t size;
  };
  std::vector<TagEntry> tags;
  bool valid;

  RawProfileContext() : tagCount(0), valid(false) {
    memset(header, 0, sizeof(header));
  }

  size_t fileSize() const { return static_cast<size_t>(fh.fileSize); }

  // Read bytes at absolute file offset.
  bool ReadAt(size_t offset, void *buf, size_t count) {
    if (!valid || offset + count > fileSize()) return false;
    return fh.Seek(static_cast<long>(offset)) && fh.ReadBytes(buf, count);
  }

  // Find first tag entry matching a signature (or nullptr).
  const TagEntry *FindTag(uint32_t sig) const {
    for (const auto &t : tags)
      if (t.sig == sig) return &t;
    return nullptr;
  }
};

struct RawMpePositionIssue {
  uint32_t tagSig = 0;
  uint32_t tagSize = 0;
  uint32_t procElementCount = 0;
  uint32_t entryIndex = 0;
  uint32_t elementOffset = 0;
  uint32_t elementSize = 0;
  uint32_t elementSig = 0;
  bool positionTableTruncated = false;
  bool offsetSizeWrap = false;
  bool exceedsTagSize = false;
};

inline std::string FormatRawMpePositionIssue(const RawMpePositionIssue &issue) {
  char tagName[5] = {};
  char elemName[5] = {};
  SigToChars(issue.tagSig, tagName);
  SigToChars(issue.elementSig, elemName);

  char msg[512];
  if (issue.positionTableTruncated) {
    snprintf(msg, sizeof(msg),
             "Tag '%s': mpet position table requires %u entries (%llu bytes) but tag size is %u",
             tagName,
             issue.procElementCount,
             static_cast<unsigned long long>(issue.procElementCount) * 8ull,
             issue.tagSize);
    return msg;
  }

  if (issue.elementSig) {
    snprintf(msg, sizeof(msg),
             "Tag '%s': mpet element table entry %u ('%s') offset=%u size=%u %s%s tag size=%u",
             tagName,
             issue.entryIndex,
             elemName,
             issue.elementOffset,
             issue.elementSize,
             issue.offsetSizeWrap ? "wraps 32-bit offset+size" : "extends beyond tag bounds",
             issue.exceedsTagSize ? " and exceeds" : "",
             issue.tagSize);
  } else {
    snprintf(msg, sizeof(msg),
             "Tag '%s': mpet element table entry %u offset=%u size=%u %s%s tag size=%u",
             tagName,
             issue.entryIndex,
             issue.elementOffset,
             issue.elementSize,
             issue.offsetSizeWrap ? "wraps 32-bit offset+size" : "extends beyond",
             issue.exceedsTagSize ? " and exceeds" : "",
             issue.tagSize);
  }
  return msg;
}

inline std::vector<RawMpePositionIssue>
ScanRawMpePositionIssues(RawProfileContext &ctx, size_t maxIssues = 8) {
  std::vector<RawMpePositionIssue> issues;
  if (!ctx.valid) return issues;

  constexpr uint32_t kMpeType = 0x6D706574u; // 'mpet'
  constexpr uint32_t kMpeHeaderSize = 16u;

  for (const auto &tag : ctx.tags) {
    if (tag.size < kMpeHeaderSize) continue;
    if ((uint64_t)tag.offset + kMpeHeaderSize > ctx.fileSize()) continue;

    uint8_t hdr[16] = {};
    if (!ctx.ReadAt(tag.offset, hdr, sizeof(hdr))) continue;
    if (ReadU32BE(hdr) != kMpeType) continue;

    uint32_t nProcElements = ReadU32BE(hdr + 12);
    uint64_t requiredTableBytes =
        (uint64_t)kMpeHeaderSize + (uint64_t)nProcElements * 8ull;

    if (requiredTableBytes > tag.size) {
      RawMpePositionIssue issue;
      issue.tagSig = tag.sig;
      issue.tagSize = tag.size;
      issue.procElementCount = nProcElements;
      issue.positionTableTruncated = true;
      issues.push_back(issue);
      if (issues.size() >= maxIssues) return issues;
    }

    uint64_t availableSlots64 = tag.size > kMpeHeaderSize
        ? ((uint64_t)tag.size - kMpeHeaderSize) / 8ull
        : 0ull;
    uint32_t scanCount = nProcElements;
    if ((uint64_t)scanCount > availableSlots64) {
      scanCount = static_cast<uint32_t>(availableSlots64);
    }
    if (scanCount > 4096u) scanCount = 4096u;

    for (uint32_t i = 0; i < scanCount; ++i) {
      uint8_t posBuf[8] = {};
      size_t posOff = static_cast<size_t>(tag.offset) + kMpeHeaderSize + (size_t)i * 8u;
      if (!ctx.ReadAt(posOff, posBuf, sizeof(posBuf))) break;

      uint32_t elemOff = ReadU32BE(posBuf);
      uint32_t elemSize = ReadU32BE(posBuf + 4);
      uint64_t sum64 = (uint64_t)elemOff + (uint64_t)elemSize;
      bool wrap = sum64 > 0xFFFFFFFFull;
      bool beyondTag = sum64 > tag.size;
      if (!wrap && !beyondTag) continue;

      RawMpePositionIssue issue;
      issue.tagSig = tag.sig;
      issue.tagSize = tag.size;
      issue.procElementCount = nProcElements;
      issue.entryIndex = i;
      issue.elementOffset = elemOff;
      issue.elementSize = elemSize;
      issue.offsetSizeWrap = wrap;
      issue.exceedsTagSize = beyondTag;

      if ((uint64_t)elemOff + 4ull <= tag.size &&
          (uint64_t)tag.offset + elemOff + 4ull <= ctx.fileSize()) {
        uint8_t elemHdr[4] = {};
        if (ctx.ReadAt((size_t)tag.offset + elemOff, elemHdr, sizeof(elemHdr))) {
          issue.elementSig = ReadU32BE(elemHdr);
        }
      }

      issues.push_back(issue);
      if (issues.size() >= maxIssues) return issues;
    }
  }

  return issues;
}

enum class RawMpeNullApplyIssueKind {
  MissingClutWithActiveCurves,
  ZeroChannelMpe,
};

struct RawMpeNullApplyIssue {
  RawMpeNullApplyIssueKind kind = RawMpeNullApplyIssueKind::MissingClutWithActiveCurves;
  uint32_t tagSig = 0;
  uint32_t typeSig = 0;
  uint16_t inputChannels = 0;
  uint16_t outputChannels = 0;
  uint32_t clutOffset = 0;
  uint32_t bCurveOffset = 0;
  uint32_t aCurveOffset = 0;
  uint32_t procElementCount = 0;
};

inline const char *MpeTypeName(uint32_t sig) {
  switch (sig) {
    case 0x6D414220u: return "mAB";
    case 0x6D424120u: return "mBA";
    case 0x6D706574u: return "MPET";
    default: return "MPE";
  }
}

inline std::string FormatRawMpeNullApplyIssue(const RawMpeNullApplyIssue &issue) {
  char msg[512];
  char tagName[5];
  SigToChars(issue.tagSig, tagName);
  if (issue.kind == RawMpeNullApplyIssueKind::MissingClutWithActiveCurves) {
    snprintf(msg, sizeof(msg),
             "HEURISTIC: Tag '%s' (%s) has %u→%u channels with CLUT offset=0 but active curves — "
             "m_pCLUT will be NULL in Apply() — ICC.1-2022-05 §10.10",
             tagName,
             MpeTypeName(issue.typeSig),
             static_cast<unsigned>(issue.inputChannels),
             static_cast<unsigned>(issue.outputChannels));
    return msg;
  }

  snprintf(msg, sizeof(msg),
           "HEURISTIC: Tag '%s' MPET has %u elements with %u→%u channels — "
           "zero channels create null internal state in Begin() — ICC.2-2023 §10.14",
           tagName,
           issue.procElementCount,
           static_cast<unsigned>(issue.inputChannels),
           static_cast<unsigned>(issue.outputChannels));
  return msg;
}

inline std::string MpeNullApplyIssueCweNote(const RawMpeNullApplyIssue &issue) {
  if (issue.kind == RawMpeNullApplyIssueKind::MissingClutWithActiveCurves) {
    return "CWE-476: IccMpeBasic.cpp:5712 — m_pCLUT->InterpNd() null deref";
  }
  return "CWE-476: CIccMpeCurveSet::Begin() returns false → Apply() null deref";
}

inline std::vector<RawMpeNullApplyIssue>
ScanRawMpeNullApplyIssues(RawProfileContext &ctx, size_t maxIssues = 8) {
  std::vector<RawMpeNullApplyIssue> issues;
  if (!ctx.valid || !ctx.fh) return issues;

  const size_t fs = ctx.fileSize();
  constexpr uint32_t kMabType = 0x6D414220u;  // 'mAB '
  constexpr uint32_t kMbaType = 0x6D424120u;  // 'mBA '
  constexpr uint32_t kMpetType = 0x6D706574u; // 'mpet'

  for (const auto &tag : ctx.tags) {
    if (issues.size() >= maxIssues) break;
    if (tag.size < 8 || static_cast<uint64_t>(tag.offset) + 8 > fs) continue;

    uint8_t typeHdr[4] = {};
    if (!ctx.ReadAt(tag.offset, typeHdr, sizeof(typeHdr))) continue;
    uint32_t type = ReadU32BE(typeHdr);

    if ((type == kMabType || type == kMbaType) &&
        tag.size >= 32 &&
        static_cast<uint64_t>(tag.offset) + 32 <= fs) {
      uint8_t mabHdr[24] = {};
      if (!ctx.ReadAt(tag.offset + 8, mabHdr, sizeof(mabHdr))) continue;

      RawMpeNullApplyIssue issue;
      issue.kind = RawMpeNullApplyIssueKind::MissingClutWithActiveCurves;
      issue.tagSig = tag.sig;
      issue.typeSig = type;
      issue.inputChannels = mabHdr[0];
      issue.outputChannels = mabHdr[1];
      issue.bCurveOffset = ReadU32BE(&mabHdr[4]);
      issue.clutOffset = ReadU32BE(&mabHdr[20]);

      if (tag.size >= 40 &&
          static_cast<uint64_t>(tag.offset) + 40 <= fs) {
        uint8_t extra[4] = {};
        if (ctx.ReadAt(tag.offset + 36, extra, sizeof(extra))) {
          issue.aCurveOffset = ReadU32BE(extra);
        }
      }

      if (issue.clutOffset == 0 &&
          issue.inputChannels > 0 &&
          issue.outputChannels > 0 &&
          (issue.bCurveOffset != 0 || issue.aCurveOffset != 0)) {
        issues.push_back(issue);
        if (issues.size() >= maxIssues) return issues;
      }
      continue;
    }

    if (type == kMpetType &&
        tag.size >= 16 &&
        static_cast<uint64_t>(tag.offset) + 16 <= fs) {
      uint8_t mpetHdr[8] = {};
      if (!ctx.ReadAt(tag.offset + 8, mpetHdr, sizeof(mpetHdr))) continue;

      uint16_t nInputCh = static_cast<uint16_t>(mpetHdr[0]) << 8 | mpetHdr[1];
      uint16_t nOutputCh = static_cast<uint16_t>(mpetHdr[2]) << 8 | mpetHdr[3];
      uint32_t nElements = ReadU32BE(&mpetHdr[4]);

      if ((nInputCh == 0 || nOutputCh == 0) && nElements > 0) {
        RawMpeNullApplyIssue issue;
        issue.kind = RawMpeNullApplyIssueKind::ZeroChannelMpe;
        issue.tagSig = tag.sig;
        issue.typeSig = type;
        issue.inputChannels = nInputCh;
        issue.outputChannels = nOutputCh;
        issue.procElementCount = nElements;
        issues.push_back(issue);
        if (issues.size() >= maxIssues) return issues;
      }
    }
  }

  return issues;
}

enum class RawCurveElementIssueKind {
  OversizedSampleCount,
  SegmentedCurveTruncation,
};

struct RawCurveElementIssue {
  RawCurveElementIssueKind kind = RawCurveElementIssueKind::OversizedSampleCount;
  uint32_t elementSig = 0;
  uint64_t fileOffset = 0;
  uint32_t count = 0;
  uint64_t allocBytes = 0;
  uint64_t requiredBytes = 0;
  uint64_t remainingBytes = 0;
};

inline const char *CurveElementName(uint32_t sig) {
  switch (sig) {
    case 0x736E6766u: return "SingleSampledCurve";      // 'sngf'
    case 0x73616D66u: return "SampledCurveSegment";     // 'samf'
    case 0x636C6366u: return "SampledCalculatorCurve";  // 'clcf'
    case 0x63757266u: return "SegmentedCurve";          // 'curf'
    default: return "CurveElement";
  }
}

inline const char *CurveElementFixRef(const RawCurveElementIssue &issue) {
  switch (issue.elementSig) {
    case 0x736E6766u: return "IccMpeBasic.cpp:1638, CFL-021";
    case 0x73616D66u: return "IccMpeBasic.cpp:1070";
    case 0x636C6366u: return "IccMpeBasic.cpp:2446";
    case 0x63757266u: return "IccMpeBasic.cpp:2779, CFL-064";
    default: return "iccDEV sampled-curve parsing path";
  }
}

inline std::string FormatRawCurveElementIssue(const RawCurveElementIssue &issue) {
  char msg[512];

  if (issue.kind == RawCurveElementIssueKind::SegmentedCurveTruncation) {
    snprintf(msg, sizeof(msg),
             "SegmentedCurve at offset 0x%llX: nSegments=%u needs %llu bytes minimum, only %llu available",
             static_cast<unsigned long long>(issue.fileOffset),
             issue.count,
             static_cast<unsigned long long>(issue.requiredBytes),
             static_cast<unsigned long long>(issue.remainingBytes));
    return msg;
  }

  snprintf(msg, sizeof(msg),
           "%s at offset 0x%llX: nCount=%u -> %.1f GB allocation (file has %llu bytes remaining)",
           CurveElementName(issue.elementSig),
           static_cast<unsigned long long>(issue.fileOffset),
           issue.count,
           static_cast<double>(issue.allocBytes) / (1024.0 * 1024.0 * 1024.0),
           static_cast<unsigned long long>(issue.remainingBytes));
  return msg;
}

inline std::string CurveElementIssueCweNote(const RawCurveElementIssue &issue) {
  char msg[256];
  if (issue.kind == RawCurveElementIssueKind::SegmentedCurveTruncation) {
    snprintf(msg, sizeof(msg),
             "CWE-191: Unsigned underflow in CIccSegmentedCurve::Read() "
             "size-(pos-startPos) at %s",
             CurveElementFixRef(issue));
    return msg;
  }

  snprintf(msg, sizeof(msg),
           "CWE-770: Allocation without limits — OOM abort (%s)",
           CurveElementFixRef(issue));
  return msg;
}

inline std::vector<RawCurveElementIssue>
ScanRawCurveElementIssues(RawProfileContext &ctx, size_t maxIssues = 8) {
  std::vector<RawCurveElementIssue> issues;
  if (!ctx.fh) return issues;

  const size_t fs = ctx.fileSize();
  if (fs < 12) return issues;

  constexpr size_t kChunkSize = 1u << 20; // 1 MiB
  constexpr size_t kOverlap = 11u;        // Need 12 bytes total for pattern+count
  std::vector<unsigned char> buf(kChunkSize + kOverlap);

  for (size_t base = 0; base < fs; base += kChunkSize) {
    size_t readLen = fs - base;
    if (readLen > buf.size()) {
      readLen = buf.size();
    }

    if (!ctx.fh.Seek(static_cast<long>(base)) ||
        !ctx.fh.ReadBytes(buf.data(), readLen)) {
      break;
    }

    if (readLen < 12) {
      continue;
    }

    size_t scanStarts = readLen - 11;
    if (scanStarts > kChunkSize) {
      scanStarts = kChunkSize;
    }

    for (size_t rel = 0; rel < scanStarts; ++rel) {
      size_t absolute = base + rel;
      uint32_t sig = ReadU32BE(buf.data() + rel);

      if (sig == 0x63757266u) { // 'curf'
        uint16_t nSeg = static_cast<uint16_t>((buf[rel + 8] << 8) | buf[rel + 9]);
        if (nSeg == 0) {
          continue;
        }

        uint64_t bpBytes = nSeg > 1 ? (static_cast<uint64_t>(nSeg) - 1ull) * 4ull : 0ull;
        uint64_t segMin = static_cast<uint64_t>(nSeg) * 12ull;
        uint64_t totalMin = 12ull + bpBytes + segMin;
        uint64_t remaining = static_cast<uint64_t>(fs) - static_cast<uint64_t>(absolute);
        if (totalMin > remaining) {
          RawCurveElementIssue issue;
          issue.kind = RawCurveElementIssueKind::SegmentedCurveTruncation;
          issue.elementSig = sig;
          issue.fileOffset = absolute;
          issue.count = nSeg;
          issue.requiredBytes = totalMin;
          issue.remainingBytes = remaining;
          issues.push_back(issue);
          if (issues.size() >= maxIssues) return issues;
        }
        continue;
      }

      if (sig != 0x736E6766u && // 'sngf'
          sig != 0x73616D66u && // 'samf'
          sig != 0x636C6366u) { // 'clcf'
        continue;
      }

      uint32_t nCount = ReadU32BE(buf.data() + rel + 8);
      uint64_t allocBytes = static_cast<uint64_t>(nCount) * 4ull;
      uint64_t remaining = static_cast<uint64_t>(fs) - static_cast<uint64_t>(absolute) - 12ull;

      if (allocBytes > 256ull * 1024ull * 1024ull ||
          allocBytes > remaining * 64ull) {
        RawCurveElementIssue issue;
        issue.kind = RawCurveElementIssueKind::OversizedSampleCount;
        issue.elementSig = sig;
        issue.fileOffset = absolute;
        issue.count = nCount;
        issue.allocBytes = allocBytes;
        issue.remainingBytes = remaining;
        issues.push_back(issue);
        if (issues.size() >= maxIssues) return issues;
      }
    }
  }

  return issues;
}

// Factory: opens file, reads 132-byte header, parses tag table.
inline RawProfileContext OpenRawProfileContext(const char *filename) {
  RawProfileContext ctx;
  ctx.fh = OpenRawFile(filename);
  if (!ctx.fh) return ctx;
  if (ctx.fileSize() < 132) return ctx;
  if (!ctx.fh.ReadBytes(ctx.header, 132)) return ctx;

  ctx.tagCount = ReadU32BE(&ctx.header[128]);
  if (ctx.tagCount > kMaxContextTags) ctx.tagCount = kMaxContextTags;

  ctx.tags.reserve(ctx.tagCount);
  for (uint32_t i = 0; i < ctx.tagCount; i++) {
    size_t ePos = 132 + i * 12;
    if (ePos + 12 > ctx.fileSize()) break;
    uint8_t entry[12];
    if (!ctx.fh.Seek(static_cast<long>(ePos)) || !ctx.fh.ReadBytes(entry, 12)) break;
    RawProfileContext::TagEntry t;
    t.sig    = ReadU32BE(entry);
    t.offset = ReadU32BE(&entry[4]);
    t.size   = ReadU32BE(&entry[8]);
    ctx.tags.push_back(t);
  }

  ctx.valid = true;
  return ctx;
}

// ── ICC Signature Validation (Analyzer-Owned) ──
// These replace IccSignatureUtils.h from iccDEV.
// No logging noise — validation findings are reported through heuristics.

#ifndef icSigSpectralPcsData
#define icSigSpectralPcsData ((icColorSpaceSignature)0x73706320)
#endif

inline bool IsSpaceSpectralPCS(icColorSpaceSignature sig) {
  return sig == icSigSpectralPcsData;
}

inline const char* ColorSpaceSignatureToStr(icUInt32Number sig) {
  switch (sig) {
    case (icUInt32Number)icSigXYZData:    return "XYZ";
    case (icUInt32Number)icSigLabData:    return "Lab";
    case (icUInt32Number)icSigRgbData:    return "RGB";
    case (icUInt32Number)icSigCmykData:   return "CMYK";
    case (icUInt32Number)icSigGrayData:   return "Gray";
    case (icUInt32Number)icSigNamedData:  return "Named";
    case (icUInt32Number)icSigMCH1Data:   return "MCH1";
    case (icUInt32Number)icSigMCH2Data:   return "MCH2";
    case (icUInt32Number)icSigMCH3Data:   return "MCH3";
    case (icUInt32Number)icSigMCH4Data:   return "MCH4";
    case (icUInt32Number)icSigMCH5Data:   return "MCH5";
    case (icUInt32Number)icSigMCH6Data:   return "MCH6";
    case (icUInt32Number)icSigMCH7Data:   return "MCH7";
    case (icUInt32Number)icSigMCH8Data:   return "MCH8";
    case (icUInt32Number)icSigMCH9Data:   return "MCH9";
    case (icUInt32Number)icSigMCHAData:   return "MCHA";
    case (icUInt32Number)icSigMCHBData:   return "MCHB";
    case (icUInt32Number)icSigMCHCData:   return "MCHC";
    case (icUInt32Number)icSigMCHDData:   return "MCHD";
    case (icUInt32Number)icSigMCHEData:   return "MCHE";
    case (icUInt32Number)icSigMCHFData:   return "MCHF";
    default:                              return "Unknown";
  }
}

// Validates ICC color space signatures: v4 MCH1-MCHF + v5 N-channel + MCS.
// Silent — no stderr output. Heuristics H3/H4 report findings.
inline bool IsValidColorSpaceSignature(icUInt32Number sig) {
  switch (sig) {
    case (icUInt32Number)icSigXYZData:
    case (icUInt32Number)icSigLabData:
    case (icUInt32Number)icSigRgbData:
    case (icUInt32Number)icSigCmykData:
    case (icUInt32Number)icSigGrayData:
    case (icUInt32Number)icSigNamedData:
    case (icUInt32Number)icSigMCH1Data:
    case (icUInt32Number)icSigMCH2Data:
    case (icUInt32Number)icSigMCH3Data:
    case (icUInt32Number)icSigMCH4Data:
    case (icUInt32Number)icSigMCH5Data:
    case (icUInt32Number)icSigMCH6Data:
    case (icUInt32Number)icSigMCH7Data:
    case (icUInt32Number)icSigMCH8Data:
    case (icUInt32Number)icSigMCH9Data:
    case (icUInt32Number)icSigMCHAData:
    case (icUInt32Number)icSigMCHBData:
    case (icUInt32Number)icSigMCHCData:
    case (icUInt32Number)icSigMCHDData:
    case (icUInt32Number)icSigMCHEData:
    case (icUInt32Number)icSigMCHFData:
      return true;
    default: {
      // v5/iccMAX N-channel (0x6e630001-0x6e63FFFF) and MCS (0x6d630001-0x6d63FFFF)
      icUInt32Number csType = icGetColorSpaceType((icColorSpaceSignature)sig);
      icUInt32Number nChan  = icNumColorSpaceChannels(sig);
      if ((csType == (icUInt32Number)icSigNChannelData ||
           csType == (icUInt32Number)icSigSrcMCSChannelData) && nChan > 0)
        return true;
      return false;
    }
  }
}

// Silent technology signature validation — no stderr output.
inline bool IsValidTechnologySignature(icUInt32Number sig) {
  switch (sig) {
    case (icUInt32Number)icSigDigitalCamera:
    case (icUInt32Number)icSigFilmScanner:
    case (icUInt32Number)icSigReflectiveScanner:
    case (icUInt32Number)icSigInkJetPrinter:
    case (icUInt32Number)icSigThermalWaxPrinter:
    case (icUInt32Number)icSigElectrophotographicPrinter:
    case (icUInt32Number)icSigElectrostaticPrinter:
    case (icUInt32Number)icSigDyeSublimationPrinter:
    case (icUInt32Number)icSigPhotographicPaperPrinter:
    case (icUInt32Number)icSigFilmWriter:
    case (icUInt32Number)icSigVideoMonitor:
    case (icUInt32Number)icSigVideoCamera:
    case (icUInt32Number)icSigProjectionTelevision:
    case (icUInt32Number)icSigCRTDisplay:
    case (icUInt32Number)icSigPMDisplay:
    case (icUInt32Number)icSigAMDisplay:
    case (icUInt32Number)icSigPhotoCD:
    case (icUInt32Number)icSigPhotoImageSetter:
    case (icUInt32Number)icSigGravure:
    case (icUInt32Number)icSigOffsetLithography:
    case (icUInt32Number)icSigSilkscreen:
    case (icUInt32Number)icSigFlexography:
      return true;
    default:
      return false;
  }
}

struct IccColorSpaceDescription {
  const char* name;
  bool isKnown;
  char bytes[5];
};

inline IccColorSpaceDescription DescribeColorSpaceSignature(icUInt32Number sig) {
  IccColorSpaceDescription desc;
  desc.name = ColorSpaceSignatureToStr(sig);
  desc.isKnown = IsValidColorSpaceSignature(sig);
  desc.bytes[0] = static_cast<char>(static_cast<unsigned char>((sig >> 24) & 0xFF));
  desc.bytes[1] = static_cast<char>(static_cast<unsigned char>((sig >> 16) & 0xFF));
  desc.bytes[2] = static_cast<char>(static_cast<unsigned char>((sig >> 8) & 0xFF));
  desc.bytes[3] = static_cast<char>(static_cast<unsigned char>(sig & 0xFF));
  desc.bytes[4] = '\0';
  return desc;
}

#endif
