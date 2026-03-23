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
#include <cstring>
#include <string>
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
