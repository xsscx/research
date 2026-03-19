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
