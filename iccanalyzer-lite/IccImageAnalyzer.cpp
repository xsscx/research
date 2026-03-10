/*
 * IccImageAnalyzer.cpp — Image file ICC extraction and security analysis
 *
 * Phase 1: TIFF support via libtiff
 * - Extract embedded ICC profile from TIFFTAG_ICCPROFILE (tag 34675)
 * - Report TIFF metadata (dimensions, BPS, SPP, compression, photometric)
 * - Detect xnuimagefuzzer injection signatures in strip/tile data
 * - Run full heuristic ICC analysis on extracted profile (H1-H138)
 * - TIFF security heuristics H139-H141, H149-H150 for strip/tile geometry,
 *   dimensions, IFD bounds, IFD chain cycles, and tile layout validation
 *
 * Copyright (c) 2026 David H Hoyt LLC
 */

#include "IccImageAnalyzer.h"
#include "IccAnalyzerColors.h"
#include "IccAnalyzerSecurity.h"
#include "IccAnalyzerHeuristics.h"
#include "IccHeuristicsHelpers.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <set>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>

#include <tiffio.h>
#include <png.h>
#include <jpeglib.h>
#include <setjmp.h>

// ── Forward declarations for ICC analysis functions ──
extern int HeuristicAnalyze(const char *profilePath, const char *fingerprintDb);
extern int ComprehensiveAnalyze(const char *profilePath, const char *fingerprintDb);
extern int RoundTripAnalyze(const char *profilePath);
extern void ResetAllocGuard();

// ═══════════════════════════════════════════════════════════════════════
// Shared ICC Extraction Helper
// ═══════════════════════════════════════════════════════════════════════

/// Write ICC data to a secure temp file (mkstemp + O_EXCL), run full
/// heuristic analysis, then clean up. Returns finding count from analysis.
/// Uses mkstemp() to prevent TOCTOU symlink attacks (predictable /tmp names).
static int ExtractAndAnalyzeICC(const uint8_t *iccData, size_t iccLen,
                                 const char *sourceDesc,
                                 const char *fingerprintDb) {
  int findings = 0;

  // Create secure temp file with mkstemp (atomic, O_EXCL semantics)
  char tmpPath[] = "/tmp/iccanalyzer-XXXXXX.icc";
  // mkstemp replaces XXXXXX — we need mkstemps for the suffix
  int fd = mkstemps(tmpPath, 4);  // 4 = strlen(".icc")
  if (fd < 0) {
    printf("  %s[ERROR] Cannot create secure temp file: %s%s\n",
           ColorCritical(), strerror(errno), ColorReset());
    return 0;
  }

  // Write ICC data
  ssize_t written = 0;
  size_t remaining = iccLen;
  const uint8_t *ptr = iccData;
  while (remaining > 0) {
    ssize_t n = write(fd, ptr, remaining);
    if (n < 0) {
      if (errno == EINTR) continue;
      printf("  %s[ERROR] Write failed: %s%s\n",
             ColorCritical(), strerror(errno), ColorReset());
      close(fd);
      unlink(tmpPath);
      return 0;
    }
    written += n;
    ptr += n;
    remaining -= (size_t)n;
  }
  close(fd);

  if ((size_t)written != iccLen) {
    printf("  %s[ERROR] Incomplete write to temp ICC (%zd of %zu bytes)%s\n",
           ColorCritical(), written, iccLen, ColorReset());
    unlink(tmpPath);
    return 0;
  }

  printf("\n  Extracted ICC from %s to: %s\n\n", sourceDesc, tmpPath);
  printf("=======================================================================\n");
  printf("EXTRACTED ICC PROFILE — FULL HEURISTIC ANALYSIS\n");
  printf("=======================================================================\n\n");

  ResetAllocGuard();
  int iccResult = ComprehensiveAnalyze(tmpPath, fingerprintDb);
  if (iccResult > 0) findings += iccResult;

  unlink(tmpPath);
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════
// File Format Detection
// ═══════════════════════════════════════════════════════════════════════

ImageFormat DetectFileFormat(const char *filepath) {
  RawFileHandle fh = OpenRawFile(filepath);
  if (!fh) return ImageFormat::UNKNOWN;

  uint8_t magic[40] = {0};
  size_t n = fread(magic, 1, sizeof(magic), fh.fp);

  if (n < 4) return ImageFormat::UNKNOWN;

  // TIFF little-endian: 49 49 2A 00
  if (magic[0] == 0x49 && magic[1] == 0x49 && magic[2] == 0x2A && magic[3] == 0x00)
    return ImageFormat::TIFF_LE;

  // TIFF big-endian: 4D 4D 00 2A
  if (magic[0] == 0x4D && magic[1] == 0x4D && magic[2] == 0x00 && magic[3] == 0x2A)
    return ImageFormat::TIFF_BE;

  // BigTIFF little-endian: 49 49 2B 00
  if (magic[0] == 0x49 && magic[1] == 0x49 && magic[2] == 0x2B && magic[3] == 0x00)
    return ImageFormat::BIGTIFF_LE;

  // BigTIFF big-endian: 4D 4D 00 2B
  if (magic[0] == 0x4D && magic[1] == 0x4D && magic[2] == 0x00 && magic[3] == 0x2B)
    return ImageFormat::BIGTIFF_BE;

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (n >= 8 && magic[0] == 0x89 && magic[1] == 0x50 && magic[2] == 0x4E &&
      magic[3] == 0x47 && magic[4] == 0x0D && magic[5] == 0x0A &&
      magic[6] == 0x1A && magic[7] == 0x0A)
    return ImageFormat::PNG;

  // JPEG: FF D8 FF
  if (magic[0] == 0xFF && magic[1] == 0xD8 && magic[2] == 0xFF)
    return ImageFormat::JPEG;

  // ICC profile: 'acsp' at offset 36
  if (n >= 40 && magic[36] == 0x61 && magic[37] == 0x63 &&
      magic[38] == 0x73 && magic[39] == 0x70)
    return ImageFormat::ICC_PROFILE;

  return ImageFormat::UNKNOWN;
}

const char *FormatName(ImageFormat fmt) {
  switch (fmt) {
    case ImageFormat::ICC_PROFILE: return "ICC Profile";
    case ImageFormat::TIFF_LE:    return "TIFF (little-endian)";
    case ImageFormat::TIFF_BE:    return "TIFF (big-endian)";
    case ImageFormat::BIGTIFF_LE: return "BigTIFF (little-endian)";
    case ImageFormat::BIGTIFF_BE: return "BigTIFF (big-endian)";
    case ImageFormat::PNG:        return "PNG";
    case ImageFormat::JPEG:       return "JPEG";
    case ImageFormat::UNKNOWN:    return "Unknown";
  }
  return "Unknown";
}

// ═══════════════════════════════════════════════════════════════════════
// xnuimagefuzzer Injection Signature Detection
// ═══════════════════════════════════════════════════════════════════════

struct InjectionSignature {
  const char *name;
  const char *pattern;
  size_t length;
  const char *cwe;
};

// From xnuimagefuzzer.m INJECT_STRING_1 through INJECT_STRING_10
static const InjectionSignature kInjectionSignatures[] = {
  {"INJECT_STRING_1 (Buffer overflow A-pattern)",
   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 40,
   "CWE-120: Buffer Copy without Size Check"},

  {"INJECT_STRING_2 (XSS script injection)",
   "<script>console.error", 21,
   "CWE-79: Cross-site Scripting (XSS)"},

  {"INJECT_STRING_3 (SQL injection OR-bypass)",
   "' OR ''='", 9,
   "CWE-89: SQL Injection"},

  {"INJECT_STRING_4 (Format string)",
   "%d %s %d %s", 12,
   "CWE-134: Use of Externally-Controlled Format String"},

  {"INJECT_STRING_5 (Fuzzer provenance)",
   "XNU Image Fuzzer", 17,
   nullptr},

  {"INJECT_STRING_6 (SQL DROP TABLE)",
   "DROP TABLE", 10,
   "CWE-89: SQL Injection"},

  {"INJECT_STRING_7 (Special characters)",
   "!@#$%^&*()_+=", 13,
   "CWE-20: Improper Input Validation"},

  {"INJECT_STRING_8 (Path traversal)",
   "..//..//..//", 12,
   "CWE-22: Path Traversal"},

  {"INJECT_STRING_10 (XXE injection)",
   "<!DOCTYPE", 9,
   "CWE-611: XML External Entity (XXE)"},

  // ICC mutation patterns from mutateICCProfile()
  {"ICC tag count corruption (0xFFFF)",
   "\xFF\xFF\xFF\xFF", 4,
   "CWE-787: Out-of-bounds Write"},

  // TIFF-specific corruption signatures
  {"BigTIFF magic in standard TIFF",
   "\x00\x2B", 2,
   "CWE-843: Type Confusion"},
};

static const size_t kNumInjectionSignatures =
    sizeof(kInjectionSignatures) / sizeof(kInjectionSignatures[0]);

// Scan a byte buffer for injection signatures
static int ScanForInjections(const uint8_t *data, size_t len,
                             const char *context) {
  int found = 0;
  for (size_t s = 0; s < kNumInjectionSignatures; s++) {
    const InjectionSignature &sig = kInjectionSignatures[s];
    if (sig.length > len) continue;

    for (size_t i = 0; i <= len - sig.length; i++) {
      if (memcmp(data + i, sig.pattern, sig.length) == 0) {
        printf("      %s[INJECT] %s: '%s' at offset %zu%s\n",
               ColorCritical(), context, sig.name, i, ColorReset());
        if (sig.cwe) {
          printf("       %s%s%s\n", ColorCritical(), sig.cwe, ColorReset());
        }
        found++;
        break; // one match per signature per context
      }
    }
  }
  return found;
}

// ═══════════════════════════════════════════════════════════════════════
// TIFF Metadata Reporting
// ═══════════════════════════════════════════════════════════════════════

static const char *TiffCompressionName(uint16_t c) {
  switch (c) {
    case COMPRESSION_NONE:       return "None (Uncompressed)";
    case COMPRESSION_CCITTRLE:   return "CCITT RLE";
    case COMPRESSION_CCITTFAX3:  return "CCITT Group 3";
    case COMPRESSION_CCITTFAX4:  return "CCITT Group 4";
    case COMPRESSION_LZW:        return "LZW";
    case COMPRESSION_JPEG:       return "JPEG";
    case COMPRESSION_DEFLATE:    return "Deflate (zlib)";
    case COMPRESSION_ADOBE_DEFLATE: return "Adobe Deflate";
    case COMPRESSION_PACKBITS:   return "PackBits";
    default:                     return "Unknown";
  }
}

static const char *TiffPhotometricName(uint16_t p) {
  switch (p) {
    case PHOTOMETRIC_MINISWHITE: return "MinIsWhite (Grayscale)";
    case PHOTOMETRIC_MINISBLACK: return "MinIsBlack (Grayscale)";
    case PHOTOMETRIC_RGB:        return "RGB";
    case PHOTOMETRIC_PALETTE:    return "Palette (Indexed)";
    case PHOTOMETRIC_SEPARATED:  return "CMYK (Separated)";
    case PHOTOMETRIC_YCBCR:      return "YCbCr";
    case PHOTOMETRIC_CIELAB:     return "CIE L*a*b*";
    case PHOTOMETRIC_ICCLAB:     return "ICC L*a*b*";
    case PHOTOMETRIC_LOGL:       return "LogL";
    case PHOTOMETRIC_LOGLUV:     return "LogLuv";
    default:                     return "Unknown";
  }
}

static const char *TiffSampleFormatName(uint16_t sf) {
  switch (sf) {
    case SAMPLEFORMAT_UINT:          return "Unsigned Integer";
    case SAMPLEFORMAT_INT:           return "Signed Integer";
    case SAMPLEFORMAT_IEEEFP:        return "IEEE Floating-Point";
    case SAMPLEFORMAT_VOID:          return "Untyped";
    case SAMPLEFORMAT_COMPLEXINT:    return "Complex Integer";
    case SAMPLEFORMAT_COMPLEXIEEEFP: return "Complex Float";
    default:                         return "Unknown";
  }
}

static const char *TiffPlanarName(uint16_t p) {
  switch (p) {
    case PLANARCONFIG_CONTIG:   return "Contiguous (Chunky)";
    case PLANARCONFIG_SEPARATE: return "Separate (Planar)";
    default:                    return "Unknown";
  }
}

// ═══════════════════════════════════════════════════════════════════════
// TIFF Analysis — Core Implementation
// ═══════════════════════════════════════════════════════════════════════

// Suppress libtiff warning/error output during analysis
static void TiffSilentWarning(const char*, const char*, va_list) {}
static void TiffSilentError(const char*, const char*, va_list) {}

// ═══════════════════════════════════════════════════════════════════════
// TIFF Security Heuristics H139-H141
// ═══════════════════════════════════════════════════════════════════════

/// H139: TIFF Strip Geometry Validation (CWE-122/CWE-190)
/// Validates strip buffer size calculations against integer overflow and
/// buffer underallocation. Detects the exact bug pattern from CFL-082
/// (CTiffImg::ReadLine heap-buffer-overflow) and CodeQL alerts
/// cpp/integer-multiplication-cast-to-long, cpp/multiplication-overflow-in-alloc.
int RunHeuristic_H139_TiffStripGeometry(TIFF *tif, const char * /*filepath*/,
                                         uint32_t width, uint16_t bps,
                                         uint16_t spp, uint32_t rowsPerStrip,
                                         uint16_t planarConfig) {
  printf("[H139] TIFF Strip Geometry Validation (CWE-122/CWE-190)\n");

  if (!tif) {
    printf("      [SKIP] No TIFF handle\n\n");
    return 0;
  }

  // Only applies to strip-based images (not tiled)
  uint32_t tileW = 0, tileH = 0;
  TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tileW);
  TIFFGetField(tif, TIFFTAG_TILELENGTH, &tileH);
  if (tileW > 0 || tileH > 0) {
    printf("      [OK] Tiled image — strip geometry N/A\n\n");
    return 0;
  }

  if (rowsPerStrip == 0) {
    printf("      [OK] RowsPerStrip=0 — no strip layout\n\n");
    return 0;
  }

  int findings = 0;
  tmsize_t stripSize = TIFFStripSize(tif);

  // Check 1: Zero or negative strip size
  if (stripSize <= 0) {
    printf("      %s[CRIT]  HEURISTIC: Zero or negative strip size — corrupted geometry%s\n",
           ColorCritical(), ColorReset());
    printf("       %sCWE-122: Heap buffer overflow in ReadLine/ReadEncodedStrip%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check 2: Integer multiplication overflow in bytesPerLine
  // CodeQL cpp/integer-multiplication-cast-to-long: width*bps*spp can overflow uint32
  uint64_t bytesPerLine = ((uint64_t)width * (uint64_t)bps * (uint64_t)spp + 7) >> 3;
  if (bps > 0 && spp > 0 && width > 0 && bytesPerLine > (uint64_t)UINT32_MAX) {
    printf("      %s[CRIT]  HEURISTIC: Integer overflow in bytesPerLine: %u × %u × %u overflows uint32%s\n",
           ColorCritical(), width, bps, spp, ColorReset());
    printf("       %sCWE-190: Integer overflow in buffer size calculation%s\n",
           ColorCritical(), ColorReset());
    printf("       %sCodeQL: cpp/integer-multiplication-cast-to-long — TiffImg.cpp:324%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check 3: Strip buffer underallocation (CFL-082 pattern)
  uint64_t expectedStripBuf = bytesPerLine * (uint64_t)rowsPerStrip;
  if (expectedStripBuf > 0 && stripSize > 0 && (uint64_t)stripSize < expectedStripBuf) {
    printf("      %s[CRIT]  HEURISTIC: Strip buffer too small: stripSize=%lld < rowsPerStrip×bytesPerLine=%llu%s\n",
           ColorCritical(), (long long)stripSize, (unsigned long long)expectedStripBuf, ColorReset());
    printf("       %sCWE-122: Heap buffer overflow — ReadLine memcpy exceeds strip allocation%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check 4: stripSize * nStripSamples allocation overflow
  // CodeQL cpp/multiplication-overflow-in-alloc
  uint32_t nStripSamples = (planarConfig == PLANARCONFIG_SEPARATE && spp > 1) ? spp : 1;
  uint64_t allocSize = (uint64_t)stripSize * (uint64_t)nStripSamples;
  if (nStripSamples > 1 && allocSize > (uint64_t)SIZE_MAX / 2) {
    printf("      %s[CRIT]  HEURISTIC: Strip allocation overflow: stripSize(%lld) × nStripSamples(%u) exceeds safe limit%s\n",
           ColorCritical(), (long long)stripSize, nStripSamples, ColorReset());
    printf("       %sCWE-190: Integer overflow in malloc argument%s\n",
           ColorCritical(), ColorReset());
    printf("       %sCodeQL: cpp/multiplication-overflow-in-alloc — TiffImg.cpp:324%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  if (findings == 0) {
    printf("      [OK] Strip geometry valid (bytesPerLine=%llu, stripSize=%lld, rowsPerStrip=%u)\n",
           (unsigned long long)bytesPerLine, (long long)stripSize, rowsPerStrip);
  }
  printf("\n");
  return findings;
}

/// H140: TIFF Dimension and Sample Validation (CWE-400/CWE-131/CWE-369)
/// Validates image dimensions, BitsPerSample, and SamplesPerPixel against
/// resource exhaustion, buffer miscalculation, and division-by-zero patterns.
int RunHeuristic_H140_TiffDimensionValidation(uint32_t width, uint32_t height,
                                               uint16_t bps, uint16_t spp) {
  printf("[H140] TIFF Dimension and Sample Validation (CWE-400/CWE-131)\n");

  int findings = 0;

  // Check 1: Zero dimensions — division by zero in row/stride calculations
  if (width == 0 || height == 0) {
    printf("      %s[CRIT]  HEURISTIC: Zero dimension: %u×%u%s\n",
           ColorCritical(), width, height, ColorReset());
    printf("       %sCWE-369: Division by zero in image processing%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check 2: Extreme dimensions — resource exhaustion
  uint64_t pixelCount = (uint64_t)width * (uint64_t)height;
  if (pixelCount > 100000000ULL) {
    printf("      %s[WARN]  HEURISTIC: Extreme dimensions: %u×%u = %llu pixels (>100M)%s\n",
           ColorWarning(), width, height, (unsigned long long)pixelCount, ColorReset());
    printf("       %sCWE-400: Resource exhaustion via large image decode%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check 3: Unusual BitsPerSample — buffer miscalculation risk
  if (bps != 0 && bps != 1 && bps != 2 && bps != 4 && bps != 8 &&
      bps != 16 && bps != 32 && bps != 64) {
    printf("      %s[WARN]  HEURISTIC: Unusual BitsPerSample: %u (expected 1/2/4/8/16/32/64)%s\n",
           ColorWarning(), bps, ColorReset());
    printf("       %sCWE-131: Incorrect buffer size calculation%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check 4: Excessive SamplesPerPixel — buffer overflow in channel loops
  if (spp > 16) {
    printf("      %s[WARN]  HEURISTIC: Excessive SamplesPerPixel: %u (>16)%s\n",
           ColorWarning(), spp, ColorReset());
    printf("       %sCWE-131: Buffer size overflow (nOutput×BPS×width)%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check 5: Total uncompressed size overflow
  uint64_t bytesPerPixel = ((uint64_t)bps * (uint64_t)spp + 7) >> 3;
  uint64_t totalBytes = pixelCount * bytesPerPixel;
  if (bytesPerPixel > 0 && totalBytes / bytesPerPixel != pixelCount) {
    printf("      %s[CRIT]  HEURISTIC: Uncompressed size overflows uint64: %u×%u×%llu%s\n",
           ColorCritical(), width, height, (unsigned long long)bytesPerPixel, ColorReset());
    printf("       %sCWE-190: Integer overflow in image buffer allocation%s\n",
           ColorCritical(), ColorReset());
    findings++;
  } else if (totalBytes > 4ULL * 1024 * 1024 * 1024) {
    printf("      %s[WARN]  HEURISTIC: Uncompressed size %llu bytes (>4GB)%s\n",
           ColorWarning(), (unsigned long long)totalBytes, ColorReset());
    printf("       %sCWE-400: Memory exhaustion via large uncompressed image%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  if (findings == 0) {
    printf("      [OK] Dimensions %u×%u, BPS=%u, SPP=%u (%llu pixels)\n",
           width, height, bps, spp, (unsigned long long)pixelCount);
  }
  printf("\n");
  return findings;
}

/// H141: TIFF IFD Offset Bounds Validation (CWE-125)
/// Validates that strip/tile data offsets and byte counts reference data
/// within the file boundaries. Detects file truncation attacks and
/// corrupted offset tables that cause out-of-bounds reads.
int RunHeuristic_H141_TiffIfdOffsetBounds(TIFF *tif, const char *filepath) {
  printf("[H141] TIFF IFD Offset Bounds Validation (CWE-125)\n");

  if (!tif || !filepath) {
    printf("      [SKIP] No TIFF handle or filepath\n\n");
    return 0;
  }

  int findings = 0;

  // Get file size for bounds checking
  struct stat st;
  if (stat(filepath, &st) != 0) {
    printf("      [SKIP] Cannot stat file\n\n");
    return 0;
  }
  uint64_t fileSize = (uint64_t)st.st_size;

  // Check strip offsets (strip-based images)
  uint32_t tileW = 0, tileH = 0;
  TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tileW);
  TIFFGetField(tif, TIFFTAG_TILELENGTH, &tileH);

  if (tileW == 0 && tileH == 0) {
    // Strip-based: check strip offsets and byte counts
    uint32_t nStrips = TIFFNumberOfStrips(tif);
    uint64_t *offsets = nullptr;
    uint64_t *bytecounts = nullptr;

    if (TIFFGetField(tif, TIFFTAG_STRIPOFFSETS, &offsets) &&
        TIFFGetField(tif, TIFFTAG_STRIPBYTECOUNTS, &bytecounts) &&
        offsets && bytecounts) {
      uint32_t checkLimit = (nStrips < 256) ? nStrips : 256;
      for (uint32_t s = 0; s < checkLimit; s++) {
        if (bytecounts[s] > 0 && offsets[s] + bytecounts[s] > fileSize) {
          printf("      %s[CRIT]  HEURISTIC: Strip %u: offset+size (%llu+%llu) exceeds file size (%llu)%s\n",
                 ColorCritical(), s,
                 (unsigned long long)offsets[s], (unsigned long long)bytecounts[s],
                 (unsigned long long)fileSize, ColorReset());
          printf("       %sCWE-125: Out-of-bounds read via corrupted strip offset%s\n",
                 ColorCritical(), ColorReset());
          findings++;
          if (findings >= 3) break;
        }
      }
      // Check for zero-offset strips with non-zero byte counts (corruption)
      for (uint32_t s = 0; s < checkLimit; s++) {
        if (offsets[s] == 0 && bytecounts[s] > 0 && s > 0) {
          printf("      %s[WARN]  HEURISTIC: Strip %u: offset=0 with bytecount=%llu (null data pointer)%s\n",
                 ColorWarning(), s, (unsigned long long)bytecounts[s], ColorReset());
          printf("       %sCWE-476: Null pointer in strip data access%s\n",
                 ColorCritical(), ColorReset());
          findings++;
          break;
        }
      }
    }
  } else {
    // Tile-based: check tile offsets and byte counts
    uint32_t nTiles = TIFFNumberOfTiles(tif);
    uint64_t *offsets = nullptr;
    uint64_t *bytecounts = nullptr;

    if (TIFFGetField(tif, TIFFTAG_TILEOFFSETS, &offsets) &&
        TIFFGetField(tif, TIFFTAG_TILEBYTECOUNTS, &bytecounts) &&
        offsets && bytecounts) {
      uint32_t checkLimit = (nTiles < 256) ? nTiles : 256;
      for (uint32_t t = 0; t < checkLimit; t++) {
        if (bytecounts[t] > 0 && offsets[t] + bytecounts[t] > fileSize) {
          printf("      %s[CRIT]  HEURISTIC: Tile %u: offset+size (%llu+%llu) exceeds file size (%llu)%s\n",
                 ColorCritical(), t,
                 (unsigned long long)offsets[t], (unsigned long long)bytecounts[t],
                 (unsigned long long)fileSize, ColorReset());
          printf("       %sCWE-125: Out-of-bounds read via corrupted tile offset%s\n",
                 ColorCritical(), ColorReset());
          findings++;
          if (findings >= 3) break;
        }
      }
    }
  }

  // Count IFD pages (multi-directory detection)
  int nPages = 0;
  do {
    nPages++;
    if (nPages > 1000) {
      printf("      %s[WARN]  HEURISTIC: Excessive IFD pages: >1000 directories%s\n",
             ColorWarning(), ColorReset());
      printf("       %sCWE-400: Resource exhaustion via IFD chain loop%s\n",
             ColorCritical(), ColorReset());
      findings++;
      break;
    }
  } while (TIFFReadDirectory(tif));

  // Reset to first directory for subsequent operations
  TIFFSetDirectory(tif, 0);

  if (nPages > 1 && nPages <= 1000) {
    printf("      [INFO] Multi-page TIFF: %d directories\n", nPages);
  }

  if (findings == 0) {
    printf("      [OK] All IFD offsets within file bounds (size=%llu, pages=%d)\n",
           (unsigned long long)fileSize, nPages);
  }
  printf("\n");
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════
// H149: TIFF IFD Chain Cycle Detection (CWE-835)
// ═══════════════════════════════════════════════════════════════════════

int RunHeuristic_H149_TiffIfdChainCycle(TIFF *tif, const char *filepath) {
  printf("[H149] TIFF IFD Chain Cycle Detection (CWE-835)\n");

  if (!tif || !filepath) {
    printf("      [SKIP] No TIFF handle or filepath\n\n");
    return 0;
  }

  int findings = 0;

  // Read raw IFD offsets from the file to detect circular pointers.
  // libtiff's TIFFReadDirectory follows the chain but may loop forever
  // on circular references. We read the raw next-IFD pointer from each
  // directory to build a visited set.
  struct stat st;
  if (stat(filepath, &st) != 0) {
    printf("      [SKIP] Cannot stat file\n\n");
    return 0;
  }
  uint64_t fileSize = static_cast<uint64_t>(st.st_size);

  FILE *fp = fopen(filepath, "rb");
  if (!fp) {
    printf("      [SKIP] Cannot open file for raw IFD scan\n\n");
    return 0;
  }

  // Read byte order and first IFD offset
  uint8_t header[8];
  if (fread(header, 1, 8, fp) < 8) {
    fclose(fp);
    printf("      [SKIP] File too small for TIFF header\n\n");
    return 0;
  }

  bool littleEndian = (header[0] == 'I' && header[1] == 'I');
  bool isBigTiff = false;
  uint64_t ifdOffset = 0;

  auto readU16 = [&](const uint8_t *p) -> uint16_t {
    return littleEndian
      ? (uint16_t)(p[0] | (p[1] << 8))
      : (uint16_t)((p[0] << 8) | p[1]);
  };
  auto readU32 = [&](const uint8_t *p) -> uint32_t {
    return littleEndian
      ? ((uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24))
      : (((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3]);
  };

  uint16_t magic = readU16(header + 2);
  if (magic == 43) {
    isBigTiff = true;
    // BigTIFF: 8-byte offset at bytes 8-15
    uint8_t ext[8];
    if (fread(ext, 1, 8, fp) < 8) { fclose(fp); return 0; }
    // Simplified: read lower 4 bytes (BigTIFFs > 4GB are rare in fuzzing)
    ifdOffset = readU32(ext);
  } else {
    ifdOffset = readU32(header + 4);
  }

  // Walk IFD chain, tracking visited offsets
  std::set<uint64_t> visited;
  int chainLen = 0;
  static constexpr int kMaxChainDepth = 1024;

  while (ifdOffset != 0 && ifdOffset < fileSize && chainLen < kMaxChainDepth) {
    if (visited.count(ifdOffset)) {
      printf("      %s[CRIT]  HEURISTIC: Circular IFD chain — offset %llu revisited at depth %d%s\n",
             ColorCritical(), (unsigned long long)ifdOffset, chainLen, ColorReset());
      printf("       %sCWE-835: Infinite loop via circular IFD next-pointer%s\n",
             ColorCritical(), ColorReset());
      findings++;
      break;
    }
    visited.insert(ifdOffset);
    chainLen++;

    // Seek to IFD, read entry count, skip entries, read next-IFD pointer
    if (fseek(fp, (long)ifdOffset, SEEK_SET) != 0) break;

    if (isBigTiff) {
      // BigTIFF: 8-byte entry count, 20-byte entries, 8-byte next offset
      uint8_t countBuf[8];
      if (fread(countBuf, 1, 8, fp) < 8) break;
      uint64_t entryCount = readU32(countBuf); // simplified for lower counts
      uint64_t skipBytes = entryCount * 20;
      if (fseek(fp, (long)skipBytes, SEEK_CUR) != 0) break;
      uint8_t nextBuf[8];
      if (fread(nextBuf, 1, 8, fp) < 8) break;
      ifdOffset = readU32(nextBuf);
    } else {
      // Classic TIFF: 2-byte entry count, 12-byte entries, 4-byte next offset
      uint8_t countBuf[2];
      if (fread(countBuf, 1, 2, fp) < 2) break;
      uint16_t entryCount = readU16(countBuf);
      long skipBytes = (long)entryCount * 12;
      if (fseek(fp, skipBytes, SEEK_CUR) != 0) break;
      uint8_t nextBuf[4];
      if (fread(nextBuf, 1, 4, fp) < 4) break;
      ifdOffset = readU32(nextBuf);
    }
  }

  fclose(fp);

  if (chainLen >= kMaxChainDepth && findings == 0) {
    printf("      %s[WARN]  HEURISTIC: IFD chain exceeds %d directories — possible loop%s\n",
           ColorWarning(), kMaxChainDepth, ColorReset());
    printf("       %sCWE-835: Excessive IFD chain depth%s\n",
           ColorWarning(), ColorReset());
    findings++;
  }

  if (findings == 0) {
    printf("      [OK] IFD chain is acyclic (%d %s)\n",
           chainLen, chainLen == 1 ? "directory" : "directories");
  }
  printf("\n");
  return findings;
}

// ═══════════════════════════════════════════════════════════════════════
// H150: TIFF Tile Geometry Validation (CWE-122/CWE-131)
// ═══════════════════════════════════════════════════════════════════════

int RunHeuristic_H150_TiffTileGeometry(TIFF *tif, const char *filepath,
                                        uint32_t width, uint32_t height,
                                        uint16_t bps, uint16_t spp) {
  printf("[H150] TIFF Tile Geometry Validation (CWE-122/CWE-131)\n");

  if (!tif) {
    printf("      [SKIP] No TIFF handle\n\n");
    return 0;
  }

  uint32_t tileW = 0, tileH = 0;
  TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tileW);
  TIFFGetField(tif, TIFFTAG_TILELENGTH, &tileH);

  if (tileW == 0 && tileH == 0) {
    printf("      [OK] Strip-based image — tile geometry N/A\n\n");
    return 0;
  }

  int findings = 0;

  // Tile dimensions must be multiples of 16 (TIFF 6.0 §15)
  if (tileW % 16 != 0) {
    printf("      %s[WARN]  HEURISTIC: TileWidth=%u is not a multiple of 16 (TIFF 6.0 §15)%s\n",
           ColorWarning(), tileW, ColorReset());
    findings++;
  }
  if (tileH % 16 != 0) {
    printf("      %s[WARN]  HEURISTIC: TileLength=%u is not a multiple of 16 (TIFF 6.0 §15)%s\n",
           ColorWarning(), tileH, ColorReset());
    findings++;
  }

  // Tile dimensions must not be zero
  if (tileW == 0 || tileH == 0) {
    printf("      %s[CRIT]  HEURISTIC: Zero tile dimension (TileWidth=%u, TileLength=%u)%s\n",
           ColorCritical(), tileW, tileH, ColorReset());
    printf("       %sCWE-369: Division by zero in tile count calculation%s\n",
           ColorCritical(), ColorReset());
    findings++;
    printf("\n");
    return findings;
  }

  // Tile dimensions should not exceed image dimensions unreasonably
  if (tileW > width * 2 && width > 0) {
    printf("      %s[WARN]  HEURISTIC: TileWidth=%u exceeds 2× image width=%u%s\n",
           ColorWarning(), tileW, width, ColorReset());
    findings++;
  }
  if (tileH > height * 2 && height > 0) {
    printf("      %s[WARN]  HEURISTIC: TileLength=%u exceeds 2× image height=%u%s\n",
           ColorWarning(), tileH, height, ColorReset());
    findings++;
  }

  // Validate tile byte counts
  uint32_t nTiles = TIFFNumberOfTiles(tif);
  if (nTiles == 0) {
    printf("      %s[WARN]  HEURISTIC: Tiled image reports 0 tiles%s\n",
           ColorWarning(), ColorReset());
    findings++;
    printf("\n");
    return findings;
  }

  // Expected tiles = ceil(width/tileW) × ceil(height/tileH) × (planar ? spp : 1)
  uint32_t tilesAcross = (width + tileW - 1) / tileW;
  uint32_t tilesDown = (height + tileH - 1) / tileH;
  uint16_t planar = PLANARCONFIG_CONTIG;
  TIFFGetField(tif, TIFFTAG_PLANARCONFIG, &planar);
  uint32_t expectedTiles = tilesAcross * tilesDown;
  if (planar == PLANARCONFIG_SEPARATE) expectedTiles *= spp;

  if (nTiles != expectedTiles) {
    printf("      %s[WARN]  HEURISTIC: Tile count mismatch: expected %u (%u×%u), got %u%s\n",
           ColorWarning(), expectedTiles, tilesAcross, tilesDown, nTiles, ColorReset());
    findings++;
  }

  // Validate individual tile byte counts against expected uncompressed size
  uint64_t *bytecounts = nullptr;
  if (TIFFGetField(tif, TIFFTAG_TILEBYTECOUNTS, &bytecounts) && bytecounts) {
    uint64_t bytesPerPixel = ((uint64_t)bps * spp + 7) / 8;
    if (planar == PLANARCONFIG_SEPARATE) bytesPerPixel = ((uint64_t)bps + 7) / 8;
    uint64_t expectedTileBytes = (uint64_t)tileW * tileH * bytesPerPixel;

    // Check for integer overflow in tile size calculation
    if (bytesPerPixel > 0 &&
        (uint64_t)tileW * tileH > UINT32_MAX / bytesPerPixel) {
      printf("      %s[CRIT]  HEURISTIC: Integer overflow in tile byte count: %u × %u × %llu%s\n",
             ColorCritical(), tileW, tileH, (unsigned long long)bytesPerPixel, ColorReset());
      printf("       %sCWE-190: Integer overflow → heap buffer overflow%s\n",
             ColorCritical(), ColorReset());
      findings++;
    }

    // Check for suspicious tile sizes (much larger than expected)
    uint32_t checkLimit = (nTiles < 64) ? nTiles : 64;
    for (uint32_t t = 0; t < checkLimit; t++) {
      if (bytecounts[t] > expectedTileBytes * 4 && bytecounts[t] > 1048576) {
        printf("      %s[WARN]  HEURISTIC: Tile %u bytecount=%llu far exceeds expected=%llu (4× threshold)%s\n",
               ColorWarning(), t, (unsigned long long)bytecounts[t],
               (unsigned long long)expectedTileBytes, ColorReset());
        printf("       %sCWE-131: Incorrect buffer size calculation%s\n",
               ColorWarning(), ColorReset());
        findings++;
        break;  // Report once to avoid flooding
      }
    }
  }

  // Get file size for tile offset bounds
  struct stat st;
  if (stat(filepath, &st) == 0) {
    uint64_t fileSize = static_cast<uint64_t>(st.st_size);
    uint64_t *offsets = nullptr;
    if (TIFFGetField(tif, TIFFTAG_TILEOFFSETS, &offsets) && offsets && bytecounts) {
      uint32_t checkLimit = (nTiles < 64) ? nTiles : 64;
      for (uint32_t t = 0; t < checkLimit; t++) {
        if (offsets[t] + bytecounts[t] > fileSize && bytecounts[t] > 0) {
          printf("      %s[CRIT]  HEURISTIC: Tile %u extends beyond EOF: offset=%llu + size=%llu > filesize=%llu%s\n",
                 ColorCritical(), t, (unsigned long long)offsets[t],
                 (unsigned long long)bytecounts[t], (unsigned long long)fileSize, ColorReset());
          printf("       %sCWE-122: Heap buffer overflow via out-of-bounds tile read%s\n",
                 ColorCritical(), ColorReset());
          findings++;
          if (findings >= 5) break;
        }
      }
    }
  }

  if (findings == 0) {
    printf("      [OK] Tile geometry valid (TileWidth=%u, TileLength=%u, tiles=%u)\n",
           tileW, tileH, nTiles);
  }
  printf("\n");
  return findings;
}

int AnalyzeTiffImage(const char *filepath, const char *fingerprintDb) {
  int findings = 0;

  printf("=======================================================================\n");
  printf("IMAGE FILE ANALYSIS — TIFF\n");
  printf("=======================================================================\n");
  printf("File: %s\n\n", filepath);

  // Suppress libtiff console output (we do our own reporting)
  TIFFErrorHandler oldWarn = TIFFSetWarningHandler(TiffSilentWarning);
  TIFFErrorHandler oldErr = TIFFSetErrorHandler(TiffSilentError);

  TIFF *tif = TIFFOpen(filepath, "r");
  if (!tif) {
    printf("%s[ERROR] Cannot open TIFF file (libtiff TIFFOpen failed)%s\n",
           ColorCritical(), ColorReset());
    printf("        This may indicate a severely corrupted or non-TIFF file.\n\n");
    TIFFSetWarningHandler(oldWarn);
    TIFFSetErrorHandler(oldErr);
    return -1;
  }

  // ── TIFF Metadata ──
  printf("--- TIFF Metadata ---\n");

  uint32_t width = 0, height = 0;
  uint16_t bps = 0, spp = 0, compression = 0, photometric = 0;
  uint16_t planar = 0, sampleFormat = 0, orientation = 0;
  uint32_t rowsPerStrip = 0;
  uint16_t tileWidth = 0, tileHeight = 0;
  float xRes = 0, yRes = 0;
  uint16_t resUnit = 0;
  char *software = nullptr;
  char *datetime = nullptr;
  char *imagedesc = nullptr;

  TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
  TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);
  TIFFGetField(tif, TIFFTAG_BITSPERSAMPLE, &bps);
  TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &spp);
  TIFFGetField(tif, TIFFTAG_COMPRESSION, &compression);
  TIFFGetField(tif, TIFFTAG_PHOTOMETRIC, &photometric);
  TIFFGetField(tif, TIFFTAG_PLANARCONFIG, &planar);
  TIFFGetField(tif, TIFFTAG_SAMPLEFORMAT, &sampleFormat);
  TIFFGetField(tif, TIFFTAG_ORIENTATION, &orientation);
  TIFFGetField(tif, TIFFTAG_ROWSPERSTRIP, &rowsPerStrip);
  TIFFGetField(tif, TIFFTAG_TILEWIDTH, &tileWidth);
  TIFFGetField(tif, TIFFTAG_TILELENGTH, &tileHeight);
  TIFFGetField(tif, TIFFTAG_XRESOLUTION, &xRes);
  TIFFGetField(tif, TIFFTAG_YRESOLUTION, &yRes);
  TIFFGetField(tif, TIFFTAG_RESOLUTIONUNIT, &resUnit);
  TIFFGetField(tif, TIFFTAG_SOFTWARE, &software);
  TIFFGetField(tif, TIFFTAG_DATETIME, &datetime);
  TIFFGetField(tif, TIFFTAG_IMAGEDESCRIPTION, &imagedesc);

  printf("  Dimensions:      %u × %u pixels\n", width, height);
  printf("  Bits/Sample:     %u\n", bps);
  printf("  Samples/Pixel:   %u\n", spp);
  printf("  Compression:     %s (%u)\n", TiffCompressionName(compression), compression);
  printf("  Photometric:     %s (%u)\n", TiffPhotometricName(photometric), photometric);
  printf("  Planar Config:   %s (%u)\n", TiffPlanarName(planar), planar);
  if (sampleFormat) {
    printf("  Sample Format:   %s (%u)\n", TiffSampleFormatName(sampleFormat), sampleFormat);
  }
  if (orientation) {
    printf("  Orientation:     %u\n", orientation);
  }
  if (tileWidth > 0 && tileHeight > 0) {
    printf("  Tile Size:       %u × %u\n", tileWidth, tileHeight);
  } else if (rowsPerStrip > 0) {
    printf("  Rows/Strip:      %u\n", rowsPerStrip);
    uint32_t nStrips = TIFFNumberOfStrips(tif);
    printf("  Strip Count:     %u\n", nStrips);
  }
  if (xRes > 0 || yRes > 0) {
    const char *unit = (resUnit == RESUNIT_INCH) ? "dpi" :
                       (resUnit == RESUNIT_CENTIMETER) ? "dpcm" : "units";
    printf("  Resolution:      %.1f × %.1f %s\n", xRes, yRes, unit);
  }
  if (software) printf("  Software:        %s\n", software);
  if (datetime) printf("  DateTime:        %s\n", datetime);
  if (imagedesc) printf("  Description:     %.80s%s\n", imagedesc,
                        strlen(imagedesc) > 80 ? "..." : "");
  printf("\n");

  // ── TIFF Security Heuristics (H139-H141, H149-H150) ──
  printf("--- TIFF Security Heuristics ---\n");

  findings += RunHeuristic_H139_TiffStripGeometry(tif, filepath, width, bps, spp,
                                                   rowsPerStrip, planar);
  findings += RunHeuristic_H140_TiffDimensionValidation(width, height, bps, spp);
  findings += RunHeuristic_H141_TiffIfdOffsetBounds(tif, filepath);
  findings += RunHeuristic_H149_TiffIfdChainCycle(tif, filepath);
  findings += RunHeuristic_H150_TiffTileGeometry(tif, filepath, width, height, bps, spp);

  // Check for xnuimagefuzzer provenance in metadata
  if (software && strstr(software, "XNUImageFuzzer")) {
    printf("  %s[INFO] xnuimagefuzzer provenance detected in Software tag%s\n",
           ColorInfo(), ColorReset());
  }
  if (imagedesc && strstr(imagedesc, "fuzzed")) {
    printf("  %s[INFO] Fuzzed image indicator in ImageDescription%s\n",
           ColorInfo(), ColorReset());
  }

  printf("\n");

  // ── Injection Signature Scan ──
  printf("--- Injection Signature Scan ---\n");
  {
    int injections = 0;

    // Scan TIFF tag string values for injections
    const char *tagStrings[] = {software, datetime, imagedesc, nullptr};
    const char *tagNames[] = {"Software", "DateTime", "ImageDescription"};
    for (int t = 0; tagStrings[t]; t++) {
      if (tagStrings[t]) {
        injections += ScanForInjections(
            (const uint8_t *)tagStrings[t], strlen(tagStrings[t]),
            tagNames[t]);
      }
    }

    // Scan first strip/tile of pixel data for injection patterns
    // (xnuimagefuzzer embeds INJECT_STRING_1-10 in pixel data via bitwise OR)
    tmsize_t scanSize = 0;
    void *scanBuf = nullptr;

    if (TIFFIsTiled(tif)) {
      scanSize = TIFFTileSize(tif);
      if (scanSize > 0 && scanSize < 4 * 1024 * 1024) { // cap at 4MB
        scanBuf = _TIFFmalloc(scanSize);
        if (scanBuf) {
          tmsize_t readBytes = TIFFReadEncodedTile(tif, 0, scanBuf, scanSize);
          if (readBytes > 0) {
            injections += ScanForInjections(
                (const uint8_t *)scanBuf, (size_t)readBytes,
                "PixelData(tile0)");
          }
          _TIFFfree(scanBuf);
        }
      }
    } else {
      scanSize = TIFFStripSize(tif);
      if (scanSize > 0 && scanSize < 4 * 1024 * 1024) { // cap at 4MB
        scanBuf = _TIFFmalloc(scanSize);
        if (scanBuf) {
          tmsize_t readBytes = TIFFReadEncodedStrip(tif, 0, scanBuf, scanSize);
          if (readBytes > 0) {
            injections += ScanForInjections(
                (const uint8_t *)scanBuf, (size_t)readBytes,
                "PixelData(strip0)");
          }
          _TIFFfree(scanBuf);
        }
      }
    }

    if (injections > 0) {
      printf("  %s[WARN] %d injection signature(s) detected%s\n",
             ColorWarning(), injections, ColorReset());
      findings += injections;
    } else {
      printf("  %s[OK] No injection signatures detected%s\n",
             ColorSuccess(), ColorReset());
    }
  }
  printf("\n");

  // ── ICC Profile Extraction ──
  printf("--- Embedded ICC Profile ---\n");
  {
    uint32_t iccLen = 0;
    void *iccData = nullptr;

    if (TIFFGetField(tif, TIFFTAG_ICCPROFILE, &iccLen, &iccData)) {
      printf("  %s[FOUND] ICC profile embedded (TIFFTAG_ICCPROFILE, tag 34675)%s\n",
             ColorSuccess(), ColorReset());
      printf("  Profile Size:    %u bytes (%.1f KB)\n", iccLen, iccLen / 1024.0);

      // Validate ICC magic
      if (iccLen >= 40) {
        const uint8_t *iccBytes = (const uint8_t *)iccData;
        bool hasAcsp = (iccBytes[36] == 'a' && iccBytes[37] == 'c' &&
                        iccBytes[38] == 's' && iccBytes[39] == 'p');
        if (hasAcsp) {
          printf("  ICC Magic:       %s[OK] 'acsp' at offset 36%s\n",
                 ColorSuccess(), ColorReset());
        } else {
          printf("  %s[CRIT] Missing 'acsp' magic — corrupted ICC profile%s\n",
                 ColorCritical(), ColorReset());
          printf("   %sCWE-20: Invalid ICC header (tag data may be non-ICC)%s\n",
                 ColorCritical(), ColorReset());
          findings++;
        }

        // Extract version, class, color space from header
        uint8_t majVer = iccBytes[8];
        uint8_t minVer = iccBytes[9] >> 4;
        printf("  ICC Version:     %u.%u\n", majVer, minVer);

        // Profile size in header vs actual tag size
        uint32_t hdrSize = ((uint32_t)iccBytes[0] << 24) | ((uint32_t)iccBytes[1] << 16) |
                           ((uint32_t)iccBytes[2] << 8)  | (uint32_t)iccBytes[3];
        if (hdrSize != iccLen) {
          printf("  %s[WARN] Size mismatch: header says %u, tag has %u bytes%s\n",
                 ColorWarning(), hdrSize, iccLen, ColorReset());
          printf("   %sCWE-131: Size field inconsistency (mutation indicator)%s\n",
                 ColorCritical(), ColorReset());
          findings++;
        }

        // Detect ICC mutation patterns from xnuimagefuzzer
        // mutateICCProfile() strategy 1: tag count = 0xFFFF
        if (iccLen > 132) {
          uint32_t tagCount = ((uint32_t)iccBytes[128] << 24) |
                              ((uint32_t)iccBytes[129] << 16) |
                              ((uint32_t)iccBytes[130] << 8) |
                              (uint32_t)iccBytes[131];
          if (tagCount > 1000) {
            printf("  %s[CRIT] Suspicious ICC tag count: %u (mutated profile)%s\n",
                   ColorCritical(), tagCount, ColorReset());
            printf("   %sxnuimagefuzzer mutateICCProfile() strategy 1: tag count corruption%s\n",
                   ColorWarning(), ColorReset());
            findings++;
          }
        }

        // mutateICCProfile() strategy 5: size mismatch (2× actual or 64 bytes)
        if (hdrSize == 64 || (hdrSize > iccLen && hdrSize == 2 * iccLen)) {
          printf("  %s[CRIT] ICC size field indicates mutation (hdr=%u, actual=%u)%s\n",
                 ColorCritical(), hdrSize, iccLen, ColorReset());
          printf("   %sxnuimagefuzzer mutateICCProfile() strategy 5: size mismatch%s\n",
                 ColorWarning(), ColorReset());
          findings++;
        }
      } else {
        printf("  %s[CRIT] ICC profile too small (%u bytes < 40 minimum)%s\n",
               ColorCritical(), iccLen, ColorReset());
        findings++;
      }

      // Write extracted ICC to temp file for full heuristic analysis
      findings += ExtractAndAnalyzeICC(
          static_cast<const uint8_t *>(iccData),
          static_cast<size_t>(iccLen), "TIFF", fingerprintDb);

    } else {
      printf("  %s[INFO] No embedded ICC profile (TIFFTAG_ICCPROFILE absent)%s\n",
             ColorInfo(), ColorReset());
      printf("  This TIFF relies on implicit color space from Photometric tag.\n");

      // Check photometric interpretation for color management implications
      if (photometric == PHOTOMETRIC_RGB) {
        printf("  %s[INFO] Photometric=RGB without ICC → assumed sRGB%s\n",
               ColorInfo(), ColorReset());
      } else if (photometric == PHOTOMETRIC_SEPARATED) {
        printf("  %s[WARN] Photometric=CMYK without ICC → undefined color rendering%s\n",
               ColorWarning(), ColorReset());
        findings++;
      }
    }
  }

  TIFFClose(tif);
  TIFFSetWarningHandler(oldWarn);
  TIFFSetErrorHandler(oldErr);

  printf("\n=======================================================================\n");
  printf("IMAGE ANALYSIS SUMMARY\n");
  printf("=======================================================================\n");
  printf("Format:     TIFF\n");
  printf("Dimensions: %u × %u\n", width, height);
  printf("Findings:   %d\n", findings);
  printf("=======================================================================\n\n");

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════
// PNG Analysis — ICC extraction from iCCP chunk
// ═══════════════════════════════════════════════════════════════════════

static const char *PngColorTypeName(int ct) {
  switch (ct) {
    case PNG_COLOR_TYPE_GRAY:       return "Grayscale";
    case PNG_COLOR_TYPE_PALETTE:    return "Palette (Indexed)";
    case PNG_COLOR_TYPE_RGB:        return "RGB";
    case PNG_COLOR_TYPE_RGB_ALPHA:  return "RGBA";
    case PNG_COLOR_TYPE_GRAY_ALPHA: return "Grayscale+Alpha";
    default:                        return "Unknown";
  }
}

static const char *PngInterlaceName(int il) {
  switch (il) {
    case PNG_INTERLACE_NONE:  return "None";
    case PNG_INTERLACE_ADAM7: return "Adam7";
    default:                   return "Unknown";
  }
}

int AnalyzePngImage(const char *filepath, const char *fingerprintDb) {
  int findings = 0;

  printf("=======================================================================\n");
  printf("IMAGE FILE ANALYSIS — PNG\n");
  printf("=======================================================================\n");
  printf("File: %s\n\n", filepath);

  FILE *fp = fopen(filepath, "rb");
  if (!fp) {
    printf("%s[ERROR] Cannot open PNG file%s\n", ColorCritical(), ColorReset());
    return -1;
  }

  // Verify PNG signature (first 8 bytes)
  uint8_t sig[8];
  if (fread(sig, 1, 8, fp) != 8 || png_sig_cmp(sig, 0, 8) != 0) {
    printf("%s[ERROR] Invalid PNG signature%s\n", ColorCritical(), ColorReset());
    fclose(fp);
    return -1;
  }

  png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
  if (!png) {
    printf("%s[ERROR] png_create_read_struct failed%s\n", ColorCritical(), ColorReset());
    fclose(fp);
    return -1;
  }

  png_infop info = png_create_info_struct(png);
  if (!info) {
    png_destroy_read_struct(&png, nullptr, nullptr);
    fclose(fp);
    return -1;
  }

  if (setjmp(png_jmpbuf(png))) {
    printf("%s[ERROR] libpng read error (longjmp triggered)%s\n",
           ColorCritical(), ColorReset());
    png_destroy_read_struct(&png, &info, nullptr);
    fclose(fp);
    return -1;
  }

  png_init_io(png, fp);
  png_set_sig_bytes(png, 8);  // we already read 8 bytes
  png_read_info(png, info);

  // ── PNG Metadata ──
  printf("--- PNG Metadata ---\n");

  png_uint_32 width = png_get_image_width(png, info);
  png_uint_32 height = png_get_image_height(png, info);
  int bitDepth = png_get_bit_depth(png, info);
  int colorType = png_get_color_type(png, info);
  int interlace = png_get_interlace_type(png, info);
  int channels = png_get_channels(png, info);
  int compression = png_get_compression_type(png, info);
  int filter = png_get_filter_type(png, info);

  printf("  Dimensions:      %u × %u pixels\n", width, height);
  printf("  Bit Depth:       %d\n", bitDepth);
  printf("  Color Type:      %s (%d)\n", PngColorTypeName(colorType), colorType);
  printf("  Channels:        %d\n", channels);
  printf("  Interlace:       %s (%d)\n", PngInterlaceName(interlace), interlace);
  printf("  Compression:     %d (deflate)\n", compression);
  printf("  Filter:          %d\n", filter);

  // Resolution (pHYs chunk)
  png_uint_32 xPPU = 0, yPPU = 0;
  int unitType = 0;
  if (png_get_pHYs(png, info, &xPPU, &yPPU, &unitType)) {
    const char *unit = (unitType == PNG_RESOLUTION_METER) ? "pixels/meter" : "units";
    printf("  Resolution:      %u × %u %s\n", xPPU, yPPU, unit);
  }

  // Text chunks (tEXt/zTXt/iTXt)
  png_textp textPtr = nullptr;
  int numText = 0;
  if (png_get_text(png, info, &textPtr, &numText) > 0 && numText > 0) {
    printf("  Text Chunks:     %d\n", numText);
    for (int t = 0; t < numText && t < 5; t++) {
      printf("    %s: %.60s%s\n", textPtr[t].key,
             textPtr[t].text ? textPtr[t].text : "(null)",
             (textPtr[t].text && strlen(textPtr[t].text) > 60) ? "..." : "");
    }
  }

  // Gamma (gAMA chunk)
  double gamma = 0;
  if (png_get_gAMA(png, info, &gamma)) {
    printf("  Gamma:           %.5f\n", gamma);
  }

  // sRGB rendering intent (sRGB chunk)
  int srgbIntent = -1;
  if (png_get_sRGB(png, info, &srgbIntent)) {
    const char *intentNames[] = {"Perceptual", "Relative", "Saturation", "Absolute"};
    printf("  sRGB Intent:     %s (%d)\n",
           (srgbIntent >= 0 && srgbIntent <= 3) ? intentNames[srgbIntent] : "Unknown",
           srgbIntent);
  }

  printf("\n");

  // ── Security Checks ──
  printf("--- PNG Security Checks ---\n");

  // Check 1: Extreme dimensions (DoS via decompression)
  uint64_t pixelCount = (uint64_t)width * (uint64_t)height;
  if (pixelCount > 100000000ULL) {
    printf("      %s[WARN]  Extreme dimensions: %u×%u = %llu pixels (>100M)%s\n",
           ColorWarning(), width, height, (unsigned long long)pixelCount, ColorReset());
    printf("       %sCWE-400: Resource exhaustion via large PNG%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check 2: Zero dimensions
  if (width == 0 || height == 0) {
    printf("      %s[CRIT]  Zero dimension: %u×%u%s\n",
           ColorCritical(), width, height, ColorReset());
    printf("       %sCWE-369: Division by zero in row calculations%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check 3: Unusual bit depth
  if (bitDepth != 1 && bitDepth != 2 && bitDepth != 4 && bitDepth != 8 && bitDepth != 16) {
    printf("      %s[WARN]  Unusual bit depth: %d (expected 1/2/4/8/16)%s\n",
           ColorWarning(), bitDepth, ColorReset());
    printf("       %sCWE-131: Incorrect buffer size calculation%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check 4: Uncompressed size overflow
  uint64_t bytesPerPixel = ((uint64_t)bitDepth * (uint64_t)channels + 7) >> 3;
  uint64_t totalBytes = pixelCount * bytesPerPixel;
  if (totalBytes > 4ULL * 1024 * 1024 * 1024) {
    printf("      %s[WARN]  Uncompressed size %llu bytes (>4GB)%s\n",
           ColorWarning(), (unsigned long long)totalBytes, ColorReset());
    printf("       %sCWE-400: Memory exhaustion via large decoded image%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Scan text chunks for injection patterns
  if (numText > 0 && textPtr) {
    for (int t = 0; t < numText; t++) {
      if (textPtr[t].text && textPtr[t].text_length > 0) {
        findings += ScanForInjections(
            (const uint8_t *)textPtr[t].text, textPtr[t].text_length,
            textPtr[t].key ? textPtr[t].key : "tEXt");
      }
    }
  }

  if (findings == 0) {
    printf("      %s[OK] No security issues in PNG structure%s\n",
           ColorSuccess(), ColorReset());
  }
  printf("\n");

  // ── ICC Profile Extraction (iCCP chunk) ──
  printf("--- Embedded ICC Profile ---\n");

  png_charp iccpName = nullptr;
  int iccpCompression = 0;
  png_bytep iccpData = nullptr;
  png_uint_32 iccpLen = 0;

  if (png_get_iCCP(png, info, &iccpName, &iccpCompression, &iccpData, &iccpLen)) {
    printf("  %s[FOUND] ICC profile in iCCP chunk%s\n", ColorSuccess(), ColorReset());
    printf("  Profile Name:    %s\n", iccpName ? iccpName : "(null)");
    printf("  Profile Size:    %u bytes (%.1f KB)\n", iccpLen, iccpLen / 1024.0);
    printf("  iCCP Compression: %d (deflate)\n", iccpCompression);

    // Validate ICC magic in decompressed data
    if (iccpLen >= 40 && iccpData) {
      bool hasAcsp = (iccpData[36] == 'a' && iccpData[37] == 'c' &&
                      iccpData[38] == 's' && iccpData[39] == 'p');
      if (hasAcsp) {
        printf("  ICC Magic:       %s[OK] 'acsp' at offset 36%s\n",
               ColorSuccess(), ColorReset());
      } else {
        printf("  %s[CRIT] Missing 'acsp' magic — corrupted ICC profile in iCCP%s\n",
               ColorCritical(), ColorReset());
        printf("   %sCWE-20: Invalid ICC header embedded in PNG%s\n",
               ColorCritical(), ColorReset());
        findings++;
      }

      // ICC version
      uint8_t majVer = iccpData[8];
      uint8_t minVer = iccpData[9] >> 4;
      printf("  ICC Version:     %u.%u\n", majVer, minVer);

      // Profile size vs iCCP data size
      uint32_t hdrSize = ((uint32_t)iccpData[0] << 24) | ((uint32_t)iccpData[1] << 16) |
                          ((uint32_t)iccpData[2] << 8)  | (uint32_t)iccpData[3];
      if (hdrSize != iccpLen) {
        printf("  %s[WARN] Size mismatch: header says %u, iCCP has %u bytes%s\n",
               ColorWarning(), hdrSize, iccpLen, ColorReset());
        printf("   %sCWE-131: Size field inconsistency%s\n",
               ColorCritical(), ColorReset());
        findings++;
      }

      // Suspicious tag count
      if (iccpLen > 132) {
        uint32_t tagCount = ((uint32_t)iccpData[128] << 24) |
                            ((uint32_t)iccpData[129] << 16) |
                            ((uint32_t)iccpData[130] << 8) |
                            (uint32_t)iccpData[131];
        if (tagCount > 1000) {
          printf("  %s[CRIT] Suspicious ICC tag count: %u (mutated profile)%s\n",
                 ColorCritical(), tagCount, ColorReset());
          findings++;
        }
      }

      // Write to temp file for full heuristic analysis
      findings += ExtractAndAnalyzeICC(
          static_cast<const uint8_t *>(iccpData),
          static_cast<size_t>(iccpLen), "PNG iCCP", fingerprintDb);
    } else if (iccpLen > 0) {
      printf("  %s[CRIT] ICC profile too small (%u bytes < 40 minimum)%s\n",
             ColorCritical(), iccpLen, ColorReset());
      findings++;
    }
  } else if (srgbIntent >= 0) {
    printf("  %s[INFO] No iCCP chunk — sRGB chunk present (implicit sRGB)%s\n",
           ColorInfo(), ColorReset());
  } else {
    printf("  %s[INFO] No embedded ICC profile (no iCCP or sRGB chunk)%s\n",
           ColorInfo(), ColorReset());
  }

  png_destroy_read_struct(&png, &info, nullptr);
  fclose(fp);

  printf("\n=======================================================================\n");
  printf("IMAGE ANALYSIS SUMMARY\n");
  printf("=======================================================================\n");
  printf("Format:     PNG\n");
  printf("Dimensions: %u × %u\n", width, height);
  printf("Findings:   %d\n", findings);
  printf("=======================================================================\n\n");

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════
// JPEG Analysis — ICC extraction from APP2 ICC_PROFILE markers
// ═══════════════════════════════════════════════════════════════════════

// ICC_PROFILE APP2 marker: 14-byte header = "ICC_PROFILE\0" + seq_no + num_markers
static const uint8_t kIccProfileTag[] = {
  'I','C','C','_','P','R','O','F','I','L','E','\0'
};
static constexpr size_t kIccProfileTagLen = 12;
static constexpr size_t kIccProfileHeaderLen = 14; // 12 tag + 1 seq + 1 total

// Custom error manager for libjpeg that uses longjmp instead of exit()
struct JpegErrorMgr {
  struct jpeg_error_mgr pub;
  jmp_buf setjmp_buffer;
};

static void JpegErrorExit(j_common_ptr cinfo) {
  JpegErrorMgr *err = (JpegErrorMgr *)cinfo->err;
  longjmp(err->setjmp_buffer, 1);
}

static void JpegEmitMessage(j_common_ptr /*cinfo*/, int /*level*/) {
  // Suppress libjpeg warning messages
}

int AnalyzeJpegImage(const char *filepath, const char *fingerprintDb) {
  int findings = 0;

  printf("=======================================================================\n");
  printf("IMAGE FILE ANALYSIS — JPEG\n");
  printf("=======================================================================\n");
  printf("File: %s\n\n", filepath);

  FILE *fp = fopen(filepath, "rb");
  if (!fp) {
    printf("%s[ERROR] Cannot open JPEG file%s\n", ColorCritical(), ColorReset());
    return -1;
  }

  struct jpeg_decompress_struct cinfo;
  JpegErrorMgr jerr;
  cinfo.err = jpeg_std_error(&jerr.pub);
  jerr.pub.error_exit = JpegErrorExit;
  jerr.pub.emit_message = JpegEmitMessage;

  if (setjmp(jerr.setjmp_buffer)) {
    printf("%s[ERROR] libjpeg read error (longjmp triggered)%s\n",
           ColorCritical(), ColorReset());
    jpeg_destroy_decompress(&cinfo);
    fclose(fp);
    return -1;
  }

  jpeg_create_decompress(&cinfo);

  // Save APP2 markers (ICC_PROFILE) — up to 255 segments × 65533 bytes each
  jpeg_save_markers(&cinfo, JPEG_APP0 + 2, 0xFFFF);
  // Also save APP1 (EXIF) and APP0 (JFIF) for metadata
  jpeg_save_markers(&cinfo, JPEG_APP0 + 1, 0xFFFF);
  jpeg_save_markers(&cinfo, JPEG_APP0, 0xFFFF);

  jpeg_stdio_src(&cinfo, fp);
  jpeg_read_header(&cinfo, TRUE);

  // ── JPEG Metadata ──
  printf("--- JPEG Metadata ---\n");

  printf("  Dimensions:      %u × %u pixels\n", cinfo.image_width, cinfo.image_height);
  printf("  Components:      %d\n", cinfo.num_components);

  const char *csName = "Unknown";
  switch (cinfo.jpeg_color_space) {
    case JCS_GRAYSCALE: csName = "Grayscale"; break;
    case JCS_RGB:       csName = "RGB"; break;
    case JCS_YCbCr:     csName = "YCbCr"; break;
    case JCS_CMYK:      csName = "CMYK"; break;
    case JCS_YCCK:      csName = "YCCK"; break;
    default: break;
  }
  printf("  Color Space:     %s\n", csName);
  printf("  Data Precision:  %d bits\n", cinfo.data_precision);

  // Report density info
  if (cinfo.saw_JFIF_marker) {
    const char *dUnit = (cinfo.density_unit == 1) ? "dpi" :
                        (cinfo.density_unit == 2) ? "dpcm" : "aspect";
    printf("  JFIF Version:    %d.%02d\n", cinfo.JFIF_major_version, cinfo.JFIF_minor_version);
    printf("  Density:         %u × %u %s\n",
           cinfo.X_density, cinfo.Y_density, dUnit);
  }

  // Count marker types
  int app0Count = 0, app1Count = 0, app2Count = 0;
  for (jpeg_saved_marker_ptr m = cinfo.marker_list; m; m = m->next) {
    if (m->marker == JPEG_APP0)     app0Count++;
    if (m->marker == JPEG_APP0 + 1) app1Count++;
    if (m->marker == JPEG_APP0 + 2) app2Count++;
  }
  printf("  APP0 (JFIF):     %d marker(s)\n", app0Count);
  printf("  APP1 (EXIF):     %d marker(s)\n", app1Count);
  printf("  APP2 (ICC):      %d marker(s)\n", app2Count);
  printf("\n");

  // ── Security Checks ──
  printf("--- JPEG Security Checks ---\n");

  // Check 1: Extreme dimensions
  uint64_t pixelCount = (uint64_t)cinfo.image_width * (uint64_t)cinfo.image_height;
  if (pixelCount > 100000000ULL) {
    printf("      %s[WARN]  Extreme dimensions: %u×%u = %llu pixels (>100M)%s\n",
           ColorWarning(), cinfo.image_width, cinfo.image_height,
           (unsigned long long)pixelCount, ColorReset());
    printf("       %sCWE-400: Resource exhaustion via large JPEG%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check 2: Zero dimensions
  if (cinfo.image_width == 0 || cinfo.image_height == 0) {
    printf("      %s[CRIT]  Zero dimension: %u×%u%s\n",
           ColorCritical(), cinfo.image_width, cinfo.image_height, ColorReset());
    findings++;
  }

  // Check 3: Unusual data precision
  if (cinfo.data_precision != 8 && cinfo.data_precision != 12) {
    printf("      %s[WARN]  Unusual data precision: %d (expected 8 or 12)%s\n",
           ColorWarning(), cinfo.data_precision, ColorReset());
    printf("       %sCWE-131: Non-standard JPEG precision%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check 4: Excessive component count (JPEG supports max 255, but >4 is suspicious)
  if (cinfo.num_components > 4) {
    printf("      %s[WARN]  Excessive components: %d (>4)%s\n",
           ColorWarning(), cinfo.num_components, ColorReset());
    findings++;
  }

  if (findings == 0) {
    printf("      %s[OK] No security issues in JPEG structure%s\n",
           ColorSuccess(), ColorReset());
  }
  printf("\n");

  // ── ICC Profile Extraction (APP2 ICC_PROFILE markers) ──
  // Per ICC spec, profiles >64KB are split across multiple APP2 markers.
  // Each marker has: "ICC_PROFILE\0" (12 bytes) + seq_no (1) + num_markers (1) + data
  printf("--- Embedded ICC Profile ---\n");

  // Pass 1: Count ICC_PROFILE markers and determine total size
  int numIccMarkers = 0;
  int expectedTotal = 0;
  size_t totalIccSize = 0;

  for (jpeg_saved_marker_ptr m = cinfo.marker_list; m; m = m->next) {
    if (m->marker != JPEG_APP0 + 2) continue;
    if (m->data_length < kIccProfileHeaderLen) continue;
    if (memcmp(m->data, kIccProfileTag, kIccProfileTagLen) != 0) continue;

    int seqNo = m->data[12];
    int total = m->data[13];
    (void)seqNo;

    if (expectedTotal == 0) {
      expectedTotal = total;
    } else if (total != expectedTotal) {
      printf("  %s[CRIT] Inconsistent ICC marker count: marker says %d, expected %d%s\n",
             ColorCritical(), total, expectedTotal, ColorReset());
      printf("   %sCWE-20: Marker count mismatch (potential crafted JPEG)%s\n",
             ColorCritical(), ColorReset());
      findings++;
    }

    totalIccSize += (m->data_length - kIccProfileHeaderLen);
    numIccMarkers++;
  }

  if (numIccMarkers > 0 && totalIccSize > 0) {
    printf("  %s[FOUND] ICC profile in APP2 marker(s)%s\n", ColorSuccess(), ColorReset());
    printf("  ICC Segments:    %d of %d\n", numIccMarkers, expectedTotal);
    printf("  Total Size:      %zu bytes (%.1f KB)\n", totalIccSize, totalIccSize / 1024.0);

    if (numIccMarkers != expectedTotal) {
      printf("  %s[WARN] Missing ICC segments: have %d, expected %d%s\n",
             ColorWarning(), numIccMarkers, expectedTotal, ColorReset());
      printf("   %sCWE-20: Incomplete multi-segment ICC profile%s\n",
             ColorCritical(), ColorReset());
      findings++;
    }

    // Sanity check total size (cap at 20MB)
    if (totalIccSize > 20 * 1024 * 1024) {
      printf("  %s[CRIT] ICC profile too large: %zu bytes (>20MB)%s\n",
             ColorCritical(), totalIccSize, ColorReset());
      printf("   %sCWE-400: Excessive ICC profile size in JPEG%s\n",
             ColorCritical(), ColorReset());
      findings++;
    } else {
      // Pass 2: Reassemble ICC profile from markers (in sequence order)
      std::vector<uint8_t> iccBuf(totalIccSize);
      size_t offset = 0;
      bool orderValid = true;

      // Collect segments in order (seq_no is 1-based)
      for (int seq = 1; seq <= expectedTotal; seq++) {
        bool found = false;
        for (jpeg_saved_marker_ptr m = cinfo.marker_list; m; m = m->next) {
          if (m->marker != JPEG_APP0 + 2) continue;
          if (m->data_length < kIccProfileHeaderLen) continue;
          if (memcmp(m->data, kIccProfileTag, kIccProfileTagLen) != 0) continue;
          if (m->data[12] != seq) continue;

          size_t dataLen = m->data_length - kIccProfileHeaderLen;
          if (offset + dataLen <= totalIccSize) {
            memcpy(iccBuf.data() + offset, m->data + kIccProfileHeaderLen, dataLen);
            offset += dataLen;
          }
          found = true;
          break;
        }
        if (!found) {
          printf("  %s[WARN] Missing ICC segment %d/%d%s\n",
                 ColorWarning(), seq, expectedTotal, ColorReset());
          orderValid = false;
        }
      }

      if (orderValid && offset == totalIccSize && totalIccSize >= 40) {
        // Validate ICC magic
        bool hasAcsp = (iccBuf[36] == 'a' && iccBuf[37] == 'c' &&
                        iccBuf[38] == 's' && iccBuf[39] == 'p');
        if (hasAcsp) {
          printf("  ICC Magic:       %s[OK] 'acsp' at offset 36%s\n",
                 ColorSuccess(), ColorReset());
        } else {
          printf("  %s[CRIT] Missing 'acsp' magic — corrupted ICC in APP2%s\n",
                 ColorCritical(), ColorReset());
          printf("   %sCWE-20: Invalid ICC header in JPEG%s\n",
                 ColorCritical(), ColorReset());
          findings++;
        }

        // ICC version
        uint8_t majVer = iccBuf[8];
        uint8_t minVer = iccBuf[9] >> 4;
        printf("  ICC Version:     %u.%u\n", majVer, minVer);

        // Profile size check
        uint32_t hdrSize = ((uint32_t)iccBuf[0] << 24) | ((uint32_t)iccBuf[1] << 16) |
                            ((uint32_t)iccBuf[2] << 8)  | (uint32_t)iccBuf[3];
        if (hdrSize != totalIccSize) {
          printf("  %s[WARN] Size mismatch: header says %u, APP2 total %zu bytes%s\n",
                 ColorWarning(), hdrSize, totalIccSize, ColorReset());
          findings++;
        }

        // Write extracted ICC to temp file for full analysis
        findings += ExtractAndAnalyzeICC(
            reinterpret_cast<const uint8_t *>(iccBuf.data()),
            totalIccSize, "JPEG APP2", fingerprintDb);
      } else if (totalIccSize < 40) {
        printf("  %s[CRIT] Reassembled ICC too small (%zu bytes < 40)%s\n",
               ColorCritical(), totalIccSize, ColorReset());
        findings++;
      }
    }
  } else {
    printf("  %s[INFO] No embedded ICC profile (no APP2 ICC_PROFILE markers)%s\n",
           ColorInfo(), ColorReset());
    if (cinfo.saw_JFIF_marker) {
      printf("  JFIF present — color space interpretation depends on component IDs.\n");
    }
  }

  jpeg_destroy_decompress(&cinfo);
  fclose(fp);

  printf("\n=======================================================================\n");
  printf("IMAGE ANALYSIS SUMMARY\n");
  printf("=======================================================================\n");
  printf("Format:     JPEG\n");
  printf("Dimensions: %u × %u\n", cinfo.image_width, cinfo.image_height);
  printf("Findings:   %d\n", findings);
  printf("=======================================================================\n\n");

  return findings;
}

// ═══════════════════════════════════════════════════════════════════════
// Format Handler Table — add new formats here
// ═══════════════════════════════════════════════════════════════════════

static const ImageFormat kTiffFormats[] = {
  ImageFormat::TIFF_LE, ImageFormat::TIFF_BE,
  ImageFormat::BIGTIFF_LE, ImageFormat::BIGTIFF_BE
};
static const ImageFormat kPngFormats[] = { ImageFormat::PNG };
static const ImageFormat kJpegFormats[] = { ImageFormat::JPEG };

static const ImageFormatHandler kFormatHandlers[] = {
  { "TIFF", kTiffFormats, 4, AnalyzeTiffImage },
  { "PNG",  kPngFormats,  1, AnalyzePngImage },
  { "JPEG", kJpegFormats, 1, AnalyzeJpegImage },
};
static constexpr int kNumFormatHandlers = sizeof(kFormatHandlers) / sizeof(kFormatHandlers[0]);

// ═══════════════════════════════════════════════════════════════════════
// Top-Level Dispatcher (table-driven)
// ═══════════════════════════════════════════════════════════════════════

int AnalyzeImageFile(const char *filepath, const char *fingerprintDb) {
  ImageFormat fmt = DetectFileFormat(filepath);

  // ICC_PROFILE and UNKNOWN fall through to ComprehensiveAnalyze
  if (fmt == ImageFormat::ICC_PROFILE) {
    return ComprehensiveAnalyze(filepath, fingerprintDb);
  }
  if (fmt == ImageFormat::UNKNOWN) {
    printf("[INFO] Unknown file format. Attempting ICC profile analysis...\n");
    return ComprehensiveAnalyze(filepath, fingerprintDb);
  }

  // Look up handler from table
  for (int i = 0; i < kNumFormatHandlers; i++) {
    for (int j = 0; j < kFormatHandlers[i].formatCount; j++) {
      if (kFormatHandlers[i].formats[j] == fmt) {
        return kFormatHandlers[i].analyze(filepath, fingerprintDb);
      }
    }
  }

  // No handler found — fall back to ICC analysis
  printf("[INFO] No image handler for format '%s'. Attempting ICC profile analysis...\n",
         FormatName(fmt));
  return ComprehensiveAnalyze(filepath, fingerprintDb);
}
