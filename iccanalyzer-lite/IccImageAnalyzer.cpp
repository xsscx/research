/*
 * IccImageAnalyzer.cpp — Image file ICC extraction and security analysis
 *
 * Phase 1: TIFF support via libtiff
 * - Extract embedded ICC profile from TIFFTAG_ICCPROFILE (tag 34675)
 * - Report TIFF metadata (dimensions, BPS, SPP, compression, photometric)
 * - Detect xnuimagefuzzer injection signatures in strip/tile data
 * - Run full 138-heuristic ICC analysis on extracted profile
 *
 * Copyright (c) 2026 David H Hoyt LLC
 */

#include "IccImageAnalyzer.h"
#include "IccAnalyzerColors.h"
#include "IccAnalyzerSecurity.h"
#include "IccAnalyzerHeuristics.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

#include <tiffio.h>

// ── Forward declarations for ICC analysis functions ──
extern int HeuristicAnalyze(const char *profilePath, const char *fingerprintDb);
extern int ComprehensiveAnalyze(const char *profilePath, const char *fingerprintDb);
extern int RoundTripAnalyze(const char *profilePath);
extern void ResetAllocGuard();

// ═══════════════════════════════════════════════════════════════════════
// File Format Detection
// ═══════════════════════════════════════════════════════════════════════

ImageFormat DetectFileFormat(const char *filepath) {
  FILE *f = fopen(filepath, "rb");
  if (!f) return ImageFormat::UNKNOWN;

  uint8_t magic[40] = {0};
  size_t n = fread(magic, 1, sizeof(magic), f);
  fclose(f);

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

  // ── IFD count (multi-page TIFF detection) ──
  int ifdCount = 0;
  do { ifdCount++; } while (TIFFReadDirectory(tif));
  if (ifdCount > 1) {
    printf("  IFD Count:       %d (multi-page TIFF)\n", ifdCount);
  }
  // Return to first IFD for ICC extraction
  TIFFSetDirectory(tif, 0);
  printf("\n");

  // ── TIFF Security Checks ──
  printf("--- TIFF Security Checks ---\n");

  // Check for suspicious dimensions
  uint64_t pixelCount = (uint64_t)width * (uint64_t)height;
  if (pixelCount > 100000000ULL) { // 100M pixels
    printf("  %s[WARN] Extreme dimensions: %u×%u = %llu pixels (>100M)%s\n",
           ColorWarning(), width, height, (unsigned long long)pixelCount, ColorReset());
    printf("   %sCWE-400: Resource exhaustion via large image decode%s\n",
           ColorCritical(), ColorReset());
    findings++;
  } else {
    printf("  %s[OK] Dimensions: %u×%u (%llu pixels)%s\n",
           ColorSuccess(), width, height, (unsigned long long)pixelCount, ColorReset());
  }

  // Check for zero dimensions
  if (width == 0 || height == 0) {
    printf("  %s[CRIT] Zero dimension: %u×%u%s\n",
           ColorCritical(), width, height, ColorReset());
    printf("   %sCWE-369: Division by zero in image processing%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check BPS validity (common: 1, 8, 16, 32)
  if (bps != 0 && bps != 1 && bps != 2 && bps != 4 && bps != 8 &&
      bps != 16 && bps != 32 && bps != 64) {
    printf("  %s[WARN] Unusual BitsPerSample: %u%s\n",
           ColorWarning(), bps, ColorReset());
    printf("   %sCWE-131: Incorrect buffer size calculation%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check SPP validity
  if (spp > 16) {
    printf("  %s[WARN] Excessive SamplesPerPixel: %u (>16)%s\n",
           ColorWarning(), spp, ColorReset());
    printf("   %sCWE-131: Buffer size overflow (nOutput×BPS×width)%s\n",
           ColorCritical(), ColorReset());
    findings++;
  }

  // Check for xnuimagefuzzer provenance in metadata
  if (software && strstr(software, "XNUImageFuzzer")) {
    printf("  %s[INFO] xnuimagefuzzer provenance detected in Software tag%s\n",
           ColorInfo(), ColorReset());
  }
  if (imagedesc && strstr(imagedesc, "fuzzed")) {
    printf("  %s[INFO] Fuzzed image indicator in ImageDescription%s\n",
           ColorInfo(), ColorReset());
  }

  // Strip/tile geometry validation (CFL-082 pattern)
  if (tileWidth == 0 && tileHeight == 0 && rowsPerStrip > 0) {
    uint32_t nStrips = TIFFNumberOfStrips(tif);
    tmsize_t stripSize = TIFFStripSize(tif);
    if (stripSize <= 0) {
      printf("  %s[CRIT] Zero or negative strip size — corrupted geometry%s\n",
             ColorCritical(), ColorReset());
      printf("   %sCWE-122: Heap buffer overflow in ReadLine/ReadEncodedStrip%s\n",
             ColorCritical(), ColorReset());
      findings++;
    }
    // Check strip offset bounds
    for (uint32_t s = 0; s < nStrips && s < 100; s++) {
      uint64_t *offsets = nullptr;
      uint64_t *bytecounts = nullptr;
      if (TIFFGetField(tif, TIFFTAG_STRIPOFFSETS, &offsets) &&
          TIFFGetField(tif, TIFFTAG_STRIPBYTECOUNTS, &bytecounts)) {
        // Report suspicious strip configurations
        if (offsets && bytecounts && bytecounts[s] > 0) {
          struct stat st;
          if (stat(filepath, &st) == 0) {
            if (offsets[s] + bytecounts[s] > (uint64_t)st.st_size) {
              printf("  %s[CRIT] Strip %u: offset+size (%llu+%llu) exceeds file size (%lld)%s\n",
                     ColorCritical(), s,
                     (unsigned long long)offsets[s], (unsigned long long)bytecounts[s],
                     (long long)st.st_size, ColorReset());
              printf("   %sCWE-125: Out-of-bounds read via corrupted strip offset%s\n",
                     ColorCritical(), ColorReset());
              findings++;
              break; // one report is enough
            }
          }
        }
        break; // only check first strip for offset arrays
      }
    }
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
      char tmpIcc[256];
      snprintf(tmpIcc, sizeof(tmpIcc), "/tmp/iccanalyzer-extracted-%d.icc", getpid());
      FILE *fOut = fopen(tmpIcc, "wb");
      if (fOut) {
        fwrite(iccData, 1, iccLen, fOut);
        fclose(fOut);
        printf("\n  Extracted to: %s\n\n", tmpIcc);

        printf("=======================================================================\n");
        printf("EXTRACTED ICC PROFILE — FULL HEURISTIC ANALYSIS\n");
        printf("=======================================================================\n\n");

        // Reset OOM guard for fresh ICC analysis
        ResetAllocGuard();

        // Run the full comprehensive analysis on the extracted ICC
        int iccResult = ComprehensiveAnalyze(tmpIcc, fingerprintDb);
        if (iccResult > 0) findings += iccResult;

        // Clean up temp file
        unlink(tmpIcc);
      } else {
        printf("  %s[ERROR] Cannot write temp ICC file: %s%s\n",
               ColorCritical(), tmpIcc, ColorReset());
      }

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
// Top-Level Dispatcher
// ═══════════════════════════════════════════════════════════════════════

int AnalyzeImageFile(const char *filepath, const char *fingerprintDb) {
  ImageFormat fmt = DetectFileFormat(filepath);

  switch (fmt) {
    case ImageFormat::TIFF_LE:
    case ImageFormat::TIFF_BE:
    case ImageFormat::BIGTIFF_LE:
    case ImageFormat::BIGTIFF_BE:
      return AnalyzeTiffImage(filepath, fingerprintDb);

    case ImageFormat::PNG:
      printf("[INFO] PNG image analysis not yet implemented.\n");
      printf("       Use 'exiftool -icc_profile -b %s > extracted.icc' to extract ICC.\n",
             filepath);
      return 0;

    case ImageFormat::JPEG:
      printf("[INFO] JPEG image analysis not yet implemented.\n");
      printf("       Use 'exiftool -icc_profile -b %s > extracted.icc' to extract ICC.\n",
             filepath);
      return 0;

    case ImageFormat::ICC_PROFILE:
      // Not an image — raw ICC profile. Use standard path.
      return ComprehensiveAnalyze(filepath, fingerprintDb);

    case ImageFormat::UNKNOWN:
    default:
      printf("[INFO] Unknown file format. Attempting ICC profile analysis...\n");
      return ComprehensiveAnalyze(filepath, fingerprintDb);
  }
}
