/*
 * IccImageAnalyzer.h — Image file ICC extraction and security analysis
 *
 * Extracts embedded ICC profiles from image files (TIFF, PNG, JPEG)
 * and runs the full 141-heuristic analysis on the extracted profile.
 * TIFF security heuristics H139-H141 validate strip geometry, dimensions,
 * and IFD offset bounds via defensive programming.
 *
 * Copyright (c) 2026 David H Hoyt LLC
 */

#ifndef ICC_IMAGE_ANALYZER_H
#define ICC_IMAGE_ANALYZER_H

#include <cstdint>
#include <tiffio.h>

// File format detected from magic bytes
enum class ImageFormat {
  ICC_PROFILE,    // Raw ICC profile ('acsp' at offset 36)
  TIFF_LE,        // TIFF little-endian (49 49 2A 00)
  TIFF_BE,        // TIFF big-endian (4D 4D 00 2A)
  BIGTIFF_LE,     // BigTIFF little-endian (49 49 2B 00)
  BIGTIFF_BE,     // BigTIFF big-endian (4D 4D 00 2B)
  PNG,            // PNG (89 50 4E 47 0D 0A 1A 0A)
  JPEG,           // JPEG (FF D8 FF)
  UNKNOWN
};

// Detect file format from first bytes
ImageFormat DetectFileFormat(const char *filepath);

// Return human-readable format name
const char *FormatName(ImageFormat fmt);

// ── TIFF Security Heuristics H139-H141 ──

// H139: Strip geometry validation — integer overflow, buffer underallocation
int RunHeuristic_H139_TiffStripGeometry(TIFF *tif, const char *filepath,
                                         uint32_t width, uint16_t bps,
                                         uint16_t spp, uint32_t rowsPerStrip,
                                         uint16_t planarConfig);

// H140: Dimension and sample validation — zero/extreme dims, unusual BPS/SPP
int RunHeuristic_H140_TiffDimensionValidation(uint32_t width, uint32_t height,
                                               uint16_t bps, uint16_t spp);

// H141: IFD offset bounds validation — strip/tile offsets within file
int RunHeuristic_H141_TiffIfdOffsetBounds(TIFF *tif, const char *filepath);

// Analyze a TIFF file: runs H139-H141, extracts embedded ICC, report metadata,
// scans for injection signatures, then runs ICC heuristics H1-H138 on extracted ICC.
// Returns 0 on clean, >0 on findings, <0 on error.
int AnalyzeTiffImage(const char *filepath, const char *fingerprintDb);

// Top-level image analysis dispatcher.
// Detects format, routes to appropriate handler.
int AnalyzeImageFile(const char *filepath, const char *fingerprintDb);

#endif // ICC_IMAGE_ANALYZER_H
