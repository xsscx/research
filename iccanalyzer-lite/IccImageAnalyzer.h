/*
 * IccImageAnalyzer.h — Image file ICC extraction and security analysis
 *
 * Extracts embedded ICC profiles from image files (TIFF, PNG, JPEG)
 * and runs the full heuristic analysis on the extracted profile.
 * TIFF security heuristics H139-H141, H149-H150 validate strip/tile geometry,
 * dimensions, IFD offset bounds, IFD chain cycles, and tile layout.
 * PNG analysis extracts ICC from iCCP chunks; JPEG from APP2 ICC_PROFILE markers.
 *
 * Copyright (c) 2026 David H Hoyt LLC
 */

#ifndef ICC_IMAGE_ANALYZER_H
#define ICC_IMAGE_ANALYZER_H

#include <cstdint>
#include <tiffio.h>
#include <png.h>
#include <jpeglib.h>

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

// Image format handler — table-driven dispatcher for extensibility.
// To add a new format: implement the analyze function, add one entry to kFormatHandlers[].
typedef int (*ImageAnalyzeFunc)(const char *filepath, const char *fingerprintDb);

struct ImageFormatHandler {
  const char *name;
  const ImageFormat *formats;
  int formatCount;
  ImageAnalyzeFunc analyze;
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

// H149: IFD chain cycle detection — detect circular next-IFD pointers (CWE-835)
int RunHeuristic_H149_TiffIfdChainCycle(TIFF *tif, const char *filepath);

// H150: Tile geometry validation — TileWidth/TileLength/TileByteCounts consistency (CWE-122)
int RunHeuristic_H150_TiffTileGeometry(TIFF *tif, const char *filepath,
                                        uint32_t width, uint32_t height,
                                        uint16_t bps, uint16_t spp);

// Analyze a TIFF file: runs H139-H141, extracts embedded ICC, report metadata,
// scans for injection signatures, then runs ICC heuristics H1-H138 on extracted ICC.
// Returns 0 on clean, >0 on findings, <0 on error.
int AnalyzeTiffImage(const char *filepath, const char *fingerprintDb);

// Analyze a PNG file: extracts ICC from iCCP chunk, reports metadata,
// validates iCCP compression, runs full ICC heuristics on extracted profile.
int AnalyzePngImage(const char *filepath, const char *fingerprintDb);

// Analyze a JPEG file: extracts ICC from APP2 ICC_PROFILE marker(s),
// reassembles multi-segment profiles (>64KB), reports metadata,
// runs full ICC heuristics on extracted profile.
int AnalyzeJpegImage(const char *filepath, const char *fingerprintDb);

// Top-level image analysis dispatcher.
// Detects format, routes to appropriate handler.
int AnalyzeImageFile(const char *filepath, const char *fingerprintDb);

#endif // ICC_IMAGE_ANALYZER_H
