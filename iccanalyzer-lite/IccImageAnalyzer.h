/*
 * IccImageAnalyzer.h — Image file ICC extraction and security analysis
 *
 * Extracts embedded ICC profiles from image files (TIFF, PNG, JPEG)
 * and runs the full 138-heuristic analysis on the extracted profile.
 * Also reports image-level metadata and detects xnuimagefuzzer
 * injection signatures.
 *
 * Copyright (c) 2026 David H Hoyt LLC
 */

#ifndef ICC_IMAGE_ANALYZER_H
#define ICC_IMAGE_ANALYZER_H

#include <cstdint>

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

// Analyze a TIFF file: extract embedded ICC, report metadata,
// scan for injection signatures, then run ICC heuristics.
// Returns 0 on clean, >0 on findings, <0 on error.
int AnalyzeTiffImage(const char *filepath, const char *fingerprintDb);

// Top-level image analysis dispatcher.
// Detects format, routes to appropriate handler.
int AnalyzeImageFile(const char *filepath, const char *fingerprintDb);

#endif // ICC_IMAGE_ANALYZER_H
