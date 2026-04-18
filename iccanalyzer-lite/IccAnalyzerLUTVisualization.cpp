/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * This software and associated documentation files (the "Software") are the
 * exclusive intellectual property of David H Hoyt LLC.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "David H Hoyt LLC" must not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID H HOYT LLC "AS IS" AND ANY EXPRESSED
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL DAVID H HOYT LLC BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Contact: https://hoyt.net
 *
 * LUT Visualization and DumpAll functionality for iccanalyzer-lite.
 * Ported from ChrisCoxArt's dumpProfile-LUTs branch with security hardening.
 * - SVG 1D curve rendering for TRC and MBB curve tags
 * - TIFF 3D CLUT export for AToB/BToA/Gamut/Preview LUTs
 * - v5/iccMAX summary (spectral, BRDF, MPE, MCS)
 * - MPE element chain visualization
 * - Full tag enumeration (DumpAll)
 */

#include "IccAnalyzerLUTVisualization.h"
#include "IccAnalyzerSafeArithmetic.h"
#include "IccAnalyzerSecurity.h"

#include <cmath>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <fstream>
#include <algorithm>
#include <unordered_map>
#include <fcntl.h>
#include <libgen.h>
#include <unistd.h>
#include <climits>

// iccDEV headers
#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagLut.h"
#include "IccTagMPE.h"
#include "IccMpeBasic.h"
#include "IccUtil.h"

// ============================================================================
// Safe multiplication helpers (SIZE_MAX-based, matching dumpProfile pattern)
// ============================================================================

static inline bool SafeMulSz(size_t a, size_t b, size_t &result) {
  if (a != 0 && b > SIZE_MAX / a) return false;
  result = a * b;
  return true;
}

static inline bool SafeMulSz3(size_t a, size_t b, size_t c, size_t &result) {
  size_t tmp = 0;
  if (!SafeMulSz(a, b, tmp)) return false;
  return SafeMulSz(tmp, c, result);
}

static inline bool SafeMulSz4(size_t a, size_t b, size_t c, size_t d, size_t &result) {
  size_t tmp = 0;
  if (!SafeMulSz3(a, b, c, tmp)) return false;
  return SafeMulSz(tmp, d, result);
}

static bool ResolveWritablePath(const std::string &path, std::string &resolvedPath) {
  if (path.empty() || path.size() >= PATH_MAX || path.find('\0') != std::string::npos) {
    return false;
  }

  char pathCopy[PATH_MAX];
  std::strncpy(pathCopy, path.c_str(), PATH_MAX - 1);
  pathCopy[PATH_MAX - 1] = '\0';
  char *dir = dirname(pathCopy);
  if (!dir) return false;

  char resolvedDir[PATH_MAX];
  if (!realpath(dir, resolvedDir)) return false;

  char pathCopy2[PATH_MAX];
  std::strncpy(pathCopy2, path.c_str(), PATH_MAX - 1);
  pathCopy2[PATH_MAX - 1] = '\0';
  char *base = basename(pathCopy2);
  if (!base || !base[0] || std::strcmp(base, ".") == 0 || std::strcmp(base, "..") == 0) {
    return false;
  }

  char resolvedBuf[PATH_MAX];
  int n = std::snprintf(resolvedBuf, PATH_MAX, "%s/%s", resolvedDir, base);
  if (n < 0 || n >= PATH_MAX) return false;

  resolvedPath.assign(resolvedBuf);
  return true;
}

// ============================================================================
// XML escape for SVG output (CWE-79)
// ============================================================================

static std::string xmlEscape(const std::string &input) {
  std::string result;
  result.reserve(input.size());
  for (char c : input) {
    switch (c) {
      case '&':  result += "&amp;";  break;
      case '<':  result += "&lt;";   break;
      case '>':  result += "&gt;";   break;
      case '"':  result += "&quot;"; break;
      case '\'': result += "&#39;";  break;
      default:   result += c;        break;
    }
  }
  return result;
}

// ============================================================================
// SVG geometry types
// ============================================================================

static const float kInch2mm = 25.4f;
static const float kMm2point = 72.0f / kInch2mm;

struct Point2D {
  float x, y;
  Point2D() : x(0.0f), y(0.0f) {}
  Point2D(float xx, float yy) : x(xx), y(yy) {}
};

static inline Point2D operator+(const Point2D &a, const Point2D &b) {
  return Point2D(a.x + b.x, a.y + b.y);
}
static inline Point2D operator*(const Point2D &a, float s) {
  return Point2D(a.x * s, a.y * s);
}

typedef std::vector<Point2D> PointList;

// ============================================================================
// SVG Writer class
// ============================================================================

class SVGWriter {
public:
  SVGWriter() : m_groupLevel(0) {}
  ~SVGWriter() { Close(); }

  bool Open(const std::string &path) {
    if (m_out.is_open()) m_out.close();
    m_groupLevel = 0;
    std::string resolvedPath;
    if (!ResolveWritablePath(path, resolvedPath)) {
      return false;
    }
    m_out.open(resolvedPath);
    return m_out.is_open();
  }

  void WriteHeader(const Point2D &topLeft, const Point2D &bottomRight) {
    m_out << "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n";
    m_out << "<svg version=\"1.1\" xmlns=\"http://www.w3.org/2000/svg\"\n";
    m_out << "  x=\"0\" y=\"0\" viewBox=\""
          << (topLeft.x * kMm2point) << " " << (topLeft.y * kMm2point) << " "
          << (bottomRight.x * kMm2point) << " " << (bottomRight.y * kMm2point) << "\" "
          << "xml:space=\"preserve\">\n";
  }

  void AddLine(const Point2D &start, const Point2D &end) {
    m_out << "<line x1=\"" << start.x << "mm\" y1=\"" << start.y
          << "mm\" x2=\"" << end.x << "mm\" y2=\"" << end.y << "mm\" "
          << FillStroke(false) << " />\n";
  }

  void AddPolyLine(const PointList &points, bool closed, bool filled) {
    m_out << "<polyline points=\"";
    for (auto &p : points)
      m_out << kMm2point * p.x << "," << kMm2point * p.y << " ";
    if (closed && !points.empty())
      m_out << kMm2point * points[0].x << "," << kMm2point * points[0].y << " ";
    m_out << "\" " << FillStroke(filled) << " />\n";
  }

  void AddText(float x, float y, const std::string &text,
               float size, const std::string &font,
               const std::string &style, const std::string &align,
               float rotation = 0.0f) {
    m_out << "<text";
    if (align == "Center" || align == "center")
      m_out << " text-anchor=\"middle\"";
    else if (align == "right" || align == "Right")
      m_out << " text-anchor=\"end\"";
    float xx = x * kMm2point;
    float yy = y * kMm2point;
    m_out << " x=\"" << xx << "\" y=\"" << yy << "\"";
    if (rotation != 0.0f)
      m_out << " transform=\"rotate(" << rotation << ", " << xx << ", " << yy << ")\"";
    if (!font.empty())
      m_out << " font-family=\"" << font << "\"";
    if (style == "Bold")
      m_out << " font-weight=\"bold\"";
    else if (style == "Italic")
      m_out << " font-style=\"italic\"";
    m_out << " font-size=\"" << size << "pt\"";
    m_out << ">" << xmlEscape(text) << "</text>\n";
  }

  void StartGroup(const std::string &name) {
    m_out << "<g id=\"" << xmlEscape(name) << "\">\n";
    m_groupLevel++;
  }

  void EndGroup() {
    m_out << "</g>\n";
    m_groupLevel--;
  }

  void Close() {
    if (m_out.is_open()) {
      if (m_groupLevel > 0)
        fprintf(stderr, "[LUTViz] WARNING: %d unclosed SVG groups\n", m_groupLevel);
      m_out << "</svg>\n";
      m_out.close();
    }
  }

private:
  std::string FillStroke(bool filled) {
    return filled
      ? std::string("fill=\"black\" stroke=\"none\"")
      : std::string("fill=\"none\" stroke=\"black\" stroke-width=\"0.5\"");
  }

  int m_groupLevel;
  std::ofstream m_out;
};

// ============================================================================
// SVG axis drawing
// ============================================================================

static void DrawAxis(SVGWriter &svg, const Point2D &base, const Point2D &range,
                     const Point2D &tickLen, const std::string &label) {
  svg.AddLine(base, base + range);
  // Marks at 0.0, 0.5, 1.0
  svg.AddLine(base, base + tickLen);
  svg.AddLine(base + range, base + range + tickLen);
  svg.AddLine(base + range * 0.5f, base + range * 0.5f + tickLen);
  // Tenth marks
  for (int i = 1; i < 10; ++i) {
    if (i == 5) continue;
    Point2D p = base + range * (i / 10.0f);
    svg.AddLine(p, p + tickLen * 0.5f);
  }
  // Hundredth marks
  for (int i = 1; i < 100; ++i) {
    if ((i % 10) == 0) continue;
    Point2D p = base + range * (i / 100.0f);
    svg.AddLine(p, p + tickLen * 0.25f);
  }
  Point2D labelPt = base + range * 0.5f + tickLen * 2.0f;
  float rot = (range.x == 0.0f) ? 90.0f : 0.0f;
  svg.AddText(labelPt.x, labelPt.y, label, 14, "Arial", "Regular", "Center", rot);
}

// ============================================================================
// 1D LUT → SVG curve graphing
// ============================================================================

static void Graph1DLUT(CIccCurve *curve, const std::string &name,
                       const std::string &description, SVGWriter &svg, int steps) {
  svg.StartGroup(name);
  svg.AddText(8 * 0.5f * kInch2mm, 0.25f * kInch2mm,
              name + "  " + description, 14, "Arial", "Bold", "Center");

  Point2D base(0.5f * kInch2mm, 7.5f * kInch2mm);
  DrawAxis(svg, base, Point2D(7.0f * kInch2mm, 0.0f), Point2D(0, 5), "Input");
  DrawAxis(svg, base, Point2D(0.0f, -7.0f * kInch2mm), Point2D(-5, 0), "Output");

  PointList points(static_cast<size_t>(steps + 1));
  float scale = (7.5f - 0.5f) * kInch2mm;
  for (int i = 0; i <= steps; ++i) {
    float input = static_cast<float>(i) / static_cast<float>(steps);
    float output = curve->Apply(input);
    if (std::isnan(output) || std::isinf(output)) output = 0.0f;
    points[static_cast<size_t>(i)] = Point2D(input * scale, -output * scale) + base;
  }
  svg.AddPolyLine(points, false, false);
  svg.EndGroup();
}

static void Describe1DLUT(CIccTagCurve *curve, std::string &desc) {
  auto size = curve->GetSize();
  if (size == 0)
    desc += "Y = X";
  else if (size == 1)
    desc += "Y = X ^ " + std::to_string(static_cast<double>((*curve)[0]) * 65535.0 / 256.0);
  else
    desc += "LookupTable[" + std::to_string(size) + "]";
}

static void Output1DLUT(CIccProfile *pIcc, CIccTag *tag,
                         const std::string &sigDesc, SVGWriter &svg, int verbosity) {
  (void)pIcc;
  (void)verbosity;
  icTagTypeSignature typeSig = tag->GetType();

  switch (typeSig) {
    case icSigCurveType: {
      CIccTagCurve *curve = dynamic_cast<CIccTagCurve*>(tag);
      if (curve) {
        std::string desc;
        Describe1DLUT(curve, desc);
        int size = static_cast<int>(curve->GetSize());
        int steps = std::max(1000, size);
        Graph1DLUT(curve, sigDesc, desc, svg, steps);
      }
      break;
    }
    case icSigParametricCurveType: {
      CIccTagParametricCurve *pc = dynamic_cast<CIccTagParametricCurve*>(tag);
      if (pc) {
        std::string desc;
        pc->Describe(desc, 100);
        Graph1DLUT(pc, sigDesc, desc, svg, 1000);
      }
      break;
    }
    case icSigSegmentedCurveType: {
      CIccTagSegmentedCurve *sc = dynamic_cast<CIccTagSegmentedCurve*>(tag);
      if (sc) {
        std::string desc;
        sc->Describe(desc, 100);
        Graph1DLUT(sc, sigDesc, desc, svg, 1000);
      }
      break;
    }
    default: {
      CIccCurve *uc = dynamic_cast<CIccCurve*>(tag);
      if (uc) {
        std::string desc;
        uc->Describe(desc, 100);
        Graph1DLUT(uc, sigDesc, desc, svg, 1000);
      }
      break;
    }
  }
}

// ============================================================================
// TIFF writer (manual, self-contained — no libtiff dependency for output)
// ============================================================================

static const bool kBigEndian = [] {
  const uint32_t test = 0x01020304;
  const uint8_t *p = reinterpret_cast<const uint8_t*>(&test);
  return (*p == 0x01);
}();

static bool PutShort(uint16_t val, FILE *f) {
  uint8_t buf[2];
  if (kBigEndian) {
    buf[0] = static_cast<uint8_t>(val >> 8);
    buf[1] = static_cast<uint8_t>(val & 0xFF);
  } else {
    buf[0] = static_cast<uint8_t>(val & 0xFF);
    buf[1] = static_cast<uint8_t>(val >> 8);
  }
  return fwrite(buf, 2, 1, f) == 1;
}

static bool PutLong(uint32_t val, FILE *f) {
  uint8_t buf[4];
  if (kBigEndian) {
    buf[0] = static_cast<uint8_t>(val >> 24);
    buf[1] = static_cast<uint8_t>(val >> 16);
    buf[2] = static_cast<uint8_t>(val >> 8);
    buf[3] = static_cast<uint8_t>(val & 0xFF);
  } else {
    buf[0] = static_cast<uint8_t>(val & 0xFF);
    buf[1] = static_cast<uint8_t>(val >> 8);
    buf[2] = static_cast<uint8_t>(val >> 16);
    buf[3] = static_cast<uint8_t>(val >> 24);
  }
  return fwrite(buf, 4, 1, f) == 1;
}

static bool PutIFDLong(uint16_t tag, uint16_t type, uint32_t count,
                       uint32_t value, FILE *f) {
  bool ok = PutShort(tag, f);
  ok &= PutShort(type, f);
  ok &= PutLong(count, f);
  ok &= PutLong(value, f);
  return ok;
}

// TIFF constants
enum { kTIFF_BYTE=1, kTIFF_SHORT=3, kTIFF_LONG=4, kTIFF_RATIO=5, kTIFF_FLOAT_T=11 };
enum {
  kTIFF_WIDTH=256, kTIFF_HEIGHT=257, kTIFF_BPS=258, kTIFF_COMPRESSION=259,
  kTIFF_PHOTOMETRIC=262, kTIFF_STRIPOFFSETS=273, kTIFF_SPP=277,
  kTIFF_ROWSPERSTRIP=278, kTIFF_STRIPBYTECOUNTS=279, kTIFF_XRES=282,
  kTIFF_YRES=283, kTIFF_PLANARCONFIG=284, kTIFF_RESUNIT=296,
  kTIFF_PREDICTOR=317, kTIFF_SAMPLEFORMAT=339
};
enum { kTIFF_COMPRESS_NONE=1 };
enum { kTIFF_UINT=1, kTIFF_SINT=2, kTIFF_FLOAT_S=3 };
enum {
  kTIFF_GRAY_BLACK=1, kTIFF_RGB=2, kTIFF_CMYK=5, kTIFF_CIELAB=8
};

static int TIFFColorModelFromICC(icColorSpaceSignature sig) {
  switch (sig) {
    case icSigRgbData: case icSigCmyData: case icSigXYZData:
    case icSigLuvData: case icSigYCbCrData: case icSigYxyData:
    case icSigHsvData: case icSigHlsData:
      return kTIFF_RGB;
    case icSigCmykData:
      return kTIFF_CMYK;
    case icSigLabData:
      return kTIFF_CIELAB;
    default:
      return kTIFF_GRAY_BLACK;
  }
}

static void ShiftTIFFLab8(uint8_t *in, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    size_t idx = 3 * i;
    int a = in[idx + 1];
    int b = in[idx + 2];
    in[idx + 1] = static_cast<uint8_t>(a - 128);
    in[idx + 2] = static_cast<uint8_t>(b - 128);
  }
}

static void ShiftTIFFLab16(uint16_t *in, size_t count) {
  for (size_t i = 0; i < count; ++i) {
    size_t idx = 3 * i;
    int a = in[idx + 1];
    int b = in[idx + 2];
    in[idx + 1] = static_cast<uint16_t>(a - 0x8000);
    in[idx + 2] = static_cast<uint16_t>(b - 0x8000);
  }
}

static bool WriteTIFF(const char *name, float dpi, int colorModel,
                      uint8_t *buffer, size_t width, size_t height,
                      int channels, int depth) {
  std::string resolvedPath;
  if (!name || !ResolveWritablePath(name, resolvedPath)) {
    fprintf(stderr, "[LUTViz] Invalid output path: %s\n", name ? name : "(null)");
    return false;
  }

  // Secure file open (owner rw only)
  int fd = open(resolvedPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP);
  if (fd < 0) {
    fprintf(stderr, "[LUTViz] Could not create output file: %s\n", resolvedPath.c_str());
    return false;
  }
  FILE *out = fdopen(fd, "wb");
  if (!out) {
    close(fd);
    fprintf(stderr, "[LUTViz] fdopen failed for: %s\n", resolvedPath.c_str());
    return false;
  }

  bool ok = true;

  // TIFF header
  if (kBigEndian) { fputc('M', out); fputc('M', out); }
  else            { fputc('I', out); fputc('I', out); }
  ok &= PutShort(42, out);
  ok &= PutLong(8, out);  // offset to IFD

  // IFD
  uint16_t tagCount = 15;
  ok &= PutShort(tagCount, out);

  uint32_t w32 = static_cast<uint32_t>(width);
  uint32_t h32 = static_cast<uint32_t>(height);
  uint16_t bits = static_cast<uint16_t>(depth);

  uint32_t ifdEnd = 8 + 2 + 4 + tagCount * 12;
  uint32_t alignBytes = (4 - (ifdEnd & 0x03)) & 0x03;
  uint32_t startData = ifdEnd + alignBytes;

  uint32_t bitsOff = startData;
  uint32_t xresOff = bitsOff + static_cast<uint32_t>(channels) * 2;
  uint32_t yresOff = xresOff + 8;

  ok &= PutIFDLong(kTIFF_WIDTH, kTIFF_LONG, 1, w32, out);
  ok &= PutIFDLong(kTIFF_HEIGHT, kTIFF_LONG, 1, h32, out);
  if (channels == 1)
    ok &= PutIFDLong(kTIFF_BPS, kTIFF_LONG, 1, bits, out);
  else
    ok &= PutIFDLong(kTIFF_BPS, kTIFF_SHORT, static_cast<uint32_t>(channels), bitsOff, out);
  ok &= PutIFDLong(kTIFF_COMPRESSION, kTIFF_LONG, 1, kTIFF_COMPRESS_NONE, out);

  uint32_t stripOffOff = yresOff + 8;
  uint32_t stripBcOff = stripOffOff + 4;
  uint32_t pixelOff = stripBcOff + 4;

  ok &= PutIFDLong(kTIFF_PHOTOMETRIC, kTIFF_LONG, 1, static_cast<uint32_t>(colorModel), out);
  ok &= PutIFDLong(kTIFF_STRIPOFFSETS, kTIFF_LONG, 1, pixelOff, out);
  ok &= PutIFDLong(kTIFF_SPP, kTIFF_LONG, 1, static_cast<uint32_t>(channels), out);
  ok &= PutIFDLong(kTIFF_ROWSPERSTRIP, kTIFF_LONG, 1, h32, out);

  long bcOffset = ftell(out);
  if (bcOffset < 0) { fclose(out); return false; }
  ok &= PutIFDLong(kTIFF_STRIPBYTECOUNTS, kTIFF_LONG, 1, 0, out);

  uint32_t resDenom = 1000;
  uint32_t resNum = (dpi > 0.0f && std::isfinite(dpi) &&
                     static_cast<double>(dpi) * resDenom <= static_cast<double>(UINT32_MAX))
                    ? static_cast<uint32_t>(dpi * resDenom) : 72000u;

  ok &= PutIFDLong(kTIFF_XRES, kTIFF_RATIO, 1, xresOff, out);
  ok &= PutIFDLong(kTIFF_YRES, kTIFF_RATIO, 1, yresOff, out);
  ok &= PutIFDLong(kTIFF_PLANARCONFIG, kTIFF_LONG, 1, 1, out);
  ok &= PutIFDLong(kTIFF_RESUNIT, kTIFF_LONG, 1, 2, out);
  ok &= PutIFDLong(kTIFF_PREDICTOR, kTIFF_LONG, 1, 1, out);

  if (bits == 32 || bits == 64)
    ok &= PutIFDLong(kTIFF_SAMPLEFORMAT, kTIFF_LONG, 1, kTIFF_FLOAT_S, out);
  else
    ok &= PutIFDLong(kTIFF_SAMPLEFORMAT, kTIFF_LONG, 1, kTIFF_UINT, out);

  ok &= PutLong(0, out);  // next IFD offset

  for (uint32_t i = 0; i < alignBytes; ++i) fputc(0, out);

  // bits per sample array
  for (int i = 0; i < channels; ++i) ok &= PutShort(bits, out);

  // resolution ratios
  ok &= PutLong(resNum, out); ok &= PutLong(resDenom, out);
  ok &= PutLong(resNum, out); ok &= PutLong(resDenom, out);

  // strip offset and byte count placeholders
  ok &= PutLong(0, out);
  ok &= PutLong(0, out);

  if (!ok || ferror(out)) {
    fprintf(stderr, "[LUTViz] I/O error writing TIFF header\n");
    fclose(out);
    return false;
  }

  // Pixel data
  if (colorModel == kTIFF_CIELAB) {
    if (depth == 8) ShiftTIFFLab8(buffer, width * height);
    else if (depth == 16) {
      // Buffer was allocated for 16-bit data — alignment guaranteed by calloc/new
      void *vp = buffer;
      ShiftTIFFLab16(static_cast<uint16_t*>(vp), width * height);
    }
  }

  long stripStart = ftell(out);
  if (stripStart < 0) { fclose(out); return false; }

  size_t pixelBytes = 0;
  if (!SafeMulSz3(width, static_cast<size_t>(channels), static_cast<size_t>(depth / 8), pixelBytes)) {
    fprintf(stderr, "[LUTViz] Pixel data size overflow\n");
    fclose(out);
    return false;
  }
  if (fwrite(buffer, pixelBytes, height, out) != height) {
    fprintf(stderr, "[LUTViz] Failed to write pixel data\n");
    fclose(out);
    return false;
  }

  long stripEnd = ftell(out);
  if (stripEnd < 0) { fclose(out); return false; }

  // Backfill strip byte count
  if (fseek(out, bcOffset, SEEK_SET) != 0) { fclose(out); return false; }
  uint32_t compressed = static_cast<uint32_t>(stripEnd - stripStart);
  ok &= PutIFDLong(kTIFF_STRIPBYTECOUNTS, kTIFF_LONG, 1, compressed, out);

  if (!ok || ferror(out)) {
    fprintf(stderr, "[LUTViz] I/O error writing TIFF data\n");
    fclose(out);
    return false;
  }

  fclose(out);
  return true;
}

// ============================================================================
// Channel name helper
// ============================================================================

static std::string ChannelName(int index, bool isInputSide,
                               icColorSpaceSignature inputSpace,
                               icColorSpaceSignature outputSpace,
                               int inCh, int outCh) {
  const size_t bufSz = 128;
  char buf[bufSz];
  icColorIndexName(buf, bufSz, isInputSide ? inputSpace : outputSpace,
                   index, isInputSide ? inCh : outCh,
                   isInputSide ? "In" : "Out");
  return std::string(buf);
}

// ============================================================================
// 3D LUT → TIFF export
// ============================================================================

static void Output3DLUT(CIccProfile *pIcc, CIccTag *tag,
                        const std::string &sigDesc,
                        const std::string &basename,
                        SVGWriter &svg, int verbosity) {
  (void)verbosity;
  icTagTypeSignature typeSig = tag->GetType();

  switch (typeSig) {
    case icSigLut8Type:
    case icSigLut16Type:
    case icSigLutAtoBType:
    case icSigLutBtoAType: {
      CIccMBB *lut = dynamic_cast<CIccMBB*>(tag);
      if (!lut) break;

      int inCh = lut->InputChannels();
      int outCh = lut->OutputChannels();
      icColorSpaceSignature inSpace = lut->GetCsInput();
      icColorSpaceSignature outSpace = lut->GetCsOutput();
      bool isInputMatrix = lut->IsInputMatrix();
      std::string curveDesc = sigDesc + ": ";

      // Output sub-curves to SVG
      CIccCurve **curveA = lut->GetCurvesA();
      CIccCurve **curveB = lut->GetCurvesB();
      CIccCurve **curveM = lut->GetCurvesM();

      if (curveA) {
        int n = isInputMatrix ? outCh : inCh;
        for (int i = 0; i < n; ++i) {
          if (curveA[i]) {
            std::string ch = ChannelName(i, !isInputMatrix, inSpace, outSpace, inCh, outCh);
            Output1DLUT(pIcc, curveA[i], curveDesc + "curveA[ " + ch + " ]", svg, verbosity);
          }
        }
      }
      if (curveB) {
        int n = isInputMatrix ? inCh : outCh;
        for (int i = 0; i < n; ++i) {
          if (curveB[i]) {
            std::string ch = ChannelName(i, isInputMatrix, inSpace, outSpace, inCh, outCh);
            Output1DLUT(pIcc, curveB[i], curveDesc + "curveB[ " + ch + " ]", svg, verbosity);
          }
        }
      }
      if (curveM) {
        int n = isInputMatrix ? inCh : outCh;
        for (int i = 0; i < n; ++i) {
          if (curveM[i]) {
            std::string ch = ChannelName(i, isInputMatrix, inSpace, outSpace, inCh, outCh);
            Output1DLUT(pIcc, curveM[i], curveDesc + "curveM[ " + ch + " ]", svg, verbosity);
          }
        }
      }

      // Extract CLUT → TIFF
      int bytes = lut->GetPrecision();
      CIccCLUT *clut = lut->GetCLUT();
      if (!clut) {
        printf("  [LUTViz] No CLUT data in %s\n", sigDesc.c_str());
        break;
      }

      clut->Begin();

      int tiles = clut->GridPoints();
      int tileW = 1, tileH = 1;
      if (inCh >= 2) tileW = clut->GridPoint(1);
      if (inCh >= 3) tileH = clut->GridPoint(2);
      if (inCh > 3) {
        for (int i = 3; i < inCh; ++i)
          tiles *= clut->GridPoint(i);
      }
      if (inCh == 1) { tileW = tiles; tiles = 1; tileH = 1; }

      if (tiles <= 0 || tileW <= 0 || tileH <= 0 || outCh <= 0 || bytes <= 0) {
        fprintf(stderr, "[LUTViz] Invalid LUT dimensions for TIFF export\n");
        break;
      }

      const size_t tileCount = static_cast<size_t>(tiles);
      const size_t tileWCount = static_cast<size_t>(tileW);
      const size_t tileHCount = static_cast<size_t>(tileH);
      const size_t outStride = static_cast<size_t>(outCh);

      size_t clutSize = 0;
      if (!SafeMulSz4(tileCount, tileWCount, tileHCount, outStride, clutSize)) {
        fprintf(stderr, "[LUTViz] CLUT size overflow\n");
        break;
      }

      double sqrtTiles = sqrt(static_cast<double>(tileCount));
      size_t tilesWide = (std::isfinite(sqrtTiles) && sqrtTiles > 0.0)
                         ? static_cast<size_t>(ceil(sqrtTiles)) : 1u;
      if (tilesWide == 0) tilesWide = 1;
      size_t tilesHigh = (tileCount + (tilesWide - 1)) / tilesWide;

      size_t imgW = 0;
      size_t imgH = 0;
      if (!SafeMulSz(tilesWide, tileWCount, imgW) ||
          !SafeMulSz(tilesHigh, tileHCount, imgH)) {
        fprintf(stderr, "[LUTViz] Image dimension overflow\n");
        break;
      }

      size_t bufSize = 0;
      if (!SafeMulSz4(imgW, imgH, outStride, static_cast<size_t>(bytes), bufSize)) {
        fprintf(stderr, "[LUTViz] Buffer size overflow\n");
        break;
      }

      size_t availableClutElems = 0;
      if (!SafeMulSz(clut->NumPoints(), outStride, availableClutElems) ||
          clutSize > availableClutElems) {
        fprintf(stderr, "[LUTViz] CLUT data exceeds available data\n");
        break;
      }

      // Allocate with alignment for float access (4-byte aligned)
      void *rawBuf = calloc(bufSize, 1);
      if (!rawBuf) {
        fprintf(stderr, "[LUTViz] Failed to allocate %zu bytes for TIFF buffer\n", bufSize);
        break;
      }
      std::unique_ptr<void, decltype(&free)> imgBuf(rawBuf, &free);

      uint8_t *buf8 = static_cast<uint8_t*>(rawBuf);
      uint16_t *buf16 = static_cast<uint16_t*>(rawBuf);
      float *buf32 = static_cast<float*>(rawBuf);

      icFloatNumber *clutData = clut->GetData(0);
      if (!clutData) {
        fprintf(stderr, "[LUTViz] CLUT data is null\n");
        break;
      }

      // Copy CLUT → tiled image buffer
      size_t n001 = tileWCount * tileHCount * outStride;
      size_t n010 = tileWCount * outStride;
      size_t n100 = outStride;
      size_t outTileV = imgW * tileHCount * outStride;
      size_t outTileH = tileWCount * outStride;
      size_t outRow = imgW * outStride;
      size_t imgSamples = bufSize / static_cast<size_t>(bytes);
      bool copyOk = (clutSize >= outStride && imgSamples >= outStride);

      if (!copyOk) {
        fprintf(stderr, "[LUTViz] CLUT/image buffers too small for output stride\n");
        break;
      }

      for (size_t x = 0; x < tileWCount && copyOk; ++x)
        for (size_t y = 0; y < tileHCount && copyOk; ++y)
          for (size_t z = 0; z < tileCount; ++z) {
            size_t inIdx = z * n001 + y * n010 + x * n100;
            size_t z2 = z % tilesWide;
            size_t z3 = z / tilesWide;
            size_t outIdx = z3 * outTileV + z2 * outTileH + y * outRow + x * outStride;

            if (inIdx > clutSize - outStride || outIdx > imgSamples - outStride) {
              fprintf(stderr, "[LUTViz] CLUT tiling index exceeded buffer bounds\n");
              copyOk = false;
              break;
            }

            const icFloatNumber *src = clutData + inIdx;
            if (bytes == 4 || bytes == 8) {
              float *dst32 = buf32 + outIdx;
              for (size_t c = 0; c < outStride; ++c)
                dst32[c] = src[c];
            } else if (bytes == 2) {
              uint16_t *dst16 = buf16 + outIdx;
              for (size_t c = 0; c < outStride; ++c) {
                float v = src[c];
                if (!std::isfinite(v)) v = 0.0f;
                else if (v < 0.0f) v = 0.0f;
                else if (v > 1.0f) v = 1.0f;
                dst16[c] = static_cast<uint16_t>(v * 65535.0f);
              }
            } else {
              uint8_t *dst8 = buf8 + outIdx;
              for (size_t c = 0; c < outStride; ++c) {
                float v = src[c];
                if (!std::isfinite(v)) v = 0.0f;
                else if (v < 0.0f) v = 0.0f;
                else if (v > 1.0f) v = 1.0f;
                dst8[c] = static_cast<uint8_t>(v * 255.0f);
              }
            }
          }

      if (!copyOk) {
        break;
      }

      std::string tiffPath = basename + "_" + sigDesc + ".tif";
      int tiffColor = TIFFColorModelFromICC(outSpace);
      if (!WriteTIFF(tiffPath.c_str(), 100.0f, tiffColor, buf8,
                     imgW, imgH,
                     outCh, 8 * bytes)) {
        fprintf(stderr, "[LUTViz] Failed to write TIFF: %s\n", tiffPath.c_str());
      } else {
        printf("  [LUTViz] Wrote 3D CLUT TIFF: %s (%zux%zu, %d ch, %d-bit)\n",
               tiffPath.c_str(), imgW, imgH, outCh, 8 * bytes);
      }
      break;
    }
    default: {
      const size_t bs = 64;
      char b[bs];
      printf("  [LUTViz] Unknown nD LUT type %s for tag %s\n",
             icGetSig(b, bs, typeSig), sigDesc.c_str());
      break;
    }
  }
}

// ============================================================================
// Remove file extension
// ============================================================================

static std::string RemoveExtension(const std::string &path) {
  size_t dot = path.find_last_of(".");
  if (dot == std::string::npos || dot == 0) return path;
  return path.substr(0, dot);
}

// ============================================================================
// processLuts orchestrator
// ============================================================================

static void ProcessLutsInternal(CIccProfile *pIcc, const std::string &basename) {
  const size_t bufSz = 64;
  char buf[bufSz];

  std::string svgPath = basename + "_luts.svg";
  SVGWriter svg;
  if (!svg.Open(svgPath)) {
    fprintf(stderr, "[LUTViz] Failed to create SVG: %s\n", svgPath.c_str());
    return;
  }
  svg.WriteHeader(Point2D(0, 0), Point2D(8.0f * kInch2mm, 8.0f * kInch2mm));

  int curveCount = 0;
  int clutCount = 0;

  for (auto &tag : pIcc->m_Tags) {
    icTagSignature sig = tag.TagInfo.sig;

    switch (sig) {
      // 1D LUTs (TRC tags)
      case icSigRedTRCTag:
      case icSigGreenTRCTag:
      case icSigBlueTRCTag:
      case icSigGrayTRCTag: {
        const char *sigDesc = icGetSigStr(buf, bufSz, sig);
        CIccTag *pTag = pIcc->FindTag(tag);
        if (pTag) {
          Output1DLUT(pIcc, pTag, sigDesc, svg, 100);
          curveCount++;
        }
        break;
      }

      // nD LUTs (AToB, BToA, Gamut, Preview)
      case icSigAToB0Tag: case icSigAToB1Tag:
      case icSigAToB2Tag: case icSigAToB3Tag:
      case icSigBToA0Tag: case icSigBToA1Tag:
      case icSigBToA2Tag: case icSigBToA3Tag:
      case icSigGamutTag:
      case icSigPreview0Tag: case icSigPreview1Tag: case icSigPreview2Tag: {
        std::string sigDesc = icGetSigStr(buf, bufSz, sig);
        CIccTag *pTag = pIcc->FindTag(tag);
        if (pTag) {
          Output3DLUT(pIcc, pTag, sigDesc, basename, svg, 100);
          clutCount++;
        }
        break;
      }

      default:
        break;
    }
  }

  svg.Close();
  printf("\n[LUTViz] SVG written: %s (%d curves)\n", svgPath.c_str(), curveCount);
  if (clutCount > 0)
    printf("[LUTViz] %d CLUT TIFF file(s) written with base: %s\n", clutCount, basename.c_str());
  if (curveCount == 0 && clutCount == 0)
    printf("[LUTViz] No LUT tags found in profile\n");
}

// ============================================================================
// Public API: ProcessLutVisualization
// ============================================================================

int ProcessLutVisualization(const char *profilePath, const char *outputBase) {
  if (!profilePath) {
    fprintf(stderr, "[LUTViz] No profile path provided\n");
    return 2;
  }

  CIccProfile *pIcc = OpenIccProfile(profilePath);
  if (!pIcc) {
    fprintf(stderr, "[LUTViz] Unable to parse '%s' as ICC profile\n", profilePath);
    return 2;
  }

  printf("\n=======================================================================\n");
  printf("LUT VISUALIZATION\n");
  printf("=======================================================================\n\n");
  printf("Profile: %s\n", profilePath);

  std::string basename;
  if (outputBase)
    basename = outputBase;
  else
    basename = RemoveExtension(std::string(profilePath));

  // DumpV5Summary first
  DumpV5Summary(pIcc);

  // Process LUTs
  ProcessLutsInternal(pIcc, basename);

  delete pIcc;
  return 0;
}

// ============================================================================
// DumpV5Summary — v5/iccMAX spectral, BRDF, MPE summary
// ============================================================================

void DumpV5Summary(CIccProfile *pIcc) {
  if (!pIcc) return;
  icHeader *pHdr = &pIcc->m_Header;
  if (pHdr->version < icVersionNumberV5) return;

  printf("\nv5/iccMAX Extended Summary\n");
  printf("-------------------------\n");

  // Spectral tags
  const icTagSignature spectralTags[] = {
    icSigSpectralViewingConditionsTag,
    icSigSpectralDataInfoTag,
    icSigSpectralWhitePointTag,
    icSigCustomToStandardPccTag,
    icSigStandardToCustomPccTag,
  };
  const char *spectralNames[] = {
    "svcn (SpectralViewingConditions)",
    "sdin (SpectralDataInfo)",
    "swpt (SpectralWhitePoint)",
    "c2sp (CustomToStandardPCC)",
    "s2cp (StandardToCustomPCC)",
  };
  int nSpectral = 0;
  for (int i = 0; i < 5; i++) {
    CIccTag *pTag = pIcc->FindTag(spectralTags[i]);
    if (pTag) {
      printf("  [v5] %s — present\n", spectralNames[i]);
      nSpectral++;
    }
  }
  if (nSpectral == 0)
    printf("  [v5] No spectral tags found\n");

  // Count MPE tags
  int nMPE = 0;
  int totalElements = 0;
  for (auto &tag : pIcc->m_Tags) {
    CIccTag *pTag = pIcc->FindTag(tag);
    if (pTag && pTag->GetType() == icSigMultiProcessElementType) {
      nMPE++;
      CIccTagMultiProcessElement *mpe = dynamic_cast<CIccTagMultiProcessElement*>(pTag);
      if (mpe)
        totalElements += static_cast<int>(mpe->NumElements());
    }
  }
  if (nMPE > 0)
    printf("  [v5] MPE tags: %d (total elements: %d)\n", nMPE, totalElements);

  printf("\n");
}

// ============================================================================
// DumpMPEChain — visualize MPE element chain for a tag
// ============================================================================

void DumpMPEChain(CIccTag *pTag, icTagSignature sig) {
  if (!pTag || pTag->GetType() != icSigMultiProcessElementType) return;

  CIccTagMultiProcessElement *mpe = dynamic_cast<CIccTagMultiProcessElement*>(pTag);
  if (!mpe) return;

  const size_t bufSz = 64;
  char buf[bufSz];

  printf("  MPE Chain: %u input → %u output channels\n",
         mpe->NumInputChannels(), mpe->NumOutputChannels());

  icUInt32Number nElem = mpe->NumElements();
  for (icUInt32Number idx = 0; idx < nElem; idx++) {
    CIccMultiProcessElement *elem = mpe->GetElement(static_cast<int>(idx));
    if (elem) {
      icElemTypeSignature elemSig = elem->GetType();
      const char *lateBinding = "";
      // Check for late-binding spectral elements
      if (elemSig == icSigEmissionMatrixElemType ||
          elemSig == icSigInvEmissionMatrixElemType ||
          elemSig == icSigEmissionObserverElemType ||
          elemSig == icSigReflectanceObserverElemType) {
        lateBinding = " [LATE-BINDING SPECTRAL]";
      }
      printf("    [%u] %s: %u→%u channels%s\n",
             idx,
             icGetSig(buf, bufSz, static_cast<icUInt32Number>(elemSig)),
             elem->NumInputChannels(),
             elem->NumOutputChannels(),
             lateBinding);
    }
  }
}

// ============================================================================
// DumpTagDetail — dump a single tag with type info, MPE chain, and Describe
// ============================================================================

void DumpTagDetail(CIccProfile *pIcc, icTagSignature sig, int verbosity) {
  if (!pIcc) return;

  const size_t bufSz = 64;
  char buf[bufSz];
  CIccInfo Fmt;

  CIccTag *pTag = pIcc->FindTag(sig);
  if (!pTag) {
    printf("Tag (%s) not found in profile\n", icGetSig(buf, bufSz, sig));
    return;
  }

  printf("\nContents of %s tag (%s)\n",
         Fmt.GetTagSigName(sig), icGetSig(buf, bufSz, sig));
  printf("Type: ");
  if (pTag->IsArrayType()) printf("Array of ");
  printf("%s (%s)\n",
         Fmt.GetTagTypeSigName(pTag->GetType()),
         icGetSig(buf, bufSz, pTag->GetType()));

  // MPE chain visualization
  DumpMPEChain(pTag, sig);

  // Tag content via Describe
  std::string contents;
  pTag->Describe(contents, verbosity);
  if (!contents.empty()) {
    if (fwrite(contents.c_str(), contents.length(), 1, stdout) != 1) {
      fprintf(stderr, "Warning: failed to write tag contents to stdout\n");
    }
  }
}

// ============================================================================
// DumpAllAnalysis — full profile dump (header, tags, v5 summary)
// ============================================================================

int DumpAllAnalysis(const char *profilePath, int verbosity) {
  if (!profilePath) return 2;

  CIccProfile *pIcc = OpenIccProfile(profilePath);
  if (!pIcc) {
    fprintf(stderr, "[DumpAll] Unable to parse '%s' as ICC profile\n", profilePath);
    return 2;
  }

  CIccInfo Fmt;
  icHeader *pHdr = &pIcc->m_Header;
  const size_t bufSz = 64;
  char buf[bufSz];

  printf("\n=======================================================================\n");
  printf("ICC PROFILE DUMP (DumpAll)\n");
  printf("=======================================================================\n\n");

  printf("Profile:         '%s'\n", profilePath);
  if (Fmt.IsProfileIDCalculated(&pHdr->profileID))
    printf("Profile ID:      %s\n", Fmt.GetProfileID(&pHdr->profileID));
  else
    printf("Profile ID:      Not calculated\n");
  printf("Size:            %u (0x%x) bytes\n", pHdr->size, pHdr->size);

  printf("\nHeader\n------\n");
  printf("Attributes:      %s\n", Fmt.GetDeviceAttrName(pHdr->attributes));
  printf("Cmm:             %s\n", Fmt.GetCmmSigName(static_cast<icCmmSignature>(pHdr->cmmId)));
  printf("Creation Date:   %d/%d/%d %02u:%02u:%02u\n",
         pHdr->date.month, pHdr->date.day, pHdr->date.year,
         pHdr->date.hours, pHdr->date.minutes, pHdr->date.seconds);
  printf("Creator:         %s\n", icGetSig(buf, bufSz, pHdr->creator));
  printf("Device Mfg:      %s\n", icGetSig(buf, bufSz, pHdr->manufacturer));
  printf("Device Model:    %s\n", icGetSig(buf, bufSz, pHdr->model));
  printf("Flags:           %s\n", Fmt.GetProfileFlagsName(pHdr->flags));
  printf("PCS Illuminant:  X=%.4f, Y=%.4f, Z=%.4f\n",
         icFtoD(pHdr->illuminant.X),
         icFtoD(pHdr->illuminant.Y),
         icFtoD(pHdr->illuminant.Z));
  printf("Platform:        %s\n", Fmt.GetPlatformSigName(pHdr->platform));
  printf("Rendering Intent:%s\n", Fmt.GetRenderingIntentName(
         static_cast<icRenderingIntent>(pHdr->renderingIntent)));
  printf("Profile Class:   %s\n", Fmt.GetProfileClassSigName(pHdr->deviceClass));
  printf("Color Space:     %s\n", Fmt.GetColorSpaceSigName(pHdr->colorSpace));
  printf("PCS:             %s\n", Fmt.GetColorSpaceSigName(pHdr->pcs));
  printf("Version:         %s\n", Fmt.GetVersionName(pHdr->version));
  printf("SubClass:        %s\n", Fmt.GetSubClassVersionName(pHdr->deviceSubClass));

  // Tag table
  printf("\nProfile Tags (%d)\n", static_cast<int>(pIcc->m_Tags.size()));
  printf("%-30s %-8s %8s %8s\n", "Tag", "ID", "Offset", "Size");
  for (auto &tag : pIcc->m_Tags) {
    printf("%-30s %-8s %8u %8u\n",
           Fmt.GetTagSigName(tag.TagInfo.sig),
           icGetSig(buf, bufSz, tag.TagInfo.sig),
           tag.TagInfo.offset,
           tag.TagInfo.size);
  }

  // Duplicate detection
  std::unordered_map<uint32_t, int> tagLookup;
  int tagIdx = 0;
  for (auto &tag : pIcc->m_Tags) {
    auto it = tagLookup.find(static_cast<uint32_t>(tag.TagInfo.sig));
    if (it != tagLookup.end()) {
      printf("  [WARN] Duplicate tag %s at position %d (first at %d)\n",
             icGetSig(buf, bufSz, tag.TagInfo.sig), tagIdx, it->second);
    } else {
      tagLookup[static_cast<uint32_t>(tag.TagInfo.sig)] = tagIdx;
    }
    tagIdx++;
  }

  // v5 summary
  DumpV5Summary(pIcc);

  // Dump all tag details
  printf("\n=== Tag Details ===\n");
  for (auto &tag : pIcc->m_Tags) {
    DumpTagDetail(pIcc, tag.TagInfo.sig, verbosity);
  }

  delete pIcc;
  printf("\n");
  return 0;
}
