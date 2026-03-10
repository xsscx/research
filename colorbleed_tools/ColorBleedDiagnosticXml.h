/*!
 *  @file ColorBleedDiagnosticXml.h
 *  @brief Diagnostic XML generation for malformed ICC profiles
 *  @author David Hoyt
 *  @date 10 MAR 2026
 *  @version 1.0.0
 *
 *  When the iccDEV library cannot Read() a malformed ICC profile,
 *  this module generates a diagnostic XML representation from
 *  raw binary analysis. This gives analysts structured output
 *  for ANY ICC blob — even totally malformed ones that crash
 *  the library's parser.
 *
 *  Modeled on iccanalyzer-lite's defensive handling: never trust
 *  file-controlled values as buffer sizes, validate all offsets
 *  against actual file size, cap iteration counts.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#ifndef COLORBLEED_DIAGNOSTIC_XML_H
#define COLORBLEED_DIAGNOSTIC_XML_H

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// Known ICC profile class codes
static const char* ClassNameFromSig(uint32_t sig) {
  switch (sig) {
    case 0x73636E72: return "scnr (Input)";
    case 0x6D6E7472: return "mntr (Display)";
    case 0x70727472: return "prtr (Output)";
    case 0x6C696E6B: return "link (DeviceLink)";
    case 0x73706163: return "spac (ColorSpace)";
    case 0x61627374: return "abst (Abstract)";
    case 0x6E6D636C: return "nmcl (NamedColor)";
    default:         return "unknown";
  }
}

// Known ICC tag type names
static const char* TypeNameFromSig(uint32_t sig) {
  switch (sig) {
    case 0x64657363: return "descType";
    case 0x74657874: return "textType";
    case 0x58595A20: return "XYZType";
    case 0x63757276: return "curveType";
    case 0x6D414220: return "lutAtoBType";
    case 0x6D424120: return "lutBtoAType";
    case 0x6D667431: return "lut8Type";
    case 0x6D667432: return "lut16Type";
    case 0x70617261: return "parametricCurveType";
    case 0x73663332: return "s15Fixed16ArrayType";
    case 0x6D6C7563: return "multiLocalizedUnicodeType";
    case 0x636C7274: return "colorantTableType";
    case 0x74617279: return "tagArrayType";
    case 0x73696720: return "signatureType";
    case 0x64617461: return "dataType";
    case 0x75693136: return "uInt16ArrayType";
    case 0x75693332: return "uInt32ArrayType";
    case 0x6D706574: return "multiProcessElementType";
    default:         return nullptr;
  }
}

// Sanitize a 4-byte ICC signature for safe XML display
static inline void DiagSanitizeSig(const uint8_t* raw, char out[5]) {
  for (int i = 0; i < 4; i++) {
    uint8_t c = raw[i];
    out[i] = (c >= 0x20 && c <= 0x7E) ? static_cast<char>(c) : '?';
  }
  out[4] = '\0';
}

static inline uint32_t DiagReadBE32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8)  |  (uint32_t)p[3];
}

static inline uint16_t DiagReadBE16(const uint8_t* p) {
  return ((uint16_t)p[0] << 8) | (uint16_t)p[1];
}

static inline int32_t DiagReadBE32S(const uint8_t* p) {
  return static_cast<int32_t>(DiagReadBE32(p));
}

// Hex dump helper — up to maxBytes, returns hex string
static std::string HexDump(const uint8_t* data, size_t len, size_t maxBytes = 64) {
  std::string result;
  size_t limit = (len < maxBytes) ? len : maxBytes;
  result.reserve(limit * 3);
  for (size_t i = 0; i < limit; i++) {
    char hex[4];
    snprintf(hex, sizeof(hex), "%02X", data[i]);
    if (i > 0) result += ' ';
    result += hex;
  }
  if (len > maxBytes) {
    result += " ...";
  }
  return result;
}

// XML-escape a string for safe embedding in XML content
static std::string XmlEscape(const char* s) {
  std::string out;
  for (; *s; s++) {
    switch (*s) {
      case '&':  out += "&amp;"; break;
      case '<':  out += "&lt;"; break;
      case '>':  out += "&gt;"; break;
      case '"':  out += "&quot;"; break;
      case '\'': out += "&apos;"; break;
      default:
        if (static_cast<unsigned char>(*s) >= 0x20 || *s == '\n' || *s == '\t')
          out += *s;
        else {
          char esc[8];
          snprintf(esc, sizeof(esc), "&#x%02X;", static_cast<unsigned char>(*s));
          out += esc;
        }
    }
  }
  return out;
}

/// Generate a diagnostic XML representation of a malformed ICC profile.
/// Reads raw binary data — no iccDEV library calls.
/// Returns true if XML was generated successfully.
static bool GenerateDiagnosticXml(const char* icc_path,
                                   std::string& xml_out,
                                   const char* failure_reason = nullptr) {
  xml_out.clear();

  int fd = open(icc_path, O_RDONLY);
  if (fd < 0) return false;

  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
    close(fd);
    return false;
  }
  size_t fileSize = static_cast<size_t>(st.st_size);

  if (fileSize < 132) {
    close(fd);
    // Still generate minimal diagnostic
    xml_out += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
    xml_out += "<!-- ColorBleed Diagnostic XML: file too small for ICC header -->\n";
    xml_out += "<IccProfileDiagnostic>\n";
    xml_out += "  <Status>MALFORMED</Status>\n";
    char buf[128];
    snprintf(buf, sizeof(buf), "  <FileSize>%zu</FileSize>\n", fileSize);
    xml_out += buf;
    xml_out += "  <Error>File smaller than minimum ICC header (132 bytes)</Error>\n";
    xml_out += "</IccProfileDiagnostic>\n";
    return true;
  }

  // Read header + tag count (132 bytes minimum)
  uint8_t hdr[132];
  FILE* fp = fdopen(fd, "rb");
  if (!fp) { close(fd); return false; }

  if (fread(hdr, 1, 132, fp) != 132) {
    fclose(fp);
    return false;
  }

  // Parse header fields
  uint32_t profileSize = DiagReadBE32(hdr + 0);
  uint32_t cmmType     = DiagReadBE32(hdr + 4);
  uint32_t version     = DiagReadBE32(hdr + 8);
  uint32_t devClass    = DiagReadBE32(hdr + 12);
  uint32_t colorSpace  = DiagReadBE32(hdr + 16);
  uint32_t pcs         = DiagReadBE32(hdr + 20);
  uint16_t year        = DiagReadBE16(hdr + 24);
  uint16_t month       = DiagReadBE16(hdr + 26);
  uint16_t day         = DiagReadBE16(hdr + 28);
  uint16_t hour        = DiagReadBE16(hdr + 30);
  uint16_t minute      = DiagReadBE16(hdr + 32);
  uint16_t second      = DiagReadBE16(hdr + 34);
  // magic at 36-39
  uint32_t platform    = DiagReadBE32(hdr + 40);
  uint32_t flags       = DiagReadBE32(hdr + 44);
  uint32_t manufacturer = DiagReadBE32(hdr + 48);
  uint32_t model       = DiagReadBE32(hdr + 52);
  uint32_t intent      = DiagReadBE32(hdr + 64);
  int32_t  illumX      = DiagReadBE32S(hdr + 68);
  int32_t  illumY      = DiagReadBE32S(hdr + 72);
  int32_t  illumZ      = DiagReadBE32S(hdr + 76);
  uint32_t creator     = DiagReadBE32(hdr + 80);
  uint32_t tagCount    = DiagReadBE32(hdr + 128);

  // Signature display helpers
  auto sigStr = [](uint32_t sig) -> std::string {
    char s[5];
    uint8_t raw[4] = {
      static_cast<uint8_t>((sig >> 24) & 0xFF),
      static_cast<uint8_t>((sig >> 16) & 0xFF),
      static_cast<uint8_t>((sig >> 8) & 0xFF),
      static_cast<uint8_t>(sig & 0xFF)
    };
    DiagSanitizeSig(raw, s);
    return std::string(s);
  };

  // ── Generate XML ──
  xml_out.reserve(32768);
  xml_out += "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  xml_out += "<!-- ColorBleed Diagnostic XML -->\n";
  xml_out += "<!-- Generated from raw binary analysis (library Read() failed) -->\n";
  if (failure_reason) {
    xml_out += "<!-- Failure: ";
    xml_out += XmlEscape(failure_reason);
    xml_out += " -->\n";
  }
  xml_out += "<!-- WARNING: This profile is MALFORMED — data may be incomplete or corrupt -->\n";
  xml_out += "<IccProfileDiagnostic>\n";
  xml_out += "  <Status>MALFORMED</Status>\n";

  // File metadata
  char buf[512];
  snprintf(buf, sizeof(buf), "  <FileSize>%zu</FileSize>\n", fileSize);
  xml_out += buf;

  // Header section
  xml_out += "  <Header>\n";
  snprintf(buf, sizeof(buf), "    <ProfileSize declared=\"%u\" actual=\"%zu\"%s/>\n",
           profileSize, fileSize,
           (profileSize != fileSize) ? " mismatch=\"true\"" : "");
  xml_out += buf;

  snprintf(buf, sizeof(buf), "    <CMMType>%s</CMMType>\n", sigStr(cmmType).c_str());
  xml_out += buf;

  uint8_t majorVer = (version >> 24) & 0xFF;
  uint8_t minorVer = ((version >> 20) & 0xF);
  uint8_t bugfixVer = ((version >> 16) & 0xF);
  snprintf(buf, sizeof(buf), "    <Version>%u.%u.%u (0x%08X)</Version>\n",
           majorVer, minorVer, bugfixVer, version);
  xml_out += buf;

  snprintf(buf, sizeof(buf), "    <DeviceClass sig=\"%s\">%s</DeviceClass>\n",
           sigStr(devClass).c_str(), ClassNameFromSig(devClass));
  xml_out += buf;

  snprintf(buf, sizeof(buf), "    <ColorSpace>%s</ColorSpace>\n", sigStr(colorSpace).c_str());
  xml_out += buf;

  snprintf(buf, sizeof(buf), "    <PCS>%s</PCS>\n", sigStr(pcs).c_str());
  xml_out += buf;

  snprintf(buf, sizeof(buf), "    <DateTime>%04u-%02u-%02uT%02u:%02u:%02u</DateTime>\n",
           year, month, day, hour, minute, second);
  xml_out += buf;

  bool validMagic = (memcmp(hdr + 36, "acsp", 4) == 0);
  snprintf(buf, sizeof(buf), "    <Magic valid=\"%s\">0x%02X%02X%02X%02X</Magic>\n",
           validMagic ? "true" : "false", hdr[36], hdr[37], hdr[38], hdr[39]);
  xml_out += buf;

  snprintf(buf, sizeof(buf), "    <Platform>%s</Platform>\n", sigStr(platform).c_str());
  xml_out += buf;

  snprintf(buf, sizeof(buf), "    <Flags>0x%08X</Flags>\n", flags);
  xml_out += buf;

  snprintf(buf, sizeof(buf), "    <Manufacturer>%s</Manufacturer>\n", sigStr(manufacturer).c_str());
  xml_out += buf;

  snprintf(buf, sizeof(buf), "    <Model>%s (0x%08X)</Model>\n", sigStr(model).c_str(), model);
  xml_out += buf;

  snprintf(buf, sizeof(buf), "    <RenderingIntent>%u</RenderingIntent>\n", intent);
  xml_out += buf;

  snprintf(buf, sizeof(buf), "    <Illuminant X=\"%.4f\" Y=\"%.4f\" Z=\"%.4f\"/>\n",
           illumX / 65536.0, illumY / 65536.0, illumZ / 65536.0);
  xml_out += buf;

  snprintf(buf, sizeof(buf), "    <Creator>%s</Creator>\n", sigStr(creator).c_str());
  xml_out += buf;

  // Profile ID (MD5, bytes 84-99)
  xml_out += "    <ProfileID>";
  for (int i = 84; i < 100; i++) {
    char h[3];
    snprintf(h, sizeof(h), "%02X", hdr[i]);
    xml_out += h;
  }
  xml_out += "</ProfileID>\n";

  // Header hex dump
  xml_out += "    <RawHeaderHex>";
  xml_out += HexDump(hdr, 128, 128);
  xml_out += "</RawHeaderHex>\n";

  xml_out += "  </Header>\n";

  // Tag table section
  snprintf(buf, sizeof(buf), "  <TagTable count=\"%u\">\n", tagCount);
  xml_out += buf;

  // Cap iteration to prevent DoS
  uint32_t safeTagCount = (tagCount > 256) ? 256 : tagCount;
  size_t tagTableSize = static_cast<size_t>(safeTagCount) * 12;

  if (tagTableSize > 0 && 132 + tagTableSize <= fileSize) {
    std::vector<uint8_t> tagData(tagTableSize);
    fseek(fp, 132, SEEK_SET);
    if (fread(tagData.data(), 1, tagTableSize, fp) == tagTableSize) {
      for (uint32_t i = 0; i < safeTagCount; i++) {
        const uint8_t* e = tagData.data() + i * 12;
        uint32_t tSig    = DiagReadBE32(e + 0);
        uint32_t tOffset = DiagReadBE32(e + 4);
        uint32_t tSize   = DiagReadBE32(e + 8);

        std::string tagSig = sigStr(tSig);

        snprintf(buf, sizeof(buf),
                 "    <Tag index=\"%u\" sig=\"%s\" offset=\"%u\" size=\"%u\"",
                 i, tagSig.c_str(), tOffset, tSize);
        xml_out += buf;

        // Validate offset+size against file
        bool oob = false;
        if (tOffset > fileSize || tSize > fileSize ||
            static_cast<uint64_t>(tOffset) + tSize > fileSize) {
          xml_out += " outOfBounds=\"true\"";
          oob = true;
        }

        // Read tag type signature and hex preview
        if (!oob && tOffset >= 128 && tSize >= 4) {
          uint8_t tagHdr[4];
          fseek(fp, tOffset, SEEK_SET);
          if (fread(tagHdr, 1, 4, fp) == 4) {
            uint32_t typeSig = DiagReadBE32(tagHdr);
            std::string typeStr = sigStr(typeSig);
            const char* typeName = TypeNameFromSig(typeSig);

            snprintf(buf, sizeof(buf), " typeSig=\"%s\"", typeStr.c_str());
            xml_out += buf;
            if (typeName) {
              snprintf(buf, sizeof(buf), " typeName=\"%s\"", typeName);
              xml_out += buf;
            }
          }
        }

        xml_out += ">\n";

        // Hex preview of tag data (up to 128 bytes)
        if (!oob && tOffset >= 128 && tSize > 0) {
          size_t previewLen = (tSize < 128) ? tSize : 128;
          std::vector<uint8_t> preview(previewLen);
          fseek(fp, tOffset, SEEK_SET);
          size_t got = fread(preview.data(), 1, previewLen, fp);
          if (got > 0) {
            xml_out += "      <HexPreview>";
            xml_out += HexDump(preview.data(), got, 128);
            xml_out += "</HexPreview>\n";
          }

          // For small tags, attempt ASCII interpretation
          if (tSize <= 256 && got >= 8) {
            bool hasAscii = false;
            size_t asciiStart = 8; // skip type sig + reserved
            if (asciiStart < got) {
              std::string ascii;
              for (size_t j = asciiStart; j < got; j++) {
                uint8_t c = preview[j];
                if (c >= 0x20 && c <= 0x7E) {
                  ascii += static_cast<char>(c);
                  hasAscii = true;
                } else if (c == 0) {
                  break; // null terminator
                } else {
                  ascii += '.';
                }
              }
              if (hasAscii && ascii.size() >= 3) {
                xml_out += "      <AsciiPreview>";
                xml_out += XmlEscape(ascii.c_str());
                xml_out += "</AsciiPreview>\n";
              }
            }
          }
        }

        xml_out += "    </Tag>\n";
      }
    }
  } else if (tagCount > 0) {
    snprintf(buf, sizeof(buf),
             "    <!-- Tag table extends beyond file: need %zu bytes at offset 132, file is %zu bytes -->\n",
             tagTableSize, fileSize);
    xml_out += buf;
  }

  xml_out += "  </TagTable>\n";

  // Anomalies section — document what makes this profile suspicious
  xml_out += "  <Anomalies>\n";

  if (!validMagic) {
    xml_out += "    <Anomaly severity=\"CRITICAL\">Invalid magic bytes (expected 'acsp')</Anomaly>\n";
  }
  if (profileSize != fileSize) {
    snprintf(buf, sizeof(buf),
             "    <Anomaly severity=\"WARNING\">Size mismatch: header=%u file=%zu</Anomaly>\n",
             profileSize, fileSize);
    xml_out += buf;
  }
  if (illumX < 0 || illumY < 0 || illumZ < 0) {
    xml_out += "    <Anomaly severity=\"WARNING\">Negative illuminant XYZ values</Anomaly>\n";
  }
  if (intent > 3) {
    snprintf(buf, sizeof(buf),
             "    <Anomaly severity=\"WARNING\">Rendering intent %u out of range (0-3)</Anomaly>\n",
             intent);
    xml_out += buf;
  }
  if (tagCount == 0) {
    xml_out += "    <Anomaly severity=\"WARNING\">Zero tags</Anomaly>\n";
  }
  if (tagCount > 200) {
    snprintf(buf, sizeof(buf),
             "    <Anomaly severity=\"CRITICAL\">Excessive tag count: %u</Anomaly>\n", tagCount);
    xml_out += buf;
  }

  // Check for repeat-byte patterns (fuzz artifacts)
  uint32_t headerSigs[] = {colorSpace, pcs, devClass, platform, manufacturer, model};
  for (int i = 0; i < 6; i++) {
    uint8_t b = headerSigs[i] & 0xFF;
    if (b == ((headerSigs[i] >> 8) & 0xFF) &&
        b == ((headerSigs[i] >> 16) & 0xFF) &&
        b == ((headerSigs[i] >> 24) & 0xFF) &&
        headerSigs[i] != 0x20202020 && headerSigs[i] != 0) {
      snprintf(buf, sizeof(buf),
               "    <Anomaly severity=\"WARNING\">Repeat-byte pattern 0x%08X (fuzz artifact)</Anomaly>\n",
               headerSigs[i]);
      xml_out += buf;
    }
  }

  xml_out += "  </Anomalies>\n";
  xml_out += "</IccProfileDiagnostic>\n";

  fclose(fp);
  return true;
}

#endif // COLORBLEED_DIAGNOSTIC_XML_H
