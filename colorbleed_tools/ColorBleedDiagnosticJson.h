/*!
 *  @file ColorBleedDiagnosticJson.h
 *  @brief Diagnostic JSON generation for malformed ICC profiles
 *  @author David Hoyt
 *  @date 17 NOV 2026
 *  @version 1.0.0
 *
 *  When the iccDEV library cannot Read() a malformed ICC profile, this
 *  module generates a bounded diagnostic JSON representation from raw
 *  binary analysis. The result is diagnostic data, not an IccJSON profile.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#ifndef COLORBLEED_DIAGNOSTIC_JSON_H
#define COLORBLEED_DIAGNOSTIC_JSON_H

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

static inline uint32_t DiagJsonReadBE32(const uint8_t* p) {
  return (static_cast<uint32_t>(p[0]) << 24) |
         (static_cast<uint32_t>(p[1]) << 16) |
         (static_cast<uint32_t>(p[2]) << 8) |
         static_cast<uint32_t>(p[3]);
}

static inline uint16_t DiagJsonReadBE16(const uint8_t* p) {
  return (static_cast<uint16_t>(p[0]) << 8) |
         static_cast<uint16_t>(p[1]);
}

static inline int32_t DiagJsonReadBE32S(const uint8_t* p) {
  return static_cast<int32_t>(DiagJsonReadBE32(p));
}

static std::string DiagJsonHex32(uint32_t value) {
  char buffer[64];
  snprintf(buffer, sizeof(buffer), "0x%08X", value);
  return std::string(buffer);
}

static std::string DiagJsonSignature(uint32_t signature) {
  char value[5];
  for (int i = 0; i < 4; i++) {
    uint8_t c = static_cast<uint8_t>(signature >> (24 - i * 8));
    value[i] = (c >= 0x20 && c <= 0x7e) ? static_cast<char>(c) : '?';
  }
  value[4] = '\0';
  return std::string(value);
}

static const char* DiagJsonClassName(uint32_t signature) {
  switch (signature) {
    case 0x73636e72: return "scnr (Input)";
    case 0x6d6e7472: return "mntr (Display)";
    case 0x70727472: return "prtr (Output)";
    case 0x6c696e6b: return "link (DeviceLink)";
    case 0x73706163: return "spac (ColorSpace)";
    case 0x61627374: return "abst (Abstract)";
    case 0x6e6d636c: return "nmcl (NamedColor)";
    default:         return "unknown";
  }
}

static const char* DiagJsonTypeName(uint32_t signature) {
  switch (signature) {
    case 0x64657363: return "descType";
    case 0x74657874: return "textType";
    case 0x58595a20: return "XYZType";
    case 0x63757276: return "curveType";
    case 0x6d414220: return "lutAtoBType";
    case 0x6d424120: return "lutBtoAType";
    case 0x6d667431: return "lut8Type";
    case 0x6d667432: return "lut16Type";
    case 0x70617261: return "parametricCurveType";
    case 0x73663332: return "s15Fixed16ArrayType";
    case 0x6d6c7563: return "multiLocalizedUnicodeType";
    case 0x636c7274: return "colorantTableType";
    case 0x74617279: return "tagArrayType";
    case 0x73696720: return "signatureType";
    case 0x64617461: return "dataType";
    case 0x75693136: return "uInt16ArrayType";
    case 0x75693332: return "uInt32ArrayType";
    case 0x6d706574: return "multiProcessElementType";
    default:         return nullptr;
  }
}

static std::string DiagJsonHex(const uint8_t* data, size_t length,
                               size_t maximum) {
  std::string result;
  size_t limit = length < maximum ? length : maximum;
  result.reserve(limit * 3);
  for (size_t i = 0; i < limit; i++) {
    char value[3];
    snprintf(value, sizeof(value), "%02X", data[i]);
    if (i) {
      result += ' ';
    }
    result += value;
  }
  if (length > maximum) {
    result += " ...";
  }
  return result;
}

static void DiagJsonAddAnomaly(IccJson& anomalies, const char* severity,
                               const std::string& message) {
  IccJson anomaly;
  anomaly["Severity"] = severity;
  anomaly["Message"] = message;
  anomalies.push_back(anomaly);
}

/// Generate diagnostic JSON from raw ICC bytes without using iccDEV parsing.
/// The top-level key is IccProfileDiagnostic, never IccProfile.
static bool GenerateDiagnosticJson(const char* icc_path,
                                   std::string& json_out,
                                   const char* failure_reason = nullptr,
                                   int indent = 2) {
  json_out.clear();

  int fd = open(icc_path, O_RDONLY);
  if (fd < 0) {
    return false;
  }

  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
    close(fd);
    return false;
  }
  size_t file_size = static_cast<size_t>(st.st_size);

  IccJson diagnostic;
  diagnostic["Status"] = "MALFORMED";
  if (failure_reason) {
    diagnostic["FailureReason"] = failure_reason;
  }
  diagnostic["Warning"] =
      "Raw binary analysis only; this is not a valid IccJSON profile";
  diagnostic["FileSize"] = file_size;

  if (file_size < 132) {
    close(fd);
    diagnostic["Error"] = "File smaller than minimum ICC header (132 bytes)";
    IccJson root;
    root["IccProfileDiagnostic"] = diagnostic;
    json_out = root.dump(indent, ' ', true,
                         nlohmann::detail::error_handler_t::replace);
    return true;
  }

  FILE* fp = fdopen(fd, "rb");
  if (!fp) {
    close(fd);
    return false;
  }

  uint8_t raw_header[132];
  if (fread(raw_header, 1, sizeof(raw_header), fp) != sizeof(raw_header)) {
    fclose(fp);
    return false;
  }

  uint32_t profile_size = DiagJsonReadBE32(raw_header);
  uint32_t cmm_type = DiagJsonReadBE32(raw_header + 4);
  uint32_t version = DiagJsonReadBE32(raw_header + 8);
  uint32_t device_class = DiagJsonReadBE32(raw_header + 12);
  uint32_t color_space = DiagJsonReadBE32(raw_header + 16);
  uint32_t pcs = DiagJsonReadBE32(raw_header + 20);
  uint16_t year = DiagJsonReadBE16(raw_header + 24);
  uint16_t month = DiagJsonReadBE16(raw_header + 26);
  uint16_t day = DiagJsonReadBE16(raw_header + 28);
  uint16_t hour = DiagJsonReadBE16(raw_header + 30);
  uint16_t minute = DiagJsonReadBE16(raw_header + 32);
  uint16_t second = DiagJsonReadBE16(raw_header + 34);
  uint32_t platform = DiagJsonReadBE32(raw_header + 40);
  uint32_t flags = DiagJsonReadBE32(raw_header + 44);
  uint32_t manufacturer = DiagJsonReadBE32(raw_header + 48);
  uint32_t model = DiagJsonReadBE32(raw_header + 52);
  uint32_t intent = DiagJsonReadBE32(raw_header + 64);
  int32_t illuminant_x = DiagJsonReadBE32S(raw_header + 68);
  int32_t illuminant_y = DiagJsonReadBE32S(raw_header + 72);
  int32_t illuminant_z = DiagJsonReadBE32S(raw_header + 76);
  uint32_t creator = DiagJsonReadBE32(raw_header + 80);
  uint32_t tag_count = DiagJsonReadBE32(raw_header + 128);

  IccJson header;
  IccJson profile_size_json;
  profile_size_json["Declared"] = profile_size;
  profile_size_json["Actual"] = file_size;
  profile_size_json["Mismatch"] = profile_size != file_size;
  header["ProfileSize"] = profile_size_json;
  header["CMMType"] = DiagJsonSignature(cmm_type);

  char buffer[256];
  snprintf(buffer, sizeof(buffer), "%u.%u.%u (0x%08X)",
           (version >> 24) & 0xff, (version >> 20) & 0x0f,
           (version >> 16) & 0x0f, version);
  header["Version"] = buffer;

  IccJson device_class_json;
  device_class_json["Signature"] = DiagJsonSignature(device_class);
  device_class_json["Name"] = DiagJsonClassName(device_class);
  header["DeviceClass"] = device_class_json;
  header["ColorSpace"] = DiagJsonSignature(color_space);
  header["PCS"] = DiagJsonSignature(pcs);

  snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02u",
           year, month, day, hour, minute, second);
  header["DateTime"] = buffer;

  bool valid_magic = memcmp(raw_header + 36, "acsp", 4) == 0;
  IccJson magic;
  magic["Valid"] = valid_magic;
  snprintf(buffer, sizeof(buffer), "0x%02X%02X%02X%02X", raw_header[36],
           raw_header[37], raw_header[38], raw_header[39]);
  magic["Value"] = buffer;
  header["Magic"] = magic;
  header["Platform"] = DiagJsonSignature(platform);
  header["Flags"] = DiagJsonHex32(flags);
  header["Manufacturer"] = DiagJsonSignature(manufacturer);

  IccJson model_json;
  model_json["Signature"] = DiagJsonSignature(model);
  model_json["Value"] = DiagJsonHex32(model);
  header["Model"] = model_json;
  header["RenderingIntent"] = intent;

  IccJson illuminant;
  illuminant["X"] = illuminant_x / 65536.0;
  illuminant["Y"] = illuminant_y / 65536.0;
  illuminant["Z"] = illuminant_z / 65536.0;
  header["Illuminant"] = illuminant;
  header["Creator"] = DiagJsonSignature(creator);

  std::string profile_id;
  profile_id.reserve(32);
  for (int i = 84; i < 100; i++) {
    char byte[3];
    snprintf(byte, sizeof(byte), "%02X", raw_header[i]);
    profile_id += byte;
  }
  header["ProfileID"] = profile_id;
  header["RawHeaderHex"] = DiagJsonHex(raw_header, 128, 128);
  diagnostic["Header"] = header;

  uint32_t safe_tag_count = tag_count > 256 ? 256 : tag_count;
  size_t tag_table_size = static_cast<size_t>(safe_tag_count) * 12;
  IccJson tag_table;
  tag_table["Count"] = tag_count;
  tag_table["AnalyzedCount"] = 0;
  tag_table["Capped"] = tag_count > safe_tag_count;
  tag_table["Tags"] = IccJson::array();

  if (tag_table_size > 0 && 132 + tag_table_size <= file_size) {
    std::vector<uint8_t> raw_tags(tag_table_size);
    if (fseek(fp, 132, SEEK_SET) == 0 &&
        fread(raw_tags.data(), 1, tag_table_size, fp) == tag_table_size) {
      for (uint32_t i = 0; i < safe_tag_count; i++) {
        const uint8_t* raw_tag = raw_tags.data() + i * 12;
        uint32_t signature = DiagJsonReadBE32(raw_tag);
        uint32_t offset = DiagJsonReadBE32(raw_tag + 4);
        uint32_t size = DiagJsonReadBE32(raw_tag + 8);
        bool out_of_bounds = offset > file_size || size > file_size ||
            static_cast<uint64_t>(offset) + size > file_size;

        IccJson tag;
        tag["Index"] = i;
        tag["Signature"] = DiagJsonSignature(signature);
        tag["Offset"] = offset;
        tag["Size"] = size;
        tag["OutOfBounds"] = out_of_bounds;

        if (!out_of_bounds && offset >= 128 && size >= 4) {
          uint8_t raw_type[4];
          if (fseek(fp, static_cast<long>(offset), SEEK_SET) == 0 &&
              fread(raw_type, 1, sizeof(raw_type), fp) == sizeof(raw_type)) {
            uint32_t type_signature = DiagJsonReadBE32(raw_type);
            tag["TypeSignature"] = DiagJsonSignature(type_signature);
            const char* type_name = DiagJsonTypeName(type_signature);
            if (type_name) {
              tag["TypeName"] = type_name;
            }
          }
        }

        if (!out_of_bounds && offset >= 128 && size > 0) {
          size_t preview_length = size < 128 ? size : 128;
          std::vector<uint8_t> preview(preview_length);
          if (fseek(fp, static_cast<long>(offset), SEEK_SET) == 0) {
            size_t bytes_read =
                fread(preview.data(), 1, preview_length, fp);
            if (bytes_read > 0) {
              tag["HexPreview"] =
                  DiagJsonHex(preview.data(), bytes_read, 128);

              if (size <= 256 && bytes_read >= 8) {
                std::string ascii;
                bool has_ascii = false;
                for (size_t j = 8; j < bytes_read; j++) {
                  uint8_t c = preview[j];
                  if (c >= 0x20 && c <= 0x7e) {
                    ascii += static_cast<char>(c);
                    has_ascii = true;
                  } else if (c == 0) {
                    break;
                  } else {
                    ascii += '.';
                  }
                }
                if (has_ascii && ascii.size() >= 3) {
                  tag["AsciiPreview"] = ascii;
                }
              }
            }
          }
        }

        tag_table["Tags"].push_back(tag);
      }
      tag_table["AnalyzedCount"] = safe_tag_count;
    }
  } else if (tag_count > 0) {
    snprintf(buffer, sizeof(buffer),
             "Tag table extends beyond file: need %zu bytes at offset 132, "
             "file is %zu bytes",
             tag_table_size, file_size);
    tag_table["Error"] = buffer;
  }
  diagnostic["TagTable"] = tag_table;

  IccJson anomalies = IccJson::array();
  if (!valid_magic) {
    DiagJsonAddAnomaly(anomalies, "CRITICAL",
                       "Invalid magic bytes (expected 'acsp')");
  }
  if (profile_size != file_size) {
    snprintf(buffer, sizeof(buffer),
             "Size mismatch: header=%u file=%zu", profile_size, file_size);
    DiagJsonAddAnomaly(anomalies, "WARNING", buffer);
  }
  if (illuminant_x < 0 || illuminant_y < 0 || illuminant_z < 0) {
    DiagJsonAddAnomaly(anomalies, "WARNING",
                       "Negative illuminant XYZ values");
  }
  if (intent > 3) {
    snprintf(buffer, sizeof(buffer),
             "Rendering intent %u out of range (0-3)", intent);
    DiagJsonAddAnomaly(anomalies, "WARNING", buffer);
  }
  if (tag_count == 0) {
    DiagJsonAddAnomaly(anomalies, "WARNING", "Zero tags");
  }
  if (tag_count > 200) {
    snprintf(buffer, sizeof(buffer), "Excessive tag count: %u", tag_count);
    DiagJsonAddAnomaly(anomalies, "CRITICAL", buffer);
  }

  uint32_t signatures[] = {
      color_space, pcs, device_class, platform, manufacturer, model};
  for (uint32_t signature : signatures) {
    uint8_t byte = signature & 0xff;
    if (byte == ((signature >> 8) & 0xff) &&
        byte == ((signature >> 16) & 0xff) &&
        byte == ((signature >> 24) & 0xff) &&
        signature != 0x20202020 && signature != 0) {
      snprintf(buffer, sizeof(buffer),
               "Repeat-byte pattern 0x%08X (fuzz artifact)", signature);
      DiagJsonAddAnomaly(anomalies, "WARNING", buffer);
    }
  }
  diagnostic["Anomalies"] = anomalies;

  IccJson root;
  root["IccProfileDiagnostic"] = diagnostic;
  json_out = root.dump(indent, ' ', true,
                       nlohmann::detail::error_handler_t::replace);
  fclose(fp);
  return true;
}

#endif // COLORBLEED_DIAGNOSTIC_JSON_H
