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
 */

#ifndef _ICCTAGPARSERS_H
#define _ICCTAGPARSERS_H

#include <string>
#include <sstream>
#include <iomanip>
#include <cstring>

// Tag signature to XML element name mapping
struct TagNameMapping {
  uint32_t sig;
  const char* xml_name;
};

static const TagNameMapping g_tag_name_map[] = {
  { 0x64657363, "profileDescriptionTag" },     // 'desc'
  { 0x63707274, "copyrightTag" },              // 'cprt'
  { 0x77747074, "mediaWhitePointTag" },        // 'wtpt'
  { 0x626B7074, "mediaBlackPointTag" },        // 'bkpt'
  { 0x7258595A, "redMatrixColumnTag" },        // 'rXYZ'
  { 0x6758595A, "greenMatrixColumnTag" },      // 'gXYZ'
  { 0x6258595A, "blueMatrixColumnTag" },       // 'bXYZ'
  { 0x72545243, "redTRCTag" },                 // 'rTRC'
  { 0x67545243, "greenTRCTag" },               // 'gTRC'
  { 0x62545243, "blueTRCTag" },                // 'bTRC'
  { 0x41324230, "AToB0Tag" },                  // 'A2B0'
  { 0x41324231, "AToB1Tag" },                  // 'A2B1'
  { 0x41324232, "AToB2Tag" },                  // 'A2B2'
  { 0x42324130, "BToA0Tag" },                  // 'B2A0'
  { 0x42324131, "BToA1Tag" },                  // 'B2A1'
  { 0x42324132, "BToA2Tag" },                  // 'B2A2'
  { 0x44324230, "DToB0Tag" },                  // 'D2B0'
  { 0x44324231, "DToB1Tag" },                  // 'D2B1'
  { 0x44324232, "DToB2Tag" },                  // 'D2B2'
  { 0x44324233, "DToB3Tag" },                  // 'D2B3'
  { 0x42324430, "BToD0Tag" },                  // 'B2D0'
  { 0x42324431, "BToD1Tag" },                  // 'B2D1'
  { 0x42324432, "BToD2Tag" },                  // 'B2D2'
  { 0x42324433, "BToD3Tag" },                  // 'B2D3'
  { 0x6C756D69, "luminanceTag" },              // 'lumi'
  { 0x6D656173, "measurementTag" },            // 'meas'
  { 0x74657875, "technologyTag" },             // 'tech'
  { 0x76696577, "viewingConditionsTag" },      // 'view'
  { 0x63686164, "chromaticAdaptationTag" },    // 'chad'
  { 0x63686172, "charTargetTag" },             // 'char'
  { 0x636C726F, "colorantOrderTag" },          // 'clro'
  { 0x636C7274, "colorantTableTag" },          // 'clrt'
  { 0x636C6F74, "colorantTableOutTag" },       // 'clot'
  { 0x64657654, "deviceMfgDescTag" },          // 'dmnd'
  { 0x646D6464, "deviceModelDescTag" },        // 'dmdd'
  { 0x67616D74, "gamutTag" },                  // 'gamt'
  { 0x6B545243, "grayTRCTag" },                // 'kTRC'
  { 0x70726530, "preview0Tag" },               // 'pre0'
  { 0x70726531, "preview1Tag" },               // 'pre1'
  { 0x70726532, "preview2Tag" },               // 'pre2'
  { 0x70736571, "profileSequenceDescTag" },    // 'pseq'
  { 0x70736964, "profileSequenceIdTag" },      // 'psid'
  { 0x72657370, "outputResponseTag" },         // 'resp'
  { 0x6E636C32, "namedColor2Tag" },            // 'ncl2'
  { 0x6E636F6C, "namedColorTag" },             // 'ncol' (obsolete)
  { 0, NULL }
};

inline const char* GetTagXMLName(uint32_t sig) {
  for (int i = 0; g_tag_name_map[i].xml_name != NULL; i++) {
    if (g_tag_name_map[i].sig == sig) {
      return g_tag_name_map[i].xml_name;
    }
  }
  // Return generic name for unknown tags
  static char generic_name[16];
  snprintf(generic_name, sizeof(generic_name), "Tag_%08X", sig);
  return generic_name;
}

inline uint32_t Read32(const unsigned char* data) {
  return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}

inline uint16_t Read16(const unsigned char* data) {
  return (data[0] << 8) | data[1];
}

inline double ReadS15Fixed16(const unsigned char* data) {
  int32_t val = (int32_t)Read32(data);
  return val / 65536.0;
}

inline double ReadU16Fixed16(const unsigned char* data) {
  uint32_t val = Read32(data);
  return val / 65536.0;
}

// Parse multiLocalizedUnicode (mluc) tag
inline bool ParseMLUCTag(std::ostringstream& xml, const unsigned char* data, size_t size, const char* indent) {
  if (size < 16) return false;
  
  uint32_t type_sig = Read32(data);
  if (type_sig != 0x6D6C7563) return false; // 'mluc'
  
  uint32_t num_records = Read32(data + 8);
  uint32_t record_size = Read32(data + 12);
  
  if (num_records > 100 || record_size != 12) return false; // Safety check
  if (size < 16 + (num_records * 12)) return false;
  
  xml << indent << "<multiLocalizedUnicodeType>\n";
  
  for (uint32_t i = 0; i < num_records; i++) {
    size_t rec_offset = 16 + (i * 12);
    if (rec_offset + 12 > size) break;
    
    uint16_t lang_code = Read16(data + rec_offset);
    uint16_t country_code = Read16(data + rec_offset + 2);
    uint32_t str_len = Read32(data + rec_offset + 4);
    uint32_t str_offset = Read32(data + rec_offset + 8);
    
    if (str_offset + str_len > size || str_len > 10000) continue; // Safety
    
    char lang[3] = {0};
    char country[3] = {0};
    lang[0] = (lang_code >> 8) & 0xFF;
    lang[1] = lang_code & 0xFF;
    country[0] = (country_code >> 8) & 0xFF;
    country[1] = country_code & 0xFF;
    
    xml << indent << "  <LocalizedText LanguageCountry=\"" << lang << country << "\"><![CDATA[";
    
    // Convert UTF-16BE to ASCII (simplified - just take low bytes)
    for (uint32_t j = 0; j < str_len/2; j++) {
      if (str_offset + j*2 + 1 < size) {
        unsigned char c = data[str_offset + j*2 + 1];
        if (c >= 32 && c < 127) xml << c;
      }
    }
    
    xml << "]]></LocalizedText>\n";
  }
  
  xml << indent << "</multiLocalizedUnicodeType>";
  return true;
}

// Parse XYZ tag
inline bool ParseXYZTag(std::ostringstream& xml, const unsigned char* data, size_t size, const char* indent) {
  if (size < 20) return false;
  
  uint32_t type_sig = Read32(data);
  if (type_sig != 0x58595A20) return false; // 'XYZ '
  
  double x = ReadS15Fixed16(data + 8);
  double y = ReadS15Fixed16(data + 12);
  double z = ReadS15Fixed16(data + 16);
  
  xml << indent << "<XYZType>\n";
  xml << indent << "  <XYZNumber X=\"" << std::fixed << std::setprecision(12) << x 
      << "\" Y=\"" << y << "\" Z=\"" << z << "\"/>\n";
  xml << indent << "</XYZType>";
  return true;
}

// Parse text description (desc) tag - legacy
inline bool ParseTextDescTag(std::ostringstream& xml, const unsigned char* data, size_t size, const char* indent) {
  if (size < 12) return false;
  
  uint32_t type_sig = Read32(data);
  if (type_sig != 0x64657363) return false; // 'desc'
  
  uint32_t ascii_count = Read32(data + 8);
  if (ascii_count == 0 || ascii_count > 1000 || size < 12 + ascii_count) return false;
  
  xml << indent << "<textDescriptionType>\n";
  xml << indent << "  <Description><![CDATA[";
  
  for (uint32_t i = 0; i < ascii_count - 1 && (12 + i) < size; i++) {
    unsigned char c = data[12 + i];
    if (c >= 32 && c < 127) xml << c;
  }
  
  xml << "]]></Description>\n";
  xml << indent << "</textDescriptionType>";
  return true;
}

// Parse curve (curv) tag
inline bool ParseCurveTag(std::ostringstream& xml, const unsigned char* data, size_t size, const char* indent) {
  if (size < 12) return false;
  
  uint32_t type_sig = Read32(data);
  if (type_sig != 0x63757276) return false; // 'curv'
  
  uint32_t count = Read32(data + 8);
  if (count > 4096 || size < 12 + count * 2) return false; // Safety
  
  xml << indent << "<curveType>\n";
  xml << indent << "  <Curve count=\"" << count << "\">";
  
  if (count > 0) {
    xml << "\n" << indent << "    ";
    for (uint32_t i = 0; i < count && (12 + i * 2 + 1) < size; i++) {
      if (i > 0 && (i % 8) == 0) xml << "\n" << indent << "    ";
      uint16_t val = Read16(data + 12 + i * 2);
      xml << val;
      if (i < count - 1) xml << " ";
    }
    xml << "\n" << indent << "  ";
  }
  
  xml << "</Curve>\n";
  xml << indent << "</curveType>";
  return true;
}

// Parse parametric curve (para) tag
inline bool ParseParaTag(std::ostringstream& xml, const unsigned char* data, size_t size, const char* indent) {
  if (size < 12) return false;
  
  uint32_t type_sig = Read32(data);
  if (type_sig != 0x70617261) return false; // 'para'
  
  uint16_t func_type = Read16(data + 8);
  if (func_type > 4) return false;
  
  // Calculate expected parameters
  uint32_t num_params = 0;
  switch (func_type) {
    case 0: num_params = 1; break; // gamma
    case 1: num_params = 3; break; // gamma, a, b
    case 2: num_params = 4; break; // gamma, a, b, c
    case 3: num_params = 5; break; // gamma, a, b, c, d
    case 4: num_params = 7; break; // gamma, a, b, c, d, e, f
  }
  
  if (size < 12 + num_params * 4) return false;
  
  xml << indent << "<parametricCurveType>\n";
  xml << indent << "  <FunctionType>" << func_type << "</FunctionType>\n";
  xml << indent << "  <Parameters>";
  
  for (uint32_t i = 0; i < num_params; i++) {
    double val = ReadS15Fixed16(data + 12 + i * 4);
    xml << " " << std::fixed << std::setprecision(8) << val;
  }
  
  xml << "</Parameters>\n";
  xml << indent << "</parametricCurveType>";
  return true;
}

// Parse text (text) tag
inline bool ParseTextTag(std::ostringstream& xml, const unsigned char* data, size_t size, const char* indent) {
  if (size < 8) return false;
  
  uint32_t type_sig = Read32(data);
  if (type_sig != 0x74657874) return false; // 'text'
  
  xml << indent << "<textType><![CDATA[";
  
  for (size_t i = 8; i < size && i < 1000; i++) {
    unsigned char c = data[i];
    if (c == 0) break;
    if (c >= 32 && c < 127) xml << c;
  }
  
  xml << "]]></textType>";
  return true;
}

#endif // _ICCTAGPARSERS_H
