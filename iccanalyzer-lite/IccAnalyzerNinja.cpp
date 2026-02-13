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

#include "IccAnalyzerCommon.h"
#include "IccAnalyzerNinja.h"
#include "IccAnalyzerInspect.h"
#include "IccTagParsers.h"
#include <cstring>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <sys/stat.h>
#include <sys/types.h>

// Global flag for compatibility mode
static bool g_compatible_mode = false;

void SetXMLCompatibilityMode(bool enabled) {
  g_compatible_mode = enabled;
}

//==============================================================================
// Helper Functions
//==============================================================================

static std::string GetTimestamp() {
  time_t now = time(NULL);
  struct tm tm_buf;
  char buf[64];
  gmtime_r(&now, &tm_buf);
  strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S UTC", &tm_buf);
  return std::string(buf);
}

static std::string GetSessionID() {
  time_t now = time(NULL);
  struct tm tm_buf;
  char buf[32];
  gmtime_r(&now, &tm_buf);
  strftime(buf, sizeof(buf), "%Y%m%d_%H%M%S", &tm_buf);
  return std::string(buf);
}

static void CreateLogDir(const char* path) {
  mkdir(path, 0755);
}

// Helper to print 4-byte signature safely (replaces non-printable with '.')
static void PrintSig4(icUInt32Number sig) {
  for (int i = 3; i >= 0; i--) {
    unsigned char c = (sig >> (i*8)) & 0xff;
    // Print printable ASCII, otherwise use '.'
    printf("%c", (c >= 32 && c <= 126) ? c : '.');
  }
}

//==============================================================================
// Ninja Mode - Raw Profile Analysis (No Validation)
//==============================================================================

int NinjaModeAnalyze(const char *filename, bool full_dump)
{
  printf("\n");
  printf("=========================================================================\n");
  printf("|                   *** REDUCED SECURITY MODE ***                       |\n");
  printf("|                                                                       |\n");
  printf("|             Copyright (c) 2021-2026 David H Hoyt LLC                 |\n");
  printf("|                          hoyt.net                                     |\n");
  printf("=========================================================================\n");
  printf("\n");
  printf("WARNING: Analyzing malformed/corrupted ICC profile without validation.\n");
  printf("         This mode bypasses all safety checks and may expose parser bugs.\n");
  printf("         Use only for security research, fuzzing, or forensic analysis.\n");
  printf("\n");
  printf("File: %s\n", filename);
  if (full_dump) {
    printf("Mode: FULL DUMP (entire file will be displayed)\n");
  }
  printf("\n");
  
  // Open file first, then stat the fd to avoid TOCTOU race
  FILE *fp = fopen(filename, "rb");
  if (!fp) {
    printf("[ERR] ERROR: Cannot open file: %s\n", filename);
    printf("   Check that the file exists and you have read permissions.\n\n");
    return -1;
  }
  
  struct stat st;
  if (fstat(fileno(fp), &st) != 0) {
    printf("[ERR] ERROR: Cannot stat file: %s\n", filename);
    fclose(fp);
    return -1;
  }
  size_t fileSize = st.st_size;
  printf("Raw file size: %zu bytes (0x%zX)\n\n", fileSize, fileSize);
  
  icUInt8Number *rawData = (icUInt8Number*)malloc(fileSize);
  if (!rawData) {
    printf("Error: Memory allocation failed\n");
    fclose(fp);
    return -1;
  }
  
  if (fread(rawData, 1, fileSize, fp) != fileSize) {
    printf("Error: Cannot read file\n");
    free(rawData);
    fclose(fp);
    return -1;
  }
  fclose(fp);
  
  // === RAW HEADER ANALYSIS ===
  printf("=== RAW HEADER DUMP (0x0000-0x007F) ===\n");
  if (fileSize >= 128) {
    PrintHexDump(rawData, 128, 0);
    printf("\n");
    
    // Manual header parsing (no validation)
    icUInt32Number size = (static_cast<icUInt32Number>(rawData[0])<<24) | (static_cast<icUInt32Number>(rawData[1])<<16) | (static_cast<icUInt32Number>(rawData[2])<<8) | rawData[3];
    icUInt32Number cmmId = (static_cast<icUInt32Number>(rawData[4])<<24) | (static_cast<icUInt32Number>(rawData[5])<<16) | (static_cast<icUInt32Number>(rawData[6])<<8) | rawData[7];
    icUInt32Number version = (static_cast<icUInt32Number>(rawData[8])<<24) | (static_cast<icUInt32Number>(rawData[9])<<16) | (static_cast<icUInt32Number>(rawData[10])<<8) | rawData[11];
    icUInt32Number deviceClass = (static_cast<icUInt32Number>(rawData[12])<<24) | (static_cast<icUInt32Number>(rawData[13])<<16) | (static_cast<icUInt32Number>(rawData[14])<<8) | rawData[15];
    icUInt32Number colorSpace = (static_cast<icUInt32Number>(rawData[16])<<24) | (static_cast<icUInt32Number>(rawData[17])<<16) | (static_cast<icUInt32Number>(rawData[18])<<8) | rawData[19];
    icUInt32Number pcs = (static_cast<icUInt32Number>(rawData[20])<<24) | (static_cast<icUInt32Number>(rawData[21])<<16) | (static_cast<icUInt32Number>(rawData[22])<<8) | rawData[23];
    
    printf("Header Fields (RAW - no validation):\n");
    printf("  Profile Size:    0x%08X (%u bytes) %s\n", size, size, 
           (size != fileSize) ? "MISMATCH" : "OK");
    printf("  CMM:             0x%08X  '", cmmId);
    PrintSig4(cmmId);
    printf("'\n");
    printf("  Version:         0x%08X\n", version);
    printf("  Device Class:    0x%08X  '", deviceClass);
    PrintSig4(deviceClass);
    printf("'\n");
    printf("  Color Space:     0x%08X  '", colorSpace);
    PrintSig4(colorSpace);
    printf("'\n");
    printf("  PCS:             0x%08X  '", pcs);
    PrintSig4(pcs);
    printf("'\n");
    printf("\n");
  } else {
    printf("WARNING: File too small for ICC header (need 128 bytes, got %zu)\n\n", fileSize);
  }
  
  // === RAW TAG TABLE ANALYSIS ===
  printf("=== RAW TAG TABLE (0x0080+) ===\n");
  if (fileSize >= 132) {
    icUInt32Number tagCount = (static_cast<icUInt32Number>(rawData[128])<<24) | (static_cast<icUInt32Number>(rawData[129])<<16) | (static_cast<icUInt32Number>(rawData[130])<<8) | rawData[131];
    printf("Tag Count: %u (0x%08X)\n", tagCount, tagCount);
    
    if (tagCount > 1000) {
      printf("WARNING: Suspicious tag count (>1000) - possible corruption\n");
    }
    
    printf("\nTag Table Raw Data:\n");
    size_t tagTableSize = 4 + ((size_t)(tagCount > 0x0FFFFFFFU ? 0x0FFFFFFFU : tagCount) * 12);
    size_t dumpSize = (tagTableSize < 256) ? tagTableSize : 256;
    if (fileSize >= 128 + dumpSize) {
      PrintHexDump(rawData + 128, dumpSize, 128);
      printf("\n");
    }
    
    // Try to parse tag entries (no bounds checking - ninja mode!)
    printf("Tag Entries (RAW - no validation):\n");
    printf("Idx  Signature    FourCC       Offset       Size         TagType      Status\n");
    printf("---  ------------ ------------ ------------ ------------ ------------ ------\n");
    
    size_t maxTags = (tagCount < 100) ? tagCount : 100;  // Limit display
    icUInt32Number tagArrayCount = 0;
    
    for (size_t i = 0; i < maxTags && (132 + i*12 + 12) <= fileSize; i++) {
      size_t pos = 132 + i*12;
      icUInt32Number sig = (static_cast<icUInt32Number>(rawData[pos])<<24) | (static_cast<icUInt32Number>(rawData[pos+1])<<16) | (static_cast<icUInt32Number>(rawData[pos+2])<<8) | rawData[pos+3];
      icUInt32Number offset = (static_cast<icUInt32Number>(rawData[pos+4])<<24) | (static_cast<icUInt32Number>(rawData[pos+5])<<16) | (static_cast<icUInt32Number>(rawData[pos+6])<<8) | rawData[pos+7];
      icUInt32Number tagSize = (static_cast<icUInt32Number>(rawData[pos+8])<<24) | (static_cast<icUInt32Number>(rawData[pos+9])<<16) | (static_cast<icUInt32Number>(rawData[pos+10])<<8) | rawData[pos+11];
      
      char sigStr[5];
      sigStr[0] = (sig>>24)&0xff;
      sigStr[1] = (sig>>16)&0xff;
      sigStr[2] = (sig>>8)&0xff;
      sigStr[3] = sig&0xff;
      sigStr[4] = '\0';
      
      // Read tag TYPE (first 4 bytes of tag data)
      char typeStr[5] = "----";
      if (offset < fileSize && offset + 4 <= fileSize) {
        icUInt32Number tagType = (static_cast<icUInt32Number>(rawData[offset])<<24) | (static_cast<icUInt32Number>(rawData[offset+1])<<16) | 
                                 (static_cast<icUInt32Number>(rawData[offset+2])<<8) | rawData[offset+3];
        typeStr[0] = (tagType>>24)&0xff;
        typeStr[1] = (tagType>>16)&0xff;
        typeStr[2] = (tagType>>8)&0xff;
        typeStr[3] = tagType&0xff;
        typeStr[4] = '\0';
        
        // Check for TagArrayType (CRITICAL security issue)
        if (tagType == 0x74617279) {  // 'tary'
          tagArrayCount++;
        }
      }
      
      const char *status = "OK";
      if (offset >= fileSize) status = "OOB offset";
      else if (offset + tagSize > fileSize) status = "OOB size";
      else if (offset < 128) status = "overlap";
      else if (tagSize == 0) status = "zero size";
      else if (tagSize > 10000000) status = "huge size";
      
      // Highlight TagArrayType with critical warning
      if (strcmp(typeStr, "tary") == 0) {
        printf("%-4zu 0x%08X   '%-4s'        0x%08X   0x%08X   '%-4s'        *** UAF RISK!\n",
               i, sig, sigStr, offset, tagSize, typeStr);
      } else {
        printf("%-4zu 0x%08X   '%-4s'        0x%08X   0x%08X   '%-4s'        %s\n",
               i, sig, sigStr, offset, tagSize, typeStr, status);
      }
    }
    
    if (tagCount > maxTags) {
      printf("... (%u more tags not shown)\n", tagCount - (unsigned)maxTags);
    }
    
    // TagArrayType summary
    if (tagArrayCount > 0) {
      printf("\n");
      printf("🚨 CRITICAL SECURITY WARNING:\n");
      printf("   Found %u TagArrayType tag(s) in this profile!\n", tagArrayCount);
      printf("   These tags trigger heap-use-after-free in CIccTagArray::Cleanup()\n");
      printf("   Location: IccProfLib/IccTagComposite.cpp:1514\n");
      printf("   Impact: Code execution, memory corruption\n");
      printf("   DO NOT PROCESS WITH IccProfLib - potential exploit attempt\n");
    }
    
    // Size inflation detection
    icUInt32Number claimedSize = (static_cast<icUInt32Number>(rawData[0])<<24) | (static_cast<icUInt32Number>(rawData[1])<<16) | (static_cast<icUInt32Number>(rawData[2])<<8) | rawData[3];
    if (claimedSize > 0 && claimedSize > fileSize * 16 && claimedSize > (128u << 20)) {
      printf("\n⚠️  SIZE INFLATION: Header claims %u bytes, file is %zu bytes (%.0fx)\n",
             claimedSize, fileSize, (double)claimedSize / fileSize);
      printf("   Risk: OOM via tag-internal allocations based on inflated header size\n");
    }
    
    // Tag overlap detection (raw)
    if (maxTags > 1) {
      int overlapCount = 0;
      for (size_t a = 0; a < maxTags && (132 + a*12 + 12) <= fileSize; a++) {
        size_t posA = 132 + a*12;
        icUInt32Number offA = (static_cast<icUInt32Number>(rawData[posA+4])<<24) | (static_cast<icUInt32Number>(rawData[posA+5])<<16) | (static_cast<icUInt32Number>(rawData[posA+6])<<8) | rawData[posA+7];
        icUInt32Number szA  = (static_cast<icUInt32Number>(rawData[posA+8])<<24) | (static_cast<icUInt32Number>(rawData[posA+9])<<16) | (static_cast<icUInt32Number>(rawData[posA+10])<<8) | rawData[posA+11];
        for (size_t b = a+1; b < maxTags && (132 + b*12 + 12) <= fileSize; b++) {
          size_t posB = 132 + b*12;
          icUInt32Number offB = (static_cast<icUInt32Number>(rawData[posB+4])<<24) | (static_cast<icUInt32Number>(rawData[posB+5])<<16) | (static_cast<icUInt32Number>(rawData[posB+6])<<8) | rawData[posB+7];
          icUInt32Number szB  = (static_cast<icUInt32Number>(rawData[posB+8])<<24) | (static_cast<icUInt32Number>(rawData[posB+9])<<16) | (static_cast<icUInt32Number>(rawData[posB+10])<<8) | rawData[posB+11];
          if (offA == offB && szA == szB) continue; // shared (allowed by spec)
          uint64_t endA = (uint64_t)offA + szA, endB = (uint64_t)offB + szB;
          if (offA < endB && offB < endA && offA != offB) {
            overlapCount++;
          }
        }
      }
      if (overlapCount > 0) {
        printf("\n⚠️  TAG OVERLAP: %d overlapping tag pair(s) detected\n", overlapCount);
        printf("   Risk: Data corruption, possible exploit crafting\n");
      }
    }
    printf("\n");
  } else {
    printf("WARNING: File too small for tag table\n\n");
  }
  
  // === FULL FILE HEX DUMP ===
  if (full_dump) {
    printf("=== FULL FILE HEX DUMP (all %zu bytes) ===\n", fileSize);
    PrintHexDump(rawData, fileSize, 0);
  } else {
    printf("=== FULL FILE HEX DUMP (first 2048 bytes) ===\n");
    size_t dumpLimit = (fileSize < 2048) ? fileSize : 2048;
    PrintHexDump(rawData, dumpLimit, 0);
    if (fileSize > 2048) {
      printf("\n... (%zu more bytes not shown)\n", fileSize - 2048);
      printf("TIP: Use -nf flag for full dump: iccAnalyzer -nf <file>\n");
    }
  }
  printf("\n");
  
  // === SUMMARY ===
  printf("=== NINJA MODE ANALYSIS COMPLETE ===\n");
  printf("Raw data inspection complete. No validation performed.\n");
  printf("Use this information for debugging malformed profiles.\n");
  printf("\n");
  
  free(rawData);
  return 0;
}

//==============================================================================
// Ninja Mode - XML Extraction (No Validation)
//==============================================================================

static icUInt32Number read32(const unsigned char* data) {
  return (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
}

static icUInt16Number read16(const unsigned char* data) {
  return (data[0] << 8) | data[1];
}

static void sig2str(char* str, icUInt32Number sig) {
  str[0] = (sig >> 24) & 0xFF;
  str[1] = (sig >> 16) & 0xFF;
  str[2] = (sig >> 8) & 0xFF;
  str[3] = sig & 0xFF;
  str[4] = 0;
  for (int i = 0; i < 4; i++) {
    if (str[i] < 32 || str[i] > 126) str[i] = '?';
  }
}

/** Extract XML representation of ICC profile tags in ninja mode. */
int NinjaModeExtractXML(const char *filename, const char *output_xml)
{
  std::string sessionID = GetSessionID();
  std::string logDir = "./xml-extraction-logs/" + sessionID;
  CreateLogDir("./xml-extraction-logs");
  CreateLogDir(logDir.c_str());
  
  std::string logFile = logDir + "/session.log";
  std::ofstream log(logFile);
  
  printf("\n");
  printf("=========================================================================\n");
  printf("|           *** REDUCED SECURITY MODE: XML EXTRACTION ***              |\n");
  printf("|                                                                       |\n");
  printf("|             Copyright (c) 2021-2026 David H Hoyt LLC                 |\n");
  printf("|                          hoyt.net                                     |\n");
  printf("|                                                                       |\n");
  printf("|  WARNING: Unsafe extraction with minimal validation                  |\n");
  printf("|  For security research and forensics ONLY                            |\n");
  printf("|  Do NOT use extracted data in production systems                     |\n");
  printf("=========================================================================\n");
  printf("\n");
  printf("Session ID:   %s\n", sessionID.c_str());
  printf("Log directory: %s\n", logDir.c_str());
  printf("Timestamp:    %s\n\n", GetTimestamp().c_str());
  printf("Extracting XML from: %s\n", filename);
  printf("Output file:         %s\n", output_xml);
  printf("\n");
  
  log << "=========================================================================\n";
  log << "|              NINJA MODE: XML EXTRACTION SESSION                       |\n";
  log << "=========================================================================\n";
  log << "Timestamp:    " << GetTimestamp() << "\n";
  log << "Session ID:   " << sessionID << "\n";
  log << "Tool:         iccAnalyzer -xml\n";
  log << "Input file:   " << filename << "\n";
  log << "Output file:  " << output_xml << "\n";
  log << "Log directory: " << logDir << "\n";
  log << "\n";
  
  std::ifstream file(filename, std::ios::binary);
  if (!file) {
    printf("[ERR] ERROR: Cannot open file: %s\n", filename);
    log << "ERROR: Cannot open input file\n";
    log << "\n=========================================================================\n";
    log << "|                      SESSION END (ERROR)                              |\n";
    log << "=========================================================================\n";
    log << "Exit timestamp: " << GetTimestamp() << "\n";
    log << "Exit code: 1\n";
    return -1;
  }

  file.seekg(0, std::ios::end);
  size_t fileSize = file.tellg();
  file.seekg(0, std::ios::beg);
  
  printf("File size: %zu bytes\n", fileSize);
  log << "File size: " << fileSize << " bytes\n";
  
  if (fileSize < 132) {
    printf("[ERR] ERROR: File too small for ICC profile (min 132 bytes)\n");
    log << "ERROR: File too small for ICC profile\n";
    log << "\n=========================================================================\n";
    log << "|                      SESSION END (ERROR)                              |\n";
    log << "=========================================================================\n";
    log << "Exit timestamp: " << GetTimestamp() << "\n";
    log << "Exit code: 1\n";
    return -1;
  }
  
  // Read entire file into memory for raw byte-level header/tag parsing
  unsigned char* data = new unsigned char[fileSize];
  file.read((char*)data, fileSize);
  file.close();
  
  std::ostringstream xml;
  xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  xml << "<!-- Generated by iccAnalyzer -xml (Ninja Mode) -->\n";
  xml << "<!-- Session ID: " << sessionID << " -->\n";
  xml << "<!-- Timestamp: " << GetTimestamp() << " -->\n";
  xml << "<!-- WARNING: Unsafe extraction - data not validated -->\n";
  xml << "<IccProfile>\n";
  
  // Parse 128-byte ICC header fields at fixed offsets per ICC spec
  icUInt32Number profSize = read32(data);
  icUInt32Number cmmType = read32(data + 4);
  icUInt32Number version = read32(data + 8);
  icUInt32Number devClass = read32(data + 12);
  icUInt32Number colorSpace = read32(data + 16);
  icUInt32Number pcs = read32(data + 20);
  
  char sigbuf[5];
  
  xml << "  <Header>\n";
  xml << "    <Size>" << profSize << "</Size>\n";
  sig2str(sigbuf, cmmType);
  xml << "    <CmmType>" << sigbuf << "</CmmType>\n";
  xml << "    <Version>" << std::hex << version << std::dec << "</Version>\n";
  sig2str(sigbuf, devClass);
  xml << "    <DeviceClass>" << sigbuf << "</DeviceClass>\n";
  sig2str(sigbuf, colorSpace);
  xml << "    <ColorSpace>" << sigbuf << "</ColorSpace>\n";
  sig2str(sigbuf, pcs);
  xml << "    <Pcs>" << sigbuf << "</Pcs>\n";
  
  icUInt16Number year = read16(data + 24);
  icUInt16Number month = read16(data + 26);
  icUInt16Number day = read16(data + 28);
  icUInt16Number hours = read16(data + 30);
  icUInt16Number minutes = read16(data + 32);
  icUInt16Number seconds = read16(data + 34);
  xml << "    <DateTime>" << year << "-" 
      << std::setfill('0') << std::setw(2) << month << "-" 
      << std::setw(2) << day << " "
      << std::setw(2) << hours << ":"
      << std::setw(2) << minutes << ":"
      << std::setw(2) << seconds << "</DateTime>\n";
  
  icUInt32Number magic = read32(data + 36);
  sig2str(sigbuf, magic);
  xml << "    <Magic>" << sigbuf << "</Magic>\n";
  
  icUInt32Number platform = read32(data + 40);
  sig2str(sigbuf, platform);
  xml << "    <Platform>" << sigbuf << "</Platform>\n";
  
  icUInt32Number flags = read32(data + 44);
  xml << "    <Flags>0x" << std::hex << flags << std::dec << "</Flags>\n";
  
  icUInt32Number manufacturer = read32(data + 48);
  sig2str(sigbuf, manufacturer);
  xml << "    <Manufacturer>" << sigbuf << "</Manufacturer>\n";
  
  icUInt32Number model = read32(data + 52);
  xml << "    <Model>0x" << std::hex << model << std::dec << "</Model>\n";
  
  icUInt64Number attributes = ((icUInt64Number)read32(data + 56) << 32) | read32(data + 60);
  xml << "    <Attributes>0x" << std::hex << attributes << std::dec << "</Attributes>\n";
  
  icUInt32Number renderingIntent = read32(data + 64);
  xml << "    <RenderingIntent>" << renderingIntent << "</RenderingIntent>\n";
  
  // PCS illuminant stored as s15Fixed16Number at offset 68 (D50 expected)
  icS15Fixed16Number illumX = read32(data + 68);
  icS15Fixed16Number illumY = read32(data + 72);
  icS15Fixed16Number illumZ = read32(data + 76);
  xml << "    <Illuminant>\n";
  xml << "      <X>" << (illumX / 65536.0) << "</X>\n";
  xml << "      <Y>" << (illumY / 65536.0) << "</Y>\n";
  xml << "      <Z>" << (illumZ / 65536.0) << "</Z>\n";
  xml << "    </Illuminant>\n";
  
  icUInt32Number creator = read32(data + 80);
  sig2str(sigbuf, creator);
  xml << "    <Creator>" << sigbuf << "</Creator>\n";
  
  xml << "    <ProfileID>";
  for (int i = 0; i < 16; i++) {
    xml << std::hex << std::setfill('0') << std::setw(2) << (int)data[84 + i];
  }
  xml << "</ProfileID>\n" << std::dec;
  
  xml << "  </Header>\n";
  
  icUInt32Number tagCount = read32(data + 128);
  printf("Tag count: %u\n", tagCount);
  log << "Tag count: " << tagCount << "\n";
  
  if (tagCount > 0 && tagCount < 1000 && fileSize >= 132 + tagCount * 12) {
    if (g_compatible_mode) {
      xml << "  <Tags>\n";
    } else {
      xml << "  <TagTable count=\"" << tagCount << "\">\n";
    }
    
    for (icUInt32Number i = 0; i < tagCount; i++) {
      size_t offset = 132 + i * 12;
      if (offset + 12 > fileSize) break;
      
      icUInt32Number tagSig = read32(data + offset);
      icUInt32Number tagOffset = read32(data + offset + 4);
      icUInt32Number tagSize = read32(data + offset + 8);
      
      sig2str(sigbuf, tagSig);
      log << "Tag " << (i+1) << "/" << tagCount << ": sig=" << sigbuf 
          << " offset=" << tagOffset << " size=" << tagSize << "\n";
      
      if (g_compatible_mode) {
        // Compatible mode: use proper tag names and try to parse content
        const char* tag_xml_name = GetTagXMLName(tagSig);
        xml << "    <" << tag_xml_name << "> ";
        
        bool parsed = false;
        if (tagOffset + tagSize <= fileSize && tagOffset >= 132 && tagSize >= 8) {
          std::ostringstream tag_content;
          unsigned char* tag_data = data + tagOffset;
          
          // Try parsing common tag types
          if (ParseMLUCTag(tag_content, tag_data, tagSize, "")) {
            xml << tag_content.str();
            parsed = true;
            log << "  Parsed as multiLocalizedUnicodeType\n";
          } else if (ParseXYZTag(tag_content, tag_data, tagSize, "")) {
            xml << tag_content.str();
            parsed = true;
            log << "  Parsed as XYZType\n";
          } else if (ParseTextDescTag(tag_content, tag_data, tagSize, "")) {
            xml << tag_content.str();
            parsed = true;
            log << "  Parsed as textDescriptionType\n";
          } else if (ParseCurveTag(tag_content, tag_data, tagSize, "")) {
            xml << tag_content.str();
            parsed = true;
            log << "  Parsed as curveType\n";
          } else if (ParseParaTag(tag_content, tag_data, tagSize, "")) {
            xml << tag_content.str();
            parsed = true;
            log << "  Parsed as parametricCurveType\n";
          } else if (ParseTextTag(tag_content, tag_data, tagSize, "")) {
            xml << tag_content.str();
            parsed = true;
            log << "  Parsed as textType\n";
          }
        }
        
        if (!parsed) {
          // Fallback: output type and note that we couldn't parse
          icUInt32Number tagType = read32(data + tagOffset);
          sig2str(sigbuf, tagType);
          xml << "<UnparsedTag type=\"" << sigbuf << "\" size=\"" << tagSize << "\"/>";
          log << "  Could not parse (type=" << sigbuf << "), left unparsed\n";
        }
        
        xml << " </" << tag_xml_name << ">\n";
      } else {
        // Forensic mode: original behavior with binary files
        xml << "    <Tag sig=\"" << sigbuf << "\" offset=\"" << tagOffset 
            << "\" size=\"" << tagSize << "\">\n";
        
        if (tagOffset + tagSize <= fileSize && tagOffset >= 132 && tagSize >= 8) {
          icUInt32Number tagType = read32(data + tagOffset);
          sig2str(sigbuf, tagType);
          xml << "      <Type>" << sigbuf << "</Type>\n";
          
          if (tagSize > 8) {
            icUInt32Number dataSize = tagSize - 8;
            
            char tagSigStr[5];
            sig2str(tagSigStr, tagSig);
            std::string binFile = logDir + "/tag_" + tagSigStr + "_offset" + 
                                  std::to_string(tagOffset) + ".bin";
            
            std::ofstream binOut(binFile, std::ios::binary);
            if (binOut) {
              binOut.write((char*)(data + tagOffset), tagSize);
              binOut.close();
              
              xml << "      <DataFile size=\"" << dataSize << "\">" 
                  << binFile.substr(binFile.find("xml-extraction-logs")) << "</DataFile>\n";
              xml << "      <DataSummary>\n";
              xml << "        <TotalSize>" << tagSize << "</TotalSize>\n";
              xml << "        <DataSize>" << dataSize << "</DataSize>\n";
              xml << "        <FirstBytes encoding=\"hex\">";
              
              size_t previewBytes = (dataSize < 64) ? dataSize : 64;
              for (size_t j = 8; j < 8 + previewBytes; j++) {
                if (tagOffset + j >= fileSize) break;
                xml << std::hex << std::setfill('0') << std::setw(2) 
                    << static_cast<unsigned>(static_cast<unsigned char>(data[tagOffset + j]));
              }
              if (dataSize > 64) {
                xml << "...";
              }
              xml << "</FirstBytes>\n" << std::dec;
              xml << "      </DataSummary>\n";
              
              log << "  Extracted to: " << binFile << " (" << tagSize << " bytes)\n";
            } else {
              xml << "      <!-- ERROR: Could not create data file: " << binFile << " -->\n";
              log << "  ERROR: Could not create data file\n";
            }
          }
        }
        xml << "    </Tag>\n";
      }
    }
    
    if (g_compatible_mode) {
      xml << "  </Tags>\n";
    } else {
      xml << "  </TagTable>\n";
    }
  } else {
    xml << "  <!-- Invalid or missing tag table -->\n";
  }
  
  xml << "</IccProfile>\n";
  
  std::string xmlStr = xml.str();
  printf("Generated XML: %zu bytes\n", xmlStr.size());
  log << "Generated XML: " << xmlStr.size() << " bytes\n";
  
  std::ofstream out(output_xml, std::ios::binary);
  if (!out) {
    printf("[ERR] ERROR: Cannot write output file: %s\n", output_xml);
    log << "ERROR: Cannot write output file: " << output_xml << "\n";
    log << "\n=========================================================================\n";
    log << "|                      SESSION END (ERROR)                              |\n";
    log << "=========================================================================\n";
    log << "Exit timestamp: " << GetTimestamp() << "\n";
    log << "Exit code: 1\n";
    delete[] data;
    return -1;
  }
  out.write(xmlStr.c_str(), xmlStr.size());
  out.close();
  
  std::string outputCopy = logDir + "/output.xml";
  std::ofstream outCopy(outputCopy, std::ios::binary);
  outCopy.write(xmlStr.c_str(), xmlStr.size());
  outCopy.close();
  
  printf("\n=========================================================================\n");
  printf("|                    [OK] EXTRACTION COMPLETE [OK]                           |\n");
  printf("=========================================================================\n");
  printf("Output file:   %s\n", output_xml);
  printf("Backup copy:   %s\n", outputCopy.c_str());
  printf("Session log:   %s\n", logFile.c_str());
  printf("Exit timestamp: %s\n\n", GetTimestamp().c_str());
  
  log << "\nOutput file: " << output_xml << "\n";
  log << "Backup copy: " << outputCopy << "\n";
  log << "\n=========================================================================\n";
  log << "|                    SESSION END (SUCCESS)                              |\n";
  log << "=========================================================================\n";
  log << "Exit timestamp: " << GetTimestamp() << "\n";
  log << "Exit code: 0\n";
  
  delete[] data;
  return 0;
}
