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
#include "IccAnalyzerValidation.h"
#include "IccAnalyzerSignatures.h"

//==============================================================================
// Round-Trip Tag Validation
//==============================================================================

int RoundTripAnalyze(const char *filename)
{
  printf("\n=== Round-Trip Tag Pair Analysis ===\n");
  printf("Profile: %s\n\n", filename);
  
  CIccFileIO io;
  if (!io.Open(filename, "rb")) {
    printf("Error opening file: %s\n", filename);
    return -1;
  }
  
  CIccProfile *pIcc = new CIccProfile;
  if (!pIcc->Read(&io)) {
    printf("Error reading ICC profile\n\n");
    printf("Profile failed validation. Try ninja mode: iccAnalyzer -n %s\n", filename);
    delete pIcc;
    io.Close();
    return -1;
  }
  io.Close();
  
  // Check device class
  icHeader *pHdr = &pIcc->m_Header;
  if (pHdr->deviceClass == icSigLinkClass) {
    printf("Device Class: DeviceLink\n");
    printf("Result: DeviceLink profiles are not round-tripable.\n\n");
    delete pIcc;
    return 0;
  }
  
  printf("Device Class: 0x%08X\n\n", pHdr->deviceClass);
  
  // Check tag pairs
  auto hasTag = [pIcc](icTagSignature sig) -> bool {
    return (pIcc->FindTag(sig) != nullptr);
  };
  
  // AToB/BToA pairs (v2/v4)
  bool hasAToB0 = hasTag(icSigAToB0Tag);
  bool hasBToA0 = hasTag(icSigBToA0Tag);
  bool hasAToB1 = hasTag(icSigAToB1Tag);
  bool hasBToA1 = hasTag(icSigBToA1Tag);
  bool hasAToB2 = hasTag(icSigAToB2Tag);
  bool hasBToA2 = hasTag(icSigBToA2Tag);
  
  // DToB/BToD pairs (v5)
  bool hasDToB0 = hasTag(icSigDToB0Tag);
  bool hasBToD0 = hasTag(icSigBToD0Tag);
  bool hasDToB1 = hasTag(icSigDToB1Tag);
  bool hasBToD1 = hasTag(icSigBToD1Tag);
  bool hasDToB2 = hasTag(icSigDToB2Tag);
  bool hasBToD2 = hasTag(icSigBToD2Tag);
  
  // Matrix/TRC tags
  bool hasMatrix =
    hasTag(icSigRedMatrixColumnTag) &&
    hasTag(icSigGreenMatrixColumnTag) &&
    hasTag(icSigBlueMatrixColumnTag) &&
    hasTag(icSigRedTRCTag) &&
    hasTag(icSigGreenTRCTag) &&
    hasTag(icSigBlueTRCTag);
  
  printf("Tag Pair Analysis:\n");
  printf("  AToB0/BToA0 (Perceptual):        %s %s  %s\n", 
         hasAToB0 ? "[[X]]" : "[ ]",
         hasBToA0 ? "[[X]]" : "[ ]",
         (hasAToB0 && hasBToA0) ? "[X] Round-trip capable" : "");
  printf("  AToB1/BToA1 (Rel. Colorimetric): %s %s  %s\n",
         hasAToB1 ? "[[X]]" : "[ ]",
         hasBToA1 ? "[[X]]" : "[ ]",
         (hasAToB1 && hasBToA1) ? "[X] Round-trip capable" : "");
  printf("  AToB2/BToA2 (Saturation):        %s %s  %s\n",
         hasAToB2 ? "[[X]]" : "[ ]",
         hasBToA2 ? "[[X]]" : "[ ]",
         (hasAToB2 && hasBToA2) ? "[X] Round-trip capable" : "");
  
  printf("\n  DToB0/BToD0 (Perceptual):        %s %s  %s\n",
         hasDToB0 ? "[[X]]" : "[ ]",
         hasBToD0 ? "[[X]]" : "[ ]",
         (hasDToB0 && hasBToD0) ? "[X] Round-trip capable" : "");
  printf("  DToB1/BToD1 (Rel. Colorimetric): %s %s  %s\n",
         hasDToB1 ? "[[X]]" : "[ ]",
         hasBToD1 ? "[[X]]" : "[ ]",
         (hasDToB1 && hasBToD1) ? "[X] Round-trip capable" : "");
  printf("  DToB2/BToD2 (Saturation):        %s %s  %s\n",
         hasDToB2 ? "[[X]]" : "[ ]",
         hasBToD2 ? "[[X]]" : "[ ]",
         (hasDToB2 && hasBToD2) ? "[X] Round-trip capable" : "");
  
  printf("\n  Matrix/TRC Tags:                 %s  %s\n",
         hasMatrix ? "[[X]]" : "[ ]",
         hasMatrix ? "[X] Round-trip capable" : "");
  
  // Overall result
  bool roundTripable =
    (hasAToB0 && hasBToA0) ||
    (hasAToB1 && hasBToA1) ||
    (hasAToB2 && hasBToA2) ||
    (hasDToB0 && hasBToD0) ||
    (hasDToB1 && hasBToD1) ||
    (hasDToB2 && hasBToD2) ||
    hasMatrix;
  
  printf("\n");
  if (roundTripable) {
    printf("[OK] RESULT: Profile supports round-trip validation\n");
  } else {
    printf("[ERR] RESULT: Profile does NOT support round-trip validation\n");
    printf("   (Missing symmetric AToB/BToA, DToB/BToD, or Matrix/TRC tag pairs)\n");
  }
  printf("\n");
  
  delete pIcc;
  return roundTripable ? 0 : 1;
}

//==============================================================================
// Recursive Directory Scanning
//==============================================================================

int RecursiveScan(const char *directory, bool quiet)
{
  DIR *dir = opendir(directory);
  if (!dir) {
    if (!quiet) {
      printf("Error opening directory: %s\n", directory);
    }
    return -1;
  }
  
  struct dirent *entry;
  int total = 0, valid = 0, invalid = 0, roundtrip = 0;
  
  if (!quiet) {
    printf("\n=== Recursive Profile Scan ===\n");
    printf("Directory: %s\n\n", directory);
  }
  
  while ((entry = readdir(dir)) != nullptr) {
    // Skip hidden files and parent/current directory
    if (entry->d_name[0] == '.') continue;
    
    // Build full path
    std::string fullPath = std::string(directory) + "/" + std::string(entry->d_name);
    
    // Check if it's a directory
    struct stat st;
    if (stat(fullPath.c_str(), &st) != 0) continue;
    
    if (S_ISDIR(st.st_mode)) {
      // Recurse into subdirectory
      int subResult = RecursiveScan(fullPath.c_str(), quiet);
      if (subResult >= 0) {
        (void)subResult; // Results printed by recursive call
      }
    } else {
      // Check if it's an ICC file
      size_t len = strlen(entry->d_name);
      if (len < 4) continue;
      
      const char *ext = entry->d_name + len - 4;
      if (strcasecmp(ext, ".icc") != 0 && strcasecmp(ext, ".icm") != 0) {
        if (len >= 5) {
          ext = entry->d_name + len - 5;
          if (strcasecmp(ext, ".iccp") != 0) continue;
        } else {
          continue;
        }
      }
      
      total++;
      
      // Try to load profile
      CIccFileIO io;
      if (!io.Open(fullPath.c_str(), "rb")) {
        if (!quiet) printf("  ✗ %s (cannot open)\n", fullPath.c_str());
        invalid++;
        continue;
      }
      
      CIccProfile *pIcc = new CIccProfile;
      if (!pIcc->Read(&io)) {
        if (!quiet) printf("  ✗ %s (invalid ICC)\n", fullPath.c_str());
        invalid++;
        delete pIcc;
        io.Close();
        continue;
      }
      io.Close();
      
      valid++;
      
      // Check if round-tripable
      icHeader *pHdr = &pIcc->m_Header;
      bool isRoundTrip = false;
      
      if (pHdr->deviceClass != icSigLinkClass) {
        auto hasTag = [pIcc](icTagSignature sig) -> bool {
          return (pIcc->FindTag(sig) != nullptr);
        };
        
        isRoundTrip =
          (hasTag(icSigAToB0Tag) && hasTag(icSigBToA0Tag)) ||
          (hasTag(icSigAToB1Tag) && hasTag(icSigBToA1Tag)) ||
          (hasTag(icSigAToB2Tag) && hasTag(icSigBToA2Tag)) ||
          (hasTag(icSigDToB0Tag) && hasTag(icSigBToD0Tag)) ||
          (hasTag(icSigDToB1Tag) && hasTag(icSigBToD1Tag)) ||
          (hasTag(icSigDToB2Tag) && hasTag(icSigBToD2Tag)) ||
          (hasTag(icSigRedMatrixColumnTag) &&
           hasTag(icSigGreenMatrixColumnTag) &&
           hasTag(icSigBlueMatrixColumnTag) &&
           hasTag(icSigRedTRCTag) &&
           hasTag(icSigGreenTRCTag) &&
           hasTag(icSigBlueTRCTag));
        
        if (isRoundTrip) roundtrip++;
      }
      
      if (!quiet) {
        printf("  [X] %s %s\n", fullPath.c_str(), isRoundTrip ? "[RT]" : "");
      }
      
      delete pIcc;
    }
  }
  
  closedir(dir);
  
  if (!quiet && total > 0) {
    printf("\n=== Scan Summary ===\n");
    printf("  Total ICC files:     %d\n", total);
    printf("  Valid profiles:      %d\n", valid);
    printf("  Invalid/malformed:   %d\n", invalid);
    printf("  Round-trip capable:  %d\n", roundtrip);
    printf("\n");
  }
  
  return total;
}
