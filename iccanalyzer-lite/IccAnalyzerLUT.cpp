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
#include "IccAnalyzerLUT.h"
#include <cstring>

// Sanitize tag name for safe use in filenames — strips path separators
// and non-printable characters to prevent path traversal via crafted profiles.
static std::string SanitizeTagName(const char *raw) {
  std::string out;
  if (!raw) return "unknown";
  for (const char *p = raw; *p; ++p) {
    char c = *p;
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
        (c >= '0' && c <= '9') || c == '_' || c == '-')
      out += c;
    else
      out += '_';
  }
  return out.empty() ? "unknown" : out;
}

//==============================================================================
// MPE (Multi-Process Element) Extraction Functions
//==============================================================================

void ExtractMpeCLUT(CIccMpeCLUT *pMpeCLUT, const char *tagName, const char *baseFilename, int clutIndex)
{
  std::string safeTag = SanitizeTagName(tagName);
  char filename[512];
  CIccCLUT *pCLUT = pMpeCLUT->GetCLUT();
  
  if (!pCLUT) {
    printf("    MPE CLUT[%d]: No CLUT data\n", clutIndex);
    return;
  }
  
  int inputDim = pCLUT->GetInputDim();
  int outputChannels = pCLUT->GetOutputChannels();
  
  snprintf(filename, sizeof(filename), "%s_%s_mpe_clut%d_info.txt",
           baseFilename, safeTag.c_str(), clutIndex);
  FILE *fInfo = fopen(filename, "w");
  if (fInfo) {
    fprintf(fInfo, "MPE CLUT Data\n");
    fprintf(fInfo, "Input Dimensions: %d\n", inputDim);
    fprintf(fInfo, "Output Channels: %d\n", outputChannels);
    for (int i = 0; i < inputDim; i++) {
      fprintf(fInfo, "Grid[%d]: %u\n", i, pCLUT->GetDimSize(i));
    }
    
    icUInt32Number totalEntries = outputChannels;
    for (int i = 0; i < inputDim; i++) {
      icUInt32Number dimSize = pCLUT->GetDimSize(i);
      if (dimSize > 0 && totalEntries > UINT32_MAX / dimSize) {
        fprintf(fInfo, "Warning: Total entries overflow\n");
        totalEntries = 0;
        break;
      }
      totalEntries *= dimSize;
    }
    fprintf(fInfo, "Total Entries: %u\n", totalEntries);
    fclose(fInfo);
    printf("    Wrote MPE CLUT[%d] info: %s\n", clutIndex, filename);
  }
  
  snprintf(filename, sizeof(filename), "%s_%s_mpe_clut%d.bin",
           baseFilename, safeTag.c_str(), clutIndex);
  FILE *fBin = fopen(filename, "wb");
  if (fBin) {
    icFloatNumber *data = pCLUT->GetData(0);
    if (data) {
      icUInt32Number totalEntries = outputChannels;
      for (int i = 0; i < inputDim; i++) {
        icUInt32Number dimSize = pCLUT->GetDimSize(i);
        if (dimSize > 0 && totalEntries > UINT32_MAX / dimSize) {
          printf("    MPE CLUT[%d]: Overflow detected, skipping\n", clutIndex);
          fclose(fBin);
          return;
        }
        totalEntries *= dimSize;
      }
      
      for (icUInt32Number i = 0; i < totalEntries; i++) {
        icUInt16Number val = (icUInt16Number)(data[i] * 65535.0f + 0.5f);
        icUInt16Number bigEndian = ((val >> 8) & 0xff) | ((val << 8) & 0xff00);
        if (fwrite(&bigEndian, sizeof(icUInt16Number), 1, fBin) != 1) {
          printf("    Warning: Write error at entry %u\n", i);
          break;
        }
      }
      fclose(fBin);
      printf("    Wrote MPE CLUT[%d] binary: %s (%u uint16 values)\n", clutIndex, filename, totalEntries);
    } else {
      fclose(fBin);
      printf("    MPE CLUT[%d]: No data available\n", clutIndex);
    }
  }
}

void ExtractMpeTables(CIccProfile *pIcc, const char *baseFilename)
{
  CIccInfo info;
  int mpeCount = 0;
  
  TagEntryList::iterator i;
  for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
    CIccTag *pTag = pIcc->FindTag((*i).TagInfo.sig);
    if (!pTag) continue;
    
    icTagTypeSignature tagType = pTag->GetType();
    
    if (tagType == icSigMultiProcessElementType) {
      printf("\nExtracting MPE from tag: %s (type: %s)\n", 
             info.GetTagSigName((*i).TagInfo.sig),
             info.GetTagTypeSigName(tagType));
      
      CIccTagMultiProcessElement *pMPE = (CIccTagMultiProcessElement*)pTag;
      icUInt32Number numElements = pMPE->NumElements();
      
      printf("  MultiProcessElement: %u elements\n", numElements);
      printf("  Input channels: %u, Output channels: %u\n", 
             pMPE->NumInputChannels(), pMPE->NumOutputChannels());
      
      int clutCount = 0;
      for (icUInt32Number elem = 0; elem < numElements; elem++) {
        CIccMultiProcessElement *pElem = pMPE->GetElement(elem);
        if (!pElem) continue;
        
        icElemTypeSignature elemType = pElem->GetType();
        
        if (elemType == icSigCLutElemType) {
          printf("  Element[%u]: CLUT\n", elem);
          CIccMpeCLUT *pMpeCLUT = (CIccMpeCLUT*)pElem;
          ExtractMpeCLUT(pMpeCLUT, info.GetTagSigName((*i).TagInfo.sig), baseFilename, clutCount);
          clutCount++;
        } else {
          printf("  Element[%u]: %s (not a CLUT)\n", elem, pElem->GetClassName());
        }
      }
      
      if (clutCount > 0) {
        mpeCount++;
      }
    }
  }
  
  if (mpeCount == 0) {
    printf("No MPE tags with CLUT elements found\n");
  }
}

//==============================================================================
// Legacy LUT Extraction Functions
//==============================================================================

void ExtractLutTables(CIccProfile *pIcc, const char *baseFilename)
{
  CIccInfo info;
  int lutCount = 0;
  
  TagEntryList::iterator i;
  for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
    CIccTag *pTag = pIcc->FindTag((*i).TagInfo.sig);
    if (!pTag) continue;
    
    icTagTypeSignature tagType = pTag->GetType();
    
    if (tagType == icSigLut8Type || tagType == icSigLut16Type) {
      const char *rawTagName = info.GetTagSigName((*i).TagInfo.sig);
      std::string safeTag = SanitizeTagName(rawTagName);
      printf("\nExtracting LUT from tag: %s\n", rawTagName);
      
      CIccTagLut8 *pLut8 = NULL;
      CIccTagLut16 *pLut16 = NULL;
      
      if (tagType == icSigLut8Type) {
        pLut8 = (CIccTagLut8*)pTag;
      } else {
        pLut16 = (CIccTagLut16*)pTag;
      }
      
      char filename[512];
      
      if (pLut8) {
        CIccCLUT *pCLUT = pLut8->GetCLUT();
        LPIccCurve *pCurvesA = pLut8->GetCurvesA();
        LPIccCurve *pCurvesB = pLut8->GetCurvesB();
        
        if (pCurvesA) {
          snprintf(filename, sizeof(filename), "%s_%s_curvesA.txt",
                  baseFilename, safeTag.c_str());
          FILE *f = fopen(filename, "w");
          if (f) {
            fprintf(f, "Input Curves (A-curves)\n");
            fprintf(f, "Channels: %u\n", pLut8->InputChannels());
            fclose(f);
            printf("  Wrote A-curves metadata: %s\n", filename);
          }
        }
        
        if (pCLUT) {
          snprintf(filename, sizeof(filename), "%s_%s_clut.txt",
                  baseFilename, safeTag.c_str());
          FILE *f = fopen(filename, "w");
          if (f) {
            fprintf(f, "CLUT Data (8-bit)\n");
            fprintf(f, "Input Channels: %u\n", pCLUT->GetInputDim());
            fprintf(f, "Output Channels: %u\n", pCLUT->GetOutputChannels());
            for (int i = 0; i < pCLUT->GetInputDim(); i++) {
              fprintf(f, "Grid[%d]: %u\n", i, pCLUT->GetDimSize(i));
            }
            fclose(f);
            printf("  Wrote CLUT metadata: %s\n", filename);
          }
        }
        
        if (pCurvesB) {
          snprintf(filename, sizeof(filename), "%s_%s_curvesB.txt",
                  baseFilename, safeTag.c_str());
          FILE *f = fopen(filename, "w");
          if (f) {
            fprintf(f, "Output Curves (B-curves)\n");
            fprintf(f, "Channels: %u\n", pLut8->OutputChannels());
            fclose(f);
            printf("  Wrote B-curves metadata: %s\n", filename);
          }
        }
      } else if (pLut16) {
        CIccCLUT *pCLUT = pLut16->GetCLUT();
        LPIccCurve *pCurvesA = pLut16->GetCurvesA();
        LPIccCurve *pCurvesB = pLut16->GetCurvesB();
        
        if (pCurvesA) {
          snprintf(filename, sizeof(filename), "%s_%s_curvesA.txt",
                  baseFilename, safeTag.c_str());
          FILE *f = fopen(filename, "w");
          if (f) {
            fprintf(f, "Input Curves (A-curves)\n");
            fprintf(f, "Channels: %u\n", pLut16->InputChannels());
            fclose(f);
            printf("  Wrote A-curves metadata: %s\n", filename);
          }
        }
        
        if (pCLUT) {
          snprintf(filename, sizeof(filename), "%s_%s_clut.txt",
                  baseFilename, safeTag.c_str());
          FILE *f = fopen(filename, "w");
          if (f) {
            fprintf(f, "CLUT Data (16-bit)\n");
            fprintf(f, "Input Channels: %u\n", pCLUT->GetInputDim());
            fprintf(f, "Output Channels: %u\n", pCLUT->GetOutputChannels());
            for (int i = 0; i < pCLUT->GetInputDim(); i++) {
              fprintf(f, "Grid[%d]: %u\n", i, pCLUT->GetDimSize(i));
            }
            fclose(f);
            printf("  Wrote CLUT metadata: %s\n", filename);
          }
        }
        
        if (pCurvesB) {
          snprintf(filename, sizeof(filename), "%s_%s_curvesB.txt",
                  baseFilename, safeTag.c_str());
          FILE *f = fopen(filename, "w");
          if (f) {
            fprintf(f, "Output Curves (B-curves)\n");
            fprintf(f, "Channels: %u\n", pLut16->OutputChannels());
            fclose(f);
            printf("  Wrote B-curves metadata: %s\n", filename);
          }
        }
      }
      
      snprintf(filename, sizeof(filename), "%s_%s_lut_info.txt",
              baseFilename, safeTag.c_str());
      FILE *f = fopen(filename, "w");
      if (f) {
        fprintf(f, "LUT Tag: %s\n", info.GetTagSigName((*i).TagInfo.sig));
        fprintf(f, "Type: %s\n", info.GetTagTypeSigName(tagType));
        if (pLut8) {
          fprintf(f, "Input Channels: %u\n", pLut8->InputChannels());
          fprintf(f, "Output Channels: %u\n", pLut8->OutputChannels());
        } else if (pLut16) {
          fprintf(f, "Input Channels: %u\n", pLut16->InputChannels());
          fprintf(f, "Output Channels: %u\n", pLut16->OutputChannels());
        }
        fclose(f);
        printf("  Wrote metadata: %s\n", filename);
      }
      
      lutCount++;
    }
  }
  
  if (lutCount == 0) {
    printf("\nNo LUT tags found in profile\n");
  } else {
    printf("\nExtracted %d LUT tag(s)\n", lutCount);
  }
}

//==============================================================================
// Legacy LUT Injection Functions
//==============================================================================

int InjectLutDataInternal(const char *profileFile, const char *outputFile, const char *clutFile)
{
  CIccFileIO io;
  if (!io.Open(profileFile, "rb")) {
    printf("Error opening profile: %s\n", profileFile);
    return -1;
  }
  
  CIccProfile *pIcc = new CIccProfile;
  if (!pIcc->Read(&io)) {
    printf("Error reading ICC profile\n");
    delete pIcc;
    return -1;
  }
  io.Close();
  
  bool modified = false;
  CIccInfo info;
  
  TagEntryList::iterator i;
  for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
    CIccTag *pTag = pIcc->FindTag((*i).TagInfo.sig);
    if (!pTag) continue;
    
    icTagTypeSignature tagType = pTag->GetType();
    
    if (tagType == icSigLut8Type || tagType == icSigLut16Type) {
      printf("Found LUT tag: %s\n", info.GetTagSigName((*i).TagInfo.sig));
      
      FILE *f = fopen(clutFile, "rb");
      if (!f) {
        printf("Cannot open CLUT file: %s\n", clutFile);
        continue;
      }
      
      fseek(f, 0, SEEK_END);
      long fileSize = ftell(f);
      fseek(f, 0, SEEK_SET);
      
      if (tagType == icSigLut8Type) {
        CIccTagLut8 *pLut8 = (CIccTagLut8*)pTag;
        CIccCLUT *pCLUT = pLut8->GetCLUT();
        
        if (!pCLUT) {
          printf("No CLUT in tag\n");
          fclose(f);
          continue;
        }
        
        icUInt32Number clutSize = 1;
        for (int j = 0; j < pCLUT->GetInputDim(); j++) {
          icUInt32Number dimSize = pCLUT->GetDimSize(j);
          if (dimSize > 0 && clutSize > UINT32_MAX / dimSize) {
            printf("CLUT size overflow detected\n");
            fclose(f);
            continue;
          }
          clutSize *= dimSize;
        }
        icUInt32Number outChannels = pCLUT->GetOutputChannels();
        if (outChannels > 0 && clutSize > UINT32_MAX / outChannels) {
          printf("CLUT size overflow detected\n");
          fclose(f);
          continue;
        }
        clutSize *= outChannels;
        
        if ((long)clutSize != fileSize) {
          printf("CLUT size mismatch: expected %u, got %ld\n", clutSize, fileSize);
          fclose(f);
          continue;
        }
        
        icFloatNumber *pData = pCLUT->GetData(0);
        if (!pData) {
          printf("Cannot access CLUT data\n");
          fclose(f);
          continue;
        }
        
        icUInt8Number *buffer = new icUInt8Number[fileSize];
        size_t bytesRead = fread(buffer, 1, fileSize, f);
        fclose(f);
        
        if ((long)bytesRead != fileSize) {
          printf("Read error: expected %ld bytes, got %zu\n", fileSize, bytesRead);
          delete[] buffer;
          continue;
        }
        
        for (long j = 0; j < fileSize; j++) {
          pData[j] = (icFloatNumber)buffer[j] / 255.0f;
        }
        
        delete[] buffer;
        modified = true;
        printf("Injected %ld bytes into CLUT\n", fileSize);
        
      } else if (tagType == icSigLut16Type) {
        CIccTagLut16 *pLut16 = (CIccTagLut16*)pTag;
        CIccCLUT *pCLUT = pLut16->GetCLUT();
        
        if (!pCLUT) {
          printf("No CLUT in tag\n");
          fclose(f);
          continue;
        }
        
        icUInt32Number clutSize = 1;
        for (int j = 0; j < pCLUT->GetInputDim(); j++) {
          icUInt32Number dimSize = pCLUT->GetDimSize(j);
          if (dimSize > 0 && clutSize > UINT32_MAX / dimSize) {
            printf("CLUT size overflow detected\n");
            fclose(f);
            continue;
          }
          clutSize *= dimSize;
        }
        icUInt32Number outChannels = pCLUT->GetOutputChannels();
        if (outChannels > 0 && clutSize > UINT32_MAX / outChannels) {
          printf("CLUT size overflow detected\n");
          fclose(f);
          continue;
        }
        clutSize *= outChannels;
        if (clutSize > UINT32_MAX / 2) {
          printf("CLUT size overflow detected (×2)\n");
          fclose(f);
          continue;
        }
        clutSize *= 2;
        
        if ((long)clutSize != fileSize) {
          printf("CLUT size mismatch: expected %u, got %ld\n", clutSize, fileSize);
          fclose(f);
          continue;
        }
        
        icFloatNumber *pData = pCLUT->GetData(0);
        if (!pData) {
          printf("Cannot access CLUT data\n");
          fclose(f);
          continue;
        }
        
        icUInt16Number *buffer = new icUInt16Number[fileSize / 2];
        size_t itemsRead = fread(buffer, 2, fileSize / 2, f);
        fclose(f);
        
        if ((long)itemsRead != fileSize / 2) {
          printf("Read error: expected %ld items, got %zu\n", fileSize / 2, itemsRead);
          delete[] buffer;
          continue;
        }
        
        for (long j = 0; j < fileSize / 2; j++) {
          icUInt16Number val = buffer[j];
          val = ((val >> 8) & 0xff) | ((val << 8) & 0xff00);
          pData[j] = (icFloatNumber)val / 65535.0f;
        }
        
        delete[] buffer;
        modified = true;
        printf("Injected %ld bytes into CLUT\n", fileSize);
      }
    }
  }
  
  if (!modified) {
    printf("No LUT tags modified\n");
    delete pIcc;
    return -1;
  }
  
  CIccFileIO outIO;
  if (!outIO.Open(outputFile, "wb")) {
    printf("Error opening output file: %s\n", outputFile);
    delete pIcc;
    return -1;
  }
  
  if (!pIcc->Write(&outIO)) {
    printf("Error writing modified profile\n");
    delete pIcc;
    return -1;
  }
  
  outIO.Close();
  delete pIcc;
  
  printf("Modified profile written to: %s\n", outputFile);
  return 0;
}

//==============================================================================
// MPE (Multi-Process Element) Injection Functions
//==============================================================================

int InjectMpeDataInternal(const char *profileFile, const char *outputFile, const char *clutFile)
{
  printf("=== Injecting MPE CLUT data ===\n");
  printf("Input profile: %s\n", profileFile);
  printf("CLUT file: %s\n", clutFile);
  printf("Output profile: %s\n\n", outputFile);
  
  CIccProfile *pIcc = OpenIccProfile(profileFile);
  if (!pIcc) return -1;
  
  FILE *f = fopen(clutFile, "rb");
  if (!f) {
    printf("Error opening CLUT file: %s\n", clutFile);
    delete pIcc;
    return -1;
  }
  
  fseek(f, 0, SEEK_END);
  long fileSize = ftell(f);
  fseek(f, 0, SEEK_SET);
  
  if (fileSize == 0 || fileSize > 100000000) {
    printf("Invalid CLUT file size: %ld\n", fileSize);
    fclose(f);
    delete pIcc;
    return -1;
  }
  
  icUInt16Number *buffer = new icUInt16Number[fileSize / 2];
  size_t itemsRead = fread(buffer, 2, fileSize / 2, f);
  fclose(f);
  
  if ((long)itemsRead != fileSize / 2) {
    printf("Read error: expected %ld items, got %zu\n", fileSize / 2, itemsRead);
    delete[] buffer;
    delete pIcc;
    return -1;
  }
  
  int tagsModified = 0;
  CIccInfo info;
  
  TagEntryList::iterator i;
  for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
    CIccTag *pTag = pIcc->FindTag((*i).TagInfo.sig);
    if (!pTag) continue;
    
    if (pTag->GetType() == icSigMultiProcessElementType) {
      CIccTagMultiProcessElement *pMPE = (CIccTagMultiProcessElement*)pTag;
      
      for (icUInt32Number elem = 0; elem < pMPE->NumElements(); elem++) {
        CIccMultiProcessElement *pElem = pMPE->GetElement(elem);
        if (!pElem || pElem->GetType() != icSigCLutElemType) continue;
        
        CIccMpeCLUT *pMpeCLUT = (CIccMpeCLUT*)pElem;
        CIccCLUT *pCLUT = pMpeCLUT->GetCLUT();
        if (!pCLUT) continue;
        
        int inputDim = pCLUT->GetInputDim();
        int outputChannels = pCLUT->GetOutputChannels();
        long long expectedSize = outputChannels; bool sizeOverflow = false;
        for (int d = 0; d < inputDim; d++) {
          long long dimSz = pCLUT->GetDimSize(d); if (dimSz > 0 && expectedSize > INT32_MAX / dimSz) { sizeOverflow = true; break; } expectedSize *= dimSz;
        }
        
        if (sizeOverflow) { continue; }
        long actualSize = fileSize / 2;
        if (actualSize != expectedSize) {
          printf("  Tag %s Element[%u]: Size mismatch (expected %lld, got %ld)\n",
                 info.GetTagSigName((*i).TagInfo.sig), elem, expectedSize, actualSize);
          continue;
        }
        
        printf("  Tag %s Element[%u]: Injecting CLUT (%lld entries)\n",
               info.GetTagSigName((*i).TagInfo.sig), elem, expectedSize);
        
        icFloatNumber *data = pCLUT->GetData(0);
        for (int idx = 0; idx < expectedSize; idx++) {
          icUInt16Number bigEndian = buffer[idx];
          icUInt16Number littleEndian = ((bigEndian >> 8) & 0xff) | ((bigEndian << 8) & 0xff00);
          data[idx] = littleEndian / 65535.0f;
        }
        
        tagsModified++;
      }
    }
  }
  
  delete[] buffer;
  
  if (tagsModified > 0) {
    CIccFileIO io;
    if (!io.Open(outputFile, "wb")) {
      printf("Error creating output file: %s\n", outputFile);
      delete pIcc;
      return -1;
    }
    
    if (!pIcc->Write(&io)) {
      printf("Error writing profile\n");
      delete pIcc;
      return -1;
    }
    
    printf("\nSuccessfully wrote modified profile\n");
  } else {
    printf("No MPE CLUT elements modified\n");
  }
  
  delete pIcc;
  return 0;
}

//==============================================================================
// Public API Functions
//==============================================================================

int ExtractLutData(const char *filename, const char *baseFilename)
{
  CIccFileIO io;
  if (!io.Open(filename, "rb")) {
    printf("Error opening file: %s\n", filename);
    return -1;
  }
  
  CIccProfile *pIcc = new CIccProfile;
  if (!pIcc->Read(&io)) {
    printf("Error reading ICC profile\n");
    delete pIcc;
    return -1;
  }
  
  printf("=== Extracting LUTs from: %s ===\n", filename);
  
  printf("\n--- Legacy LUT Tags (lut8/lut16) ---\n");
  ExtractLutTables(pIcc, baseFilename);
  
  printf("\n--- Modern MPE Tags (lutAtoB/lutBtoA) ---\n");
  ExtractMpeTables(pIcc, baseFilename);
  
  delete pIcc;
  return 0;
}

int InjectLutData(int argc, char *argv[])
{
  if (argc < 5) {
    printf("Usage: iccAnalyzer -i <profile.icc> <clut.bin> <output.icc>\n");
    return -1;
  }
  
  const char *profileFile = argv[2];
  const char *clutFile = argv[3];
  const char *outputFile = argv[4];
  
  printf("=== Injecting CLUT data ===\n");
  printf("Input profile: %s\n", profileFile);
  printf("CLUT file: %s\n", clutFile);
  printf("Output profile: %s\n\n", outputFile);
  
  return InjectLutDataInternal(profileFile, outputFile, clutFile);
}

int InjectMpeLutData(int argc, char *argv[])
{
  if (argc < 5) {
    printf("Usage: iccAnalyzer -im <profile.icc> <clut.bin> <output.icc>\n");
    return -1;
  }
  
  const char *profileFile = argv[2];
  const char *clutFile = argv[3];
  const char *outputFile = argv[4];
  
  return InjectMpeDataInternal(profileFile, outputFile, clutFile);
}

int InjectMpeData(const char *profileFile, const char *outputFile, const char *clutFile)
{
  printf("=== Injecting MPE CLUT data ===\n");
  printf("Input profile: %s\n", profileFile);
  printf("CLUT file: %s\n", clutFile);
  printf("Output profile: %s\n\n", outputFile);
  
  CIccProfile *pIcc = OpenIccProfile(profileFile);
  if (!pIcc) return -1;
  
  FILE *f = fopen(clutFile, "rb");
  if (!f) {
    printf("Error opening CLUT file: %s\n", clutFile);
    delete pIcc;
    return -1;
  }
  
  fseek(f, 0, SEEK_END);
  long fileSize = ftell(f);
  fseek(f, 0, SEEK_SET);
  
  if (fileSize == 0 || fileSize > 100000000) {
    printf("Invalid CLUT file size: %ld\n", fileSize);
    fclose(f);
    delete pIcc;
    return -1;
  }
  
  icUInt16Number *buffer = new icUInt16Number[fileSize / 2];
  size_t itemsRead = fread(buffer, 2, fileSize / 2, f);
  fclose(f);
  
  if ((long)itemsRead != fileSize / 2) {
    printf("Read error: expected %ld items, got %zu\n", fileSize / 2, itemsRead);
    delete[] buffer;
    delete pIcc;
    return -1;
  }
  
  int tagsModified = 0;
  CIccInfo info;
  
  TagEntryList::iterator i;
  for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++) {
    CIccTag *pTag = pIcc->FindTag((*i).TagInfo.sig);
    if (!pTag) continue;
    
    if (pTag->GetType() == icSigMultiProcessElementType) {
      CIccTagMultiProcessElement *pMPE = (CIccTagMultiProcessElement*)pTag;
      
      for (icUInt32Number elem = 0; elem < pMPE->NumElements(); elem++) {
        CIccMultiProcessElement *pElem = pMPE->GetElement(elem);
        if (!pElem || pElem->GetType() != icSigCLutElemType) continue;
        
        CIccMpeCLUT *pMpeCLUT = (CIccMpeCLUT*)pElem;
        CIccCLUT *pCLUT = pMpeCLUT->GetCLUT();
        if (!pCLUT) continue;
        
        int inputDim = pCLUT->GetInputDim();
        int outputChannels = pCLUT->GetOutputChannels();
        long long expectedSize = outputChannels; bool sizeOverflow = false;
        for (int d = 0; d < inputDim; d++) {
          long long dimSz = pCLUT->GetDimSize(d); if (dimSz > 0 && expectedSize > INT32_MAX / dimSz) { sizeOverflow = true; break; } expectedSize *= dimSz;
        }
        
        if (sizeOverflow) { continue; }
        long actualSize = fileSize / 2;
        if (actualSize != expectedSize) {
          printf("  Tag %s Element[%u]: Size mismatch (expected %lld, got %ld)\n",
                 info.GetTagSigName((*i).TagInfo.sig), elem, expectedSize, actualSize);
          continue;
        }
        
        printf("  Tag %s Element[%u]: Injecting CLUT (%lld entries)\n",
               info.GetTagSigName((*i).TagInfo.sig), elem, expectedSize);
        
        icFloatNumber *data = pCLUT->GetData(0);
        for (int idx = 0; idx < expectedSize; idx++) {
          icUInt16Number bigEndian = buffer[idx];
          icUInt16Number littleEndian = ((bigEndian >> 8) & 0xff) | ((bigEndian << 8) & 0xff00);
          data[idx] = littleEndian / 65535.0f;
        }
        
        tagsModified++;
      }
    }
  }
  
  delete[] buffer;
  
  if (tagsModified > 0) {
    CIccFileIO io;
    if (!io.Open(outputFile, "wb")) {
      printf("Error creating output file: %s\n", outputFile);
      delete pIcc;
      return -1;
    }
    
    if (!pIcc->Write(&io)) {
      printf("Error writing profile\n");
      delete pIcc;
      return -1;
    }
    
    printf("\nSuccessfully wrote modified profile\n");
  } else {
    printf("No MPE CLUT elements modified\n");
  }
  
  delete pIcc;
  return 0;
}
