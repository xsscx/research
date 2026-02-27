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
#include "IccAnalyzerSafeArithmetic.h"
#include "IccAnalyzerSecurity.h"
#include <cstring>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

// Open file with restricted permissions (0600) to prevent world-readable output.
static FILE *SecureFileOpen(const char *path, const char *mode) {
  int flags = O_WRONLY | O_CREAT | O_TRUNC;
  if (mode[0] == 'a') flags = O_WRONLY | O_CREAT | O_APPEND;
  int fd = open(path, flags, S_IRUSR | S_IWUSR);
  if (fd < 0) return nullptr;
  const char *fmode = (strchr(mode, 'b')) ? "wb" : "w";
  if (mode[0] == 'a') fmode = "a";
  FILE *f = fdopen(fd, fmode);
  if (!f) close(fd);
  return f;
}

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
  FILE *fInfo = SecureFileOpen(filename, "w");
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
      ICC_LOG_SAFE_VAL("mpeCLUT.grid", i, &dimSize, inputDim);
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
  FILE *fBin = SecureFileOpen(filename, "wb");
  if (fBin) {
    icFloatNumber *data = pCLUT->GetData(0);
    if (data) {
      icUInt32Number totalEntries = outputChannels;
      for (int i = 0; i < inputDim; i++) {
        icUInt32Number dimSize = pCLUT->GetDimSize(i);
        ICC_LOG_SAFE_VAL("mpeCLUT.grid", i, &dimSize, inputDim);
        if (dimSize > 0 && totalEntries > UINT32_MAX / dimSize) {
          printf("    MPE CLUT[%d]: Overflow detected, skipping\n", clutIndex);
          fclose(fBin);
          return;
        }
        totalEntries *= dimSize;
      }
      
      for (icUInt32Number i = 0; i < totalEntries; i++) {
        ICC_TRACE_NAN(data[i], "mpeCLUT.data");
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
      
      CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement*>(pTag);
      if (!pMPE) continue;
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
          CIccMpeCLUT *pMpeCLUT = dynamic_cast<CIccMpeCLUT*>(pElem);
          if (!pMpeCLUT) continue;
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

/** Extract LUT (Look-Up Table) data from all LUT tags in the profile. */
void ExtractLutTables(CIccProfile *pIcc, const char *baseFilename)
{
  // Iterate all tags, extracting curve and CLUT metadata for Lut8/Lut16 types
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
        pLut8 = dynamic_cast<CIccTagLut8*>(pTag);
      } else {
        pLut16 = dynamic_cast<CIccTagLut16*>(pTag);
      }
      if (!pLut8 && !pLut16) continue;
      
      char filename[512];
      
      // Extract Lut8 sub-components: input curves (A), CLUT grid, output curves (B)
      if (pLut8) {
        CIccCLUT *pCLUT = pLut8->GetCLUT();
        LPIccCurve *pCurvesA = pLut8->GetCurvesA();
        LPIccCurve *pCurvesB = pLut8->GetCurvesB();
        
        if (pCurvesA) {
          snprintf(filename, sizeof(filename), "%s_%s_curvesA.txt",
                  baseFilename, safeTag.c_str());
          FILE *f = SecureFileOpen(filename, "w");
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
          FILE *f = SecureFileOpen(filename, "w");
          if (f) {
            fprintf(f, "CLUT Data (8-bit)\n");
            fprintf(f, "Input Channels: %u\n", pCLUT->GetInputDim());
            fprintf(f, "Output Channels: %u\n", pCLUT->GetOutputChannels());
            for (int d = 0; d < pCLUT->GetInputDim(); d++) {
              fprintf(f, "Grid[%d]: %u\n", d, pCLUT->GetDimSize(d));
            }
            fclose(f);
            printf("  Wrote CLUT metadata: %s\n", filename);
          }
        }
        
        if (pCurvesB) {
          snprintf(filename, sizeof(filename), "%s_%s_curvesB.txt",
                  baseFilename, safeTag.c_str());
          FILE *f = SecureFileOpen(filename, "w");
          if (f) {
            fprintf(f, "Output Curves (B-curves)\n");
            fprintf(f, "Channels: %u\n", pLut8->OutputChannels());
            fclose(f);
            printf("  Wrote B-curves metadata: %s\n", filename);
          }
        }
      // Extract Lut16 sub-components similarly to Lut8
      } else if (pLut16) {
        CIccCLUT *pCLUT = pLut16->GetCLUT();
        LPIccCurve *pCurvesA = pLut16->GetCurvesA();
        LPIccCurve *pCurvesB = pLut16->GetCurvesB();
        
        if (pCurvesA) {
          snprintf(filename, sizeof(filename), "%s_%s_curvesA.txt",
                  baseFilename, safeTag.c_str());
          FILE *f = SecureFileOpen(filename, "w");
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
          FILE *f = SecureFileOpen(filename, "w");
          if (f) {
            fprintf(f, "CLUT Data (16-bit)\n");
            fprintf(f, "Input Channels: %u\n", pCLUT->GetInputDim());
            fprintf(f, "Output Channels: %u\n", pCLUT->GetOutputChannels());
            for (int d = 0; d < pCLUT->GetInputDim(); d++) {
              fprintf(f, "Grid[%d]: %u\n", d, pCLUT->GetDimSize(d));
            }
            fclose(f);
            printf("  Wrote CLUT metadata: %s\n", filename);
          }
        }
        
        if (pCurvesB) {
          snprintf(filename, sizeof(filename), "%s_%s_curvesB.txt",
                  baseFilename, safeTag.c_str());
          FILE *f = SecureFileOpen(filename, "w");
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
      FILE *f = SecureFileOpen(filename, "w");
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

/** Inject CLUT data into a profile LUT tag and save to output file. */
int InjectLutDataInternal(const char *profileFile, const char *outputFile, const char *clutFile)
{
  // Validate input file paths
  if (IccAnalyzerSecurity::ValidateFilePath(profileFile,
        IccAnalyzerSecurity::PathValidationMode::STRICT, true, {".icc", ".icm"})
        != IccAnalyzerSecurity::PathValidationResult::VALID ||
      IccAnalyzerSecurity::ValidateFilePath(clutFile,
        IccAnalyzerSecurity::PathValidationMode::STRICT, true)
        != IccAnalyzerSecurity::PathValidationResult::VALID) {
    printf("Error: invalid input file path\n");
    return -1;
  }

  // Open source profile and deserialize into CIccProfile for tag manipulation
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
      
      // Validate CLUT grid dimensions with overflow-safe multiplication
      if (tagType == icSigLut8Type) {
        CIccTagLut8 *pLut8 = dynamic_cast<CIccTagLut8*>(pTag);
        CIccCLUT *pCLUT = pLut8 ? pLut8->GetCLUT() : nullptr;
        
        if (!pCLUT) {
          printf("No CLUT in tag\n");
          fclose(f);
          continue;
        }
        
        uint64_t clutSize = 1;
        bool clutOverflow = false;
        for (int j = 0; j < pCLUT->GetInputDim(); j++) {
          if (!SafeMul64(&clutSize, clutSize, pCLUT->GetDimSize(j))) {
            clutOverflow = true;
            break;
          }
        }
        if (!clutOverflow) {
          if (!SafeMul64(&clutSize, clutSize, pCLUT->GetOutputChannels()))
            clutOverflow = true;
        }
        if (clutOverflow) {
          printf("CLUT size overflow detected\n");
          fclose(f);
          continue;
        }
        
        if ((long)clutSize != fileSize) {
          printf("CLUT size mismatch: expected %llu, got %ld\n",
                 (unsigned long long)clutSize, fileSize);
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
        
        // Convert 8-bit CLUT data to float [0.0, 1.0] range
        for (long j = 0; j < fileSize; j++) {
          pData[j] = (icFloatNumber)buffer[j] / 255.0f;
          ICC_TRACE_NAN(pData[j], "lut8.clutData");
        }
        
        delete[] buffer;
        modified = true;
        printf("Injected %ld bytes into CLUT\n", fileSize);
        
      // Handle Lut16 type: 16-bit CLUT data with big-endian byte swap
      } else if (tagType == icSigLut16Type) {
        CIccTagLut16 *pLut16 = dynamic_cast<CIccTagLut16*>(pTag);
        CIccCLUT *pCLUT = pLut16 ? pLut16->GetCLUT() : nullptr;
        
        if (!pCLUT) {
          printf("No CLUT in tag\n");
          fclose(f);
          continue;
        }
        
        uint64_t clutSize = 1;
        bool clutOverflow = false;
        for (int j = 0; j < pCLUT->GetInputDim(); j++) {
          if (!SafeMul64(&clutSize, clutSize, pCLUT->GetDimSize(j))) {
            clutOverflow = true;
            break;
          }
        }
        if (!clutOverflow) {
          if (!SafeMul64(&clutSize, clutSize, pCLUT->GetOutputChannels()))
            clutOverflow = true;
        }
        if (!clutOverflow) {
          if (!SafeMul64(&clutSize, clutSize, 2))
            clutOverflow = true;
        }
        if (clutOverflow) {
          printf("CLUT size overflow detected\n");
          fclose(f);
          continue;
        }
        
        if ((long)clutSize != fileSize) {
          printf("CLUT size mismatch: expected %llu, got %ld\n",
                 (unsigned long long)clutSize, fileSize);
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
          ICC_TRACE_NAN(pData[j], "lut16.clutData");
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

/** Inject MPE CLUT binary data into a profile and save to output file. */
int InjectMpeDataInternal(const char *profileFile, const char *outputFile, const char *clutFile)
{
  // Validate input file paths
  if (IccAnalyzerSecurity::ValidateFilePath(profileFile,
        IccAnalyzerSecurity::PathValidationMode::STRICT, true, {".icc", ".icm"})
        != IccAnalyzerSecurity::PathValidationResult::VALID ||
      IccAnalyzerSecurity::ValidateFilePath(clutFile,
        IccAnalyzerSecurity::PathValidationMode::STRICT, true)
        != IccAnalyzerSecurity::PathValidationResult::VALID) {
    printf("Error: invalid input file path\n");
    return -1;
  }

  // Load profile, read CLUT binary, inject into MultiProcessElement CLUT tags
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
      CIccTagMultiProcessElement *pMPE = dynamic_cast<CIccTagMultiProcessElement*>(pTag);
      if (!pMPE) continue;
      
      for (icUInt32Number elem = 0; elem < pMPE->NumElements(); elem++) {
        CIccMultiProcessElement *pElem = pMPE->GetElement(elem);
        if (!pElem || pElem->GetType() != icSigCLutElemType) continue;
        
        CIccMpeCLUT *pMpeCLUT = dynamic_cast<CIccMpeCLUT*>(pElem);
        if (!pMpeCLUT) continue;
        CIccCLUT *pCLUT = pMpeCLUT->GetCLUT();
        if (!pCLUT) continue;
        
        int inputDim = pCLUT->GetInputDim();
        int outputChannels = pCLUT->GetOutputChannels();
        uint64_t expectedSize = outputChannels;
        bool sizeOverflow = false;
        for (int d = 0; d < inputDim; d++) {
          if (!SafeMul64(&expectedSize, expectedSize, pCLUT->GetDimSize(d))) {
            sizeOverflow = true;
            break;
          }
        }
        
        if (sizeOverflow) { continue; }
        long actualSize = fileSize / 2;
        if ((uint64_t)actualSize != expectedSize) {
          printf("  Tag %s Element[%u]: Size mismatch (expected %llu, got %ld)\n",
                 info.GetTagSigName((*i).TagInfo.sig), elem,
                 (unsigned long long)expectedSize, actualSize);
          continue;
        }
        
        printf("  Tag %s Element[%u]: Injecting CLUT (%llu entries)\n",
               info.GetTagSigName((*i).TagInfo.sig), elem,
               (unsigned long long)expectedSize);
        
        // Byte-swap 16-bit big-endian CLUT entries and normalize to float [0.0, 1.0]
        icFloatNumber *data = pCLUT->GetData(0);
        if (!data) {
          printf("  Tag %s Element[%u]: No CLUT data available\n",
                 info.GetTagSigName((*i).TagInfo.sig), elem);
          continue;
        }
        for (uint64_t idx = 0; idx < expectedSize; idx++) {
          icUInt16Number bigEndian = buffer[idx];
          icUInt16Number littleEndian = ((bigEndian >> 8) & 0xff) | ((bigEndian << 8) & 0xff00);
          data[idx] = littleEndian / 65535.0f;
        }
        
        tagsModified++;
      }
    }
  }
  
  delete[] buffer;
  
  // Write modified profile to output file if any CLUT elements were injected
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

/** Extract all LUT and MPE data from an ICC profile to files. */
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

/** Inject LUT CLUT data from command-line arguments. */
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

/** Inject MPE CLUT data into profile — delegates to InjectMpeDataInternal. */
int InjectMpeData(const char *profileFile, const char *outputFile, const char *clutFile)
{
  return InjectMpeDataInternal(profileFile, outputFile, clutFile);
}
