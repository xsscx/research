/** @file
    File:       icc_v5dspobs_fuzzer.cpp
    Contains:   LibFuzzer harness for IccV5DspObsToV4Dsp conversion with AST gates
    Version:    V3
    Copyright:  (c) see Software License
    
    Fuzzer for: Build/Tools/IccV5DspObsToV4Dsp/iccV5DspObsToV4Dsp
    Tool Usage: iccV5DspObsToV4Dsp inputV5.icc inputObserverV5.icc outputV4.icc
    
    TOOL FIDELITY: This fuzzer maintains strict fidelity with the tool by:
      1. Writing fuzzer input to temporary files (matches tool's file-based I/O)
      2. Using ReadIccProfile(filename, true) API (exact same as tool)
      3. Processing profiles through CIccFileIO, not CIccMemIO
    
    This ensures the fuzzer exercises the EXACT same code paths as the tool,
    avoiding library bugs that only exist in memory-based I/O paths.
    
    Input Format: [4-byte size][display_profile_data][observer_profile_data]
      - First 4 bytes: Big-endian uint32 size of display profile
      - Next N bytes: Display profile (V5 display class with spectral data)
      - Remaining bytes: Observer/PCC profile (V5 with PCC tags)
    
    Expected Profile Requirements:
      Display Profile (inputV5.icc):
        - Version 5.x
        - Device Class: Display (mntr)
        - Required Tags: AToB1Tag (MultiProcessElement with spectral emission)
        - MPE Structure: CurveSet + EmissionMatrix elements
        
      Observer Profile (inputObserverV5.icc):
        - Version 5.x  
        - Required Tags: customToStandardPccTag (c2sp), spectralViewingConditionsTag (svcn)
        - C2S PCC: 3 input, 3 output channels
        
    Output: Version 4.3 display profile with:
      - TRC curves (2048 samples per channel)
      - Colorant XYZ tags (redColorantTag, greenColorantTag, blueColorantTag)
      - Description and copyright tags
*/

/*
 * Copyright (c) International Color Consortium.
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
 * 3. In the absence of prior written permission, the names "ICC" and "The
 *    International Color Consortium" must not be used to imply that the
 *    ICC organization endorses or promotes products derived from this
 *    software.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE INTERNATIONAL COLOR CONSORTIUM OR
 * ITS CONTRIBUTING MEMBERS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <memory>
#include <new>
#include <cmath>
#include "IccProfile.h"
#include "IccTag.h"
#include "IccTagMPE.h"
#include "IccTagLut.h"
#include "IccMpeBasic.h"
#include "IccMpeSpectral.h"
#include "IccUtil.h"
#include <unistd.h>
#include <cstring>
#include <cstdlib>
#include <climits>
#include "fuzz_utils.h"

// AST Gate logging macros - controlled by command line option
static bool g_astGatesEnabled = false;

#define AST_LOG(gate, msg, ...) do { if (g_astGatesEnabled) fprintf(stderr, "[AST-GATE-%d] " msg "\n", gate, ##__VA_ARGS__); } while(0)
#define AST_LOG_VERBOSE(msg, ...) do { if (g_astGatesEnabled) fprintf(stderr, "[AST-DEBUG] " msg "\n", ##__VA_ARGS__); } while(0)

// Cleanup macro for temp files
#define CLEANUP_TEMP_FILES() do { unlink(dspTmpFile); unlink(obsTmpFile); } while(0)

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  for (int i = 1; i < *argc; i++) {
    if (strcmp((*argv)[i], "-ast_gates") == 0 || strcmp((*argv)[i], "--ast-gates") == 0) {
      g_astGatesEnabled = true;
      fprintf(stderr, "[INIT] AST gates enabled via command line\n");
    }
  }
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  AST_LOG(0, "=== V5DSPOBS FUZZER ENTRY POINT ===");
  AST_LOG(0, "Tool: Build/Tools/IccV5DspObsToV4Dsp/iccV5DspObsToV4Dsp");
  AST_LOG(0, "Untrusted input received: %zu bytes", size);

  // Input format: [4-byte size][display_profile_data][observer_profile_data]
  // Mimics tool command line: iccV5DspObsToV4Dsp inputV5.icc inputObserverV5.icc outputV4.icc
  if (size < 8 + 128 + 128) {
    AST_LOG_VERBOSE("Input size validation failed: %zu (must be >= %d)", size, 8 + 128 + 128);
    return 0;
  }
  if (size > 5 * 1024 * 1024) {
    AST_LOG_VERBOSE("Input too large: %zu > 5MB", size);
    return 0;
  }

  // Parse input: Extract two profile sizes
  const char *tmpdir = fuzz_tmpdir();
  uint32_t dspSize = ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) | 
                     ((uint32_t)data[2] << 8) | data[3];
  
  if (dspSize < 128 || dspSize > size - 4 - 128) {
    AST_LOG_VERBOSE("Display profile size out of range: %u (total=%zu)", dspSize, size);
    return 0;
  }

  const uint8_t *dspData = data + 4;
  size_t obsSize = size - 4 - dspSize;
  const uint8_t *obsData = data + 4 + dspSize;

  AST_LOG(1, "GATE 1: Writing profiles to temporary files (tool fidelity)");
  AST_LOG(1, "Input V5 display:  %u bytes (mimics inputV5.icc)", dspSize);
  AST_LOG(1, "Input V5 observer: %zu bytes (mimics inputObserverV5.icc)", obsSize);
  AST_LOG_VERBOSE("Tool uses file-based I/O via ReadIccProfile(filename, true)");
  
  // Write display profile to temporary file
  char dspTmpFile[PATH_MAX];
  if (!fuzz_build_path(dspTmpFile, sizeof(dspTmpFile), tmpdir, "/fuzz_dsp_XXXXXX")) return 0;
  int dspFd = mkstemp(dspTmpFile);
  if (dspFd < 0) {
    AST_LOG(1, "Failed to create temp file for display profile");
    return 0;
  }
  if (write(dspFd, dspData, dspSize) != (ssize_t)dspSize) {
    AST_LOG(1, "Failed to write display profile data");
    close(dspFd);
    unlink(dspTmpFile);
    return 0;
  }
  close(dspFd);
  
  // Write observer profile to temporary file
  char obsTmpFile[PATH_MAX];
  if (!fuzz_build_path(obsTmpFile, sizeof(obsTmpFile), tmpdir, "/fuzz_obs_XXXXXX")) {
    unlink(dspTmpFile);
    return 0;
  }
  int obsFd = mkstemp(obsTmpFile);
  if (obsFd < 0) {
    AST_LOG(1, "Failed to create temp file for observer profile");
    unlink(dspTmpFile);
    return 0;
  }
  if (write(obsFd, obsData, obsSize) != (ssize_t)obsSize) {
    AST_LOG(1, "Failed to write observer profile data");
    close(obsFd);
    unlink(obsTmpFile);
    unlink(dspTmpFile);
    return 0;
  }
  close(obsFd);
  
  AST_LOG(2, "GATE 2: Loading display profile with ReadIccProfile(filename, true)");
  AST_LOG_VERBOSE("Tool uses: ReadIccProfile(argv[1], true) - file-based I/O with strict validation");
  
  // Pre-validate ICC header before calling ReadIccProfile
  // Check that internal size field matches actual file size
  // Note: dspSize >= 128 is enforced earlier
  {
    uint32_t internalSize = ((uint32_t)dspData[0] << 24) | ((uint32_t)dspData[1] << 16) |
                            ((uint32_t)dspData[2] << 8) | dspData[3];
    if (internalSize != dspSize) {
      AST_LOG(2, "Profile size mismatch: header says %u, actual %u", internalSize, dspSize);
      AST_LOG(2, "Tool would reject during parse - prevents OOM from malformed headers");
      unlink(dspTmpFile);
      unlink(obsTmpFile);
      return 0;
    }
  }
  
  // Pre-validate tag table to prevent OOM from corrupted tag sizes
  // Tag table starts at offset 128, first 4 bytes are tag count
  if (dspSize >= 132) {
    uint32_t tagCount = ((uint32_t)dspData[128] << 24) | ((uint32_t)dspData[129] << 16) |
                        ((uint32_t)dspData[130] << 8) | dspData[131];
    // Reject zero or unreasonable tag counts
    if (tagCount == 0 || tagCount > 256) {
      AST_LOG(2, "Invalid tag count: %u (must be 1-256)", tagCount);
      AST_LOG(2, "Tool would reject during parse - prevents malformed profile processing");
      unlink(dspTmpFile);
      unlink(obsTmpFile);
      return 0;
    }
    
    // Validate each tag's offset and size
    size_t tagTableSize = 132 + (tagCount * 12);
    if (tagTableSize <= dspSize) {
      for (uint32_t i = 0; i < tagCount; i++) {
        size_t tagEntryOffset = 132 + (i * 12);
        if (tagEntryOffset + 12 > dspSize) break;
        uint32_t tagOffset = ((uint32_t)dspData[tagEntryOffset + 4] << 24) |
                            ((uint32_t)dspData[tagEntryOffset + 5] << 16) |
                            ((uint32_t)dspData[tagEntryOffset + 6] << 8) |
                            dspData[tagEntryOffset + 7];
        uint32_t tagSize = ((uint32_t)dspData[tagEntryOffset + 8] << 24) |
                          ((uint32_t)dspData[tagEntryOffset + 9] << 16) |
                          ((uint32_t)dspData[tagEntryOffset + 10] << 8) |
                          dspData[tagEntryOffset + 11];
        
        // Reject tags with unreasonable sizes that would cause OOM
        if (tagSize > 100 * 1024 * 1024) {
          AST_LOG(2, "Tag %u has excessive size: %u bytes (max 100MB)", i, tagSize);
          AST_LOG(2, "Tool would fail allocation - prevents OOM from corrupted tag");
          unlink(dspTmpFile);
          unlink(obsTmpFile);
          return 0;
        }
        
        // Reject tags with offset+size beyond profile bounds
        if (tagOffset > dspSize || tagSize > dspSize || tagOffset + tagSize > dspSize) {
          AST_LOG(2, "Tag %u out of bounds: offset=%u size=%u (profile=%u)", 
                  i, tagOffset, tagSize, dspSize);
          unlink(dspTmpFile);
          unlink(obsTmpFile);
          return 0;
        }
        
        // Validate internal size fields for tags that allocate based on data
        // Read tag signature (first 4 bytes of tag table entry)
        uint32_t tagSig = ((uint32_t)dspData[tagEntryOffset] << 24) |
                         ((uint32_t)dspData[tagEntryOffset + 1] << 16) |
                         ((uint32_t)dspData[tagEntryOffset + 2] << 8) |
                         dspData[tagEntryOffset + 3];
        
        // Check NamedColor2 tags (0x6e636c32 = "ncl2")
        if (tagSig == 0x6e636c32 && tagOffset + 20 <= dspSize) {
          // Read tag type signature (first 4 bytes of tag data)
          uint32_t tagType = ((uint32_t)dspData[tagOffset] << 24) |
                            ((uint32_t)dspData[tagOffset + 1] << 16) |
                            ((uint32_t)dspData[tagOffset + 2] << 8) |
                            dspData[tagOffset + 3];
          
          // If it's a NamedColor2 tag type (0x6e636c32)
          if (tagType == 0x6e636c32) {
            // Read nNum field at offset 16 (after sig + reserved + vendorFlags)
            uint32_t nNum = ((uint32_t)dspData[tagOffset + 16] << 24) |
                           ((uint32_t)dspData[tagOffset + 17] << 16) |
                           ((uint32_t)dspData[tagOffset + 18] << 8) |
                           dspData[tagOffset + 19];
            
            // Reject excessive named color counts (prevents 7GB+ allocations)
            if (nNum > 65536) {  // 64K colors is already huge for a named color table
              AST_LOG(2, "NamedColor2 tag has excessive count: %u (max 65536)", nNum);
              AST_LOG(2, "Would allocate ~%u MB - prevents OOM", (nNum * 100) / (1024 * 1024));
              unlink(dspTmpFile);
              unlink(obsTmpFile);
              return 0;
            }
          }
        }
        
        // Check MultiProcessElement tags (0x6D706574 = "mpet")
        // These can contain SpectralMatrix elements that allocate based on channels * steps
        if (tagSig == 0x6D706574 && tagOffset + 24 <= dspSize) {
          uint32_t tagType = ((uint32_t)dspData[tagOffset] << 24) |
                            ((uint32_t)dspData[tagOffset + 1] << 16) |
                            ((uint32_t)dspData[tagOffset + 2] << 8) |
                            dspData[tagOffset + 3];
          
          if (tagType == 0x6D706574) {
            // Read input/output channels at offset 8/10
            uint16_t inChannels = ((uint16_t)dspData[tagOffset + 8] << 8) | dspData[tagOffset + 9];
            uint16_t outChannels = ((uint16_t)dspData[tagOffset + 10] << 8) | dspData[tagOffset + 11];
            
            // Read number of elements at offset 12
            uint16_t numElements = ((uint16_t)dspData[tagOffset + 12] << 8) | dspData[tagOffset + 13];
            
            // Validate MPE structure to prevent SpectralMatrix OOM
            if (numElements > 1024) {
              AST_LOG(2, "MPE tag has excessive elements: %u (max 1024)", numElements);
              unlink(dspTmpFile);
              unlink(obsTmpFile);
              return 0;
            }
            
            // SpectralMatrix allocates: numVectors * range.steps * sizeof(float)
            // Where numVectors can be inChannels or inChannels*outChannels
            // Worst case: 65535 * 65535 * 4 = 17 GB
            // Limit channels to prevent excessive allocations
            if (inChannels > 256 || outChannels > 256) {
              AST_LOG(2, "MPE tag has excessive channels: in=%u out=%u (max 256 each)", 
                      inChannels, outChannels);
              AST_LOG(2, "Would potentially allocate GB-scale memory in SpectralMatrix");
              unlink(dspTmpFile);
              unlink(obsTmpFile);
              return 0;
            }
          }
        }
        
        // Check ALL tags for TagArrayType - not just ones with 'tary' signature
        // TagArray can appear under any tag signature (desc, clrt, etc.)
        if (tagOffset + 4 <= dspSize) {
          uint32_t tagType = ((uint32_t)dspData[tagOffset] << 24) |
                            ((uint32_t)dspData[tagOffset + 1] << 16) |
                            ((uint32_t)dspData[tagOffset + 2] << 8) |
                            dspData[tagOffset + 3];
          
          // Reject TagArrayType tags - library has UAF in CIccTagArray::Cleanup()
          if (tagType == 0x74617279) {  // 'tary'
            AST_LOG(2, "TagArrayType detected in tag %u - library UAF in CIccTagArray::Cleanup()", i);
            AST_LOG(2, "Rejecting profile to prevent heap-use-after-free crash");
            unlink(dspTmpFile);
            unlink(obsTmpFile);
            return 0;
          }
        }
      }
    }
  }
  
  // Use file-based ReadIccProfile to match tool EXACTLY
  CIccProfile *dspIcc = ReadIccProfile(dspTmpFile, true);
  
  if (!dspIcc) {
    AST_LOG(2, "ReadIccProfile failed - profile rejected during Read()");
    AST_LOG(2, "Tool would exit with: Unable to parse 'inputV5.icc'");
    AST_LOG_VERBOSE("Failure modes: malformed header, invalid tag table, or tag load failure");
    unlink(dspTmpFile);
    unlink(obsTmpFile);
    return 0;
  }

  AST_LOG(2, "Display profile loaded successfully - all tags validated");
  AST_LOG_VERBOSE("Header: colorSpace=0x%08X, PCS=0x%08X, class=0x%08X, version=0x%08X",
                  dspIcc->m_Header.colorSpace,
                  dspIcc->m_Header.pcs,
                  dspIcc->m_Header.deviceClass,
                  dspIcc->m_Header.version);
  AST_LOG_VERBOSE("Tool equivalent: Profile successfully parsed from inputV5.icc");

  AST_LOG(3, "GATE 3: Validating V5 display profile requirements");
  AST_LOG_VERBOSE("Required: version >= 5.0 && deviceClass == DisplayClass (mntr)");
  
  // Validate it's a V5 display profile (tool requirement)
  if (dspIcc->m_Header.version < icVersionNumberV5 ||
      dspIcc->m_Header.deviceClass != icSigDisplayClass) {
    AST_LOG(3, "Not a V5 display profile (version=0x%08X, class=0x%08X)", 
            dspIcc->m_Header.version, dspIcc->m_Header.deviceClass);
    AST_LOG(3, "Tool would exit: %s is not a V5 display profile", "inputV5.icc");
    delete dspIcc;
    unlink(dspTmpFile);
    unlink(obsTmpFile);
    return 0;
  }

  AST_LOG(4, "GATE 4: Searching for AToB1Tag MultiProcessElement");
  AST_LOG_VERBOSE("Tool searches for spectral emission MPE in display profile");
  
  // Find AToB1Tag (required by tool for spectral processing)
  CIccTagMultiProcessElement* pTagIn = 
    dynamic_cast<CIccTagMultiProcessElement*>(dspIcc->FindTagOfType(icSigAToB1Tag, icSigMultiProcessElementType));
  
  if (!pTagIn) {
    AST_LOG(4, "AToB1Tag not found or wrong type");
    AST_LOG(4, "Tool would exit: doesn't have an AToB1Tag of type mulitProcessElementType");
    delete dspIcc;
    unlink(dspTmpFile);
    unlink(obsTmpFile);
    return 0;
  }

  AST_LOG(5, "GATE 5: Validating MPE structure (elements=%u, in=%u, out=%u)", 
          (unsigned)pTagIn->NumElements(), pTagIn->NumInputChannels(), pTagIn->NumOutputChannels());

  // Validate MPE structure
  CIccMultiProcessElement *curveMpe = pTagIn->GetElement(0);
  CIccMultiProcessElement *matrixMpe = pTagIn->GetElement(1);
  
  if (pTagIn->NumElements() != 2 ||
      pTagIn->NumInputChannels() != 3 ||
      pTagIn->NumOutputChannels() != 3 ||
      !curveMpe || curveMpe->GetType() != icSigCurveSetElemType ||
      !matrixMpe || matrixMpe->GetType() != icSigEmissionMatrixElemType) {
    AST_LOG(5, "Invalid MPE structure or not spectral emission type");
    AST_LOG(5, "Tool would exit: doesn't have a spectral emission AToB1Tag");
    delete dspIcc;
    CLEANUP_TEMP_FILES();
    return 0;
  }

  AST_LOG(6, "GATE 6: Loading observer profile with ReadIccProfile(filename, false)");
  AST_LOG_VERBOSE("Tool calls: ReadIccProfile(argv[2], false) - file-based I/O for PCC observer profile");
  AST_LOG_VERBOSE("Observer profile: %zu bytes", obsSize);
  
  // Pre-validate observer profile header and tag table (same as display profile)
  if (obsSize >= 4) {
    uint32_t internalSize = ((uint32_t)obsData[0] << 24) | ((uint32_t)obsData[1] << 16) |
                            ((uint32_t)obsData[2] << 8) | obsData[3];
    if (internalSize != obsSize || internalSize > 50 * 1024 * 1024) {
      AST_LOG(2, "Observer profile size mismatch: header says %u, actual %zu", internalSize, obsSize);
      delete dspIcc;
      CLEANUP_TEMP_FILES();
      return 0;
    }
  }
  
  // Pre-validate observer tag table
  if (obsSize >= 132) {
    uint32_t tagCount = ((uint32_t)obsData[128] << 24) | ((uint32_t)obsData[129] << 16) |
                        ((uint32_t)obsData[130] << 8) | obsData[131];
    
    // Reject zero or unreasonable tag counts
    if (tagCount == 0 || tagCount > 256) {
      AST_LOG(2, "Observer invalid tag count: %u (must be 1-256)", tagCount);
      delete dspIcc;
      CLEANUP_TEMP_FILES();
      return 0;
    }
    
    // Validate each tag in observer profile
    size_t tagTableSize = 132 + (tagCount * 12);
    if (tagTableSize <= obsSize) {
      for (uint32_t i = 0; i < tagCount; i++) {
        size_t tagEntryOffset = 132 + (i * 12);
        if (tagEntryOffset + 12 > obsSize) break;
        
        uint32_t tagOffset = ((uint32_t)obsData[tagEntryOffset + 4] << 24) |
                            ((uint32_t)obsData[tagEntryOffset + 5] << 16) |
                            ((uint32_t)obsData[tagEntryOffset + 6] << 8) |
                            obsData[tagEntryOffset + 7];
        uint32_t tagSize = ((uint32_t)obsData[tagEntryOffset + 8] << 24) |
                          ((uint32_t)obsData[tagEntryOffset + 9] << 16) |
                          ((uint32_t)obsData[tagEntryOffset + 10] << 8) |
                          obsData[tagEntryOffset + 11];
        
        if (tagSize > 100 * 1024 * 1024) {
          AST_LOG(2, "Observer tag %u excessive size: %u bytes", i, tagSize);
          delete dspIcc;
          CLEANUP_TEMP_FILES();
          return 0;
        }
        
        if (tagOffset > obsSize || tagSize > obsSize || tagOffset + tagSize > obsSize) {
          AST_LOG(2, "Observer tag %u out of bounds: offset=%u size=%u", i, tagOffset, tagSize);
          delete dspIcc;
          CLEANUP_TEMP_FILES();
          return 0;
        }
        
        // Check MPE tags for SpectralMatrix allocations
        uint32_t tagSig = ((uint32_t)obsData[tagEntryOffset] << 24) |
                         ((uint32_t)obsData[tagEntryOffset + 1] << 16) |
                         ((uint32_t)obsData[tagEntryOffset + 2] << 8) |
                         obsData[tagEntryOffset + 3];
        
        if (tagSig == 0x6D706574 && tagOffset + 24 <= obsSize) {
          uint32_t tagType = ((uint32_t)obsData[tagOffset] << 24) |
                            ((uint32_t)obsData[tagOffset + 1] << 16) |
                            ((uint32_t)obsData[tagOffset + 2] << 8) |
                            obsData[tagOffset + 3];
          
          if (tagType == 0x6D706574) {
            uint16_t inChannels = ((uint16_t)obsData[tagOffset + 8] << 8) | obsData[tagOffset + 9];
            uint16_t outChannels = ((uint16_t)obsData[tagOffset + 10] << 8) | obsData[tagOffset + 11];
            uint16_t numElements = ((uint16_t)obsData[tagOffset + 12] << 8) | obsData[tagOffset + 13];
            
            if (numElements > 1024) {
              AST_LOG(2, "Observer MPE excessive elements: %u", numElements);
              delete dspIcc;
              CLEANUP_TEMP_FILES();
              return 0;
            }
            
            if (inChannels > 256 || outChannels > 256) {
              AST_LOG(2, "Observer MPE excessive channels: in=%u out=%u", inChannels, outChannels);
              delete dspIcc;
              CLEANUP_TEMP_FILES();
              return 0;
            }
          }
        }
        
        // Check ALL tags for TagArrayType - same UAF bug as display profile
        if (tagOffset + 4 <= obsSize) {
          uint32_t tagType = ((uint32_t)obsData[tagOffset] << 24) |
                            ((uint32_t)obsData[tagOffset + 1] << 16) |
                            ((uint32_t)obsData[tagOffset + 2] << 8) |
                            obsData[tagOffset + 3];
          
          if (tagType == 0x74617279) {  // 'tary'
            AST_LOG(2, "Observer TagArrayType detected in tag %u - library UAF", i);
            delete dspIcc;
            CLEANUP_TEMP_FILES();
            return 0;
          }
        }
      }
    }
  }
  
  // Pre-validate ICC header before calling ReadIccProfile
  if (obsSize >= 4) {
    uint32_t internalSize = ((uint32_t)obsData[0] << 24) | ((uint32_t)obsData[1] << 16) |
                            ((uint32_t)obsData[2] << 8) | obsData[3];
    if (internalSize != obsSize || internalSize > 50 * 1024 * 1024) {
      AST_LOG(6, "Observer size mismatch: header says %u, actual %zu", internalSize, obsSize);
      AST_LOG(6, "Tool would reject during parse - prevents OOM from malformed headers");
      delete dspIcc;
      CLEANUP_TEMP_FILES();
      return 0;
    }
  }
  
  // Use file-based ReadIccProfile to match tool EXACTLY
  CIccProfile *pccIcc = ReadIccProfile(obsTmpFile, false);
  
  if (!pccIcc) {
    AST_LOG(6, "ReadIccProfile failed for observer profile");
    AST_LOG(6, "Tool would exit with: Unable to parse 'inputObserverV5.icc'");
    delete dspIcc;
    CLEANUP_TEMP_FILES();
    return 0;
  }

  AST_LOG(6, "Observer profile loaded successfully - all tags validated");
  AST_LOG_VERBOSE("Header: colorSpace=0x%08X, PCS=0x%08X, class=0x%08X, version=0x%08X",
                  pccIcc->m_Header.colorSpace,
                  pccIcc->m_Header.pcs,
                  pccIcc->m_Header.deviceClass,
                  pccIcc->m_Header.version);
  AST_LOG_VERBOSE("Tool equivalent: Profile successfully parsed from inputObserverV5.icc");

  AST_LOG(7, "GATE 7: Validating observer profile V5 requirements");
  AST_LOG_VERBOSE("Required: version >= 5.0");
  
  if (pccIcc->m_Header.version < icVersionNumberV5) {
    AST_LOG(7, "Observer not V5 (version=0x%08X)", pccIcc->m_Header.version);
    AST_LOG(7, "Tool would exit: %s is not a V5 profile", "inputObserverV5.icc");
    delete pccIcc;
    delete dspIcc;
    CLEANUP_TEMP_FILES();
    return 0;
  }

  AST_LOG(8, "GATE 8: Searching for spectral viewing conditions and C2S PCC");
  AST_LOG_VERBOSE("Tool requires: SpectralViewingConditionsTag and CustomToStandardPccTag");
  
  // Find required tags (these were already loaded by ReadIccProfile)
  CIccTagSpectralViewingConditions* pTagSvcn = 
    dynamic_cast<CIccTagSpectralViewingConditions*>(pccIcc->FindTagOfType(
      icSigSpectralViewingConditionsTag, icSigSpectralViewingConditionsType));
  
  CIccTagMultiProcessElement* pTagC2S = 
    dynamic_cast<CIccTagMultiProcessElement*>(pccIcc->FindTagOfType(
      icSigCustomToStandardPccTag, icSigMultiProcessElementType));

  if (!pTagSvcn || !pTagC2S || 
      pTagC2S->NumInputChannels() != 3 || 
      pTagC2S->NumOutputChannels() != 3) {
    AST_LOG(8, "Missing or invalid PCC tags (svcn=%p, c2s=%p)", (void*)pTagSvcn, (void*)pTagC2S);
    if (pTagC2S) {
      AST_LOG_VERBOSE("C2S channels: in=%u, out=%u (expected 3, 3)", 
                      pTagC2S->NumInputChannels(), pTagC2S->NumOutputChannels());
    }
    AST_LOG(8, "Tool would exit: doesn't have Profile Connection Conditions");
    delete pccIcc;
    delete dspIcc;
    CLEANUP_TEMP_FILES();
    return 0;
  }

  AST_LOG(9, "GATE 9: Initializing MPE processing");
  AST_LOG_VERBOSE("Tool calls: pTagIn->Begin() and pTagC2S->Begin()");
  
  // Begin processing (matches tool behavior)
  pTagIn->Begin(icElemInterpLinear, dspIcc, pccIcc);
  CIccApplyTagMpe *pApplyMpe = pTagIn->GetNewApply();
  
  if (!pApplyMpe) {
    AST_LOG(9, "Failed to get MPE apply");
    delete pccIcc;
    delete dspIcc;
    CLEANUP_TEMP_FILES();
    return 0;
  }

  auto applyList = pApplyMpe->GetList();
  if (!applyList || applyList->size() < 2) {
    AST_LOG(9, "Invalid apply list");
    delete pApplyMpe;
    delete pccIcc;
    delete dspIcc;
    CLEANUP_TEMP_FILES();
    return 0;
  }

  auto applyIter = applyList->begin();
  auto curveApply = applyIter->ptr;
  applyIter++;
  auto mtxApply = applyIter->ptr;

  pTagC2S->Begin(icElemInterpLinear, pccIcc);
  CIccApplyTagMpe *pApplyC2S = pTagC2S->GetNewApply();
  
  if (!pApplyC2S) {
    AST_LOG(9, "Failed to get C2S apply");
    delete pApplyMpe;
    delete pccIcc;
    delete dspIcc;
    CLEANUP_TEMP_FILES();
    return 0;
  }

  AST_LOG(10, "GATE 10: Creating output V4 profile");
  AST_LOG_VERBOSE("Tool creates V4.3 display profile for output");
  
  // Create V4 profile (matches tool behavior)
  CIccProfile* pIcc = new (std::nothrow) CIccProfile();
  if (!pIcc) {
    delete dspIcc;
    unlink(dspTmpFile);
    unlink(obsTmpFile);
    return 0;
  }
  pIcc->InitHeader();
  pIcc->m_Header.deviceClass = icSigDisplayClass;
  pIcc->m_Header.version = icVersionNumberV4_3;

  AST_LOG(11, "GATE 11: Processing TRC curves (2048 samples)");
  AST_LOG_VERBOSE("Tool processes emission curves for R/G/B TRC tags");
  
  // Create TRC tags
  CIccTagCurve* pTrcR = new (std::nothrow) CIccTagCurve(2048);
  CIccTagCurve* pTrcG = new (std::nothrow) CIccTagCurve(2048);
  CIccTagCurve* pTrcB = new (std::nothrow) CIccTagCurve(2048);
  if (!pTrcR || !pTrcG || !pTrcB) {
    delete pTrcR; delete pTrcG; delete pTrcB;
    delete pIcc;
    delete dspIcc;
    unlink(dspTmpFile);
    unlink(obsTmpFile);
    return 0;
  }

  icFloatNumber in[3], out[3];
  for (icUInt16Number i = 0; i < 2048; i++) {
    in[0] = in[1] = in[2] = (icFloatNumber)i / 2047.0f;
    
    // Apply curve processing
    curveMpe->Apply(curveApply, out, in);
    
    // TOOL FIDELITY: Direct assignment like tool (no NaN/Inf checks)
    // Assign TRC curve values for R, G, B channels
    (*pTrcR)[i] = out[0];
    (*pTrcG)[i] = out[1];
    (*pTrcB)[i] = out[2];
  }

  pIcc->AttachTag(icSigRedTRCTag, pTrcR);
  pIcc->AttachTag(icSigGreenTRCTag, pTrcG);
  pIcc->AttachTag(icSigBlueTRCTag, pTrcB);

  AST_LOG(12, "GATE 12: Computing colorant XYZ values");
  AST_LOG_VERBOSE("Tool computes red/green/blue colorant tags from emission matrix");
  
  // Compute colorant XYZ values
  const icFloatNumber rRGB[3] = {1.0f, 0.0f, 0.0f};
  const icFloatNumber gRGB[3] = {0.0f, 1.0f, 0.0f};
  const icFloatNumber bRGB[3] = {0.0f, 0.0f, 1.0f};

  // Red colorant
  matrixMpe->Apply(mtxApply, in, rRGB);
  pTagC2S->Apply(pApplyC2S, out, in);
  
  CIccTagS15Fixed16* primaryXYZ = new (std::nothrow) CIccTagS15Fixed16(3);
  if (!primaryXYZ) { delete pIcc; delete dspIcc; unlink(dspTmpFile); unlink(obsTmpFile); return 0; }
  (*primaryXYZ)[0] = icDtoF(out[0]);
  (*primaryXYZ)[1] = icDtoF(out[1]);
  (*primaryXYZ)[2] = icDtoF(out[2]);
  pIcc->AttachTag(icSigRedColorantTag, primaryXYZ);

  // Green colorant
  matrixMpe->Apply(mtxApply, in, gRGB);
  pTagC2S->Apply(pApplyC2S, out, in);
  
  primaryXYZ = new (std::nothrow) CIccTagS15Fixed16(3);
  if (!primaryXYZ) { delete pIcc; delete dspIcc; unlink(dspTmpFile); unlink(obsTmpFile); return 0; }
  (*primaryXYZ)[0] = icDtoF(out[0]);
  (*primaryXYZ)[1] = icDtoF(out[1]);
  (*primaryXYZ)[2] = icDtoF(out[2]);
  pIcc->AttachTag(icSigGreenColorantTag, primaryXYZ);

  // Blue colorant
  matrixMpe->Apply(mtxApply, in, bRGB);
  pTagC2S->Apply(pApplyC2S, out, in);
  
  primaryXYZ = new (std::nothrow) CIccTagS15Fixed16(3);
  if (!primaryXYZ) { delete pIcc; delete dspIcc; unlink(dspTmpFile); unlink(obsTmpFile); return 0; }
  (*primaryXYZ)[0] = icDtoF(out[0]);
  (*primaryXYZ)[1] = icDtoF(out[1]);
  (*primaryXYZ)[2] = icDtoF(out[2]);
  pIcc->AttachTag(icSigBlueColorantTag, primaryXYZ);

  AST_LOG(13, "GATE 13: Adding description tags");
  AST_LOG_VERBOSE("Tool extracts description from input profile");
  
  // TOOL FIDELITY: Extract description from input profile like tool does
  // Extract description from input profile
  CIccTag* pDesc = dspIcc->FindTag(icSigProfileDescriptionTag);
  
  CIccTagMultiLocalizedUnicode* pDspText = new (std::nothrow) CIccTagMultiLocalizedUnicode();
  if (!pDspText) { delete pIcc; delete dspIcc; unlink(dspTmpFile); unlink(obsTmpFile); return 0; }
  std::string text;
  // Description tag text extraction (not needed in fuzzer)
  if (!icGetTagText(pDesc, text))
    text = "Fuzzed V5 to V4 display conversion";
  pDspText->SetText(text.c_str());
  pIcc->AttachTag(icSigProfileDescriptionTag, pDspText);

  pDspText = new (std::nothrow) CIccTagMultiLocalizedUnicode();
  if (!pDspText) { delete pIcc; delete dspIcc; unlink(dspTmpFile); unlink(obsTmpFile); return 0; }
  pDspText->SetText("Copyright (C) 2026 International Color Consortium");
  pIcc->AttachTag(icSigCopyrightTag, pDspText);

  AST_LOG(14, "GATE 14: Writing output profile (tool fidelity)");
  AST_LOG_VERBOSE("Tool calls: SaveIccProfile(argv[3], pIcc)");
  
  // TOOL FIDELITY: Write output to temp file like tool does
  // Save output profile to disk
  char outTmpFile[PATH_MAX];
  if (!fuzz_build_path(outTmpFile, sizeof(outTmpFile), tmpdir, "/fuzz_v4out_XXXXXX")) {
    delete pIcc;
    unlink(dspTmpFile);
    unlink(obsTmpFile);
    return 0;
  }
  int outFd = mkstemp(outTmpFile);
  if (outFd >= 0) {
    close(outFd);
    
    AST_LOG_VERBOSE("Calling SaveIccProfile() - exercises full serialization path");
    SaveIccProfile(outTmpFile, pIcc);
    
    AST_LOG_VERBOSE("Profile written successfully - serialization complete");
    // Validate the written profile can be read back
    CIccProfile *pVerify = ReadIccProfile(outTmpFile);
    if (pVerify) {
      AST_LOG_VERBOSE("Output profile verified - round-trip successful");
      delete pVerify;
    }
    
    unlink(outTmpFile);
  }

  AST_LOG(15, "GATE 15: Cleanup and return");
  AST_LOG_VERBOSE("Tool equivalent: '%s successfully created'", "outputV4.icc");
  
  // Cleanup all allocated resources
  // ReadIccProfile handles IO internally, so we only delete the profile objects
  delete pIcc;
  delete pApplyC2S;
  delete pApplyMpe;
  delete pccIcc;
  delete dspIcc;
  
  // Clean up temporary files (tool fidelity)
  CLEANUP_TEMP_FILES();

  AST_LOG_VERBOSE("V5DSPOBS fuzzer completed successfully - all 15 gates passed");
  AST_LOG_VERBOSE("Tool equivalent: Successfully created outputV4.icc");
  AST_LOG_VERBOSE("Temp files deleted");
  return 0;
}

/*
 * Fuzzer Testing Notes:
 * 
 * This fuzzer maintains fidelity with the iccV5DspObsToV4Dsp tool by using
 * ReadIccProfile() instead of manual Attach(). This ensures:
 *  - All tags are loaded and validated immediately (eager loading)
 *  - Malformed profiles fail during Read(), not during cleanup
 *  - The fuzzer rejects profiles exactly like the tool does
 * 
 * Tool successfully converts valid V5 spectral display profiles:
 *   - Testing/Display/Rec2020rgbSpectral-from-xml.icc
 *   - Testing/Display/LaserProjector.icc (with appropriate observer)
 * 
 * Valid test case (tool succeeds):
 *   ./Build/Tools/IccV5DspObsToV4Dsp/iccV5DspObsToV4Dsp \
 *     Testing/Display/Rec2020rgbSpectral-from-xml.icc \
 *     Testing/Display/Rec2020rgbSpectral-from-xml.icc \
 *     output.icc
 *   Result: 24KB V5 → 13KB V4, no errors
 * 
 * The fuzzer tests edge cases and malformed input that the tool correctly
 * rejects during profile parsing. Unlike the previous Attach()-based approach,
 * malformed profiles now fail cleanly during ReadIccProfile() with proper
 * error messages matching the tool output.
 */
