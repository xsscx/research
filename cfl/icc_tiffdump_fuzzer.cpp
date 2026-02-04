/** @file
    File:       icc_tiffdump_fuzzer_optimized.cpp
    Contains:   Optimized LibFuzzer harness for TIFF ICC profile extraction
    Version:    V2 - In-memory TIFF processing
    Copyright:  (c) see Software License
*/

/*
 * Copyright (c) International Color Consortium.
 * [Full BSD 3-Clause License - same as original]
 */

#include <stdint.h>
#include <stddef.h>
#include <string>
#include <cstring>
#include <algorithm>
#include <tiffio.h>

#include "IccProfile.h"
#include "IccTag.h"
#include "IccUtil.h"
#include "TiffImg.h"

// In-memory TIFF structure for zero-copy processing
struct MemTIFF {
  const uint8_t* data;
  size_t size;
  size_t offset;
};

// Custom TIFF I/O callbacks for in-memory operation
static tmsize_t mem_read(thandle_t handle, void* buf, tmsize_t size) {
  MemTIFF* mem = (MemTIFF*)handle;
  if (!mem || mem->offset >= mem->size) return 0;
  
  size_t to_read = std::min((size_t)size, mem->size - mem->offset);
  memcpy(buf, mem->data + mem->offset, to_read);
  mem->offset += to_read;
  return (tmsize_t)to_read;
}

static tmsize_t mem_write(thandle_t, void*, tmsize_t) {
  return 0; // Read-only
}

static toff_t mem_seek(thandle_t handle, toff_t offset, int whence) {
  MemTIFF* mem = (MemTIFF*)handle;
  if (!mem) return 0;
  
  size_t new_offset = mem->offset;
  switch (whence) {
    case SEEK_SET: new_offset = offset; break;
    case SEEK_CUR: new_offset = mem->offset + offset; break;
    case SEEK_END: new_offset = mem->size + offset; break;
    default: return -1;
  }
  
  if (new_offset > mem->size) return -1;
  mem->offset = new_offset;
  return (toff_t)new_offset;
}

static int mem_close(thandle_t) {
  return 0; // No cleanup needed
}

static toff_t mem_size(thandle_t handle) {
  MemTIFF* mem = (MemTIFF*)handle;
  return mem ? (toff_t)mem->size : 0;
}

static int mem_map(thandle_t, void**, toff_t*) {
  return 0; // Not supported
}

static void mem_unmap(thandle_t, void*, toff_t) {
  // Not supported
}

// Suppress TIFF library warnings/errors during fuzzing
static void SilentTIFFErrorHandler(const char*, const char*, va_list) {}
static void SilentTIFFWarningHandler(const char*, const char*, va_list) {}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  TIFFSetErrorHandler(SilentTIFFErrorHandler);
  TIFFSetWarningHandler(SilentTIFFWarningHandler);
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Quick validation - TIFF requires minimum 8 bytes header
  if (size < 8 || size > 50 * 1024 * 1024) return 0;

  // Check for TIFF magic (II or MM)
  if (!((data[0] == 'I' && data[1] == 'I') || 
        (data[0] == 'M' && data[1] == 'M'))) {
    return 0;
  }

  // Setup in-memory TIFF structure
  MemTIFF mem_tiff = { data, size, 0 };

  // Open TIFF from memory using custom I/O
  TIFF* tif = TIFFClientOpen(
    "memory", "rm",
    (thandle_t)&mem_tiff,
    mem_read, mem_write, mem_seek, mem_close,
    mem_size, mem_map, mem_unmap
  );

  if (!tif) return 0;

  // Exercise TIFF directory reading
  do {
    uint32_t width = 0, height = 0;
    uint16_t samples = 0, bps = 0, photo = 0;
    uint32_t rowsPerStrip = 0;
    uint16_t sampleFormat = SAMPLEFORMAT_UINT;
    uint16_t orientation = ORIENTATION_TOPLEFT;
    
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);
    TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &samples);
    TIFFGetField(tif, TIFFTAG_BITSPERSAMPLE, &bps);
    TIFFGetField(tif, TIFFTAG_PHOTOMETRIC, &photo);
    TIFFGetField(tif, TIFFTAG_ROWSPERSTRIP, &rowsPerStrip);
    TIFFGetField(tif, TIFFTAG_SAMPLEFORMAT, &sampleFormat);
    TIFFGetField(tif, TIFFTAG_ORIENTATION, &orientation);

    // Validation matching CTiffImg::Open() to maintain tool fidelity
    // Reject corrupt parameters that the production tool rejects
    if (rowsPerStrip == 0 || samples == 0 || bps == 0) {
      TIFFClose(tif);
      return 0;
    }

    // Validate sample format and orientation (tool requirement)
    if ((bps == 32 && sampleFormat != SAMPLEFORMAT_IEEEFP) ||
        (bps != 32 && sampleFormat != SAMPLEFORMAT_UINT) ||
        orientation != ORIENTATION_TOPLEFT) {
      TIFFClose(tif);
      return 0;
    }

    // Extract embedded ICC profile
    uint32_t icc_len = 0;
    void* icc_data = nullptr;
    if (TIFFGetField(tif, TIFFTAG_ICCPROFILE, &icc_len, &icc_data)) {
      if (icc_data && icc_len > 128 && icc_len < 10 * 1024 * 1024) {
        unsigned char* prof_mem = (unsigned char*)icc_data;
        
        CIccProfile *pProfile = OpenIccProfile(prof_mem, icc_len);
        if (pProfile) {
          icHeader *pHdr = &pProfile->m_Header;
          CIccInfo Fmt;

          // Exercise header formatting
          Fmt.GetVersionName(pHdr->version);
          
          if (pHdr->colorSpace)
            Fmt.GetColorSpaceSigName(pHdr->colorSpace);
          
          if (pHdr->pcs)
            Fmt.GetColorSpaceSigName(pHdr->pcs);
          
          if (pHdr->spectralPCS) {
            Fmt.GetSpectralColorSigName(pHdr->spectralPCS);
            if (pHdr->spectralRange.steps) {
              (void)icF16toF(pHdr->spectralRange.start);
              (void)icF16toF(pHdr->spectralRange.end);
            }
            if (pHdr->biSpectralRange.steps) {
              (void)icF16toF(pHdr->biSpectralRange.start);
              (void)icF16toF(pHdr->biSpectralRange.end);
            }
          }

          // Exercise profile description tag
          CIccTag *pDesc = pProfile->FindTag(icSigProfileDescriptionTag);
          if (pDesc) {
            if (pDesc->GetType() == icSigTextDescriptionType) {
              CIccTagTextDescription *pText = (CIccTagTextDescription*)pDesc;
              (void)pText->GetText();
            }
            else if (pDesc->GetType() == icSigMultiLocalizedUnicodeType) {
              CIccTagMultiLocalizedUnicode *pStrs = (CIccTagMultiLocalizedUnicode*)pDesc;
              if (pStrs->m_Strings && !pStrs->m_Strings->empty()) {
                std::string line;
                pStrs->m_Strings->begin()->GetText(line);
              }
            }
          }

          // Exercise embedded profile tag (recursive extraction)
          CIccTag *pEmbedded = pProfile->FindTag(icSigEmbeddedV5ProfileTag);
          if (pEmbedded && pEmbedded->GetType() == icSigEmbeddedProfileType) {
            CIccTagEmbeddedProfile *pEmbeddedTag = (CIccTagEmbeddedProfile*)pEmbedded;
            CIccProfile *pSubProfile = pEmbeddedTag->GetProfile();
            if (pSubProfile) {
              icHeader *pSubHdr = &pSubProfile->m_Header;
              if (pSubHdr->version) {
                Fmt.GetVersionName(pSubHdr->version);
              }
              
              // Read tags from embedded profile
              pSubProfile->ReadTags(pSubProfile);
            }
          }

          // Read all tags (increases coverage)
          pProfile->ReadTags(pProfile);

          delete pProfile;
        }
      }
    }
  } while (TIFFReadDirectory(tif));

  TIFFClose(tif);
  return 0;
}
