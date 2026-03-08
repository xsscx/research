/** @file
    File:       icc_tiffdump_fuzzer.cpp
    Contains:   LibFuzzer harness for TIFF ICC profile extraction and processing
    Version:    V3 - Extended coverage: CTiffImg paths, pixel reading, Validate/Describe
    Copyright:  (c) see Software License

    Coverage targets:
    - TiffImg.cpp: Open(), ReadLine(), GetPhoto(), GetIccProfile(), Close()
    - IccProfile: Read(), Validate(), ReadTags(), FindTag(), Describe()
    - IccTag: Describe() on all tag types found in profile
    - libtiff: TIFFReadEncodedStrip(), TIFFReadDirectory(), multi-IFD
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
#include "IccCmm.h"
#include "IccTagBasic.h"
#include "IccIO.h"
#include "TiffImg.h"
#include "fuzz_utils.h"

#include <unistd.h>
#include <sys/stat.h>
#include <climits>

// In-memory TIFF structure for zero-copy processing
struct MemTIFF {
  const uint8_t* data;
  size_t size;
  size_t offset;
};

static tmsize_t mem_read(thandle_t handle, void* buf, tmsize_t size) {
  MemTIFF* mem = (MemTIFF*)handle;
  if (!mem || mem->offset >= mem->size) return 0;
  size_t to_read = std::min((size_t)size, mem->size - mem->offset);
  memcpy(buf, mem->data + mem->offset, to_read);
  mem->offset += to_read;
  return (tmsize_t)to_read;
}

static tmsize_t mem_write(thandle_t, void*, tmsize_t) { return 0; }

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

static int mem_close(thandle_t) { return 0; }

static toff_t mem_size(thandle_t handle) {
  MemTIFF* mem = (MemTIFF*)handle;
  return mem ? (toff_t)mem->size : 0;
}

static int mem_map(thandle_t, void**, toff_t*) { return 0; }
static void mem_unmap(thandle_t, void*, toff_t) {}

static void SilentTIFFErrorHandler(const char*, const char*, va_list) {}
static void SilentTIFFWarningHandler(const char*, const char*, va_list) {}

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  TIFFSetErrorHandler(SilentTIFFErrorHandler);
  TIFFSetWarningHandler(SilentTIFFWarningHandler);
  return 0;
}

// Exercise profile deeply — matches and extends iccTiffDump DumpProfileInfo()
static void ExerciseProfile(CIccProfile *pProfile, int depth) {
  if (!pProfile || depth > 2) return;

  // Guard: check declared profile size vs sanity limit (256MB)
  // Prevents CWE-789 OOM from malformed tag sizes in embedded ICC profiles
  icUInt32Number profileSize = pProfile->m_Header.size;
  if (profileSize > 256 * 1024 * 1024) return;

  icHeader *pHdr = &pProfile->m_Header;
  CIccInfo Fmt;

  // Header formatting — all branches in CIccInfo
  (void)Fmt.GetVersionName(pHdr->version);
  (void)Fmt.GetDeviceAttrName(pHdr->attributes);
  (void)Fmt.GetProfileFlagsName(pHdr->flags);

  if (pHdr->colorSpace)
    (void)Fmt.GetColorSpaceSigName(pHdr->colorSpace);
  if (pHdr->pcs)
    (void)Fmt.GetColorSpaceSigName(pHdr->pcs);
  if (pHdr->deviceClass)
    (void)Fmt.GetProfileClassSigName(pHdr->deviceClass);
  if (pHdr->platform)
    (void)Fmt.GetPlatformSigName(pHdr->platform);
  if (pHdr->renderingIntent <= 3)
    (void)Fmt.GetRenderingIntentName((icRenderingIntent)pHdr->renderingIntent);

  if (pHdr->spectralPCS) {
    (void)Fmt.GetSpectralColorSigName(pHdr->spectralPCS);
    if (pHdr->spectralRange.steps) {
      (void)icF16toF(pHdr->spectralRange.start);
      (void)icF16toF(pHdr->spectralRange.end);
    }
    if (pHdr->biSpectralRange.steps) {
      (void)icF16toF(pHdr->biSpectralRange.start);
      (void)icF16toF(pHdr->biSpectralRange.end);
    }
  }

  // Validate() — exercises the largest validation code path
  std::string report;
  pProfile->Validate(report);

  // Tag iteration with Describe() — exercises every tag type's Describe()
  // Guard against CWE-789 OOM: CIccTagArray::Read() and MPE element parsers
  // can allocate based on internal element counts that far exceed the tag's
  // declared size. Only exercise tags if the profile is large enough to
  // contain realistic tag data (>= 1KB), and skip individual tags that
  // exceed reasonable bounds.
  if (profileSize >= 1024) {
    int tagCount = 0;
    for (auto entry = pProfile->m_Tags.begin(); entry != pProfile->m_Tags.end() && tagCount < 64; ++entry, ++tagCount) {
      icUInt32Number tSize = entry->TagInfo.size;
      icUInt32Number tOffset = entry->TagInfo.offset;
      // Skip tags that are clearly malformed
      if (tSize > profileSize || tSize > 256 * 1024) continue;
      if (tOffset > profileSize || tOffset + tSize > profileSize) continue;
      // Skip tags whose size could trigger exponential allocation in MPE/Array parsers
      // A 300-byte mBA tag can request 2GB+ allocation via crafted element counts
      if (tSize > 128 && tSize * 1024 > profileSize) continue;
      CIccTag *pTag = pProfile->FindTag(entry->TagInfo.sig);
      if (!pTag) continue;

      // Exercise GetType() and IsArrayType() dispatchers
      (void)pTag->GetType();
      (void)pTag->IsArrayType();
      (void)pTag->IsNumArrayType();

      // Describe() with 64KB cap — the core coverage target
      std::string desc;
      pTag->Describe(desc, 0);
      if (desc.size() > 65536) desc.resize(65536);

      // Profile description tag — specific branches
      if (entry->TagInfo.sig == icSigProfileDescriptionTag) {
        if (pTag->GetType() == icSigTextDescriptionType) {
          CIccTagTextDescription *pText = dynamic_cast<CIccTagTextDescription*>(pTag);
          if (pText) (void)pText->GetText();
        }
        else if (pTag->GetType() == icSigMultiLocalizedUnicodeType) {
          CIccTagMultiLocalizedUnicode *pStrs = dynamic_cast<CIccTagMultiLocalizedUnicode*>(pTag);
          if (pStrs && pStrs->m_Strings && !pStrs->m_Strings->empty()) {
            std::string line;
            pStrs->m_Strings->begin()->GetText(line);
          }
        }
      }
    }
  }

  // Embedded V5 profile — recursive extraction
  CIccTag *pEmbedded = pProfile->FindTag(icSigEmbeddedV5ProfileTag);
  if (pEmbedded && pEmbedded->GetType() == icSigEmbeddedProfileType) {
    CIccTagEmbeddedProfile *pEmbeddedTag = dynamic_cast<CIccTagEmbeddedProfile*>(pEmbedded);
    if (pEmbeddedTag) {
      CIccProfile *pSubProfile = pEmbeddedTag->GetProfile();
      ExerciseProfile(pSubProfile, depth + 1);
    }
  }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8 || size > 50 * 1024 * 1024) return 0;

  // Check for TIFF magic (II=little-endian or MM=big-endian)
  if (!((data[0] == 'I' && data[1] == 'I') ||
        (data[0] == 'M' && data[1] == 'M'))) {
    return 0;
  }

  // ================================================================
  // Phase 1: In-memory libtiff processing (raw TIFF API coverage)
  // ================================================================
  MemTIFF mem_tiff = { data, size, 0 };

  TIFF* tif = TIFFClientOpen(
    "memory", "rm",
    (thandle_t)&mem_tiff,
    mem_read, mem_write, mem_seek, mem_close,
    mem_size, mem_map, mem_unmap
  );

  if (!tif) return 0;

  int dirCount = 0;
  do {
    if (++dirCount > 16) break;  // Cap IFD traversal

    uint32_t width = 0, height = 0;
    uint16_t samples = 0, bps = 0, photo = 0;
    uint32_t rowsPerStrip = 0;
    uint16_t sampleFormat = SAMPLEFORMAT_UINT;
    uint16_t orientation = ORIENTATION_TOPLEFT;
    uint16_t planar = PLANARCONFIG_CONTIG;
    uint16_t compression = COMPRESSION_NONE;
    uint16_t extraSamples = 0;
    uint16_t *sampleInfo = nullptr;
    float xRes = 0, yRes = 0;

    // Read ALL tags that CTiffImg::Open() and tools read
    TIFFGetField(tif, TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tif, TIFFTAG_IMAGELENGTH, &height);
    TIFFGetField(tif, TIFFTAG_SAMPLESPERPIXEL, &samples);
    TIFFGetField(tif, TIFFTAG_BITSPERSAMPLE, &bps);
    TIFFGetField(tif, TIFFTAG_PHOTOMETRIC, &photo);
    TIFFGetField(tif, TIFFTAG_ROWSPERSTRIP, &rowsPerStrip);
    TIFFGetField(tif, TIFFTAG_SAMPLEFORMAT, &sampleFormat);
    TIFFGetField(tif, TIFFTAG_ORIENTATION, &orientation);
    TIFFGetField(tif, TIFFTAG_PLANARCONFIG, &planar);
    TIFFGetField(tif, TIFFTAG_COMPRESSION, &compression);
    TIFFGetField(tif, TIFFTAG_EXTRASAMPLES, &extraSamples, &sampleInfo);
    TIFFGetField(tif, TIFFTAG_XRESOLUTION, &xRes);
    TIFFGetField(tif, TIFFTAG_YRESOLUTION, &yRes);

    // Read pixel data via TIFFReadEncodedStrip — exercises libtiff decompression
    // Cap to prevent OOM on huge dimensions
    if (width > 0 && height > 0 && samples > 0 && bps > 0 &&
        width <= 4096 && height <= 4096 && samples <= 16 && bps <= 32) {

      tmsize_t stripSize = TIFFStripSize(tif);
      tstrip_t numStrips = TIFFNumberOfStrips(tif);

      // Read up to 8 strips to exercise strip decoding
      if (stripSize > 0 && stripSize < 4 * 1024 * 1024 && numStrips > 0) {
        unsigned char *stripBuf = (unsigned char*)malloc(stripSize);
        if (stripBuf) {
          tstrip_t maxStrips = std::min(numStrips, (tstrip_t)8);
          for (tstrip_t s = 0; s < maxStrips; s++) {
            tmsize_t bytesRead = TIFFReadEncodedStrip(tif, s, stripBuf, stripSize);
            (void)bytesRead;
          }
          free(stripBuf);
        }
      }

      // Exercise TIFFReadScanline for contiguous planar config
      if (planar == PLANARCONFIG_CONTIG && height <= 256) {
        tmsize_t scanlineSize = TIFFScanlineSize(tif);
        if (scanlineSize > 0 && scanlineSize < 1024 * 1024) {
          unsigned char *scanBuf = (unsigned char*)malloc(scanlineSize);
          if (scanBuf) {
            uint32_t maxRows = std::min(height, (uint32_t)8);
            for (uint32_t row = 0; row < maxRows; row++) {
              if (TIFFReadScanline(tif, scanBuf, row, 0) < 0) break;
            }
            free(scanBuf);
          }
        }
      }
    }

    // Extract and deeply exercise embedded ICC profile
    uint32_t icc_len = 0;
    void* icc_data = nullptr;
    if (TIFFGetField(tif, TIFFTAG_ICCPROFILE, &icc_len, &icc_data)) {
      if (icc_data && icc_len > 128 && icc_len < 10 * 1024 * 1024) {
        CIccProfile *pProfile = OpenIccProfile((unsigned char*)icc_data, icc_len);
        if (pProfile) {
          ExerciseProfile(pProfile, 0);
          delete pProfile;
        }
      }
    }
  } while (TIFFReadDirectory(tif));

  TIFFClose(tif);

  // ================================================================
  // Phase 2: CTiffImg wrapper path (exercises Open/ReadLine/GetPhoto)
  // Write fuzzer data to temp file, then process via CTiffImg
  // ================================================================
  const char *tmpdir = fuzz_tmpdir();
  char tmpfile[PATH_MAX];
  if (!fuzz_build_path(tmpfile, sizeof(tmpfile), tmpdir, "/fuzz_tiffdump_XXXXXX")) {
    return 0;
  }
  int fd = mkstemp(tmpfile);
  if (fd < 0) return 0;

  ssize_t written = write(fd, data, size);
  close(fd);
  if (written != (ssize_t)size) {
    unlink(tmpfile);
    return 0;
  }

  CTiffImg img;
  if (img.Open(tmpfile)) {
    // Exercise all CTiffImg getters — each has branching logic
    unsigned int w = img.GetWidth();
    unsigned int h = img.GetHeight();
    unsigned int bitsPS = img.GetBitsPerSample();
    unsigned int photoVal = img.GetPhoto();  // 6-branch switch
    unsigned int samp = img.GetSamples();
    unsigned int extraSamp = img.GetExtraSamples();
    unsigned int compressVal = img.GetCompress();
    unsigned int planarVal = img.GetPlanar();
    float xr = img.GetXRes();
    float yr = img.GetYRes();
    unsigned int bytesLine = img.GetBytesPerLine();
    (void)img.GetWidthIn();
    (void)img.GetHeightIn();

    (void)w; (void)h; (void)bitsPS; (void)photoVal;
    (void)samp; (void)extraSamp; (void)compressVal; (void)planarVal;
    (void)xr; (void)yr; (void)bytesLine;

    // GetIccProfile via CTiffImg — different path than raw TIFFGetField
    unsigned char *profData = nullptr;
    unsigned int profLen = 0;
    if (img.GetIccProfile(profData, profLen) && profData && profLen > 128) {
      CIccProfile *pProfile = OpenIccProfile(profData, profLen);
      if (pProfile) {
        ExerciseProfile(pProfile, 0);
        delete pProfile;
      }
    }

    // ReadLine — exercises strip reading and sep→contig conversion
    // Cap rows to prevent excessive processing
    if (bytesLine > 0 && bytesLine < 1024 * 1024 && h > 0) {
      unsigned char *lineBuf = (unsigned char*)malloc(bytesLine);
      if (lineBuf) {
        uint32_t maxRows = std::min(h, (unsigned int)32);
        for (uint32_t row = 0; row < maxRows; row++) {
          if (!img.ReadLine(lineBuf)) break;
        }
        free(lineBuf);
      }
    }

    img.Close();
  }

  unlink(tmpfile);
  return 0;
}

