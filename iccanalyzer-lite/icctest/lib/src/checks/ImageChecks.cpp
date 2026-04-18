/*
 * IccTest Library - ImageChecks.cpp
 * Heuristic checks H139-H141, H149-H150: TIFF image security.
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All Rights Reserved.
 * [BSD 3-Clause License]
 */

#include "icctest/CheckRegistry.h"
#include "util/CheckHelpers.h"

#include <tiffio.h>

#include <cstdarg>
#include <cstdio>
#include <memory>
#include <set>
#include <sys/stat.h>

namespace icctest {

static bool isTIFF(ImageFormat fmt) {
    return fmt == ImageFormat::TIFF_LE || fmt == ImageFormat::TIFF_BE ||
           fmt == ImageFormat::BIGTIFF_LE || fmt == ImageFormat::BIGTIFF_BE;
}

static void tiffSilentWarning(const char*, const char*, va_list) {}
static void tiffSilentError(const char*, const char*, va_list) {}

class ScopedTiffSilence {
public:
    ScopedTiffSilence()
        : m_oldWarn(TIFFSetWarningHandler(tiffSilentWarning)),
          m_oldErr(TIFFSetErrorHandler(tiffSilentError)) {}

    ~ScopedTiffSilence() {
        TIFFSetWarningHandler(m_oldWarn);
        TIFFSetErrorHandler(m_oldErr);
    }

private:
    TIFFErrorHandler m_oldWarn;
    TIFFErrorHandler m_oldErr;
};

using TiffPtr = std::unique_ptr<TIFF, decltype(&TIFFClose)>;

static TiffPtr openTiffReadOnly(const ProfileView& pv) {
    if (pv.filePath().empty()) {
        return TiffPtr(nullptr, &TIFFClose);
    }
    return TiffPtr(TIFFOpen(pv.filePath().c_str(), "r"), &TIFFClose);
}

// -- H139: TIFF Strip Geometry Validation --
static CheckResult check_h139_tiff_strip(const ProfileView& pv) {
    if (!pv.isImage()) return CheckResult::skip("Not an image file");
    if (!isTIFF(pv.imageFormat())) return CheckResult::skip("Not a TIFF");
    if (pv.filePath().empty()) return CheckResult::skip("Requires file-backed TIFF");

    ScopedTiffSilence silence;
    auto tif = openTiffReadOnly(pv);
    if (!tif) return CheckResult::skip("Requires parseable TIFF (TIFFOpen failed)");

    uint32_t width = 0;
    uint16_t bps = 0;
    uint16_t spp = 0;
    uint32_t rowsPerStrip = 0;
    uint16_t planar = PLANARCONFIG_CONTIG;
    uint32_t tileW = 0;
    uint32_t tileH = 0;

    TIFFGetField(tif.get(), TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tif.get(), TIFFTAG_BITSPERSAMPLE, &bps);
    TIFFGetField(tif.get(), TIFFTAG_SAMPLESPERPIXEL, &spp);
    TIFFGetField(tif.get(), TIFFTAG_ROWSPERSTRIP, &rowsPerStrip);
    TIFFGetField(tif.get(), TIFFTAG_PLANARCONFIG, &planar);
    TIFFGetField(tif.get(), TIFFTAG_TILEWIDTH, &tileW);
    TIFFGetField(tif.get(), TIFFTAG_TILELENGTH, &tileH);

    if (tileW > 0 || tileH > 0) {
        return CheckResult::ok("Tiled image - strip geometry N/A");
    }
    if (rowsPerStrip == 0) {
        return CheckResult::ok("RowsPerStrip=0 - no strip layout");
    }

    CheckBuilder cb;
    tmsize_t stripSize = TIFFStripSize(tif.get());
    if (stripSize <= 0) {
        cb.critical("HEURISTIC: Zero or negative strip size - corrupted geometry",
                    "CWE-122: Heap buffer overflow in ReadLine/ReadEncodedStrip");
    }

    uint64_t bytesPerLine =
        ((uint64_t)width * (uint64_t)bps * (uint64_t)spp + 7) >> 3;
    if (bps > 0 && spp > 0 && width > 0 &&
        bytesPerLine > static_cast<uint64_t>(UINT32_MAX)) {
        cb.critical(
            sfmt("HEURISTIC: Integer overflow in bytesPerLine: %u x %u x %u overflows uint32",
                 width, bps, spp),
            "CWE-190: Integer overflow in buffer size calculation");
    }

    uint64_t expectedStripBuf = bytesPerLine * static_cast<uint64_t>(rowsPerStrip);
    if (expectedStripBuf > 0 && stripSize > 0 &&
        static_cast<uint64_t>(stripSize) < expectedStripBuf) {
        cb.critical(
            sfmt("HEURISTIC: Strip buffer too small: stripSize=%lld < rowsPerStripxbytesPerLine=%llu",
                 static_cast<long long>(stripSize),
                 static_cast<unsigned long long>(expectedStripBuf)),
            "CWE-122: Heap buffer overflow - ReadLine memcpy exceeds strip allocation");
    }

    uint32_t nStripSamples =
        (planar == PLANARCONFIG_SEPARATE && spp > 1) ? spp : 1;
    uint64_t allocSize = static_cast<uint64_t>(stripSize) *
                         static_cast<uint64_t>(nStripSamples);
    if (nStripSamples > 1 &&
        allocSize > static_cast<uint64_t>(SIZE_MAX) / 2) {
        cb.critical(
            sfmt("HEURISTIC: Strip allocation overflow: stripSize(%lld) x nStripSamples(%u) exceeds safe limit",
                 static_cast<long long>(stripSize), nStripSamples),
            "CWE-190: Integer overflow in malloc argument");
    }

    return cb.done("Strip geometry valid");
}

// -- H140: TIFF Dimension Validation --
static CheckResult check_h140_tiff_dims(const ProfileView& pv) {
    if (!pv.isImage()) return CheckResult::skip("Not an image file");
    if (!isTIFF(pv.imageFormat())) return CheckResult::skip("Not a TIFF");
    if (pv.filePath().empty()) return CheckResult::skip("Requires file-backed TIFF");

    ScopedTiffSilence silence;
    auto tif = openTiffReadOnly(pv);
    if (!tif) return CheckResult::skip("Requires parseable TIFF (TIFFOpen failed)");

    uint32_t width = 0;
    uint32_t height = 0;
    uint16_t bps = 0;
    uint16_t spp = 0;
    TIFFGetField(tif.get(), TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tif.get(), TIFFTAG_IMAGELENGTH, &height);
    TIFFGetField(tif.get(), TIFFTAG_BITSPERSAMPLE, &bps);
    TIFFGetField(tif.get(), TIFFTAG_SAMPLESPERPIXEL, &spp);

    CheckBuilder cb;

    if (width == 0 || height == 0) {
        cb.critical(sfmt("HEURISTIC: Zero dimension: %ux%u", width, height),
                    "CWE-369: Division by zero in image processing");
    }

    uint64_t pixelCount = static_cast<uint64_t>(width) * static_cast<uint64_t>(height);
    if (pixelCount > 100000000ULL) {
        cb.warn(
            sfmt("HEURISTIC: Extreme dimensions: %ux%u = %llu pixels (>100M)",
                 width, height, static_cast<unsigned long long>(pixelCount)),
            "CWE-400: Resource exhaustion via large image decode");
    }

    if (bps != 0 && bps != 1 && bps != 2 && bps != 4 && bps != 8 &&
        bps != 16 && bps != 32 && bps != 64) {
        cb.warn(
            sfmt("HEURISTIC: Unusual BitsPerSample: %u (expected 1/2/4/8/16/32/64)",
                 bps),
            "CWE-131: Incorrect buffer size calculation");
    }

    if (spp > 16) {
        cb.warn(
            sfmt("HEURISTIC: Excessive SamplesPerPixel: %u (>16)", spp),
            "CWE-131: Buffer size overflow (nOutputxBPSxwidth)");
    }

    uint64_t bytesPerPixel = ((uint64_t)bps * (uint64_t)spp + 7) >> 3;
    uint64_t totalBytes = pixelCount * bytesPerPixel;
    if (bytesPerPixel > 0 && totalBytes / bytesPerPixel != pixelCount) {
        cb.critical(
            sfmt("HEURISTIC: Uncompressed size overflows uint64: %ux%ux%llu",
                 width, height, static_cast<unsigned long long>(bytesPerPixel)),
            "CWE-190: Integer overflow in image buffer allocation");
    } else if (totalBytes > 4ULL * 1024 * 1024 * 1024) {
        cb.warn(
            sfmt("HEURISTIC: Uncompressed size %llu bytes (>4GB)",
                 static_cast<unsigned long long>(totalBytes)),
            "CWE-400: Memory exhaustion via large uncompressed image");
    }

    return cb.done("Dimensions valid");
}

// -- H141: TIFF IFD Offset Bounds --
static CheckResult check_h141_tiff_ifd(const ProfileView& pv) {
    if (!pv.isImage()) return CheckResult::skip("Not an image file");
    if (!isTIFF(pv.imageFormat())) return CheckResult::skip("Not a TIFF");
    if (pv.filePath().empty()) return CheckResult::skip("Requires file-backed TIFF");

    ScopedTiffSilence silence;
    auto tif = openTiffReadOnly(pv);
    if (!tif) return CheckResult::skip("Requires parseable TIFF (TIFFOpen failed)");

    struct stat st{};
    if (stat(pv.filePath().c_str(), &st) != 0) {
        return CheckResult::skip("Cannot stat file");
    }
    uint64_t fileSize = static_cast<uint64_t>(st.st_size);

    CheckBuilder cb;
    uint32_t tileW = 0;
    uint32_t tileH = 0;
    TIFFGetField(tif.get(), TIFFTAG_TILEWIDTH, &tileW);
    TIFFGetField(tif.get(), TIFFTAG_TILELENGTH, &tileH);

    int findingCount = 0;
    if (tileW == 0 && tileH == 0) {
        uint32_t nStrips = TIFFNumberOfStrips(tif.get());
        uint64_t* offsets = nullptr;
        uint64_t* bytecounts = nullptr;

        if (TIFFGetField(tif.get(), TIFFTAG_STRIPOFFSETS, &offsets) &&
            TIFFGetField(tif.get(), TIFFTAG_STRIPBYTECOUNTS, &bytecounts) &&
            offsets && bytecounts) {
            uint32_t checkLimit = (nStrips < 256) ? nStrips : 256;
            for (uint32_t s = 0; s < checkLimit; ++s) {
                if (bytecounts[s] > 0 &&
                    offsets[s] + bytecounts[s] > fileSize) {
                    cb.critical(
                        sfmt("HEURISTIC: Strip %u: offset+size (%llu+%llu) exceeds file size (%llu)",
                             s,
                             static_cast<unsigned long long>(offsets[s]),
                             static_cast<unsigned long long>(bytecounts[s]),
                             static_cast<unsigned long long>(fileSize)),
                        "CWE-125: Out-of-bounds read via corrupted strip offset");
                    if (++findingCount >= 3) break;
                }
            }
            for (uint32_t s = 0; s < checkLimit; ++s) {
                if (offsets[s] == 0 && bytecounts[s] > 0 && s > 0) {
                    cb.warn(
                        sfmt("HEURISTIC: Strip %u: offset=0 with bytecount=%llu (null data pointer)",
                             s, static_cast<unsigned long long>(bytecounts[s])),
                        "CWE-476: Null pointer in strip data access");
                    break;
                }
            }
        }
    } else {
        uint32_t nTiles = TIFFNumberOfTiles(tif.get());
        uint64_t* offsets = nullptr;
        uint64_t* bytecounts = nullptr;

        if (TIFFGetField(tif.get(), TIFFTAG_TILEOFFSETS, &offsets) &&
            TIFFGetField(tif.get(), TIFFTAG_TILEBYTECOUNTS, &bytecounts) &&
            offsets && bytecounts) {
            uint32_t checkLimit = (nTiles < 256) ? nTiles : 256;
            for (uint32_t t = 0; t < checkLimit; ++t) {
                if (bytecounts[t] > 0 &&
                    offsets[t] + bytecounts[t] > fileSize) {
                    cb.critical(
                        sfmt("HEURISTIC: Tile %u: offset+size (%llu+%llu) exceeds file size (%llu)",
                             t,
                             static_cast<unsigned long long>(offsets[t]),
                             static_cast<unsigned long long>(bytecounts[t]),
                             static_cast<unsigned long long>(fileSize)),
                        "CWE-125: Out-of-bounds read via corrupted tile offset");
                    if (++findingCount >= 3) break;
                }
            }
        }
    }

    int nPages = 0;
    do {
        ++nPages;
        if (nPages > 1000) {
            cb.warn("HEURISTIC: Excessive IFD pages: >1000 directories",
                    "CWE-400: Resource exhaustion via IFD chain loop");
            break;
        }
    } while (TIFFReadDirectory(tif.get()));

    TIFFSetDirectory(tif.get(), 0);
    return cb.done("All IFD offsets within file bounds");
}

// -- H149: TIFF IFD Chain Cycle Detection --
static CheckResult check_h149_tiff_cycle(const ProfileView& pv) {
    if (!pv.isImage()) return CheckResult::skip("Not an image file");
    if (!isTIFF(pv.imageFormat())) return CheckResult::skip("Not a TIFF");
    if (pv.filePath().empty()) return CheckResult::skip("Requires file-backed TIFF");

    FILE* fp = std::fopen(pv.filePath().c_str(), "rb");
    if (!fp) {
        return CheckResult::skip("Cannot open file for raw IFD scan");
    }

    struct stat st{};
    if (fstat(fileno(fp), &st) != 0) {
        std::fclose(fp);
        return CheckResult::skip("Cannot stat file");
    }
    uint64_t fileSize = static_cast<uint64_t>(st.st_size);

    uint8_t header[8];
    if (std::fread(header, 1, sizeof(header), fp) < sizeof(header)) {
        std::fclose(fp);
        return CheckResult::skip("File too small for TIFF header");
    }

    bool littleEndian = (header[0] == 'I' && header[1] == 'I');
    bool isBigTiff = false;
    uint64_t ifdOffset = 0;

    auto readU16 = [&](const uint8_t* p) -> uint16_t {
        return littleEndian
            ? static_cast<uint16_t>(p[0] | (p[1] << 8))
            : static_cast<uint16_t>((p[0] << 8) | p[1]);
    };
    auto readU32 = [&](const uint8_t* p) -> uint32_t {
        return littleEndian
            ? (static_cast<uint32_t>(p[0]) |
               (static_cast<uint32_t>(p[1]) << 8) |
               (static_cast<uint32_t>(p[2]) << 16) |
               (static_cast<uint32_t>(p[3]) << 24))
            : ((static_cast<uint32_t>(p[0]) << 24) |
               (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) << 8) |
               static_cast<uint32_t>(p[3]));
    };

    uint16_t magic = readU16(header + 2);
    if (magic == 43) {
        isBigTiff = true;
        uint8_t ext[8];
        if (std::fread(ext, 1, sizeof(ext), fp) < sizeof(ext)) {
            std::fclose(fp);
            return CheckResult::ok("BigTIFF header truncated");
        }
        ifdOffset = readU32(ext);
    } else {
        ifdOffset = readU32(header + 4);
    }

    CheckBuilder cb;
    std::set<uint64_t> visited;
    int chainLen = 0;
    static constexpr int kMaxChainDepth = 1024;

    while (ifdOffset != 0 && ifdOffset < fileSize && chainLen < kMaxChainDepth) {
        if (visited.count(ifdOffset)) {
            cb.critical(
                sfmt("HEURISTIC: Circular IFD chain - offset %llu revisited at depth %d",
                     static_cast<unsigned long long>(ifdOffset), chainLen),
                "CWE-835: Infinite loop via circular IFD next-pointer");
            break;
        }
        visited.insert(ifdOffset);
        ++chainLen;

        if (std::fseek(fp, static_cast<long>(ifdOffset), SEEK_SET) != 0) break;

        if (isBigTiff) {
            uint8_t countBuf[8];
            if (std::fread(countBuf, 1, sizeof(countBuf), fp) < sizeof(countBuf)) break;
            uint64_t entryCount = readU32(countBuf);
            uint64_t skipBytes = entryCount * 20;
            if (std::fseek(fp, static_cast<long>(skipBytes), SEEK_CUR) != 0) break;
            uint8_t nextBuf[8];
            if (std::fread(nextBuf, 1, sizeof(nextBuf), fp) < sizeof(nextBuf)) break;
            ifdOffset = readU32(nextBuf);
        } else {
            uint8_t countBuf[2];
            if (std::fread(countBuf, 1, sizeof(countBuf), fp) < sizeof(countBuf)) break;
            uint16_t entryCount = readU16(countBuf);
            long skipBytes = static_cast<long>(entryCount) * 12;
            if (std::fseek(fp, skipBytes, SEEK_CUR) != 0) break;
            uint8_t nextBuf[4];
            if (std::fread(nextBuf, 1, sizeof(nextBuf), fp) < sizeof(nextBuf)) break;
            ifdOffset = readU32(nextBuf);
        }
    }

    std::fclose(fp);

    if (chainLen >= kMaxChainDepth) {
        cb.warn(
            sfmt("HEURISTIC: IFD chain exceeds %d directories - possible loop",
                 kMaxChainDepth),
            "CWE-835: Excessive IFD chain depth");
    }

    return cb.done("IFD chain is acyclic");
}

// -- H150: TIFF Tile Geometry Validation --
static CheckResult check_h150_tiff_tile(const ProfileView& pv) {
    if (!pv.isImage()) return CheckResult::skip("Not an image file");
    if (!isTIFF(pv.imageFormat())) return CheckResult::skip("Not a TIFF");
    if (pv.filePath().empty()) return CheckResult::skip("Requires file-backed TIFF");

    ScopedTiffSilence silence;
    auto tif = openTiffReadOnly(pv);
    if (!tif) return CheckResult::skip("Requires parseable TIFF (TIFFOpen failed)");

    uint32_t width = 0;
    uint32_t height = 0;
    uint16_t bps = 0;
    uint16_t spp = 0;
    uint32_t tileW = 0;
    uint32_t tileH = 0;
    TIFFGetField(tif.get(), TIFFTAG_IMAGEWIDTH, &width);
    TIFFGetField(tif.get(), TIFFTAG_IMAGELENGTH, &height);
    TIFFGetField(tif.get(), TIFFTAG_BITSPERSAMPLE, &bps);
    TIFFGetField(tif.get(), TIFFTAG_SAMPLESPERPIXEL, &spp);
    TIFFGetField(tif.get(), TIFFTAG_TILEWIDTH, &tileW);
    TIFFGetField(tif.get(), TIFFTAG_TILELENGTH, &tileH);

    if (tileW == 0 && tileH == 0) {
        return CheckResult::ok("Strip-based image - tile geometry N/A");
    }

    CheckBuilder cb;
    if (tileW % 16 != 0) {
        cb.warn(
            sfmt("HEURISTIC: TileWidth=%u is not a multiple of 16 (TIFF 6.0 Sec.15)",
                 tileW));
    }
    if (tileH % 16 != 0) {
        cb.warn(
            sfmt("HEURISTIC: TileLength=%u is not a multiple of 16 (TIFF 6.0 Sec.15)",
                 tileH));
    }

    if (tileW == 0 || tileH == 0) {
        cb.critical(
            sfmt("HEURISTIC: Zero tile dimension (TileWidth=%u, TileLength=%u)",
                 tileW, tileH),
            "CWE-369: Division by zero in tile count calculation");
        return cb.done("Zero tile dimension detected");
    }

    if (tileW > width * 2 && width > 0) {
        cb.warn(sfmt("HEURISTIC: TileWidth=%u exceeds 2x image width=%u", tileW, width));
    }
    if (tileH > height * 2 && height > 0) {
        cb.warn(sfmt("HEURISTIC: TileLength=%u exceeds 2x image height=%u", tileH, height));
    }

    uint32_t nTiles = TIFFNumberOfTiles(tif.get());
    if (nTiles == 0) {
        cb.warn("HEURISTIC: Tiled image reports 0 tiles");
        return cb.done("Zero tile count detected");
    }

    uint32_t tilesAcross = (width + tileW - 1) / tileW;
    uint32_t tilesDown = (height + tileH - 1) / tileH;
    uint16_t planar = PLANARCONFIG_CONTIG;
    TIFFGetField(tif.get(), TIFFTAG_PLANARCONFIG, &planar);
    // Use uint64 to avoid overflow on large tile dimensions (CWE-190)
    uint64_t expectedTiles64 = (uint64_t)tilesAcross * tilesDown;
    if (planar == PLANARCONFIG_SEPARATE) expectedTiles64 *= spp;
    uint32_t expectedTiles = (expectedTiles64 > UINT32_MAX) ? 0 : (uint32_t)expectedTiles64;

    if (expectedTiles == 0 && expectedTiles64 > 0) {
        cb.critical(
            sfmt("HEURISTIC: Tile count overflow: %u x %u x %u exceeds uint32",
                 tilesAcross, tilesDown, (planar == PLANARCONFIG_SEPARATE) ? spp : 1),
            "CWE-190: Integer overflow in tile count calculation");
    } else if (nTiles != expectedTiles) {
        cb.warn(
            sfmt("HEURISTIC: Tile count mismatch: expected %u (%ux%u), got %u",
                 expectedTiles, tilesAcross, tilesDown, nTiles));
    }

    uint64_t* bytecounts = nullptr;
    if (TIFFGetField(tif.get(), TIFFTAG_TILEBYTECOUNTS, &bytecounts) && bytecounts) {
        uint64_t bytesPerPixel = ((uint64_t)bps * spp + 7) / 8;
        if (planar == PLANARCONFIG_SEPARATE) {
            bytesPerPixel = ((uint64_t)bps + 7) / 8;
        }
        uint64_t expectedTileBytes = static_cast<uint64_t>(tileW) * tileH * bytesPerPixel;

        if (bytesPerPixel > 0 &&
            static_cast<uint64_t>(tileW) * tileH >
                static_cast<uint64_t>(UINT32_MAX) / bytesPerPixel) {
            cb.critical(
                sfmt("HEURISTIC: Integer overflow in tile byte count: %u x %u x %llu",
                     tileW, tileH, static_cast<unsigned long long>(bytesPerPixel)),
                "CWE-190: Integer overflow -> heap buffer overflow");
        }

        uint32_t checkLimit = (nTiles < 64) ? nTiles : 64;
        for (uint32_t t = 0; t < checkLimit; ++t) {
            if (bytecounts[t] > expectedTileBytes * 4 && bytecounts[t] > 1048576) {
                cb.warn(
                    sfmt("HEURISTIC: Tile %u bytecount=%llu far exceeds expected=%llu (4x threshold)",
                         t,
                         static_cast<unsigned long long>(bytecounts[t]),
                         static_cast<unsigned long long>(expectedTileBytes)),
                    "CWE-131: Incorrect buffer size calculation");
                break;
            }
        }
    }

    struct stat st{};
    if (stat(pv.filePath().c_str(), &st) == 0) {
        uint64_t fileSize = static_cast<uint64_t>(st.st_size);
        uint64_t* offsets = nullptr;
        if (TIFFGetField(tif.get(), TIFFTAG_TILEOFFSETS, &offsets) &&
            offsets && bytecounts) {
            uint32_t checkLimit = (nTiles < 64) ? nTiles : 64;
            int oobCount = 0;
            for (uint32_t t = 0; t < checkLimit; ++t) {
                if (bytecounts[t] > 0 && offsets[t] + bytecounts[t] > fileSize) {
                    cb.critical(
                        sfmt("HEURISTIC: Tile %u extends beyond EOF: offset=%llu + size=%llu > filesize=%llu",
                             t,
                             static_cast<unsigned long long>(offsets[t]),
                             static_cast<unsigned long long>(bytecounts[t]),
                             static_cast<unsigned long long>(fileSize)),
                        "CWE-122: Heap buffer overflow via out-of-bounds tile read");
                    if (++oobCount >= 5) break;
                }
            }
        }
    }

    return cb.done("Tile geometry valid");
}

// -- Registration --

REGISTER_HEURISTIC(139, "TIFF Strip Geometry Validation",
    "TIFF 6.0 Sec.7", "CWE-122/CWE-190",
    "CWE-122", "CVE-2026-31797,CVE-2026-34539,GHSA-4f3j-q8mm-5hr6,GHSA-wh2p-cm3r-7hm3",
    Severity::CRITICAL, CheckPhase::IMAGE, check_h139_tiff_strip);

REGISTER_HEURISTIC(140, "TIFF Dimension and Sample Validation",
    "TIFF 6.0 Sec.8", "CWE-400/CWE-131",
    "CWE-400", "", Severity::HIGH, CheckPhase::IMAGE, check_h140_tiff_dims);

REGISTER_HEURISTIC(141, "TIFF IFD Offset Bounds Validation",
    "TIFF 6.0 Sec.2", "CWE-125",
    "CWE-125", "", Severity::CRITICAL, CheckPhase::IMAGE, check_h141_tiff_ifd);

REGISTER_HEURISTIC(149, "TIFF IFD Chain Cycle Detection",
    "TIFF 6.0 Sec.2", "CWE-835",
    "CWE-835", "", Severity::HIGH, CheckPhase::IMAGE, check_h149_tiff_cycle);

REGISTER_HEURISTIC(150, "TIFF Tile Geometry Validation",
    "TIFF 6.0 Sec.15", "CWE-122/CWE-131",
    "CWE-122", "", Severity::CRITICAL, CheckPhase::IMAGE, check_h150_tiff_tile);

} // namespace icctest
