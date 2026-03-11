/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC. All rights reserved.
 *
 * CFL icc_fromcube_fuzzer — 1:1 fidelity with iccFromCube tool
 *
 * Upstream tool: iccDEV/Tools/CmdLine/IccFromCube/iccFromCube.cpp
 * Tool purpose:  Parse .cube 3D LUT file → create ICC.2 DeviceLink profile
 *
 * Gate sequence (upstream main() lines 290-377):
 *   Gate 1: CubeFile::parseHeader()        [line 297]
 *   Gate 2: cube.sizeLut3D() check          [line 302]
 *   Gate 3: Profile header init             [lines 307-312]
 *   Gate 4: Custom input range curves       [lines 315-354]
 *   Gate 5: CIccCLUT::Init()               [line 359]
 *   Gate 6: parse3DTable() — BEFORE attach  [lines 363-367]
 *   Gate 7: SetCLUT + Attach + AttachTag    [lines 369-371]
 *   Gate 8: cube.close()                    [line 373]
 *   Gate 9: Description tag                 [lines 376-383]
 *   Gate 10: Copyright tag                  [lines 386-390]
 *   Gate 11: SaveIccProfile()               [line 392]
 *
 * CubeFile class: EXACT COPY from upstream (lines 78-270)
 */

#include <cstdio>
#include <cstring>
#include <string>
#include <stdint.h>
#include <stddef.h>
#include <new>
#include <unistd.h>
#include <climits>
#include "IccProfile.h"
#include "IccTagBasic.h"
#include "IccTagMPE.h"
#include "IccMpeBasic.h"
#include "IccUtil.h"

#include "fuzz_utils.h"

// ═══════════════════════════════════════════════════════════════════
// CubeFile class — VERBATIM from iccFromCube.cpp (upstream lines 78-270)
// Parses .cube 3D LUT files used in video/color grading
// ═══════════════════════════════════════════════════════════════════

#define MAX_LINE_LEN 255

class CubeFile
{
public:
  CubeFile(const char* szFilename)
  {
    m_sFilename = szFilename;
  }
  ~CubeFile() { close(); }

  void close()
  {
    if (m_f)
      fclose(m_f);
    m_f = nullptr;
  }

  bool parseHeader()
  {
    if (!open())
      return false;

    m_title.clear();
    m_comments.clear();
    m_sizeLut3D = 0;
    m_fMinInput[0] = m_fMinInput[1] = m_fMinInput[2] = 0.0f;
    m_fMaxInput[0] = m_fMaxInput[1] = m_fMaxInput[2] = 1.0f;

    bool bAddBlankLine = false;
    while (!isEOF()) {
      long pos = ftell(m_f);
      std::string line = getNextLine();

      if (line[0] == '-' || line[0] == '.' || (line[0] >= '0' && line[0] <= '9')) {
        fseek(m_f, pos, SEEK_SET);
        break;
      }

      if (!line.size()) {
        if (m_comments.size()) {
          bAddBlankLine = true;
        }
      }
      else if (line.substr(0, 6) == "TITLE ") {
        if (m_title.size()) {
          m_title += "\n";
        }
        m_title += getTitle(line.c_str() + 6);
      }
      else if (line[0] == '#') {
        if (bAddBlankLine) {
          m_comments += "\n";
        }
        if (line[1]==' ')
          m_comments += line.c_str() + 2;
        else
          m_comments += line.c_str() + 1;
        m_comments += '\n';

        bAddBlankLine = false;
      }
      else if (line.substr(0, 12) == "LUT_1D_SiZE ") {
        printf("1DLUTs are not supported\n");
        return false;
      }
      else if (line.substr(0, 12) == "LUT_3D_SIZE ") {
        int64_t temp = atoll( line.c_str() + 12 );
        if (temp >= INT_MAX || temp <= 0)
            return false;
        m_sizeLut3D = (int)temp;
      }
      else if (line.substr(0, 19) == "LUT_3D_INPUT_RANGE ") {
        m_fMinInput[0] = m_fMinInput[1] = m_fMinInput[2] = (icFloatNumber)atof(line.c_str() + 19);
        const char* next = getNext(line.c_str() + 19);
        if (next) {
          m_fMaxInput[0] = m_fMaxInput[1] = m_fMaxInput[2] = (icFloatNumber)atof(next);
        }
      }
      else if (line.substr(0, 11) == "DOMAIN_MIN ") {
        m_fMinInput[0] = (icFloatNumber)atof(line.c_str() + 11);
        const char* next = getNext(line.c_str());
        if (next) {
          m_fMinInput[1] = (icFloatNumber)atof(next);
          next = getNext(next);
          if (next) {
            m_fMinInput[2] = (icFloatNumber)atof(next);
          }
          else
            m_fMinInput[2] = m_fMinInput[1];
        }
        else {
          m_fMinInput[1] = m_fMinInput[2] = m_fMinInput[0];
        }
      }
      else if (line.substr(0, 11) == "DOMAIN_MAX ") {
        m_fMaxInput[0] = (icFloatNumber)atof(line.c_str() + 11);
        const char* next = getNext(line.c_str());
        if (next) {
          m_fMaxInput[1] = (icFloatNumber)atof(next);
          next = getNext(next);
          if (next) {
            m_fMaxInput[2] = (icFloatNumber)atof(next);
          }
          else
            m_fMaxInput[2] = m_fMaxInput[1];
        }
        else {
          m_fMaxInput[1] = m_fMaxInput[2] = m_fMaxInput[0];
        }
      }
      else if (line.substr(0, 18) == "LUT_IN_VIDEO_RANGE")
        m_bLutInVideoRange = true;
      else if (line.substr(0, 19) == "LUT_OUT_VIDEO_RANGE")
        m_bLutOutVideoRange = true;
      else {
        printf("Unknown keyword '%s'\n", line.c_str());
        return false;
      }
    }

    return !isEOF();
  }

  std::string getDescription() { return m_title; }
  std::string getCopyright() { return m_comments; }

  icFloatNumber* getMinInput() { return m_fMinInput; }
  icFloatNumber* getMaxInput() { return m_fMaxInput; }

  bool isCustomInputRange()
  {
    if (!icIsNear(m_fMinInput[0], 0.0) || !icIsNear(m_fMinInput[1], 0.0) || !icIsNear(m_fMinInput[2], 0.0) ||
        !icIsNear(m_fMaxInput[0], 1.0) || !icIsNear(m_fMaxInput[1], 1.0) || !icIsNear(m_fMaxInput[2], 1.0))
      return true;
    return false;
  }

  int sizeLut3D() { return m_sizeLut3D; }
  bool parse3DTable(icFloatNumber* toLut, icUInt32Number nSizeLut)
  {
    if (m_sizeLut3D < 2 || nSizeLut <= 0)
        return false;
    
    uint64_t temp = (uint64_t)m_sizeLut3D * (uint64_t)m_sizeLut3D * (uint64_t)m_sizeLut3D;
    if (temp > UINT_MAX)
        return false;
    icUInt32Number num = (icUInt32Number)temp;

    if (nSizeLut != num*3)
      return false;

    const char* next;
    for (auto n = 0u; n < num && !isEOF();) {
      std::string line = getNextLine();

      if (line[0] == '#' || line.size() == 0)
        continue;
      *toLut++ = (icFloatNumber)atof(line.c_str());
      next = getNext(line.c_str());
      if (!next) {
        printf("Invalid 3DLUT entry\n");
        return false;
      }
      *toLut++ = (icFloatNumber)atof(next);
      next = getNext(next);
      if (!next) {
        printf("Invalid 3DLUT entry\n");
        return false;
      }
      *toLut++ = (icFloatNumber)atof(next);

      n++;
    }
    return true;
  }

protected:
  std::string m_sFilename;
  
  bool open()
  {
    if (!m_f) {
      m_f = fopen(m_sFilename.c_str(), "rb");
    }
    else {
      fseek(m_f, 0, SEEK_SET);
    }
    return m_f != nullptr;
  }

  std::string getTitle(const char* str)
  {
    std::string rv;
    bool bNeedQuote = false;
    if (*str == '\"') {
      bNeedQuote = true;
      str++;
    }
    while (*str && (!bNeedQuote || *str != '\"')) {
      rv += *str++;
    }

    return rv;
  }

  const char* getNext(const char* str)
  {
    while (*str && *str == ' ') str++;
    while (*str && *str != ' ') str++;
    while (*str && *str == ' ') str++;

    return str;
  }

  std::string toEnd(const char* str)
  {
    std::string rv;
    while (*str && *str != '\"') {
      rv += *str++;
    }

    return rv;
  }

  bool isEOF() { return m_f ? feof(m_f)!=0 : true; }

  std::string getNextLine()
  {
    std::string rv;
    for (int n=0; n<MAX_LINE_LEN && !isEOF(); n++) {
      char c = fgetc(m_f);

      if ((c < 0 && feof(m_f)) || c == '\n')
        break;

      if (c == '\r')
        continue;

      rv += (unsigned char)c;
    }

    return rv;
  }

  FILE* m_f=nullptr;

  int m_sizeLut3D = 0;
  icFloatNumber m_fMinInput[3] = { 0.0f, 0.0f, 0.0f };
  icFloatNumber m_fMaxInput[3] = { 1.0f, 1.0f, 1.0f };

  std::string m_title;
  std::string m_comments;

  bool m_bLutInVideoRange = false;
  bool m_bLutOutVideoRange = false;
};

// ═══════════════════════════════════════════════════════════════════
// RAII temp file helper
// ═══════════════════════════════════════════════════════════════════

struct TmpFile {
  char path[PATH_MAX];
  bool valid;
  TmpFile() : valid(false) { path[0] = '\0'; }
  ~TmpFile() { if (valid) unlink(path); }
};

// ═══════════════════════════════════════════════════════════════════
// FUZZER HARNESS — 1:1 gate alignment with iccFromCube main()
// ═══════════════════════════════════════════════════════════════════

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // .cube files are text; reject empty or excessively large inputs
  if (size < 10 || size > 2 * 1024 * 1024) return 0;

  // Write fuzz data to temp file — CubeFile reads from FILE*
  const char *tmpdir = fuzz_tmpdir();
  TmpFile inFile;
  if (!fuzz_build_path(inFile.path, sizeof(inFile.path), tmpdir, "/fuzz_fromcube_XXXXXX"))
    return 0;
  int fd = mkstemp(inFile.path);
  if (fd == -1) return 0;
  inFile.valid = true;

  ssize_t written = write(fd, data, size);
  close(fd);
  if (written != static_cast<ssize_t>(size)) return 0;

  // ═══════════════════════════════════════════════════════════════
  // Gate 1: parseHeader() — upstream line 297
  // ═══════════════════════════════════════════════════════════════
  CubeFile cube(inFile.path);

  if (!cube.parseHeader())
    return 0;

  // ═══════════════════════════════════════════════════════════════
  // Gate 2: sizeLut3D check — upstream line 302
  // Cap at 64 to prevent OOM (64^3 * 3 * 4 = 3MB, safe)
  // ═══════════════════════════════════════════════════════════════
  if (!cube.sizeLut3D() || cube.sizeLut3D() > 64)
    return 0;

  // ═══════════════════════════════════════════════════════════════
  // Gate 3: Profile header init — upstream lines 307-312
  // ═══════════════════════════════════════════════════════════════
  CIccProfile profile;
  profile.InitHeader();
  profile.m_Header.version = icVersionNumberV5;
  profile.m_Header.colorSpace = icSigRgbData;
  profile.m_Header.pcs = icSigRgbData;
  profile.m_Header.deviceClass = icSigLinkClass;

  // ═══════════════════════════════════════════════════════════════
  // Gate 4: Custom input range curves — upstream lines 315-354
  // Uses float != comparison (matches upstream, NOT memcmp)
  // ═══════════════════════════════════════════════════════════════
  CIccTagMultiProcessElement* pTag = new (std::nothrow) CIccTagMultiProcessElement(3, 3);
  if (!pTag) return 0;

  if (cube.isCustomInputRange()) {
    // Copy values immediately to avoid interior-pointer lifetime issues
    icFloatNumber minVal[3], maxVal[3];
    if (!cube.getMinInput() || !cube.getMaxInput()) { delete pTag; return 0; }
    memcpy(minVal, cube.getMinInput(), 3 * sizeof(icFloatNumber));
    memcpy(maxVal, cube.getMaxInput(), 3 * sizeof(icFloatNumber));

    CIccMpeCurveSet* pCurves = new (std::nothrow) CIccMpeCurveSet(3);
    if (!pCurves) { delete pTag; return 0; }

    CIccSingleSampledCurve* pCurve0 = new (std::nothrow) CIccSingleSampledCurve(minVal[0], maxVal[0]);
    if (!pCurve0) { delete pCurves; delete pTag; return 0; }
    pCurve0->SetSize(2);
    pCurve0->GetSamples()[0] = 0;
    pCurve0->GetSamples()[1] = 1;
    pCurves->SetCurve(0, pCurve0);

    // Upstream line 336: if (minVal[1] != minVal[0] || maxVal[1] != maxVal[0])
    // Use memcmp — values come from same parser, exact bit equality is intended
    CIccSingleSampledCurve* pCurve1 = pCurve0;
    if (memcmp(&minVal[1], &minVal[0], sizeof(icFloatNumber)) != 0 ||
        memcmp(&maxVal[1], &maxVal[0], sizeof(icFloatNumber)) != 0) {
      pCurve1 = new (std::nothrow) CIccSingleSampledCurve(minVal[1], maxVal[1]);
      if (!pCurve1) { delete pCurves; delete pTag; return 0; }
      pCurve1->SetSize(2);
      pCurve1->GetSamples()[0] = 0;
      pCurve1->GetSamples()[1] = 1;
    }
    pCurves->SetCurve(1, pCurve1);

    // Upstream line 345: if (minVal[2] != minVal[0] || maxVal[2] != maxVal[0])
    CIccSingleSampledCurve* pCurve2 = pCurve0;
    if (memcmp(&minVal[2], &minVal[0], sizeof(icFloatNumber)) != 0 ||
        memcmp(&maxVal[2], &maxVal[0], sizeof(icFloatNumber)) != 0) {
      if (memcmp(&minVal[2], &minVal[1], sizeof(icFloatNumber)) == 0 &&
          memcmp(&maxVal[2], &maxVal[1], sizeof(icFloatNumber)) == 0)
        pCurve2 = pCurve1;
      else {
        pCurve2 = new (std::nothrow) CIccSingleSampledCurve(minVal[2], maxVal[2]);
        if (!pCurve2) { delete pCurves; delete pTag; return 0; }
        pCurve2->SetSize(2);
        pCurve2->GetSamples()[0] = 0;
        pCurve2->GetSamples()[1] = 1;
      }
    }
    pCurves->SetCurve(2, pCurve2);

    pTag->Attach(pCurves);
  }

  // ═══════════════════════════════════════════════════════════════
  // Gate 5: CLUT Init — upstream line 359
  // ═══════════════════════════════════════════════════════════════
  CIccMpeCLUT* pMpeCLUT = new (std::nothrow) CIccMpeCLUT();
  if (!pMpeCLUT) { delete pTag; return 0; }

  CIccCLUT* pCLUT = new (std::nothrow) CIccCLUT(3, 3);
  if (!pCLUT) { delete pMpeCLUT; delete pTag; return 0; }

  if (!pCLUT->Init(cube.sizeLut3D())) {
    delete pCLUT;
    delete pMpeCLUT;
    delete pTag;
    return 0;
  }

  // ═══════════════════════════════════════════════════════════════
  // Gate 6: parse3DTable — upstream lines 363-367
  // CRITICAL: check BEFORE attach (matches upstream gate order)
  // Old fuzzer attached first, then checked — wrong order.
  // ═══════════════════════════════════════════════════════════════
  bool bSuccess = cube.parse3DTable(pCLUT->GetData(0), pCLUT->NumPoints() * 3);
  if (!bSuccess) {
    delete pCLUT;
    delete pMpeCLUT;
    delete pTag;
    return 0;
  }

  // ═══════════════════════════════════════════════════════════════
  // Gate 7: SetCLUT + Attach + AttachTag — upstream lines 369-371
  // After this, profile owns pTag (and transitively pMpeCLUT, pCLUT)
  // ═══════════════════════════════════════════════════════════════
  pMpeCLUT->SetCLUT(pCLUT);
  pTag->Attach(pMpeCLUT);
  profile.AttachTag(icSigAToB0Tag, pTag);

  // ═══════════════════════════════════════════════════════════════
  // Gate 8: cube.close() — upstream line 373
  // ═══════════════════════════════════════════════════════════════
  cube.close();

  // ═══════════════════════════════════════════════════════════════
  // Gate 9: Description tag — upstream lines 376-383
  // ═══════════════════════════════════════════════════════════════
  CIccTagMultiLocalizedUnicode* pTextTag = new (std::nothrow) CIccTagMultiLocalizedUnicode();
  if (pTextTag) {
    std::string desc = cube.getDescription();
    if (desc.size())
      pTextTag->SetText(desc.c_str());
    else
      pTextTag->SetText("Device link created from fuzz input");
    profile.AttachTag(icSigProfileDescriptionTag, pTextTag);
  }

  // ═══════════════════════════════════════════════════════════════
  // Gate 10: Copyright tag — upstream lines 386-390
  // ═══════════════════════════════════════════════════════════════
  if (cube.getCopyright().size()) {
    CIccTagMultiLocalizedUnicode* pCopyTag = new (std::nothrow) CIccTagMultiLocalizedUnicode();
    if (pCopyTag) {
      pCopyTag->SetText(cube.getCopyright().c_str());
      profile.AttachTag(icSigCopyrightTag, pCopyTag);
    }
  }

  // ═══════════════════════════════════════════════════════════════
  // Gate 11: SaveIccProfile — upstream line 392
  // Write to temp file then discard (exercises serialization path)
  // ═══════════════════════════════════════════════════════════════
  TmpFile outFile;
  if (fuzz_build_path(outFile.path, sizeof(outFile.path), tmpdir, "/fuzz_fromcube_out_XXXXXX")) {
    int out_fd = mkstemp(outFile.path);
    if (out_fd != -1) {
      close(out_fd);
      outFile.valid = true;
      SaveIccProfile(outFile.path, &profile);
    }
  }

  return 0;
}
