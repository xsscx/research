/*
 * Analyzer-side safe overrides for selected iccDEV IccUtil.cpp helpers.
 *
 * These functions intentionally shadow upstream static-library definitions so
 * the analyzers can remain hardened against known UBSan-triggering patterns
 * without patching the vendored iccDEV source tree.
 */

#include "IccUtil.h"

#include <cctype>
#include <cstdio>
#include <cstring>

#ifdef USEICCDEVNAMESPACE
namespace iccDEV {
#endif

namespace {

static inline icUInt8Number SigByte(icUInt32Number sig, int index) {
  return static_cast<icUInt8Number>((sig >> (24 - index * 8)) & 0xFFu);
}

static inline bool IsPrintableAscii(icUInt8Number c) {
  return std::isprint(static_cast<unsigned char>(c)) && c <= 126;
}

static inline void SetBadParam(icChar *pBuf, size_t bufSize) {
  if (!pBuf || !bufSize) {
    return;
  }
  std::snprintf(pBuf, bufSize, "BADP");
}

}  // namespace

icFloat32Number ICCPROFLIB_API icF16toF(icFloat16Number num)
{
  const icUInt32Number sign = (static_cast<icUInt32Number>(num & 0x8000u) << 16);
  const icUInt32Number exp = (num >> 10) & 0x1Fu;
  icUInt32Number mant = num & 0x03FFu;
  icUInt32Number bits = 0;

  if ((num & 0x7FFFu) == 0) {
    bits = static_cast<icUInt32Number>(num) << 16;
  } else if (exp == 0) {
    int shift = -1;
    do {
      shift++;
      mant <<= 1;
    } while ((mant & 0x0400u) == 0);

    const icInt32Number exp32 = 127 - 15 - shift;
    bits = sign |
           (static_cast<icUInt32Number>(exp32) << 23) |
           ((mant & 0x03FFu) << 13);
  } else if (exp == 0x1Fu) {
    if (mant == 0) {
      bits = sign | 0x7F800000u;
    } else {
      bits = 0xFFC00000u;
    }
  } else {
    const icInt32Number exp32 = static_cast<icInt32Number>(exp) - 15 + 127;
    bits = sign |
           (static_cast<icUInt32Number>(exp32) << 23) |
           (mant << 13);
  }

  icFloat32Number rv;
  std::memcpy(&rv, &bits, sizeof(rv));
  return rv;
}

const icChar *icGetSig(icChar *pBuf, size_t bufSize, icUInt32Number nSig, bool bGetHexVal)
{
  if (!pBuf) {
    return pBuf;
  }
  if (!nSig) {
    std::snprintf(pBuf, bufSize ? bufSize : 1, "NULL");
    return pBuf;
  }
  if (bufSize < 7 || bufSize > 65535) {
    SetBadParam(pBuf, bufSize);
    return pBuf;
  }

  pBuf[0] = '\'';
  for (int i = 0; i < 4; ++i) {
    icUInt8Number c = SigByte(nSig, i);
    if (!IsPrintableAscii(c)) {
      c = '?';
      bGetHexVal = true;
    }
    pBuf[i + 1] = static_cast<icChar>(c);
  }

  if (bGetHexVal) {
    std::snprintf(pBuf + 5, bufSize - 5, "' = %08X", nSig);
  } else {
    std::snprintf(pBuf + 5, bufSize - 5, "'");
  }

  return pBuf;
}

const icChar *icGetSigStr(icChar *pBuf, size_t bufSize, icUInt32Number nSig)
{
  if (!pBuf) {
    return pBuf;
  }
  if (!nSig) {
    std::snprintf(pBuf, bufSize ? bufSize : 1, "NULL");
    return pBuf;
  }
  if (bufSize < 5 || bufSize > 65535) {
    SetBadParam(pBuf, bufSize);
    return pBuf;
  }

  int firstNull = -1;
  bool bGetHexVal = false;
  for (int i = 0; i < 4; ++i) {
    const icUInt8Number c = SigByte(nSig, i);
    pBuf[i] = static_cast<icChar>(c);
    if (!c) {
      firstNull = i;
    } else if (firstNull != -1) {
      bGetHexVal = true;
    } else if (!IsPrintableAscii(c) || c == ':') {
      bGetHexVal = true;
    }
  }

  if (bGetHexVal) {
    std::snprintf(pBuf, bufSize, "%08Xh", nSig);
  } else {
    pBuf[4] = '\0';
  }

  return pBuf;
}

const icChar *icGetColorSig(icChar *pBuf, size_t bufSize, icUInt32Number nSig, bool bGetHexVal)
{
  if (!pBuf) {
    return pBuf;
  }
  if (!nSig) {
    std::snprintf(pBuf, bufSize ? bufSize : 1, "NULL");
    return pBuf;
  }
  if (bufSize < 7 || bufSize > 65535) {
    SetBadParam(pBuf, bufSize);
    return pBuf;
  }

  switch (icGetColorSpaceType(nSig)) {
    case icSigNChannelData:
    case icSigReflectanceSpectralData:
    case icSigTransmisionSpectralData:
    case icSigRadiantSpectralData:
    case icSigBiSpectralReflectanceData:
    case icSigSparseMatrixReflectanceData:
      pBuf[0] = '\"';
      pBuf[1] = static_cast<icChar>(SigByte(nSig, 0));
      pBuf[2] = static_cast<icChar>(SigByte(nSig, 1));
      std::snprintf(pBuf + 3, bufSize - 3, "%04X\"", icNumColorSpaceChannels(nSig));
      return pBuf;

    default:
      break;
  }

  bool bNeedHexVal = false;
  pBuf[0] = '\'';
  for (int i = 0; i < 4; ++i) {
    icUInt8Number c = SigByte(nSig, i);
    if (!IsPrintableAscii(c)) {
      c = '?';
      bNeedHexVal = true;
    }
    pBuf[i + 1] = static_cast<icChar>(c);
  }

  if (bGetHexVal) {
    std::snprintf(pBuf + 5, bufSize - 5, "' = %08X", nSig);
  } else if (bNeedHexVal) {
    std::snprintf(pBuf, bufSize, "%08Xh", nSig);
  } else {
    std::snprintf(pBuf + 5, bufSize - 5, "'");
  }

  return pBuf;
}

const icChar *icGetColorSigStr(icChar *pBuf, size_t bufSize, icUInt32Number nSig)
{
  if (!pBuf) {
    return pBuf;
  }
  if (!nSig) {
    std::snprintf(pBuf, bufSize ? bufSize : 1, "NULL");
    return pBuf;
  }
  if (bufSize < 7 || bufSize > 65535) {
    SetBadParam(pBuf, bufSize);
    return pBuf;
  }

  switch (icGetColorSpaceType(nSig)) {
    case icSigNChannelData:
    case icSigReflectanceSpectralData:
    case icSigTransmisionSpectralData:
    case icSigRadiantSpectralData:
    case icSigBiSpectralReflectanceData:
    case icSigSparseMatrixReflectanceData:
      pBuf[0] = static_cast<icChar>(SigByte(nSig, 0));
      pBuf[1] = static_cast<icChar>(SigByte(nSig, 1));
      std::snprintf(pBuf + 2, bufSize - 2, "%04X", icNumColorSpaceChannels(nSig));
      return pBuf;

    default:
      break;
  }

  int firstNull = -1;
  bool bGetHexVal = false;
  for (int i = 0; i < 4; ++i) {
    const icUInt8Number c = SigByte(nSig, i);
    pBuf[i] = static_cast<icChar>(c);
    if (!c) {
      firstNull = i;
    } else if (firstNull != -1) {
      bGetHexVal = true;
    } else if (!IsPrintableAscii(c) || c == ':') {
      bGetHexVal = true;
    }
  }

  if (bGetHexVal) {
    std::snprintf(pBuf, bufSize, "%08Xh", nSig);
  } else {
    pBuf[4] = '\0';
  }

  return pBuf;
}

#ifdef USEICCDEVNAMESPACE
}  // namespace iccDEV
#endif

void ForceIccDevSafeOverrides() {}
