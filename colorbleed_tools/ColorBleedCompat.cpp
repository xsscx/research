/*!
 *  @file ColorBleedCompat.cpp
 *  @brief Compatibility overrides for upstream iccDEV behavior
 *
 *  The upstream curveType loader treats a zero-entry curve as an error even
 *  though zero-length curve data is a valid identity encoding and the XML
 *  layer already serializes it as `<Curve/>`.
 *
 *  This object is linked before libIccProfLib2-static.a so the fixed
 *  implementation is used without mutating the upstream checkout.
 */

#include <cstdlib>
#include <cstring>

#include "IccTagLut.h"
#include "IccUtil.h"

#ifdef USEICCDEVNAMESPACE
namespace iccDEV {
#endif

bool CIccTagCurve::SetSize(icUInt32Number nSize, icTagCurveSizeInit nSizeOpt)
{
  if (nSize == m_nSize)
    return true;

  if (nSize == 0) {
    if (m_Curve) {
      free(m_Curve);
      m_Curve = NULL;
    }
    m_nSize = 0;
    m_nMaxIndex = 0;
    return true;
  }

  if (!m_Curve)
    m_Curve = (icFloatNumber*)malloc(nSize * sizeof(icFloatNumber));
  else
    m_Curve = (icFloatNumber*)icRealloc(m_Curve, nSize * sizeof(icFloatNumber));

  if (!m_Curve) {
    m_nSize = 0;
    m_nMaxIndex = 0;
    return false;
  }

  switch (nSizeOpt) {
  case icInitNone:
  default:
    break;

  case icInitZero:
    if (m_nSize < nSize) {
      memset(&m_Curve[m_nSize], 0, (nSize - m_nSize) * sizeof(icFloatNumber));
    }
    break;

  case icInitIdentity:
    if (nSize > 1) {
      icUInt32Number i;
      icFloatNumber last = (icFloatNumber)(nSize - 1);

      for (i = 0; i < nSize; i++) {
        m_Curve[i] = (icFloatNumber)i / last;
      }
    }
    else {
      m_Curve[0] = (icFloatNumber)(0x0100) / (icFloatNumber)65535.0;
    }
    break;
  }

  m_nSize = nSize;
  m_nMaxIndex = (icUInt16Number)(nSize - 1);

  return true;
}

#ifdef USEICCDEVNAMESPACE
}
#endif
