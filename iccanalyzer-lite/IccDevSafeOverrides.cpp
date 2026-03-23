/*
 * Analyzer-side safe overrides for selected iccDEV helpers.
 *
 * These functions intentionally shadow upstream static-library definitions so
 * the analyzers can remain hardened against known sanitizer-triggering
 * patterns without patching the vendored iccDEV source tree.
 */

#include "IccIO.h"
#include "IccMD5.h"
#include "IccMpeBasic.h"
#include "IccUtil.h"
#include "IccUtilXml.h"

#include <cctype>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <string>

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

static inline bool IsFixedNearTenThousand(icS15Fixed16Number value, int targetTimes10000) {
  const int64_t scaled = static_cast<int64_t>(value) * 10000ll;
  const int64_t target = static_cast<int64_t>(targetTimes10000) * 65536ll;
  int64_t diff = scaled - target;
  if (diff < 0) {
    diff = -diff;
  }

  // Match the upstream "round to 4 decimals" intent without float->unsigned UB.
  return diff <= 32768ll;
}

}  // namespace

CIccEmbedIO::CIccEmbedIO() : CIccIO()
{
  m_pIO = NULL;
  m_nStartPos = 0;
  // Upstream uses -1 as a sentinel and trips signed->unsigned UBSan before
  // Attach() can provide the real embedded size. The analyzer runtime treats
  // unattached embedded I/O as zero-length until Attach() succeeds.
  m_nSize = 0;
  m_bOwnIO = false;
}

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

bool ICCPROFLIB_API icIsIllumD50(icXYZNumber xyz)
{
  return IsFixedNearTenThousand(xyz.X, 9642) &&
         IsFixedNearTenThousand(xyz.Y, 10000) &&
         IsFixedNearTenThousand(xyz.Z, 8249);
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

void CIccToneMapFunc::Describe(std::string& sDescription, int /* nVerboseness */)
{
  const size_t bufSize = 160;
  icChar buf[bufSize];

  std::snprintf(buf, bufSize, "ToneFunctionType: %04Xh\n", m_nFunctionType);
  sDescription += buf;

  switch (m_nFunctionType) {
    case 0x0000:
      if (!m_params || m_nParameters < 3) {
        std::snprintf(buf, bufSize,
                      "Invalid ToneMapFunction: funcType %u requires 3 params, has %u\n\n",
                      static_cast<unsigned>(m_nFunctionType),
                      static_cast<unsigned>(m_nParameters));
        sDescription += buf;
        return;
      }

      std::snprintf(buf, bufSize,
                    "Y = %.8f * M * ( X + %.8f) + %.8f\n\n",
                    m_params[0], m_params[1], m_params[2]);
      sDescription += buf;
      return;

    default:
      std::snprintf(buf, bufSize, "Unknown Function with %u parameters:\n\n",
                    static_cast<unsigned>(m_nParameters));
      sDescription += buf;

      if (!m_params && m_nParameters) {
        sDescription += "Parameter array missing\n\n";
        return;
      }

      for (icUInt8Number i = 0; i < m_nParameters; ++i) {
        std::snprintf(buf, bufSize, "Param[%u] = %.8lf\n\n",
                      static_cast<unsigned>(i), m_params[i]);
        sDescription += buf;
      }
      return;
  }
}

#ifdef USEICCDEVNAMESPACE
}  // namespace iccDEV
#endif

namespace {

static constexpr uint64_t kMd5U32Mask = 0xFFFFFFFFULL;

static inline UINT4 Md5F(UINT4 x, UINT4 y, UINT4 z) {
  return static_cast<UINT4>((x & y) | (~x & z));
}

static inline UINT4 Md5G(UINT4 x, UINT4 y, UINT4 z) {
  return static_cast<UINT4>((x & z) | (y & ~z));
}

static inline UINT4 Md5H(UINT4 x, UINT4 y, UINT4 z) {
  return static_cast<UINT4>(x ^ y ^ z);
}

static inline UINT4 Md5I(UINT4 x, UINT4 y, UINT4 z) {
  return static_cast<UINT4>(y ^ (x | ~z));
}

static inline UINT4 Md5Add(UINT4 a, UINT4 b) {
  return static_cast<UINT4>((static_cast<uint64_t>(a) + static_cast<uint64_t>(b)) &
                            kMd5U32Mask);
}

static inline UINT4 Md5RotateLeft(UINT4 value, unsigned int shift) {
  const uint64_t wide = static_cast<uint64_t>(value);
  return static_cast<UINT4>(((wide << shift) | (wide >> (32u - shift))) & kMd5U32Mask);
}

static inline void Md5Step(UINT4 &a,
                           UINT4 b,
                           UINT4 c,
                           UINT4 d,
                           UINT4 x,
                           unsigned int s,
                           UINT4 ac,
                           UINT4 (*func)(UINT4, UINT4, UINT4)) {
  a = Md5Add(a, func(b, c, d));
  a = Md5Add(a, x);
  a = Md5Add(a, ac);
  a = Md5RotateLeft(a, s);
  a = Md5Add(a, b);
}

static void SafeMd5Encode(unsigned char *output, const UINT4 *input, unsigned int len) {
  for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
    const UINT4 value = input[i];
    output[j + 0] = static_cast<unsigned char>(value & 0xFFu);
    output[j + 1] = static_cast<unsigned char>((value >> 8) & 0xFFu);
    output[j + 2] = static_cast<unsigned char>((value >> 16) & 0xFFu);
    output[j + 3] = static_cast<unsigned char>((value >> 24) & 0xFFu);
  }
}

static void SafeMd5Decode(UINT4 *output, const unsigned char *input, unsigned int len) {
  for (unsigned int i = 0, j = 0; j < len; i++, j += 4) {
    output[i] = static_cast<UINT4>(input[j]) |
                (static_cast<UINT4>(input[j + 1]) << 8) |
                (static_cast<UINT4>(input[j + 2]) << 16) |
                (static_cast<UINT4>(input[j + 3]) << 24);
  }
}

static void SafeMd5Transform(UINT4 state[4], const unsigned char block[64]) {
  UINT4 a = state[0];
  UINT4 b = state[1];
  UINT4 c = state[2];
  UINT4 d = state[3];
  UINT4 x[16];

  SafeMd5Decode(x, block, 64);

  Md5Step(a, b, c, d, x[ 0],  7, 0xd76aa478u, Md5F);
  Md5Step(d, a, b, c, x[ 1], 12, 0xe8c7b756u, Md5F);
  Md5Step(c, d, a, b, x[ 2], 17, 0x242070dbu, Md5F);
  Md5Step(b, c, d, a, x[ 3], 22, 0xc1bdceeeu, Md5F);
  Md5Step(a, b, c, d, x[ 4],  7, 0xf57c0fafu, Md5F);
  Md5Step(d, a, b, c, x[ 5], 12, 0x4787c62au, Md5F);
  Md5Step(c, d, a, b, x[ 6], 17, 0xa8304613u, Md5F);
  Md5Step(b, c, d, a, x[ 7], 22, 0xfd469501u, Md5F);
  Md5Step(a, b, c, d, x[ 8],  7, 0x698098d8u, Md5F);
  Md5Step(d, a, b, c, x[ 9], 12, 0x8b44f7afu, Md5F);
  Md5Step(c, d, a, b, x[10], 17, 0xffff5bb1u, Md5F);
  Md5Step(b, c, d, a, x[11], 22, 0x895cd7beu, Md5F);
  Md5Step(a, b, c, d, x[12],  7, 0x6b901122u, Md5F);
  Md5Step(d, a, b, c, x[13], 12, 0xfd987193u, Md5F);
  Md5Step(c, d, a, b, x[14], 17, 0xa679438eu, Md5F);
  Md5Step(b, c, d, a, x[15], 22, 0x49b40821u, Md5F);

  Md5Step(a, b, c, d, x[ 1],  5, 0xf61e2562u, Md5G);
  Md5Step(d, a, b, c, x[ 6],  9, 0xc040b340u, Md5G);
  Md5Step(c, d, a, b, x[11], 14, 0x265e5a51u, Md5G);
  Md5Step(b, c, d, a, x[ 0], 20, 0xe9b6c7aau, Md5G);
  Md5Step(a, b, c, d, x[ 5],  5, 0xd62f105du, Md5G);
  Md5Step(d, a, b, c, x[10],  9, 0x02441453u, Md5G);
  Md5Step(c, d, a, b, x[15], 14, 0xd8a1e681u, Md5G);
  Md5Step(b, c, d, a, x[ 4], 20, 0xe7d3fbc8u, Md5G);
  Md5Step(a, b, c, d, x[ 9],  5, 0x21e1cde6u, Md5G);
  Md5Step(d, a, b, c, x[14],  9, 0xc33707d6u, Md5G);
  Md5Step(c, d, a, b, x[ 3], 14, 0xf4d50d87u, Md5G);
  Md5Step(b, c, d, a, x[ 8], 20, 0x455a14edu, Md5G);
  Md5Step(a, b, c, d, x[13],  5, 0xa9e3e905u, Md5G);
  Md5Step(d, a, b, c, x[ 2],  9, 0xfcefa3f8u, Md5G);
  Md5Step(c, d, a, b, x[ 7], 14, 0x676f02d9u, Md5G);
  Md5Step(b, c, d, a, x[12], 20, 0x8d2a4c8au, Md5G);

  Md5Step(a, b, c, d, x[ 5],  4, 0xfffa3942u, Md5H);
  Md5Step(d, a, b, c, x[ 8], 11, 0x8771f681u, Md5H);
  Md5Step(c, d, a, b, x[11], 16, 0x6d9d6122u, Md5H);
  Md5Step(b, c, d, a, x[14], 23, 0xfde5380cu, Md5H);
  Md5Step(a, b, c, d, x[ 1],  4, 0xa4beea44u, Md5H);
  Md5Step(d, a, b, c, x[ 4], 11, 0x4bdecfa9u, Md5H);
  Md5Step(c, d, a, b, x[ 7], 16, 0xf6bb4b60u, Md5H);
  Md5Step(b, c, d, a, x[10], 23, 0xbebfbc70u, Md5H);
  Md5Step(a, b, c, d, x[13],  4, 0x289b7ec6u, Md5H);
  Md5Step(d, a, b, c, x[ 0], 11, 0xeaa127fau, Md5H);
  Md5Step(c, d, a, b, x[ 3], 16, 0xd4ef3085u, Md5H);
  Md5Step(b, c, d, a, x[ 6], 23, 0x04881d05u, Md5H);
  Md5Step(a, b, c, d, x[ 9],  4, 0xd9d4d039u, Md5H);
  Md5Step(d, a, b, c, x[12], 11, 0xe6db99e5u, Md5H);
  Md5Step(c, d, a, b, x[15], 16, 0x1fa27cf8u, Md5H);
  Md5Step(b, c, d, a, x[ 2], 23, 0xc4ac5665u, Md5H);

  Md5Step(a, b, c, d, x[ 0],  6, 0xf4292244u, Md5I);
  Md5Step(d, a, b, c, x[ 7], 10, 0x432aff97u, Md5I);
  Md5Step(c, d, a, b, x[14], 15, 0xab9423a7u, Md5I);
  Md5Step(b, c, d, a, x[ 5], 21, 0xfc93a039u, Md5I);
  Md5Step(a, b, c, d, x[12],  6, 0x655b59c3u, Md5I);
  Md5Step(d, a, b, c, x[ 3], 10, 0x8f0ccc92u, Md5I);
  Md5Step(c, d, a, b, x[10], 15, 0xffeff47du, Md5I);
  Md5Step(b, c, d, a, x[ 1], 21, 0x85845dd1u, Md5I);
  Md5Step(a, b, c, d, x[ 8],  6, 0x6fa87e4fu, Md5I);
  Md5Step(d, a, b, c, x[15], 10, 0xfe2ce6e0u, Md5I);
  Md5Step(c, d, a, b, x[ 6], 15, 0xa3014314u, Md5I);
  Md5Step(b, c, d, a, x[13], 21, 0x4e0811a1u, Md5I);
  Md5Step(a, b, c, d, x[ 4],  6, 0xf7537e82u, Md5I);
  Md5Step(d, a, b, c, x[11], 10, 0xbd3af235u, Md5I);
  Md5Step(c, d, a, b, x[ 2], 15, 0x2ad7d2bbu, Md5I);
  Md5Step(b, c, d, a, x[ 9], 21, 0xeb86d391u, Md5I);

  state[0] = Md5Add(state[0], a);
  state[1] = Md5Add(state[1], b);
  state[2] = Md5Add(state[2], c);
  state[3] = Md5Add(state[3], d);
}

static const unsigned char kMd5Padding[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

}  // namespace

void ICCPROFLIB_API icMD5Init(MD5_CTX *context)
{
  if (!context) {
    return;
  }

  context->count[0] = 0;
  context->count[1] = 0;
  context->state[0] = 0x67452301u;
  context->state[1] = 0xefcdab89u;
  context->state[2] = 0x98badcfeu;
  context->state[3] = 0x10325476u;
  std::memset(context->buffer, 0, sizeof(context->buffer));
}

void ICCPROFLIB_API icMD5Update(MD5_CTX *context, unsigned char *input, unsigned int inputLen)
{
  if (!context || !input || !inputLen) {
    return;
  }

  const uint64_t bitCount =
      (static_cast<uint64_t>(context->count[1]) << 32) |
      static_cast<uint64_t>(context->count[0]);
  const unsigned int index = static_cast<unsigned int>((bitCount >> 3) & 0x3Fu);
  const uint64_t newBitCount = bitCount + (static_cast<uint64_t>(inputLen) << 3);
  context->count[0] = static_cast<UINT4>(newBitCount & kMd5U32Mask);
  context->count[1] = static_cast<UINT4>((newBitCount >> 32) & kMd5U32Mask);

  const unsigned int partLen = 64u - index;
  unsigned int i = 0;

  if (inputLen >= partLen) {
    std::memcpy(&context->buffer[index], input, partLen);
    SafeMd5Transform(context->state, context->buffer);

    for (i = partLen; i + 63u < inputLen; i += 64u) {
      SafeMd5Transform(context->state, input + i);
    }
  }

  std::memcpy(&context->buffer[(inputLen >= partLen) ? 0u : index],
              input + i,
              inputLen - i);
}

void ICCPROFLIB_API icMD5Final(unsigned char *digest, MD5_CTX *context)
{
  if (!context || !digest) {
    return;
  }

  unsigned char bits[8];
  UINT4 countWords[2] = { context->count[0], context->count[1] };
  SafeMd5Encode(bits, countWords, 8);

  const unsigned int index = static_cast<unsigned int>((context->count[0] >> 3) & 0x3Fu);
  const unsigned int padLen = (index < 56u) ? (56u - index) : (120u - index);
  icMD5Update(context, const_cast<unsigned char*>(kMd5Padding), padLen);
  icMD5Update(context, bits, 8u);

  SafeMd5Encode(digest, context->state, 16u);
  std::memset(context, 0, sizeof(*context));
}

const std::string icGetHeaderFlagsName(icUInt32Number flags, bool bUsesMCS)
{
  const size_t lineSize = 256;
  char line[lineSize];
  std::string xml;

  if (flags & static_cast<icUInt32Number>(icEmbeddedProfileTrue))
    std::snprintf(line, lineSize, "<ProfileFlags EmbeddedInFile=\"true\"");
  else
    std::snprintf(line, lineSize, "<ProfileFlags EmbeddedInFile=\"false\"");
  xml += line;

  if (flags & static_cast<icUInt32Number>(icUseWithEmbeddedDataOnly))
    std::snprintf(line, lineSize, " UseWithEmbeddedDataOnly=\"true\"");
  else
    std::snprintf(line, lineSize, " UseWithEmbeddedDataOnly=\"false\"");
  xml += line;

  if (flags & static_cast<icUInt32Number>(icExtendedRangePCS)) {
    std::snprintf(line, lineSize, " ExtendedRangePCS=\"true\"");
    xml += line;
  }

  const icUInt32Number knownFlags =
      static_cast<icUInt32Number>(icEmbeddedProfileTrue) |
      static_cast<icUInt32Number>(icUseWithEmbeddedDataOnly) |
      static_cast<icUInt32Number>(icExtendedRangePCS);
  icUInt32Number otherFlags = static_cast<icUInt32Number>(~knownFlags);

  if (bUsesMCS) {
    if (flags & static_cast<icUInt32Number>(icMCSNeedsSubsetTrue))
      std::snprintf(line, lineSize, " MCSNeedsSubset=\"true\"");
    else
      std::snprintf(line, lineSize, " MCSNeedsSubset=\"false\"");
    xml += line;

    otherFlags &= static_cast<icUInt32Number>(
        ~static_cast<icUInt32Number>(icMCSNeedsSubsetTrue));
  }

  if (flags & otherFlags) {
    std::snprintf(line, lineSize, " VendorFlags=\"%08x\"", flags & otherFlags);
    xml += line;
  }

  xml += "/>\n";
  return xml;
}

void ForceIccDevSafeOverrides() {}
