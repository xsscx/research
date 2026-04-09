#ifndef ICC_XML_ROUND_TRIP_GUARDS_H
#define ICC_XML_ROUND_TRIP_GUARDS_H

#include <cerrno>
#include <cstring>
#include <string>
#include <unistd.h>

namespace iccxml {

inline bool WriteAllBytes(int fd, const char *data, size_t size)
{
  size_t total = 0;

  while (total < size) {
    ssize_t written = write(fd, data + total, size - total);
    if (written > 0) {
      total += static_cast<size_t>(written);
      continue;
    }
    if (written < 0 && errno == EINTR) {
      continue;
    }
    return false;
  }

  return true;
}

inline unsigned char ToLowerAscii(unsigned char ch)
{
  if (ch >= 'A' && ch <= 'Z') {
    return static_cast<unsigned char>(ch - 'A' + 'a');
  }

  return ch;
}

inline bool ContainsTokenCaseInsensitive(const std::string &text, const char *token)
{
  const size_t tokenLen = std::strlen(token);
  if (!tokenLen) {
    return true;
  }
  if (tokenLen > text.size()) {
    return false;
  }

  for (size_t offset = 0; offset + tokenLen <= text.size(); offset++) {
    size_t matched = 0;
    while (matched < tokenLen) {
      const unsigned char lhs =
          ToLowerAscii(static_cast<unsigned char>(text[offset + matched]));
      const unsigned char rhs =
          ToLowerAscii(static_cast<unsigned char>(token[matched]));
      if (lhs != rhs) {
        break;
      }
      matched++;
    }
    if (matched == tokenLen) {
      return true;
    }
  }

  return false;
}

inline bool ValidateRoundTripXmlOutput(const std::string &xmlOutput, std::string *reason)
{
  if (xmlOutput.empty()) {
    if (reason) {
      *reason = "round-trip XML is empty";
    }
    return false;
  }

  if (xmlOutput.size() > 4u * 1024u * 1024u) {
    if (reason) {
      *reason = "round-trip XML exceeds 4 MiB safety cap";
    }
    return false;
  }

  if (xmlOutput.find('\0') != std::string::npos) {
    if (reason) {
      *reason = "round-trip XML contains embedded NUL bytes";
    }
    return false;
  }

  if (!ContainsTokenCaseInsensitive(xmlOutput, "<IccProfile")) {
    if (reason) {
      *reason = "round-trip XML is missing the IccProfile root element";
    }
    return false;
  }

  static const char *const kDisallowedTokens[] = {
      "<!DOCTYPE",
      "<!ENTITY",
      "<?xml-stylesheet",
      "<xi:include",
      "<xsl:stylesheet",
      "<xsl:transform",
  };

  for (const char *token : kDisallowedTokens) {
    if (ContainsTokenCaseInsensitive(xmlOutput, token)) {
      if (reason) {
        *reason = std::string("round-trip XML contains disallowed construct: ") + token;
      }
      return false;
    }
  }

  if (reason) {
    reason->clear();
  }

  return true;
}

}  // namespace iccxml

#endif  // ICC_XML_ROUND_TRIP_GUARDS_H
