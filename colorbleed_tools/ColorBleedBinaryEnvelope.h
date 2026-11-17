/*!
 *  @file ColorBleedBinaryEnvelope.h
 *  @brief Lossless binary envelope helpers for ColorBleed diagnostics
 *  @author David Hoyt
 *  @date 17 NOV 2026
 *  @version 1.0.0
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 */

#ifndef COLORBLEED_BINARY_ENVELOPE_H
#define COLORBLEED_BINARY_ENVELOPE_H

#include <cerrno>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <limits>
#include <openssl/sha.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

static constexpr size_t kColorBleedMaxEnvelopeBytes =
    static_cast<size_t>(32) * 1024 * 1024;
static constexpr const char* kColorBleedEnvelopeFormat =
    "colorbleed-binary-envelope/v1";

struct ColorBleedBinaryEnvelope {
  bool restorable = false;
  uint64_t length = 0;
  uint64_t header_declared_profile_length = 0;
  uint64_t declared_profile_length = 0;
  uint64_t trailing_length = 0;
  std::string sha256;
  std::string declared_profile_sha256;
  std::string trailing_sha256;
  std::string data_base64;
  std::string omission_reason;
};

static std::string ColorBleedSha256(const uint8_t* data, size_t size) {
  static const uint8_t empty = 0;
  static const char hex[] = "0123456789abcdef";
  unsigned char digest[SHA256_DIGEST_LENGTH];
  const uint8_t* input = size ? data : &empty;
  if (!SHA256(input, size, digest)) {
    return std::string();
  }

  std::string result;
  result.reserve(SHA256_DIGEST_LENGTH * 2);
  for (unsigned char byte : digest) {
    result += hex[(byte >> 4) & 0x0f];
    result += hex[byte & 0x0f];
  }
  return result;
}

static std::string ColorBleedBase64Encode(const uint8_t* data, size_t size) {
  static const char alphabet[] =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  std::string output;
  output.reserve(((size + 2) / 3) * 4);

  size_t offset = 0;
  while (offset + 3 <= size) {
    uint32_t value = (static_cast<uint32_t>(data[offset]) << 16) |
                     (static_cast<uint32_t>(data[offset + 1]) << 8) |
                     static_cast<uint32_t>(data[offset + 2]);
    output += alphabet[(value >> 18) & 0x3f];
    output += alphabet[(value >> 12) & 0x3f];
    output += alphabet[(value >> 6) & 0x3f];
    output += alphabet[value & 0x3f];
    offset += 3;
  }

  size_t remaining = size - offset;
  if (remaining == 1) {
    uint32_t value = static_cast<uint32_t>(data[offset]) << 16;
    output += alphabet[(value >> 18) & 0x3f];
    output += alphabet[(value >> 12) & 0x3f];
    output += "==";
  } else if (remaining == 2) {
    uint32_t value = (static_cast<uint32_t>(data[offset]) << 16) |
                     (static_cast<uint32_t>(data[offset + 1]) << 8);
    output += alphabet[(value >> 18) & 0x3f];
    output += alphabet[(value >> 12) & 0x3f];
    output += alphabet[(value >> 6) & 0x3f];
    output += '=';
  }

  return output;
}

static int ColorBleedBase64Value(unsigned char value) {
  if (value >= 'A' && value <= 'Z') {
    return value - 'A';
  }
  if (value >= 'a' && value <= 'z') {
    return value - 'a' + 26;
  }
  if (value >= '0' && value <= '9') {
    return value - '0' + 52;
  }
  if (value == '+') {
    return 62;
  }
  if (value == '/') {
    return 63;
  }
  return -1;
}

static bool ColorBleedBase64Decode(const std::string& encoded,
                                   std::vector<uint8_t>& output,
                                   std::string& error) {
  std::string compact;
  compact.reserve(encoded.size());
  for (unsigned char value : encoded) {
    if (value == ' ' || value == '\t' || value == '\r' || value == '\n') {
      continue;
    }
    compact += static_cast<char>(value);
  }

  if (compact.size() % 4 != 0) {
    error = "base64 length is not a multiple of four";
    return false;
  }
  if (compact.size() > ((kColorBleedMaxEnvelopeBytes + 2) / 3) * 4) {
    error = "base64 payload exceeds the 32 MiB diagnostic envelope limit";
    return false;
  }

  output.clear();
  output.reserve((compact.size() / 4) * 3);
  for (size_t offset = 0; offset < compact.size(); offset += 4) {
    bool last = offset + 4 == compact.size();
    bool pad2 = compact[offset + 2] == '=';
    bool pad3 = compact[offset + 3] == '=';
    if (!last && (pad2 || pad3)) {
      error = "base64 padding appears before the final quartet";
      return false;
    }
    if (pad2 && !pad3) {
      error = "invalid base64 padding";
      return false;
    }

    int a = ColorBleedBase64Value(compact[offset]);
    int b = ColorBleedBase64Value(compact[offset + 1]);
    int c = pad2 ? 0 : ColorBleedBase64Value(compact[offset + 2]);
    int d = pad3 ? 0 : ColorBleedBase64Value(compact[offset + 3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) {
      error = "base64 payload contains an invalid character";
      return false;
    }
    if ((pad2 && (b & 0x0f) != 0) || (pad3 && !pad2 && (c & 0x03) != 0)) {
      error = "base64 payload has non-canonical padding bits";
      return false;
    }

    uint32_t value = (static_cast<uint32_t>(a) << 18) |
                     (static_cast<uint32_t>(b) << 12) |
                     (static_cast<uint32_t>(c) << 6) |
                     static_cast<uint32_t>(d);
    output.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    if (!pad2) {
      output.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    }
    if (!pad3) {
      output.push_back(static_cast<uint8_t>(value & 0xff));
    }
  }
  return true;
}

static inline bool ColorBleedReadEnvelope(
    const char* path,
    uint64_t header_declared_length,
    ColorBleedBinaryEnvelope& envelope) {
  envelope = ColorBleedBinaryEnvelope();
  envelope.header_declared_profile_length = header_declared_length;

  int fd = open(path, O_RDONLY);
  if (fd < 0) {
    envelope.omission_reason = "unable to open source binary";
    return false;
  }

  struct stat st;
  if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
    close(fd);
    envelope.omission_reason = "source is not a readable regular file";
    return false;
  }

  envelope.length = static_cast<uint64_t>(st.st_size);
  uint64_t bounded_declared = header_declared_length;
  if (bounded_declared < 128 || bounded_declared > envelope.length) {
    bounded_declared = envelope.length;
  }
  envelope.declared_profile_length = bounded_declared;
  envelope.trailing_length = envelope.length - bounded_declared;

  if (envelope.length > kColorBleedMaxEnvelopeBytes) {
    close(fd);
    envelope.omission_reason =
        "source exceeds the 32 MiB diagnostic envelope limit";
    return true;
  }
  if (envelope.length > std::numeric_limits<size_t>::max()) {
    close(fd);
    envelope.omission_reason = "source length cannot be represented in memory";
    return true;
  }

  std::vector<uint8_t> bytes(static_cast<size_t>(envelope.length));
  size_t offset = 0;
  while (offset < bytes.size()) {
    ssize_t count = read(fd, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      close(fd);
      envelope.omission_reason = "unable to read complete source binary";
      return false;
    }
    offset += static_cast<size_t>(count);
  }
  close(fd);

  const uint8_t* data = bytes.empty() ? nullptr : bytes.data();
  size_t declared_size = static_cast<size_t>(envelope.declared_profile_length);
  size_t trailing_size = static_cast<size_t>(envelope.trailing_length);
  envelope.sha256 = ColorBleedSha256(data, bytes.size());
  envelope.declared_profile_sha256 =
      ColorBleedSha256(data, declared_size);
  envelope.trailing_sha256 =
      ColorBleedSha256(data ? data + declared_size : nullptr, trailing_size);
  envelope.data_base64 = ColorBleedBase64Encode(data, bytes.size());
  envelope.restorable = !envelope.sha256.empty() &&
      !envelope.declared_profile_sha256.empty() &&
      !envelope.trailing_sha256.empty();
  if (!envelope.restorable) {
    envelope.omission_reason = "unable to hash source binary";
  }
  return true;
}

static bool ColorBleedIsSha256(const std::string& value) {
  if (value.size() != SHA256_DIGEST_LENGTH * 2) {
    return false;
  }
  for (unsigned char character : value) {
    if (!((character >= '0' && character <= '9') ||
          (character >= 'a' && character <= 'f') ||
          (character >= 'A' && character <= 'F'))) {
      return false;
    }
  }
  return true;
}

static std::string ColorBleedLower(const std::string& value) {
  std::string result = value;
  for (char& character : result) {
    if (character >= 'A' && character <= 'F') {
      character = static_cast<char>(character - 'A' + 'a');
    }
  }
  return result;
}

static inline bool ColorBleedVerifyEnvelope(
    const ColorBleedBinaryEnvelope& envelope,
    std::vector<uint8_t>& bytes,
    std::string& error) {
  if (!envelope.restorable) {
    error = envelope.omission_reason.empty()
        ? "diagnostic envelope is not restorable"
        : envelope.omission_reason;
    return false;
  }
  if (envelope.length > kColorBleedMaxEnvelopeBytes) {
    error = "declared payload exceeds the 32 MiB diagnostic envelope limit";
    return false;
  }
  if (envelope.declared_profile_length > envelope.length ||
      envelope.trailing_length > envelope.length ||
      envelope.declared_profile_length + envelope.trailing_length !=
          envelope.length) {
    error = "declared profile and trailing lengths do not match total length";
    return false;
  }
  if (!ColorBleedIsSha256(envelope.sha256) ||
      !ColorBleedIsSha256(envelope.declared_profile_sha256) ||
      !ColorBleedIsSha256(envelope.trailing_sha256)) {
    error = "diagnostic envelope contains an invalid SHA-256 value";
    return false;
  }
  if (!ColorBleedBase64Decode(envelope.data_base64, bytes, error)) {
    return false;
  }
  if (bytes.size() != envelope.length) {
    error = "decoded payload length does not match diagnostic metadata";
    return false;
  }

  if (bytes.size() >= 132) {
    uint64_t header_declared_length =
        (static_cast<uint64_t>(bytes[0]) << 24) |
        (static_cast<uint64_t>(bytes[1]) << 16) |
        (static_cast<uint64_t>(bytes[2]) << 8) |
        static_cast<uint64_t>(bytes[3]);
    if (header_declared_length != envelope.header_declared_profile_length) {
      error = "decoded ICC header length does not match diagnostic metadata";
      return false;
    }
    uint64_t bounded_declared_length = header_declared_length;
    if (bounded_declared_length < 128 ||
        bounded_declared_length > envelope.length) {
      bounded_declared_length = envelope.length;
    }
    if (bounded_declared_length != envelope.declared_profile_length) {
      error = "declared profile split does not match decoded ICC header";
      return false;
    }
  } else if (envelope.header_declared_profile_length != 0 ||
             envelope.declared_profile_length != envelope.length ||
             envelope.trailing_length != 0) {
    error = "short binary envelope has inconsistent profile split metadata";
    return false;
  }

  size_t declared_size = static_cast<size_t>(envelope.declared_profile_length);
  size_t trailing_size = static_cast<size_t>(envelope.trailing_length);
  const uint8_t* data = bytes.empty() ? nullptr : bytes.data();
  std::string full_sha256 = ColorBleedSha256(data, bytes.size());
  std::string declared_sha256 = ColorBleedSha256(data, declared_size);
  std::string trailing_sha256 =
      ColorBleedSha256(data ? data + declared_size : nullptr, trailing_size);
  if (full_sha256 != ColorBleedLower(envelope.sha256)) {
    error = "decoded payload SHA-256 does not match diagnostic metadata";
    return false;
  }
  if (declared_sha256 != ColorBleedLower(envelope.declared_profile_sha256)) {
    error = "declared profile SHA-256 does not match diagnostic metadata";
    return false;
  }
  if (trailing_sha256 != ColorBleedLower(envelope.trailing_sha256)) {
    error = "trailing payload SHA-256 does not match diagnostic metadata";
    return false;
  }
  return true;
}

static inline bool ColorBleedWriteAtomic(
    const char* path,
    const std::vector<uint8_t>& bytes,
    std::string& error) {
  std::string pattern = std::string(path) + ".tmp-XXXXXX";
  if (pattern.size() >= PATH_MAX) {
    error = "output path is too long";
    return false;
  }

  std::vector<char> temporary(pattern.begin(), pattern.end());
  temporary.push_back('\0');
  int fd = mkstemp(temporary.data());
  if (fd < 0) {
    error = std::string("unable to create output temporary: ") +
        strerror(errno);
    return false;
  }

  bool failed = fchmod(fd, 0644) != 0;
  int failure_errno = failed ? errno : 0;
  size_t offset = 0;
  while (!failed && offset < bytes.size()) {
    ssize_t count = write(fd, bytes.data() + offset, bytes.size() - offset);
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count <= 0) {
      failed = true;
      failure_errno = count < 0 ? errno : EIO;
      break;
    }
    offset += static_cast<size_t>(count);
  }
  if (!failed && fsync(fd) != 0) {
    failed = true;
    failure_errno = errno;
  }
  if (close(fd) != 0 && !failed) {
    failed = true;
    failure_errno = errno;
  }

  if (!failed && rename(temporary.data(), path) != 0) {
    failed = true;
    failure_errno = errno;
  }
  if (failed) {
    unlink(temporary.data());
    error = std::string("unable to publish restored binary: ") +
        strerror(failure_errno);
    return false;
  }
  return true;
}

#endif // COLORBLEED_BINARY_ENVELOPE_H
