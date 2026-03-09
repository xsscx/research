/*
 * IccAnalyzerHash.h — Shared cryptographic hash utilities
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

#ifndef ICC_ANALYZER_HASH_H
#define ICC_ANALYZER_HASH_H

#include <cstdio>
#include <string>
#include <openssl/evp.h>

// Compute SHA-256 of a file (no shell commands — safe from injection).
// Returns hex string on success, fallback on failure.
inline std::string ComputeFileSHA256(const char *path,
                                     const char *fallback = "(unavailable)") {
  FILE *fp = fopen(path, "rb");
  if (!fp) return fallback;

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) { fclose(fp); return fallback; }

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx); fclose(fp); return fallback;
  }

  unsigned char buf[8192];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
    EVP_DigestUpdate(ctx, buf, n);
  }
  fclose(fp);

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLen = 0;
  EVP_DigestFinal_ex(ctx, hash, &hashLen);
  EVP_MD_CTX_free(ctx);

  char hex[65] = {};
  for (unsigned int i = 0; i < hashLen && i < 32; i++) {
    snprintf(hex + i * 2, 3, "%02x", hash[i]);
  }
  return std::string(hex);
}

#endif // ICC_ANALYZER_HASH_H
