/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * This software and associated documentation files (the "Software") are the
 * exclusive intellectual property of David H Hoyt LLC.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "David H Hoyt LLC" must not be used to endorse or promote
 *    products derived from this software without prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID H HOYT LLC "AS IS" AND ANY EXPRESSED
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL DAVID H HOYT LLC BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Contact: https://hoyt.net
 */

#ifndef _ICCANALYZERSECURITY_H
#define _ICCANALYZERSECURITY_H

#include "IccAnalyzerCommon.h"
#include <string>
#include <vector>
#include <cstdint>

// Enhanced heuristic analysis with optional fingerprint database
int HeuristicAnalyze(const char *filename, const char *fingerprint_db = nullptr);

// ============================================================================
// Phase 14: Security Validation Functions
// ============================================================================

namespace IccAnalyzerSecurity {

// Path validation modes
enum class PathValidationMode {
  STRICT,      // Reject all suspicious paths (default)
  PERMISSIVE,  // Allow but warn on suspicious paths
  DISABLED     // No validation (for testing only)
};

// Path validation results
enum class PathValidationResult {
  VALID,                    // Path is safe
  INVALID_EMPTY,            // Empty path
  INVALID_TOO_LONG,         // Path exceeds system limits
  INVALID_TRAVERSAL,        // Contains path traversal (../)
  INVALID_ABSOLUTE,         // Absolute path not allowed (context-dependent)
  INVALID_SYMLINK,          // Symlink detected
  INVALID_EXTENSION,        // File extension not whitelisted
  INVALID_SPECIAL_CHAR,     // Contains special/control characters
  INVALID_NULL_BYTE,        // Contains null bytes
  INVALID_NONEXISTENT,      // Path does not exist
  INVALID_NOT_REGULAR_FILE, // Not a regular file (e.g., device, socket)
  INVALID_NOT_DIRECTORY     // Not a directory when required
};

/**
 * Validates a file path for security risks.
 * 
 * @param path The file path to validate
 * @param mode Validation strictness level
 * @param require_exists If true, path must exist
 * @param allowed_extensions Whitelist of extensions (e.g., {".icc", ".icm"}), empty = allow all
 * @return Validation result
 */
PathValidationResult ValidateFilePath(
  const std::string& path,
  PathValidationMode mode = PathValidationMode::STRICT,
  bool require_exists = false,
  const std::vector<std::string>& allowed_extensions = {}
);

/**
 * Validates a directory path for security risks.
 * 
 * @param path The directory path to validate
 * @param mode Validation strictness level
 * @param require_exists If true, directory must exist
 * @return Validation result
 */
PathValidationResult ValidateDirectoryPath(
  const std::string& path,
  PathValidationMode mode = PathValidationMode::STRICT,
  bool require_exists = false
);

/**
 * Converts validation result to human-readable error message.
 * 
 * @param result The validation result
 * @param path The path that failed validation
 * @return Error message string
 */
std::string GetValidationErrorMessage(PathValidationResult result, const std::string& path);

/**
 * Sanitizes a path by resolving it to canonical form.
 * 
 * @param path The path to sanitize
 * @param sanitized Output parameter for sanitized path
 * @return true if successful, false if path invalid or doesn't exist
 */
bool SanitizePath(const std::string& path, std::string& sanitized);

/**
 * Checks if a path is a symlink.
 * 
 * @param path The path to check
 * @return true if path is a symlink, false otherwise
 */
bool IsSymlink(const std::string& path);

/**
 * Checks if a path contains traversal sequences (../).
 * 
 * @param path The path to check
 * @return true if traversal detected, false otherwise
 */
bool ContainsPathTraversal(const std::string& path);

/**
 * Checks if a path is within allowed directory boundaries.
 * 
 * @param path The path to check
 * @param base_dir The base directory boundary
 * @return true if path is within base_dir, false otherwise
 */
bool IsWithinBoundary(const std::string& path, const std::string& base_dir);

/**
 * Validates binary database file format security.
 * 
 * @param data Raw binary data
 * @param size Size of data in bytes
 * @param error_message Output parameter for error message
 * @return true if valid, false with error message if invalid
 */
bool ValidateBinaryDatabaseFormat(
  const uint8_t* data,
  size_t size,
  std::string& error_message
);

} // namespace IccAnalyzerSecurity

#endif // _ICCANALYZERSECURITY_H
