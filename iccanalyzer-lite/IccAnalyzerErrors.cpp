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

#include "IccAnalyzerErrors.h"
#include "IccAnalyzerColors.h"
#include <cstdio>
#include <cstdlib>
#include <sys/stat.h>
#include <unistd.h>

bool g_verbose_errors = false;

void ErrorOutputDirRequired() {
  fprintf(stderr, "\n%sERROR:%s Output directory not specified\n\n", COLOR_BOLD_RED, COLOR_RESET);
  fprintf(stderr, "The %s-output%s option requires a directory path for generated reports.\n\n", COLOR_CYAN, COLOR_RESET);
  fprintf(stderr, "%sExamples:%s\n", COLOR_YELLOW, COLOR_RESET);
  fprintf(stderr, "  iccAnalyzer -batch '*.icc' -output ./reports/\n");
  fprintf(stderr, "  iccAnalyzer -watch corpus/ -output ./analysis/\n\n");
  
  if (g_verbose_errors) {
    fprintf(stderr, "Alternatively, set a default in .iccanalyzer.conf:\n");
    fprintf(stderr, "  [defaults]\n");
    fprintf(stderr, "  output_dir = ./reports\n\n");
    fprintf(stderr, "See: iccAnalyzer -config-help\n\n");
  }
}

void ErrorInvalidFormat(const char *format) {
  fprintf(stderr, "\n%sERROR:%s Invalid output format '%s%s%s'\n\n", COLOR_BOLD_RED, COLOR_RESET, COLOR_YELLOW, format, COLOR_RESET);
  fprintf(stderr, "%sValid formats:%s html, json, csv, md (markdown), sarif\n\n", COLOR_GREEN, COLOR_RESET);
  fprintf(stderr, "%sExamples:%s\n", COLOR_YELLOW, COLOR_RESET);
  fprintf(stderr, "  -format html              # Single format\n");
  fprintf(stderr, "  -format html,json         # Multiple formats\n");
  fprintf(stderr, "  -format html,json,sarif   # GitHub Security integration\n\n");
  
  if (g_verbose_errors) {
    fprintf(stderr, "Format details:\n");
    fprintf(stderr, "  html   - Visual reports with charts (default)\n");
    fprintf(stderr, "  json   - Machine-readable for automation\n");
    fprintf(stderr, "  csv    - Excel/spreadsheet compatible\n");
    fprintf(stderr, "  md     - Markdown for documentation\n");
    fprintf(stderr, "  sarif  - SARIF 2.1.0 for GitHub Security tab\n\n");
  }
}

void ErrorFileNotFound(const char *path) {
  fprintf(stderr, "\n%sERROR:%s File not found: %s%s%s\n\n", COLOR_BOLD_RED, COLOR_RESET, COLOR_YELLOW, path, COLOR_RESET);
  
  // Check if it's a relative path issue
  char cwd[1024];
  if (getcwd(cwd, sizeof(cwd))) {
    fprintf(stderr, "%sCurrent directory:%s %s\n", COLOR_CYAN, COLOR_RESET, cwd);
  }
  
  fprintf(stderr, "\n%sPlease check:%s\n", COLOR_YELLOW, COLOR_RESET);
  fprintf(stderr, "  • File path is correct\n");
  fprintf(stderr, "  • File exists in the current directory\n");
  fprintf(stderr, "  • You have read permissions\n\n");
  
  if (g_verbose_errors) {
    fprintf(stderr, "%sSuggestion:%s Use absolute path to avoid ambiguity:\n", COLOR_GREEN, COLOR_RESET);
    if (path[0] != '/') {
      fprintf(stderr, "  iccAnalyzer %s/%s\n\n", cwd, path);
    } else {
      fprintf(stderr, "  iccAnalyzer /full/path/to/profile.icc\n\n");
    }
  }
}

void ErrorPatternNoMatch(const char *pattern) {
  fprintf(stderr, "\n%sERROR:%s No files match pattern: %s%s%s\n\n", COLOR_BOLD_RED, COLOR_RESET, COLOR_YELLOW, pattern, COLOR_RESET);
  fprintf(stderr, "%sGlob pattern syntax:%s\n", COLOR_CYAN, COLOR_RESET);
  fprintf(stderr, "  *.icc              - All .icc files in current directory\n");
  fprintf(stderr, "  profiles/*.icc     - All .icc files in profiles/\n");
  fprintf(stderr, "  **/*.icc           - Recursive search (all subdirectories)\n");
  fprintf(stderr, "  {*.icc,*.icm}      - Multiple extensions\n\n");
  
  if (g_verbose_errors) {
    fprintf(stderr, "%sCommon issues:%s\n", COLOR_YELLOW, COLOR_RESET);
    fprintf(stderr, "  • Quote the pattern: -batch '*.icc' (not -batch *.icc)\n");
    fprintf(stderr, "  • Check current directory contains .icc files\n");
    fprintf(stderr, "  • Try: ls %s (to verify pattern)\n\n", pattern);
  }
}

void ErrorWatchDirNotFound(const char *path) {
  fprintf(stderr, "\n%sERROR:%s Watch directory not found: %s%s%s\n\n", COLOR_BOLD_RED, COLOR_RESET, COLOR_YELLOW, path, COLOR_RESET);
  fprintf(stderr, "The directory to monitor does not exist or is not accessible.\n\n");
  fprintf(stderr, "%sTo fix:%s\n", COLOR_GREEN, COLOR_RESET);
  fprintf(stderr, "  mkdir -p %s\n", path);
  fprintf(stderr, "  iccAnalyzer -watch %s -output reports/\n\n", path);
  
  if (g_verbose_errors) {
    fprintf(stderr, "Watch mode monitors a directory for new ICC profiles.\n");
    fprintf(stderr, "The directory must exist before starting watch mode.\n\n");
    fprintf(stderr, "%sCommon use case:%s\n", COLOR_CYAN, COLOR_RESET);
    fprintf(stderr, "  # Create fuzzer crash directory\n");
    fprintf(stderr, "  mkdir -p fuzzer-crashes\n\n");
    fprintf(stderr, "  # Monitor for new crashes\n");
    fprintf(stderr, "  iccAnalyzer -watch fuzzer-crashes/ -output crash-reports/\n\n");
  }
}

void ErrorIccProfileInvalid(const char *path, const char *reason) {
  fprintf(stderr, "\n%sERROR:%s Invalid ICC profile: %s%s%s\n", COLOR_BOLD_RED, COLOR_RESET, COLOR_YELLOW, path, COLOR_RESET);
  fprintf(stderr, "%sReason:%s %s\n\n", COLOR_RED, COLOR_RESET, reason);
  
  // Check file size
  struct stat st;
  if (stat(path, &st) == 0) {
    fprintf(stderr, "%sFile size:%s %ld bytes", COLOR_CYAN, COLOR_RESET, st.st_size);
    if (st.st_size < 128) {
      fprintf(stderr, " %s(too small, minimum 128 bytes)%s", COLOR_RED, COLOR_RESET);
    }
    fprintf(stderr, "\n\n");
  }
  
  fprintf(stderr, "%sPossible causes:%s\n", COLOR_YELLOW, COLOR_RESET);
  fprintf(stderr, "  • File is corrupted or truncated\n");
  fprintf(stderr, "  • File is not a valid ICC profile\n");
  fprintf(stderr, "  • File size < 128 bytes (minimum header size)\n");
  fprintf(stderr, "  • Magic bytes are incorrect (expected: 'acsp')\n\n");
  
  fprintf(stderr, "%sTo analyze malformed profiles:%s\n", COLOR_GREEN, COLOR_RESET);
  fprintf(stderr, "  iccAnalyzer -n %s     # Ninja mode (no validation)\n", path);
  fprintf(stderr, "  iccAnalyzer -nf %s    # Ninja mode (full dump)\n\n", path);
  
  if (g_verbose_errors) {
    fprintf(stderr, "%sAdvanced analysis:%s\n", COLOR_CYAN, COLOR_RESET);
    fprintf(stderr, "  hexdump -C %s | head -20    # View raw bytes\n", path);
    fprintf(stderr, "  file %s                     # Detect file type\n", path);
    fprintf(stderr, "  iccAnalyzer -xml %s out.xml # Extract XML structure\n\n", path);
  }
}

void ErrorPermissionDenied(const char *path) {
  fprintf(stderr, "\n%sERROR:%s Permission denied: %s%s%s\n\n", COLOR_BOLD_RED, COLOR_RESET, COLOR_YELLOW, path, COLOR_RESET);
  
  struct stat st;
  if (stat(path, &st) == 0) {
    fprintf(stderr, "%sFile permissions:%s %04o\n", COLOR_CYAN, COLOR_RESET, st.st_mode & 0777);
    fprintf(stderr, "%sOwner:%s UID=%d GID=%d\n\n", COLOR_CYAN, COLOR_RESET, st.st_uid, st.st_gid);
  }
  
  fprintf(stderr, "%sSolutions:%s\n", COLOR_GREEN, COLOR_RESET);
  fprintf(stderr, "  • Check file permissions: ls -l %s\n", path);
  fprintf(stderr, "  • Add read permission: chmod +r %s\n", path);
  fprintf(stderr, "  • Run as file owner or use sudo (if appropriate)\n\n");
  
  if (g_verbose_errors) {
    fprintf(stderr, "%sNote:%s ICC files should typically be readable by all users.\n", COLOR_YELLOW, COLOR_RESET);
    fprintf(stderr, "Recommended permissions: 644 (rw-r--r--)\n\n");
  }
}

void ErrorDatabaseNotFound(const char *path) {
  fprintf(stderr, "\n%sERROR:%s Fingerprint database not found: %s%s%s\n\n", COLOR_BOLD_RED, COLOR_RESET, COLOR_YELLOW, path, COLOR_RESET);
  fprintf(stderr, "The fingerprint database is required for this operation.\n\n");
  fprintf(stderr, "%sTo create a fingerprint database:%s\n", COLOR_GREEN, COLOR_RESET);
  fprintf(stderr, "  iccAnalyzer -fingerprint-create %s crash-file.icc\n\n", path);
  fprintf(stderr, "%sTo use an existing database:%s\n", COLOR_GREEN, COLOR_RESET);
  fprintf(stderr, "  iccAnalyzer -heuristics profile.icc %s\n", path);
  fprintf(stderr, "  iccAnalyzer -comprehensive profile.icc %s\n\n", path);
  
  if (g_verbose_errors) {
    fprintf(stderr, "%sDatabase formats supported:%s\n", COLOR_CYAN, COLOR_RESET);
    fprintf(stderr, "  • Directory with .iccdb files (fingerprints/)\n");
    fprintf(stderr, "  • Consolidated .iccdb file (SIGNATURE_DATABASE.iccdb)\n");
    fprintf(stderr, "  • JSON format (.json)\n\n");
  }
}

void ErrorDatabaseCorrupted(const char *path) {
  fprintf(stderr, "\n%sERROR:%s Fingerprint database corrupted: %s%s%s\n\n", COLOR_BOLD_RED, COLOR_RESET, COLOR_YELLOW, path, COLOR_RESET);
  fprintf(stderr, "The database file exists but cannot be parsed.\n\n");
  
  struct stat st;
  if (stat(path, &st) == 0) {
    fprintf(stderr, "%sFile size:%s %ld bytes\n\n", COLOR_CYAN, COLOR_RESET, st.st_size);
  }
  
  fprintf(stderr, "%sPossible causes:%s\n", COLOR_YELLOW, COLOR_RESET);
  fprintf(stderr, "  • Incomplete write (disk full, interrupted)\n");
  fprintf(stderr, "  • Invalid JSON syntax\n");
  fprintf(stderr, "  • Wrong file format (expected .iccdb or .json)\n");
  fprintf(stderr, "  • File truncation during transfer\n\n");
  
  fprintf(stderr, "%sRecovery options:%s\n", COLOR_GREEN, COLOR_RESET);
  fprintf(stderr, "  1. Restore from backup: cp %s.bak %s\n", path, path);
  fprintf(stderr, "  2. Rebuild database: iccAnalyzer -fingerprint-create %s <profiles>\n", path);
  fprintf(stderr, "  3. Validate JSON: python3 -m json.tool %s\n\n", path);
  
  if (g_verbose_errors) {
    fprintf(stderr, "%sDebug:%s View first 10 lines of database:\n", COLOR_CYAN, COLOR_RESET);
    fprintf(stderr, "  head -10 %s\n\n", path);
  }
}
