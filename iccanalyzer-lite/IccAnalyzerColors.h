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

#ifndef _ICCANALYZERCOLORS_H
#define _ICCANALYZERCOLORS_H

#include <stdio.h>
#include <stdbool.h>

#ifdef _WIN32
  #include <io.h>
  #define isatty _isatty
  #define fileno _fileno
#else
  #include <unistd.h>
#endif

// Global color enable flag
static bool g_useColors = true;

// ANSI color codes
#define COLOR_RESET   "\033[0m"
#define COLOR_BOLD    "\033[1m"

// Foreground colors
#define COLOR_RED     "\033[31m"
#define COLOR_GREEN   "\033[32m"
#define COLOR_YELLOW  "\033[33m"
#define COLOR_BLUE    "\033[34m"
#define COLOR_MAGENTA "\033[35m"
#define COLOR_CYAN    "\033[36m"
#define COLOR_WHITE   "\033[37m"

// Bold + color combinations for emphasis
#define COLOR_BOLD_RED     "\033[1;31m"
#define COLOR_BOLD_GREEN   "\033[1;32m"
#define COLOR_BOLD_YELLOW  "\033[1;33m"
#define COLOR_BOLD_BLUE    "\033[1;34m"
#define COLOR_BOLD_MAGENTA "\033[1;35m"
#define COLOR_BOLD_CYAN    "\033[1;36m"

// Semantic color aliases
#define COLOR_CRITICAL  COLOR_BOLD_RED
#define COLOR_ERROR     COLOR_RED
#define COLOR_WARNING   COLOR_YELLOW
#define COLOR_SUCCESS   COLOR_GREEN
#define COLOR_INFO      COLOR_CYAN
#define COLOR_HEADER    COLOR_BOLD_BLUE

inline const char* GetColor(const char* color) {
  return g_useColors ? color : "";
}

inline const char* ColorReset() {
  return GetColor(COLOR_RESET);
}

inline const char* ColorCritical() {
  return GetColor(COLOR_CRITICAL);
}

inline const char* ColorError() {
  return GetColor(COLOR_ERROR);
}

inline const char* ColorWarning() {
  return GetColor(COLOR_WARNING);
}

inline const char* ColorSuccess() {
  return GetColor(COLOR_SUCCESS);
}

inline const char* ColorInfo() {
  return GetColor(COLOR_INFO);
}

inline const char* ColorHeader() {
  return GetColor(COLOR_HEADER);
}

inline bool IsTTY(FILE* stream = stdout) {
  return isatty(fileno(stream)) != 0;
}

inline void InitializeColors(bool forceDisable = false) {
  if (forceDisable) {
    g_useColors = false;
    return;
  }
  
  // Auto-detect: only use colors if stdout is a terminal
  g_useColors = IsTTY(stdout);
  
#ifdef _WIN32
  // On Windows, enable virtual terminal processing
  if (g_useColors) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
      DWORD dwMode = 0;
      if (GetConsoleMode(hOut, &dwMode)) {
        dwMode |= 0x0004; // ENABLE_VIRTUAL_TERMINAL_PROCESSING
        SetConsoleMode(hOut, dwMode);
      }
    }
  }
#endif
}

inline void DisableColors() {
  g_useColors = false;
}

inline void EnableColors() {
  g_useColors = true;
}

inline bool ColorsEnabled() {
  return g_useColors;
}

// Utility function for colored printf
#define printf_color(color, format, ...) \
  printf("%s" format "%s", GetColor(color), ##__VA_ARGS__, ColorReset())

#define printf_critical(format, ...) printf_color(COLOR_CRITICAL, format, ##__VA_ARGS__)
#define printf_error(format, ...) printf_color(COLOR_ERROR, format, ##__VA_ARGS__)
#define printf_warning(format, ...) printf_color(COLOR_WARNING, format, ##__VA_ARGS__)
#define printf_success(format, ...) printf_color(COLOR_SUCCESS, format, ##__VA_ARGS__)
#define printf_info(format, ...) printf_color(COLOR_INFO, format, ##__VA_ARGS__)
#define printf_header(format, ...) printf_color(COLOR_HEADER, format, ##__VA_ARGS__)

#endif // _ICCANALYZERCOLORS_H
