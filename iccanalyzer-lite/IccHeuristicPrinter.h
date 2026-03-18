// IccHeuristicPrinter.h — Output helpers for iccanalyzer-lite heuristics
//
// Standardized formatting functions for writing new heuristics (H166+).
// Each function maps to one common output line pattern, ensuring consistent
// indentation, color codes, and format strings across 1000+ heuristics.
//
// Existing heuristics (H1-H165) use direct printf — do NOT refactor them
// to use these helpers (tests validate exact output byte-for-byte).
//
// Usage example:
//   int RunHeuristic_H200_ExampleCheck(CIccProfile *pIcc) {
//     H_Title(200, "Example Check (ICC.1-2022-05 §7.2.5)");
//     if (!pIcc) { H_Skip("Profile not loaded"); H_End(); return 0; }
//     if (bad_condition) {
//       H_Warn("Header field X is invalid — ICC.1-2022-05 §7.2.5");
//       H_CWE(20, "Improper Input Validation");
//       H_End();
//       return 1;
//     }
//     H_OK("Header field X is valid");
//     H_End();
//     return 0;
//   }

#pragma once

#include <cstdio>
#include <cstdarg>
#include "IccAnalyzerColors.h"

// ─── Title Line ──────────────────────────────────────────────────────
// Prints: [H{id}] {title}\n
inline void H_Title(int id, const char *title) {
  printf("[H%d] %s\n", id, title);
}

// ─── Finding Lines ───────────────────────────────────────────────────
// Prints: "      {red}[WARN]  HEURISTIC: {msg}{reset}\n"
// Caller must increment heuristicCount after calling.
__attribute__((format(printf, 1, 2)))
inline void H_Warn(const char *fmt, ...) {
  printf("      %s[WARN]  HEURISTIC: ", ColorCritical());
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  printf("%s\n", ColorReset());
}

// Prints: "      {red}[CRITICAL] {msg}{reset}\n"
__attribute__((format(printf, 1, 2)))
inline void H_Critical(const char *fmt, ...) {
  printf("      %s[CRITICAL] ", ColorCritical());
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  printf("%s\n", ColorReset());
}

// ─── CWE Reference Lines ────────────────────────────────────────────
// Prints: "       {red}{msg}{reset}\n"
// Usage: H_CWE("CWE-20: Improper Input Validation");
//        H_CWE("CWE-789: Allocation of %u bytes from file-controlled size", tSize);
__attribute__((format(printf, 1, 2)))
inline void H_CWE(const char *fmt, ...) {
  printf("       %s", ColorCritical());
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  printf("%s\n", ColorReset());
}

// ─── Risk Description ────────────────────────────────────────────────
// Prints: "      {yellow}Risk: {msg}{reset}\n"
__attribute__((format(printf, 1, 2)))
inline void H_Risk(const char *fmt, ...) {
  printf("      %sRisk: ", ColorWarning());
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  printf("%s\n", ColorReset());
}

// ─── OK / Info / Skip Lines ─────────────────────────────────────────
// Prints: "      {green}[OK] {msg}{reset}\n"
inline void H_OK(const char *msg = "No issues detected") {
  printf("      %s[OK] %s%s\n", ColorSuccess(), msg, ColorReset());
}

// Prints: "      [INFO] {msg}\n"
__attribute__((format(printf, 1, 2)))
inline void H_Info(const char *fmt, ...) {
  printf("      [INFO] ");
  va_list args;
  va_start(args, fmt);
  vprintf(fmt, args);
  va_end(args);
  printf("\n");
}

// Prints: "      [SKIP] {msg}\n"
inline void H_Skip(const char *msg) {
  printf("      [SKIP] %s\n", msg);
}

// ─── Trailing Newline ────────────────────────────────────────────────
// Required after every heuristic. Separates output blocks.
inline void H_End() {
  printf("\n");
}
