/*
 * IccHeuristicResult.cpp — HeuristicCollector implementation
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 */

#include "IccHeuristicResult.h"
#include "IccAnalyzerColors.h"

#include <cstdio>
#include <cstdarg>
#include <cstring>
#include <string>

// ── Singleton ──

HeuristicCollector::HeuristicCollector()
  : m_active(false), m_collecting(true), m_quiet(false), m_lastCount(0)
{}

HeuristicCollector &HeuristicCollector::instance()
{
  static HeuristicCollector s_instance;
  return s_instance;
}

// ── String formatting helper ──

std::string HeuristicCollector::vformat(const char *fmt, va_list ap)
{
  // Measure required length
  va_list ap2;
  va_copy(ap2, ap);
  int len = vsnprintf(nullptr, 0, fmt, ap2);
  va_end(ap2);
  if (len <= 0) return std::string();

  std::string result(static_cast<size_t>(len), '\0');
  vsnprintf(&result[0], static_cast<size_t>(len) + 1, fmt, ap);
  return result;
}

// ── begin / warn / cweNote / critical / info / end / skip ──

void HeuristicCollector::begin(int id, const char *title)
{
  m_current = HeuristicFinding();
  m_current.id = id;
  m_current.title = title ? title : "";
  m_current.status = "ok";
  m_active = true;

  // Backward-compatible printf (suppressed in quiet mode)
  if (!m_quiet)
    printf("[H%d] %s\n", id, title ? title : "");
}

void HeuristicCollector::warn(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  std::string msg = vformat(fmt, ap);
  va_end(ap);

  if (m_active) {
    m_current.details.push_back(msg);
    m_current.findingCount++;
    if (m_current.status != "critical")
      m_current.status = "warn";
  }

  // Backward-compatible printf: "      [WARN]  <message>" (suppressed in quiet mode)
  if (!m_quiet)
    printf("      %s[WARN]  %s%s\n", ColorCritical(), msg.c_str(), ColorReset());
}

void HeuristicCollector::cweNote(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  std::string msg = vformat(fmt, ap);
  va_end(ap);

  if (m_active) {
    m_current.details.push_back(msg);
  }

  // Backward-compatible printf: "       <CWE note>" (suppressed in quiet mode)
  if (!m_quiet)
    printf("       %s%s%s\n", ColorCritical(), msg.c_str(), ColorReset());
}

void HeuristicCollector::critical(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  std::string msg = vformat(fmt, ap);
  va_end(ap);

  if (m_active) {
    m_current.details.push_back(msg);
    m_current.findingCount++;
    m_current.status = "critical";
  }

  if (!m_quiet)
    printf("      %s[WARN]  CRITICAL: %s%s\n", ColorCritical(), msg.c_str(), ColorReset());
}

void HeuristicCollector::info(const char *fmt, ...)
{
  va_list ap;
  va_start(ap, fmt);
  std::string msg = vformat(fmt, ap);
  va_end(ap);

  if (m_active) {
    m_current.details.push_back(msg);
  }

  if (!m_quiet)
    printf("      %s\n", msg.c_str());
}

int HeuristicCollector::end(const char *okMessage)
{
  int count = 0;
  if (m_active) {
    count = m_current.findingCount;
    if (count == 0) {
      m_current.status = "ok";
      if (!m_quiet)
        printf("      %s[OK] %s%s\n",
               ColorSuccess(),
               okMessage ? okMessage : "No issues detected",
               ColorReset());
    }
    if (m_collecting) {
      m_results.push_back(std::move(m_current));
    }
    m_active = false;
    m_lastCount = count;
  }
  if (!m_quiet)
    printf("\n");
  return count;
}

int HeuristicCollector::skip(const char *reason)
{
  if (m_active) {
    m_current.status = "skip";
    m_current.findingCount = 0;
    if (m_collecting) {
      m_results.push_back(std::move(m_current));
    }
    m_active = false;
    m_lastCount = 0;
  }
  if (!m_quiet)
    printf("      [SKIP] %s\n\n", reason ? reason : "");
  return 0;
}

int HeuristicCollector::totalFindings() const
{
  int total = 0;
  for (const auto &r : m_results)
    total += r.findingCount;
  return total;
}

void HeuristicCollector::reset()
{
  m_results.clear();
  m_current = HeuristicFinding();
  m_active = false;
  m_lastCount = 0;
}
