/*
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * This software and associated documentation files (the "Software") are the
 * exclusive intellectual property of David H Hoyt LLC.
 *
 * Contact: https://hoyt.net
 */

#ifndef _ICCANALYZERPROGRESS_H
#define _ICCANALYZERPROGRESS_H

#include <cstdio>
#include <cstddef>

// Progress indicator for long-running operations
class CIccAnalyzerProgress {
private:
  const char* m_operation;
  size_t m_total;
  size_t m_current;
  int m_barWidth;
  bool m_enabled;
  
public:
  CIccAnalyzerProgress(const char* operation, size_t total, bool enabled = true)
    : m_operation(operation), m_total(total), m_current(0), m_barWidth(50), m_enabled(enabled) {}
  
  void Update(size_t current) {
    if (!m_enabled || m_total == 0) return;
    
    m_current = current;
    int percent = (m_current * 100) / m_total;
    int filled = (m_barWidth * m_current) / m_total;
    
    fprintf(stderr, "\r%s [", m_operation);
    for (int i = 0; i < m_barWidth; i++) {
      if (i < filled) fprintf(stderr, "=");
      else if (i == filled) fprintf(stderr, ">");
      else fprintf(stderr, " ");
    }
    fprintf(stderr, "] %3d%% (%zu/%zu)", percent, m_current, m_total);
    fflush(stderr);
    
    if (m_current >= m_total) {
      fprintf(stderr, "\n");
    }
  }
  
  void Increment() {
    Update(m_current + 1);
  }
  
  void Finish() {
    Update(m_total);
  }
  
  static void ShowSimple(const char* operation, size_t current, size_t total) {
    if (total == 0) return;
    int percent = (current * 100) / total;
    fprintf(stderr, "\r%s: %3d%% (%zu/%zu)", operation, percent, current, total);
    fflush(stderr);
    if (current >= total) fprintf(stderr, "\n");
  }
};

#endif // _ICCANALYZERPROGRESS_H
