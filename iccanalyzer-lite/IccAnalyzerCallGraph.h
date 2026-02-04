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

#ifndef _ICCANALYZERCALLGRAPH_H
#define _ICCANALYZERCALLGRAPH_H

#include "IccAnalyzerCommon.h"
#include <string>
#include <vector>
#include <map>

// Call graph node representing a function
struct CallGraphNode {
  std::string m_function_name;
  std::string m_file_path;
  unsigned int m_line_number;
  std::vector<CallGraphNode*> m_callers;
  std::vector<CallGraphNode*> m_callees;
  bool m_is_crash_site;
  bool m_is_entry_point;
  
  CallGraphNode() : m_line_number(0), m_is_crash_site(false), m_is_entry_point(false) {}
};

// ASAN stack frame data
struct ASANFrame {
  unsigned int m_frame_num;
  std::string m_function_name;
  std::string m_file_path;
  unsigned int m_line_number;
  bool m_is_crash;
  
  ASANFrame() : m_frame_num(0), m_line_number(0), m_is_crash(false) {}
};

// Vulnerability metadata from ASAN
struct VulnMetadata {
  std::string m_error_type;
  std::string m_access_type;
  unsigned int m_access_size;
  std::string m_address;
  std::string m_var_name;
  unsigned int m_var_size;
  unsigned int m_overflow_bytes;
  
  VulnMetadata() : m_access_size(0), m_var_size(0), m_overflow_bytes(0) {}
};

// Call graph generation and analysis
class CIccAnalyzerCallGraph {
public:
  // Parse ASAN crash log
  bool ParseASANLog(const char* log_file, std::vector<ASANFrame>& frames, VulnMetadata& metadata);
  
  // Generate call graph from ASAN frames
  bool GenerateCallGraphFromASAN(const std::vector<ASANFrame>& frames, const char* output_dot);
  
  // Export call graph to various formats
  bool ExportGraph(const char* dot_file, const char* output_file, const char* format);
  
  // Map ASAN crash to source code call chain
  bool MapCrashToSource(const char* asan_log, const char* source_dir, const char* output_file);
  
  // Generate DOT format call graph
  bool GenerateDOTGraph(const std::vector<ASANFrame>& frames, const char* output_file);
  
  // Analyze call chain depth
  unsigned int GetCallChainDepth(const std::vector<ASANFrame>& frames);
  
  // Identify exploitable patterns
  bool AnalyzeExploitability(const VulnMetadata& metadata, const std::vector<ASANFrame>& frames);
  
  // Print call chain in tree format
  void PrintCallChainTree(const std::vector<ASANFrame>& frames, const VulnMetadata& metadata);
};

// Mode handler
int RunCallGraphMode(int argc, char* argv[]);

#endif // _ICCANALYZERCALLGRAPH_H
