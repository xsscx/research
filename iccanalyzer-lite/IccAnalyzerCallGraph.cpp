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

/*
 * [BSD 3-Clause License - see IccAnalyzerCallGraph.h for full text]
 */

#include "IccAnalyzerCallGraph.h"
#include "IccAnalyzerSecurity.h"
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <algorithm>
#include <regex>
#include <sys/types.h>
#include <sys/wait.h>
#include <spawn.h>
#include <stdexcept>

extern char **environ;

static int safe_stoi(const std::string& s, int fallback = 0) {
  try { return std::stoi(s); }
  catch (const std::exception&) { return fallback; }
}

// Parse ASAN crash log and extract stack frames
bool CIccAnalyzerCallGraph::ParseASANLog(const char* log_file, 
                                          std::vector<ASANFrame>& frames,
                                          VulnMetadata& metadata)
{
  // CJF-11: Verify file exists
  std::ifstream file(log_file);
  if (!file.is_open()) {
    fprintf(stderr, "ERROR: Cannot open log file: %s\n", SanitizeForLog(log_file).c_str());
    return false;
  }
  
  std::string content((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
  file.close();
  
  // CJF-11: Verify file not empty
  if (content.empty()) {
    fprintf(stderr, "ERROR: Log file is empty: %s\n", SanitizeForLog(log_file).c_str());
    return false;
  }
  
  // Extract error type
  std::regex error_regex("ERROR: AddressSanitizer: ([^\\s]+)");
  std::smatch match;
  if (std::regex_search(content, match, error_regex)) {
    metadata.m_error_type = match[1];
  }
  
  // Extract access type and size
  std::regex access_regex("(READ|WRITE) of size (\\d+)");
  if (std::regex_search(content, match, access_regex)) {
    metadata.m_access_type = match[1];
    metadata.m_access_size = safe_stoi(match[2]);
  }
  
  // Extract address
  std::regex addr_regex("on address (0x[0-9a-f]+)");
  if (std::regex_search(content, match, addr_regex)) {
    metadata.m_address = match[1];
  }
  
  // Extract stack variable overflow details
  std::regex var_regex("\\[(\\d+), (\\d+)\\) '([^']+)'.*<== Memory access at offset (\\d+)");
  if (std::regex_search(content, match, var_regex)) {
    unsigned int var_start = safe_stoi(match[1]);
    unsigned int var_end = safe_stoi(match[2]);
    metadata.m_var_name = match[3];
    metadata.m_var_size = var_end - var_start;
    unsigned int overflow_offset = safe_stoi(match[4]);
    metadata.m_overflow_bytes = (overflow_offset > var_end) ? (overflow_offset - var_end) : 0;
  }
  
  // Parse stack frames
  std::regex frame_regex("\\s*#(\\d+)\\s+0x[0-9a-f]+\\s+in\\s+(.+?)\\s+(.+?):(\\d+)");
  std::string::const_iterator search_start(content.cbegin());
  
  while (std::regex_search(search_start, content.cend(), match, frame_regex)) {
    ASANFrame frame;
    frame.m_frame_num = safe_stoi(match[1]);
    
    // Extract function name (remove template parameters)
    std::string func = match[2];
    func = std::regex_replace(func, std::regex("<[^>]*>"), "<>");
    size_t paren_pos = func.find('(');
    if (paren_pos != std::string::npos) {
      func = func.substr(0, paren_pos);
    }
    frame.m_function_name = func;
    
    // Extract file and line
    std::string file_path = match[3];
    size_t slash_pos = file_path.find_last_of("/\\");
    if (slash_pos != std::string::npos) {
      file_path = file_path.substr(slash_pos + 1);
    }
    frame.m_file_path = file_path;
    frame.m_line_number = safe_stoi(match[4]);
    frame.m_is_crash = (frame.m_frame_num == 0);
    
    frames.push_back(frame);
    search_start = match.suffix().first;
  }
  
  // CJF-11: Verify parsing succeeded
  if (frames.empty()) {
    fprintf(stderr, "ERROR: No stack frames found in log\n");
    return false;
  }
  
  return true;
}

// Generate DOT format call graph
bool CIccAnalyzerCallGraph::GenerateDOTGraph(const std::vector<ASANFrame>& frames,
                                              const char* output_file)
{
  // CJF-11: Verify frames not empty
  if (frames.empty()) {
    fprintf(stderr, "ERROR: No frames to generate graph\n");
    return false;
  }
  
  std::ofstream dot_file(output_file);
  if (!dot_file.is_open()) {
    fprintf(stderr, "ERROR: Cannot create output file: %s\n", SanitizeForLog(output_file).c_str());
    return false;
  }
  
  // DOT header
  dot_file << "digraph CallChain {\n";
  dot_file << "  rankdir=TB;\n";
  dot_file << "  node [shape=box, style=filled];\n\n";
  
  // Reverse order (entry point first)
  std::vector<ASANFrame> reversed_frames = frames;
  std::reverse(reversed_frames.begin(), reversed_frames.end());
  
  // Generate nodes
  for (size_t i = 0; i < reversed_frames.size(); i++) {
    const ASANFrame& frame = reversed_frames[i];
    
    // Node color based on position
    const char* color = "lightblue";
    if (i == 0) {
      color = "lightgreen"; // Entry point
    } else if (frame.m_is_crash) {
      color = "red"; // Crash site
    } else if (i == reversed_frames.size() - 1) {
      color = "orange"; // Before crash
    }
    
    // Node label
    std::string label = SanitizeForDOT(frame.m_function_name);
    if (frame.m_is_crash) {
      label += "\\nCRASH";
    }
    
    dot_file << "  node_" << i << " [label=\"" << label << "\\n"
             << SanitizeForDOT(frame.m_file_path) << ":" << frame.m_line_number << "\", fillcolor="
             << color << "];\n";
  }
  
  dot_file << "\n";
  
  // Generate edges
  for (size_t i = 0; i < reversed_frames.size() - 1; i++) {
    dot_file << "  node_" << i << " -> node_" << (i + 1);
    if (reversed_frames[i + 1].m_is_crash) {
      dot_file << " [color=red, penwidth=2.0]";
    }
    dot_file << ";\n";
  }
  
  dot_file << "}\n";
  dot_file.close();
  
  // CJF-11: Verify file was written
  std::ifstream verify(output_file);
  if (!verify.is_open() || verify.peek() == std::ifstream::traits_type::eof()) {
    fprintf(stderr, "ERROR: Failed to write DOT file\n");
    return false;
  }
  verify.close();
  
  printf("[OK] DOT graph generated: %s\n", SanitizeForLog(output_file).c_str());
  return true;
}

// Generate call graph from ASAN frames
bool CIccAnalyzerCallGraph::GenerateCallGraphFromASAN(const std::vector<ASANFrame>& frames,
                                                       const char* output_dot)
{
  return GenerateDOTGraph(frames, output_dot);
}

// Export graph to PNG/SVG using Graphviz
bool CIccAnalyzerCallGraph::ExportGraph(const char* dot_file,
                                         const char* output_file,
                                         const char* format)
{
  // CJF-11: Verify input file exists
  std::ifstream test(dot_file);
  if (!test.is_open()) {
    fprintf(stderr, "ERROR: DOT file not found: %s\n", SanitizeForLog(dot_file).c_str());
    return false;
  }
  test.close();
  
  // Validate format
  if (strcmp(format, "png") != 0 && strcmp(format, "svg") != 0 && strcmp(format, "pdf") != 0) {
    fprintf(stderr, "ERROR: Unsupported format: %s (use png/svg/pdf)\n", SanitizeForLog(format).c_str());
    return false;
  }
  
  // SECURITY FIX: Validate paths to prevent path injection
  IccAnalyzerSecurity::PathValidationResult dot_result = IccAnalyzerSecurity::ValidateFilePath(dot_file, IccAnalyzerSecurity::PathValidationMode::STRICT, true, {".dot"});
  if (dot_result != IccAnalyzerSecurity::PathValidationResult::VALID) {
    fprintf(stderr, "ERROR: Invalid dot file path: %s\n", 
            SanitizeForLog(IccAnalyzerSecurity::GetValidationErrorMessage(dot_result, dot_file)).c_str());
    return false;
  }
  
  IccAnalyzerSecurity::PathValidationResult out_result = IccAnalyzerSecurity::ValidateFilePath(output_file, IccAnalyzerSecurity::PathValidationMode::STRICT, false, {});
  if (out_result != IccAnalyzerSecurity::PathValidationResult::VALID) {
    fprintf(stderr, "ERROR: Invalid output file path: %s\n", 
            SanitizeForLog(IccAnalyzerSecurity::GetValidationErrorMessage(out_result, output_file)).c_str());
    return false;
  }
  
  // Build argv for posix_spawn (no shell interpretation)
  std::string fmt_arg = std::string("-T") + format;
  std::string out_arg = std::string("-o") + std::string(output_file);
  const char *argv[] = {"dot", fmt_arg.c_str(), dot_file, out_arg.c_str(), nullptr};

  printf("Executing: dot %s %s %s\n", fmt_arg.c_str(), SanitizeForLog(dot_file).c_str(), SanitizeForLog(out_arg).c_str());

  pid_t pid = 0;
  int ret = posix_spawn(&pid, "/usr/bin/dot", nullptr, nullptr,
                        const_cast<char *const *>(argv), environ);
  if (ret != 0) {
    fprintf(stderr, "ERROR: posix_spawn failed: %s\n", SanitizeForLog(strerror(ret)).c_str());
    return false;
  }
  int status = 0;
  waitpid(pid, &status, 0);
  ret = WIFEXITED(status) ? WEXITSTATUS(status) : 1;
  
  if (ret != 0) {
    fprintf(stderr, "ERROR: Graphviz export failed (exit code: %d)\n", ret);
    fprintf(stderr, "Ensure Graphviz is installed: apt install graphviz\n");
    return false;
  }
  
  // CJF-11: Verify output was created
  std::ifstream verify(output_file);
  if (!verify.is_open() || verify.peek() == std::ifstream::traits_type::eof()) {
    fprintf(stderr, "ERROR: Output file was not created: %s\n", SanitizeForLog(output_file).c_str());
    return false;
  }
  verify.close();
  
  printf("[OK] Graph exported: %s\n", SanitizeForLog(output_file).c_str());
  return true;
}

// Print call chain in tree format
void CIccAnalyzerCallGraph::PrintCallChainTree(const std::vector<ASANFrame>& frames,
                                                 const VulnMetadata& metadata)
{
  printf("\n");
  printf("============================================================\n");
  printf("ASAN Call Chain Analysis\n");
  printf("============================================================\n\n");
  
  // Vulnerability details
  if (!metadata.m_error_type.empty()) {
    printf("Vulnerability Details:\n");
    printf("  Type: %s\n", metadata.m_error_type.c_str());
    
    if (!metadata.m_access_type.empty()) {
      printf("  Access: %s %u bytes\n", metadata.m_access_type.c_str(), metadata.m_access_size);
    }
    
    if (!metadata.m_address.empty()) {
      printf("  Address: %s\n", metadata.m_address.c_str());
    }
    
    if (!metadata.m_var_name.empty()) {
      printf("  Variable: '%s' (%u bytes)\n", metadata.m_var_name.c_str(), metadata.m_var_size);
      if (metadata.m_overflow_bytes > 0) {
        printf("  Overflow: %u bytes beyond buffer\n", metadata.m_overflow_bytes);
      }
    }
    printf("\n");
  }
  
  printf("Call Chain (Entry → Crash):\n\n");
  
  // Reverse order for tree display
  std::vector<ASANFrame> reversed_frames = frames;
  std::reverse(reversed_frames.begin(), reversed_frames.end());
  
  for (size_t i = 0; i < reversed_frames.size(); i++) {
    const ASANFrame& frame = reversed_frames[i];
    
    // Indentation
    for (size_t j = 0; j < i; j++) {
      printf("  ");
    }
    
    // Arrow
    const char* arrow = (i == 0) ? "→" : "└─";
    
    // Function name
    printf("%s %s()", arrow, frame.m_function_name.c_str());
    
    // Mark crash
    if (frame.m_is_crash) {
      printf(" [WARN] CRASH");
    }
    printf("\n");
    
    // File:line
    for (size_t j = 0; j < i; j++) {
      printf("  ");
    }
    printf("   [%s:%u]\n", frame.m_file_path.c_str(), frame.m_line_number);
  }
  
  printf("\n============================================================\n");
  printf("Total frames: %zu\n", frames.size());
  printf("============================================================\n\n");
}

// Get call chain depth
unsigned int CIccAnalyzerCallGraph::GetCallChainDepth(const std::vector<ASANFrame>& frames)
{
  return static_cast<unsigned int>(frames.size());
}

// Analyze exploitability
bool CIccAnalyzerCallGraph::AnalyzeExploitability(const VulnMetadata& metadata,
                                                   const std::vector<ASANFrame>& frames)
{
  printf("\n=== Exploitability Analysis ===\n\n");
  
  // Check error type
  bool is_exploitable = false;
  
  if (metadata.m_error_type == "stack-buffer-overflow") {
    printf("[CRITICAL] Stack buffer overflow detected\n");
    printf("  → Can overwrite return address\n");
    printf("  → RCE possible\n");
    is_exploitable = true;
  } else if (metadata.m_error_type == "heap-buffer-overflow") {
    printf("[WARN] Heap buffer overflow detected\n");
    printf("  → Can corrupt heap metadata\n");
    printf("  → RCE possible with heap grooming\n");
    is_exploitable = true;
  } else if (metadata.m_error_type == "heap-use-after-free") {
    printf("[CRITICAL] Use-after-free detected\n");
    printf("  → Can control freed object\n");
    printf("  → RCE highly likely\n");
    is_exploitable = true;
  }
  
  // Check overflow size
  if (metadata.m_overflow_bytes > 0) {
    printf("\nOverflow bytes: %u\n", metadata.m_overflow_bytes);
    if (metadata.m_overflow_bytes >= 8) {
      printf("  → Sufficient to overwrite pointers\n");
    }
  }
  
  // Check call depth
  unsigned int depth = GetCallChainDepth(frames);
  printf("\nCall chain depth: %u\n", depth);
  if (depth > 5) {
    printf("  → Deep call chain increases exploitation complexity\n");
  }
  
  printf("\n");
  return is_exploitable;
}

// Map ASAN crash to source code
bool CIccAnalyzerCallGraph::MapCrashToSource(const char* asan_log,
                                              const char* source_dir,
                                              const char* output_file)
{
  std::vector<ASANFrame> frames;
  VulnMetadata metadata;
  
  // Parse ASAN log
  if (!ParseASANLog(asan_log, frames, metadata)) {
    return false;
  }
  
  // Generate call chain visualization
  PrintCallChainTree(frames, metadata);
  
  // Analyze exploitability
  AnalyzeExploitability(metadata, frames);
  
  // Generate DOT graph
  std::string dot_file = std::string(output_file) + ".dot";
  if (!GenerateDOTGraph(frames, dot_file.c_str())) {
    return false;
  }
  
  // Export to PNG
  if (!ExportGraph(dot_file.c_str(), output_file, "png")) {
    fprintf(stderr, "WARNING: PNG export failed, DOT file available: %s\n", SanitizeForLog(dot_file).c_str());
  }
  
  return true;
}

// Command-line mode handler
int RunCallGraphMode(int argc, char* argv[])
{
  if (argc < 3) {
    fprintf(stderr, "Usage: iccAnalyzer -callgraph <asan.log> [output.png]\n");
    fprintf(stderr, "\nGenerates call graph from ASAN crash log\n");
    fprintf(stderr, "Output: PNG visualization + DOT file\n");
    return 1;
  }
  
  const char* asan_log = argv[2];
  const char* output_file = (argc >= 4) ? argv[3] : "callgraph.png";
  
  CIccAnalyzerCallGraph analyzer;
  
  if (!analyzer.MapCrashToSource(asan_log, ".", output_file)) {
    fprintf(stderr, "ERROR: Call graph generation failed\n");
    return 1;
  }
  
  printf("\n[OK] Call graph analysis complete\n");
  printf("  Output: %s\n", output_file);
  printf("  DOT file: %s.dot\n", output_file);
  
  return 0;
}
