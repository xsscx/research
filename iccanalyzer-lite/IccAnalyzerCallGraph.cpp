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
#include <cstdlib>
#include <climits>
#include <libgen.h>
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
  
  // Require ASAN signature — if not present, this is not an ASAN log
  std::regex error_regex("ERROR: AddressSanitizer: ([^\\s]+)");
  std::smatch match;
  if (!std::regex_search(content, match, error_regex)) {
    return false;
  }
  metadata.m_error_type = match[1];
  
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
  
  // Parse stack frames — only from the crash stack, stop at "allocated by" section
  // ASAN format: "#N 0xADDR in FUNC_SIG FILE_PATH:LINE[:COL]"
  std::regex frame_regex("\\s*#(\\d+)\\s+0x[0-9a-f]+\\s+in\\s+(.+?)\\s+([^\\s:]+\\.(?:cpp|c|cc|cxx|h|hpp)):(\\d+)");
  
  // Find crash stack boundaries — stop before "allocated by" or "freed by" sections
  std::string::size_type stack_end = content.size();
  for (const char* boundary : {"allocated by thread", "freed by thread", "previously allocated by"}) {
    std::string::size_type pos = content.find(boundary);
    if (pos != std::string::npos && pos < stack_end) {
      stack_end = pos;
    }
  }
  
  std::string crash_stack = content.substr(0, stack_end);
  std::string::const_iterator search_start(crash_stack.cbegin());
  
  while (std::regex_search(search_start, crash_stack.cend(), match, frame_regex)) {
    ASANFrame frame;
    frame.m_frame_num = safe_stoi(match[1]);
    
    // Extract function name (remove template parameters and signature)
    std::string func = match[2];
    func = std::regex_replace(func, std::regex("<[^>]*>"), "<>");
    size_t paren_pos = func.find('(');
    if (paren_pos != std::string::npos) {
      func = func.substr(0, paren_pos);
    }
    frame.m_function_name = func;
    
    // Extract file basename
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
  
  bool is_exploitable = false;
  const std::string& etype = metadata.m_error_type;

  if (etype == "stack-buffer-overflow") {
    printf("[CRITICAL] Stack buffer overflow detected\n");
    printf("  Impact: Can overwrite return address, RCE possible\n");
    is_exploitable = true;
  } else if (etype == "heap-buffer-overflow") {
    printf("[CRITICAL] Heap buffer overflow detected\n");
    printf("  Impact: Can corrupt heap metadata, RCE with heap grooming\n");
    is_exploitable = true;
  } else if (etype == "heap-use-after-free") {
    printf("[CRITICAL] Use-after-free detected\n");
    printf("  Impact: Can control freed object, RCE highly likely\n");
    is_exploitable = true;
  } else if (etype == "stack-use-after-return") {
    printf("[CRITICAL] Stack use-after-return detected\n");
    printf("  Impact: Can read/write dangling stack frame\n");
    is_exploitable = true;
  } else if (etype == "double-free") {
    printf("[CRITICAL] Double-free detected\n");
    printf("  Impact: Heap corruption, RCE with allocator exploitation\n");
    is_exploitable = true;
  } else if (etype == "stack-overflow") {
    printf("[HIGH] Stack overflow (unbounded recursion)\n");
    printf("  Impact: Denial of service, potential stack pivot\n");
    is_exploitable = false;
  } else if (etype == "alloc-dealloc-mismatch") {
    printf("[MEDIUM] Allocation/deallocation mismatch\n");
    printf("  Impact: Undefined behavior, potential heap corruption\n");
    is_exploitable = false;
  } else if (etype == "SEGV" || etype == "null-dereference") {
    printf("[HIGH] NULL pointer dereference / SEGV\n");
    printf("  Impact: Denial of service, potential info leak\n");
    is_exploitable = false;
  } else if (etype == "global-buffer-overflow") {
    printf("[HIGH] Global buffer overflow detected\n");
    printf("  Impact: Can corrupt global data, potential code execution\n");
    is_exploitable = true;
  } else if (etype.find("runtime error") != std::string::npos) {
    printf("[MEDIUM] Undefined behavior (UBSAN finding)\n");
    printf("  Detail: %s\n", etype.c_str());
    is_exploitable = false;
  } else if (!etype.empty()) {
    printf("[INFO] ASAN error: %s\n", etype.c_str());
  }
  
  if (metadata.m_overflow_bytes > 0) {
    printf("\nOverflow: %u bytes beyond buffer\n", metadata.m_overflow_bytes);
    if (metadata.m_overflow_bytes >= 8) {
      printf("  Sufficient to overwrite pointers (64-bit)\n");
    }
    if (metadata.m_overflow_bytes >= 4) {
      printf("  Sufficient to overwrite pointers (32-bit)\n");
    }
  }
  
  unsigned int depth = GetCallChainDepth(frames);
  printf("\nCall chain depth: %u\n", depth);
  if (depth > 10) {
    printf("  Deep call chain — likely recursive or deeply nested API\n");
  } else if (depth > 5) {
    printf("  Moderate call chain depth\n");
  }
  
  // Summary verdict
  printf("\nVerdict: %s\n", is_exploitable ? "EXPLOITABLE" : "NOT DIRECTLY EXPLOITABLE");
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
  
  // Try ASAN log first, fall back to UBSAN
  if (!ParseASANLog(asan_log, frames, metadata)) {
    if (!ParseUBSANLog(asan_log, frames, metadata)) {
      return false;
    }
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
  
  // Export JSON alongside DOT
  std::string json_file = std::string(output_file) + ".json";
  ExportJSON(frames, metadata, json_file.c_str());
  
  // Export to PNG
  if (!ExportGraph(dot_file.c_str(), output_file, "png")) {
    fprintf(stderr, "WARNING: PNG export failed, DOT file available: %s\n", SanitizeForLog(dot_file).c_str());
  }
  
  return true;
}

// Parse UBSAN runtime error log
bool CIccAnalyzerCallGraph::ParseUBSANLog(const char* log_file,
                                            std::vector<ASANFrame>& frames,
                                            VulnMetadata& metadata)
{
  std::ifstream file(log_file);
  if (!file.is_open()) {
    fprintf(stderr, "ERROR: Cannot open log file: %s\n", SanitizeForLog(log_file).c_str());
    return false;
  }
  
  std::string content((std::istreambuf_iterator<char>(file)),
                       std::istreambuf_iterator<char>());
  file.close();
  
  if (content.empty()) return false;
  
  // UBSAN errors: "<file>:<line>:<col>: runtime error: <message>"
  std::regex ubsan_regex("([^:\\s]+):(\\d+):(\\d+): runtime error: (.+)");
  std::smatch match;
  if (!std::regex_search(content, match, ubsan_regex)) {
    return false;
  }
  
  metadata.m_error_type = "runtime error: " + std::string(match[4]);
  
  // Build a synthetic frame from the UBSAN location
  ASANFrame frame;
  frame.m_frame_num = 0;
  frame.m_file_path = match[1];
  frame.m_line_number = safe_stoi(match[2]);
  frame.m_is_crash = true;
  frame.m_function_name = "<ubsan-location>";
  
  // Try to find a stack trace after the UBSAN error
  std::regex stack_regex("\\s*#(\\d+)\\s+0x[0-9a-f]+\\s+in\\s+(.+?)\\s+(.+?):(\\d+)");
  std::string::const_iterator search_start(content.cbegin());
  bool found_stack = false;
  
  while (std::regex_search(search_start, content.cend(), match, stack_regex)) {
    ASANFrame sframe;
    sframe.m_frame_num = safe_stoi(match[1]);
    std::string func = match[2];
    func = std::regex_replace(func, std::regex("<[^>]*>"), "<>");
    size_t paren_pos = func.find('(');
    if (paren_pos != std::string::npos) func = func.substr(0, paren_pos);
    sframe.m_function_name = func;
    
    std::string fpath = match[3];
    size_t slash_pos = fpath.find_last_of("/\\");
    if (slash_pos != std::string::npos) fpath = fpath.substr(slash_pos + 1);
    sframe.m_file_path = fpath;
    sframe.m_line_number = safe_stoi(match[4]);
    sframe.m_is_crash = (sframe.m_frame_num == 0);
    
    frames.push_back(sframe);
    search_start = match.suffix().first;
    found_stack = true;
  }
  
  // If no stack trace, use the single UBSAN location
  if (!found_stack) {
    frames.push_back(frame);
  }
  
  return !frames.empty();
}

// Export call graph as JSON
bool CIccAnalyzerCallGraph::ExportJSON(const std::vector<ASANFrame>& frames,
                                        const VulnMetadata& metadata,
                                        const char* output_file)
{
  std::ofstream jf(output_file);
  if (!jf.is_open()) {
    fprintf(stderr, "ERROR: Cannot create JSON file: %s\n", SanitizeForLog(output_file).c_str());
    return false;
  }
  
  jf << "{\n";
  jf << "  \"error_type\": \"" << metadata.m_error_type << "\",\n";
  jf << "  \"access_type\": \"" << metadata.m_access_type << "\",\n";
  jf << "  \"access_size\": " << metadata.m_access_size << ",\n";
  if (!metadata.m_var_name.empty()) {
    jf << "  \"variable\": \"" << metadata.m_var_name << "\",\n";
    jf << "  \"var_size\": " << metadata.m_var_size << ",\n";
    jf << "  \"overflow_bytes\": " << metadata.m_overflow_bytes << ",\n";
  }
  jf << "  \"call_chain_depth\": " << frames.size() << ",\n";
  jf << "  \"frames\": [\n";
  
  for (size_t i = 0; i < frames.size(); i++) {
    const ASANFrame& f = frames[i];
    jf << "    {\"frame\": " << f.m_frame_num
       << ", \"function\": \"" << f.m_function_name
       << "\", \"file\": \"" << f.m_file_path
       << "\", \"line\": " << f.m_line_number
       << ", \"is_crash\": " << (f.m_is_crash ? "true" : "false")
       << "}";
    if (i + 1 < frames.size()) jf << ",";
    jf << "\n";
  }
  
  jf << "  ]\n}\n";
  jf.close();
  
  printf("[OK] JSON report generated: %s\n", SanitizeForLog(output_file).c_str());
  return true;
}

// Command-line mode handler
int RunCallGraphMode(int argc, char* argv[])
{
  if (argc < 3) {
    fprintf(stderr, "Usage: iccAnalyzer-lite -cg <asan_or_ubsan.log> [output.png]\n");
    fprintf(stderr, "\nGenerates call graph from ASAN/UBSAN crash log\n");
    fprintf(stderr, "Output: PNG visualization + DOT file + JSON report\n");
    fprintf(stderr, "\nSupported log formats:\n");
    fprintf(stderr, "  - ASAN: stack-buffer-overflow, heap-buffer-overflow,\n");
    fprintf(stderr, "          heap-use-after-free, double-free, SEGV, etc.\n");
    fprintf(stderr, "  - UBSAN: runtime error (signed overflow, shift, etc.)\n");
    return 1;
  }
  
  const char* log_file = argv[2];
  const char* output_file = (argc >= 4) ? argv[3] : "callgraph.png";

  // Validate log_file: must exist and resolve to a real path
  char resolvedLog[PATH_MAX];
  if (!realpath(log_file, resolvedLog)) {
    fprintf(stderr, "ERROR: Cannot resolve log file path: %s\n", log_file);
    return 1;
  }
  log_file = resolvedLog;

  // Validate output_file: resolve directory via realpath, sanitize basename
  // Extract and resolve directory component
  char resolvedOutDir[PATH_MAX];
  {
    char *outDup = strdup(output_file);
    char *dirPart = dirname(outDup);
    if (!realpath(dirPart, resolvedOutDir)) {
      fprintf(stderr, "ERROR: Cannot resolve output directory: %s\n", dirPart);
      free(outDup);
      return 1;
    }
    free(outDup);
  }
  // Extract and sanitize basename: only allow safe filename characters
  char resolvedOutPath[PATH_MAX];
  {
    char *outDup2 = strdup(output_file);
    const char *basePart = basename(outDup2);
    std::string safeName;
    for (size_t i = 0; basePart[i] && safeName.size() < 255; ++i) {
      unsigned char c = static_cast<unsigned char>(basePart[i]);
      if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')
        safeName += static_cast<char>(c);
    }
    free(outDup2);
    if (safeName.empty()) safeName = "callgraph.png";
    int n = snprintf(resolvedOutPath, PATH_MAX, "%s/%s", resolvedOutDir, safeName.c_str());
    if (n < 0 || n >= PATH_MAX) {
      fprintf(stderr, "ERROR: Output path too long (truncated)\n");
      return 1;
    }
  }
  output_file = resolvedOutPath;

  CIccAnalyzerCallGraph analyzer;
  
  if (!analyzer.MapCrashToSource(log_file, ".", output_file)) {
    fprintf(stderr, "ERROR: Call graph generation failed\n");
    return 1;
  }
  
  printf("\n[OK] Call graph analysis complete\n");
  printf("  PNG:  %s\n", output_file);
  printf("  DOT:  %s.dot\n", output_file);
  printf("  JSON: %s.json\n", output_file);
  
  return 0;
}
