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

#include "IccAnalyzerConfig.h"
#include <cstdio>
#include <cstring>
#include <climits>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>

static std::string Trim(const std::string &str) {
  size_t start = 0;
  while (start < str.length() && isspace(str[start])) start++;
  
  size_t end = str.length();
  while (end > start && isspace(str[end - 1])) end--;
  
  return str.substr(start, end - start);
}

bool LoadConfig(const char *config_path, IccAnalyzerConfig &config) {
  FILE *fp = fopen(config_path, "r");
  if (!fp) {
    return false;
  }
  
  char line[1024];
  std::string current_section;
  
  while (fgets(line, sizeof(line), fp)) {
    std::string str_line = Trim(line);
    
    if (str_line.empty() || str_line[0] == '#' || str_line[0] == ';') {
      continue;
    }
    
    if (str_line[0] == '[' && str_line[str_line.length() - 1] == ']') {
      current_section = str_line.substr(1, str_line.length() - 2);
      continue;
    }
    
    size_t eq_pos = str_line.find('=');
    if (eq_pos == std::string::npos) {
      continue;
    }
    
    std::string key = Trim(str_line.substr(0, eq_pos));
    std::string value = Trim(str_line.substr(eq_pos + 1));
    
    if (current_section == "defaults") {
      if (key == "fingerprint_db") {
        config.fingerprint_db = value;
      } else if (key == "output_dir") {
        config.output_dir = value;
      } else if (key == "output_format") {
        config.output_format = value;
      }
    } else if (current_section == "heuristics") {
      if (key == "min_severity") {
        config.min_severity = value;
      }
    } else if (current_section == "watch") {
      if (key == "auto_create_dirs") {
        config.auto_create_dirs = (value == "true" || value == "1" || value == "yes");
      }
    }
  }
  
  fclose(fp);
  return true;
}

bool LoadConfigAuto(IccAnalyzerConfig &config) {
  const char *home = getenv("HOME");
  if (!home || !home[0]) {
    return false;
  }
  
  // Canonicalize HOME via realpath() to prevent path traversal
  char resolved_home[PATH_MAX];
  if (realpath(home, resolved_home) == nullptr) {
    return false;
  }
  
  // Verify resolved HOME is an absolute path without traversal
  if (resolved_home[0] != '/' || strstr(resolved_home, "..") != nullptr) {
    fprintf(stderr, "WARNING: HOME resolved to suspicious path — skipping config load\n");
    return false;
  }
  
  char config_path[PATH_MAX];
  char resolved_config[PATH_MAX];
  
  snprintf(config_path, sizeof(config_path), "%s/.iccanalyzer.conf", resolved_home);
  if (realpath(config_path, resolved_config) != nullptr &&
      strncmp(resolved_config, resolved_home, strlen(resolved_home)) == 0) {
    if (LoadConfig(resolved_config, config)) {
      return true;
    }
  }
  
  snprintf(config_path, sizeof(config_path), "%s/.config/iccanalyzer.conf", resolved_home);
  if (realpath(config_path, resolved_config) != nullptr &&
      strncmp(resolved_config, resolved_home, strlen(resolved_home)) == 0) {
    if (LoadConfig(resolved_config, config)) {
      return true;
    }
  }
  
  if (LoadConfig(".iccanalyzer.conf", config)) {
    return true;
  }
  
  return false;
}

void PrintConfigHelp() {
  printf("Configuration File Support\n");
  printf("==========================\n\n");
  printf("iccAnalyzer looks for configuration files in the following locations:\n");
  printf("  1. ./.iccanalyzer.conf (current directory)\n");
  printf("  2. ~/.config/iccanalyzer.conf (user config directory)\n");
  printf("  3. ~/.iccanalyzer.conf (user home directory)\n\n");
  printf("Configuration file format (INI-style):\n\n");
  printf("[defaults]\n");
  printf("fingerprint_db = /path/to/SIGNATURE_DATABASE.json\n");
  printf("output_dir = ./reports\n");
  printf("output_format = html,json,sarif\n\n");
  printf("[heuristics]\n");
  printf("min_severity = MEDIUM\n\n");
  printf("[watch]\n");
  printf("auto_create_dirs = true\n\n");
  printf("Example configuration file:\n");
  printf("  # ICC Analyzer Configuration\n");
  printf("  # Lines starting with # or ; are comments\n");
  printf("  \n");
  printf("  [defaults]\n");
  printf("  fingerprint_db = /opt/icc/malicious-db.json\n");
  printf("  output_dir = /var/reports/icc\n");
  printf("  output_format = html,sarif\n");
  printf("  \n");
  printf("  [heuristics]\n");
  printf("  min_severity = HIGH\n");
  printf("  \n");
  printf("  [watch]\n");
  printf("  auto_create_dirs = true\n\n");
  printf("Command-line arguments override configuration file settings.\n");
}
