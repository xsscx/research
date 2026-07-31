/*!
 *  @file IccToJson_unsafe.cpp
 *  @brief Sandboxed Unsafe ICC Blob to JSON Reader
 *
 *  Fork-isolated ICC->JSON conversion using vanilla (unpatched) iccDEV.
 *  Each profile operation runs in a child process with resource limits.
 *  Library crashes are caught and reported as security findings.
 */

#include <algorithm>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "IccTagJsonFactory.h"
#include "IccMpeJsonFactory.h"
#include "IccProfileJson.h"
#include "IccIO.h"
#include "IccProfLibVer.h"
#include "IccLibJSONVer.h"

#define COLORBLEED_SKIP_XML_PREFLIGHT
#include "ColorBleedPreflight.h"
#include "ColorBleedSandbox.h"

static std::string* g_json_output = nullptr;
static char         g_dst_path[PATH_MAX] = {0};

static constexpr int kExitUsage = 64;
static constexpr int kExitNoInput = 66;

static bool IsHelpFlag(const char* arg) {
  return arg && (!strcmp(arg, "-h") || !strcmp(arg, "--help"));
}

static void PrintUsage() {
  printf("IccToJson_unsafe built with IccProfLib Version " ICCPROFLIBVER ", IccLibJSON Version " ICCLIBJSONVER "\n");
  printf("Copyright (c) 2021-2026 David H Hoyt LLC\n");
  printf("Usage: IccToJson_unsafe src_icc_profile dest_json_file {options}\n");
  printf("  -indent=N   pretty-print with N spaces of indentation (default: 2)\n");
  printf("  -sort       sort JSON keys alphabetically (deterministic output)\n");
  printf("  Sandboxed: fork-isolated with ASan/UBSan recoverable mode\n");
  printf("\n");
}

static nlohmann::ordered_json SortJsonKeys(const IccJson& j)
{
  if (j.is_object()) {
    std::vector<std::string> keys;
    for (auto it = j.begin(); it != j.end(); ++it) {
      keys.push_back(it.key());
    }
    std::sort(keys.begin(), keys.end());

    nlohmann::ordered_json sorted = nlohmann::ordered_json::object();
    for (const auto& k : keys) {
      sorted[k] = SortJsonKeys(j[k]);
    }
    return sorted;
  }

  if (j.is_array()) {
    nlohmann::ordered_json arr = nlohmann::ordered_json::array();
    for (const auto& elem : j) {
      arr.push_back(SortJsonKeys(elem));
    }
    return arr;
  }

  return nlohmann::ordered_json::parse(j.dump());
}

static void WritePartialOutput() {
  if (!g_json_output || g_json_output->empty() || g_dst_path[0] == '\0') {
    return;
  }

  g_json_output->append("\n");

  int fd = open(g_dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    FILE* f = fdopen(fd, "wb");
    if (f) {
      size_t written = fwrite(g_json_output->c_str(), 1, g_json_output->size(), f);
      fclose(f);
      if (written == g_json_output->size()) {
        fprintf(stderr, "[ColorBleed] Wrote %zu bytes of partial JSON to %s\n",
                g_json_output->size(), g_dst_path);
      } else {
        fprintf(stderr, "[ColorBleed] Partial write: %zu of %zu bytes to %s\n",
                written, g_json_output->size(), g_dst_path);
      }
    } else {
      close(fd);
    }
  }
}

int main(int argc, char* argv[])
{
  if (argc == 2 && IsHelpFlag(argv[1])) {
    PrintUsage();
    return 0;
  }

  if (argc <= 2) {
    PrintUsage();
    return kExitUsage;
  }

  std::string safe_dst = ValidateOutputPath(argv[2]);
  if (safe_dst.empty()) {
    return kExitUsage;
  }

  int indent = 2;
  bool sort_keys = false;
  for (int i = 3; i < argc; i++) {
    if (!strncmp(argv[i], "-indent=", 8)) {
      indent = atoi(argv[i] + 8);
      if (indent < 0) {
        indent = 0;
      }
      if (indent > 20) {
        indent = 20;
      }
    } else if (!strcmp(argv[i], "-sort")) {
      sort_keys = true;
    }
  }

  if (sort_keys) {
    fprintf(stderr,
            "[ColorBleed] ERROR: -sort is disabled pending sanitizer hardening; "
            "run without -sort for ICC->JSON QA\n");
    return kExitUsage;
  }

  char resolved_src[PATH_MAX];
  if (!realpath(argv[1], resolved_src)) {
    fprintf(stderr, "[ColorBleed] Cannot resolve input path: %s\n", argv[1]);
    return kExitNoInput;
  }
  const char* src_path = resolved_src;
  const char* dst_path = safe_dst.c_str();

  printf("[ColorBleed] Sandboxed ICC->JSON conversion\n");
  printf("[ColorBleed] Input:  %s\n", src_path);
  printf("[ColorBleed] Output: %s\n", dst_path);

  PreflightResult preflight = PreflightValidateICC(src_path);
  preflight.Report(src_path);

  SandboxLimits limits;
  limits.max_mem_mb = 4096;
  limits.max_cpu_sec = 120;
  limits.max_fsize_mb = 512;
  limits.max_wall_sec = 30;

  if (preflight.worst == PreflightSeverity::CRITICAL) {
    limits.max_cpu_sec = 30;
    limits.max_fsize_mb = 128;
    limits.max_wall_sec = 15;
  }

  SandboxResult result = RunSandboxed([&]() -> int {
    CIccTagCreator::PushFactory(new CIccTagJsonFactory());
    CIccMpeCreator::PushFactory(new CIccMpeJsonFactory());

    CIccProfileJson profile;
    CIccFileIO srcIO;

    if (!srcIO.Open(src_path, "r")) {
      fprintf(stderr, "Unable to open '%s'\n", src_path);
      return 1;
    }

    if (!profile.Read(&srcIO)) {
      fprintf(stderr, "Unable to read '%s'\n", src_path);
      return 2;
    }

    static std::string json;
    json.clear();
    json.reserve(40000000);
    g_json_output = &json;
    snprintf(g_dst_path, sizeof(g_dst_path), "%s", dst_path);
    SetCrashRecoveryCallback(WritePartialOutput);

    try {
      if (sort_keys) {
        IccJson profile_json;
        if (!profile.ToJson(profile_json)) {
          fprintf(stderr, "Unable to convert '%s' to JSON\n", src_path);
          WritePartialOutput();
          g_json_output = nullptr;
          return 3;
        }
        IccJson wrapper;
        wrapper["IccProfile"] = profile_json;
        nlohmann::ordered_json sorted = SortJsonKeys(wrapper);
        json = sorted.dump(indent, ' ', true, nlohmann::detail::error_handler_t::replace);
      } else if (!profile.ToJson(json, indent)) {
        fprintf(stderr, "Unable to convert '%s' to JSON\n", src_path);
        WritePartialOutput();
        g_json_output = nullptr;
        return 3;
      }
    } catch (const std::exception& e) {
      fprintf(stderr, "JSON serialization error for '%s': %s\n", src_path, e.what());
      WritePartialOutput();
      g_json_output = nullptr;
      return 3;
    }

    int fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
      fprintf(stderr, "Unable to open '%s'\n", dst_path);
      g_json_output = nullptr;
      return 4;
    }

    FILE* f = fdopen(fd, "wb");
    if (!f) {
      close(fd);
      fprintf(stderr, "Unable to open '%s'\n", dst_path);
      g_json_output = nullptr;
      return 4;
    }

    size_t written = fwrite(json.c_str(), 1, json.size(), f);
    fclose(f);
    g_json_output = nullptr;

    if (written == json.size()) {
      printf("JSON successfully created (%zu bytes)\n", json.size());
      printf("[ColorBleed] Sanitize the outputs of Sensitive Information\n");
      return 0;
    }

    fprintf(stderr, "Unable to write '%s'\n", dst_path);
    return 5;
  }, limits);

  result.Report("ICC -> JSON", src_path);

  if (result.SanitizerFinding()) {
    printf("[ColorBleed] FINDING: Profile triggered sanitizer report\n");
    printf("[ColorBleed] Exit code: %d\n", result.exit_code);
    return result.exit_code;
  }

  if (result.crashed) {
    printf("[ColorBleed] FINDING: Profile triggered library crash\n");
    printf("[ColorBleed] Exit code: %d  Signal: %s\n",
           result.exit_code, result.SignalName());
    return 100 + result.signal_num;
  }

  return result.exit_code;
}
