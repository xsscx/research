/*!
 *  @file IccFromJson_unsafe.cpp
 *  @brief Sandboxed Unsafe JSON ICC Blob Writer
 *
 *  Fork-isolated JSON->ICC conversion using vanilla (unpatched) iccDEV.
 *  Each profile operation runs in a child process with resource limits.
 *  Library crashes are caught and reported as security findings.
 */

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <fcntl.h>
#include <string>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

#include "IccTagJsonFactory.h"
#include "IccMpeJsonFactory.h"
#include "IccProfileJson.h"
#include "IccIO.h"
#include "IccUtil.h"
#include "IccProfLibVer.h"
#include "IccLibJSONVer.h"

#include "ColorBleedBinaryEnvelope.h"
#include "ColorBleedSandbox.h"

#ifdef _WIN32
#define ICC_STRICMP _stricmp
#else
#include <strings.h>
#define ICC_STRICMP strcasecmp
#endif

static constexpr int kExitUsage = 64;
static constexpr int kExitNoInput = 66;
static constexpr off_t kMaxJsonFileBytes = static_cast<off_t>(64) * 1024 * 1024;

struct JsonPreflightSummary {
  bool parsed = false;
  bool has_profile = false;
  bool has_header = false;
  bool has_tags = false;
  bool risky = false;
  size_t tag_count = 0;
  std::string profile_version;
  std::string subclass_version;
  std::string parse_error;
  std::vector<std::string> warnings;
};

static bool IsHelpFlag(const char* arg) {
  return arg && (!strcmp(arg, "-h") || !strcmp(arg, "--help"));
}

static void PrintUsage() {
  printf("IccFromJson_unsafe built with IccProfLib Version " ICCPROFLIBVER ", IccLibJSON Version " ICCLIBJSONVER "\n");
  printf("Copyright (c) 2021-2026 David H Hoyt LLC\n");
  printf("Usage: IccFromJson_unsafe json_file saved_profile_file "
         "{-noid|--restore-diagnostic}\n");
  printf("  --restore-diagnostic  restore and verify a ColorBleed binary envelope\n");
  printf("  Sandboxed: fork-isolated with ASan/UBSan recoverable mode\n");
  printf("\n");
}

static bool IsBcdVersionPartSafe(const std::string& part) {
  if (part.empty() || part.size() > 2) {
    return false;
  }
  for (char c : part) {
    if (c < '0' || c > '9') {
      return false;
    }
  }
  const int value = atoi(part.c_str());
  return value >= 0 && value <= 99;
}

static bool IsBcdVersionSafe(const std::string& version) {
  const size_t dot = version.find('.');
  const std::string hi = dot == std::string::npos ? version : version.substr(0, dot);
  const std::string lo = dot == std::string::npos ? std::string() : version.substr(dot + 1);
  if (!IsBcdVersionPartSafe(hi)) {
    return false;
  }
  return lo.empty() || IsBcdVersionPartSafe(lo);
}

static void CheckVersionField(JsonPreflightSummary& summary,
                              const char* name,
                              const std::string& value) {
  if (!IsBcdVersionSafe(value)) {
    summary.risky = true;
    summary.warnings.push_back(std::string(name) +
                               " is not a safe ICC BCD version string: " + value);
  }
}

static JsonPreflightSummary PreflightJsonFile(const char* json_path) {
  JsonPreflightSummary summary;
  std::ifstream in(json_path, std::ios::binary);
  if (!in.is_open()) {
    summary.parse_error = "cannot open JSON for diagnostic preflight";
    return summary;
  }

  IccJson root;
  try {
    in >> root;
  } catch (const std::exception& e) {
    summary.parse_error = e.what();
    return summary;
  }

  summary.parsed = true;
  if (!root.is_object() || !root.contains("IccProfile") || !root["IccProfile"].is_object()) {
    summary.warnings.push_back("missing object root.IccProfile");
    return summary;
  }

  summary.has_profile = true;
  const IccJson& profile = root["IccProfile"];
  if (profile.contains("Header") && profile["Header"].is_object()) {
    summary.has_header = true;
    const IccJson& header = profile["Header"];
    if (header.contains("ProfileVersion") && header["ProfileVersion"].is_string()) {
      summary.profile_version = header["ProfileVersion"].get<std::string>();
      CheckVersionField(summary, "Header.ProfileVersion", summary.profile_version);
    } else {
      summary.warnings.push_back("missing string Header.ProfileVersion");
    }

    if (header.contains("ProfileSubClassVersion") &&
        header["ProfileSubClassVersion"].is_string()) {
      summary.subclass_version = header["ProfileSubClassVersion"].get<std::string>();
      CheckVersionField(summary, "Header.ProfileSubClassVersion", summary.subclass_version);
    }
  } else {
    summary.warnings.push_back("missing object IccProfile.Header");
  }

  if (profile.contains("Tags") && profile["Tags"].is_array()) {
    summary.has_tags = true;
    summary.tag_count = profile["Tags"].size();
  } else {
    summary.warnings.push_back("missing array IccProfile.Tags");
  }

  return summary;
}

static void ReportJsonPreflight(const JsonPreflightSummary& summary) {
  if (!summary.parsed) {
    fprintf(stderr, "[ColorBleed] JSON diagnostic: parse failed: %s\n",
            summary.parse_error.c_str());
    return;
  }

  fprintf(stderr,
          "[ColorBleed] JSON diagnostic: profile=%s header=%s tags=%s tag_count=%zu\n",
          summary.has_profile ? "yes" : "no",
          summary.has_header ? "yes" : "no",
          summary.has_tags ? "yes" : "no",
          summary.tag_count);

  if (!summary.profile_version.empty()) {
    fprintf(stderr, "[ColorBleed] JSON diagnostic: Header.ProfileVersion=%s\n",
            summary.profile_version.c_str());
  }
  if (!summary.subclass_version.empty()) {
    fprintf(stderr, "[ColorBleed] JSON diagnostic: Header.ProfileSubClassVersion=%s\n",
            summary.subclass_version.c_str());
  }
  for (const std::string& warning : summary.warnings) {
    fprintf(stderr, "[ColorBleed] JSON diagnostic warning: %s\n", warning.c_str());
  }
}

static bool PathExists(const char* path) {
  struct stat st;
  return path && stat(path, &st) == 0;
}

static void WriteDiagnosticSidecar(const char* icc_path,
                                   const char* json_path,
                                   const JsonPreflightSummary& summary,
                                   const SandboxResult& result) {
  if (!icc_path || PathExists(icc_path)) {
    return;
  }

  const std::string sidecar_path = std::string(icc_path) + ".diagnostic.txt";
  FILE* fp = fopen(sidecar_path.c_str(), "wb");
  if (!fp) {
    fprintf(stderr, "[ColorBleed] Unable to write diagnostic sidecar %s: %s\n",
            sidecar_path.c_str(), strerror(errno));
    return;
  }

  fprintf(fp, "ColorBleed JSON->ICC diagnostic\n");
  fprintf(fp, "input=%s\n", json_path ? json_path : "(null)");
  fprintf(fp, "requested_output=%s\n", icc_path);
  fprintf(fp, "exit_code=%d\n", result.exit_code);
  fprintf(fp, "signal=%d\n", result.signal_num);
  fprintf(fp, "timed_out=%s\n", result.timed_out ? "yes" : "no");
  fprintf(fp, "wall_timed_out=%s\n", result.wall_timed_out ? "yes" : "no");
  fprintf(fp, "json_parsed=%s\n", summary.parsed ? "yes" : "no");
  fprintf(fp, "has_profile=%s\n", summary.has_profile ? "yes" : "no");
  fprintf(fp, "has_header=%s\n", summary.has_header ? "yes" : "no");
  fprintf(fp, "has_tags=%s\n", summary.has_tags ? "yes" : "no");
  fprintf(fp, "tag_count=%zu\n", summary.tag_count);
  fprintf(fp, "profile_version=%s\n", summary.profile_version.c_str());
  fprintf(fp, "subclass_version=%s\n", summary.subclass_version.c_str());
  if (!summary.parse_error.empty()) {
    fprintf(fp, "parse_error=%s\n", summary.parse_error.c_str());
  }
  for (size_t i = 0; i < summary.warnings.size(); i++) {
    fprintf(fp, "warning_%zu=%s\n", i + 1, summary.warnings[i].c_str());
  }
  fclose(fp);
  fprintf(stderr, "[ColorBleed] Diagnostic sidecar written: %s\n", sidecar_path.c_str());
}

static bool GetJsonString(const IccJson& object,
                          const char* name,
                          std::string& value,
                          std::string& error) {
  if (!object.contains(name) || !object[name].is_string()) {
    error = std::string("BinaryEnvelope.") + name + " must be a string";
    return false;
  }
  value = object[name].get<std::string>();
  return true;
}

static bool GetJsonUnsigned(const IccJson& object,
                            const char* name,
                            uint64_t& value,
                            std::string& error) {
  if (!object.contains(name)) {
    error = std::string("BinaryEnvelope.") + name + " is missing";
    return false;
  }
  const IccJson& field = object[name];
  if (field.is_number_unsigned()) {
    value = field.get<uint64_t>();
    return true;
  }
  if (field.is_number_integer()) {
    int64_t signed_value = field.get<int64_t>();
    if (signed_value >= 0) {
      value = static_cast<uint64_t>(signed_value);
      return true;
    }
  }
  error = std::string("BinaryEnvelope.") + name +
      " must be a non-negative integer";
  return false;
}

static bool LoadJsonBinaryEnvelope(const char* json_path,
                                   ColorBleedBinaryEnvelope& envelope,
                                   std::string& error) {
  std::ifstream input(json_path, std::ios::binary);
  if (!input.is_open()) {
    error = "unable to open diagnostic JSON";
    return false;
  }

  IccJson root;
  try {
    input >> root;
  } catch (const std::exception& exception) {
    error = std::string("unable to parse diagnostic JSON: ") +
        exception.what();
    return false;
  }

  if (!root.is_object() || !root.contains("IccProfileDiagnostic") ||
      !root["IccProfileDiagnostic"].is_object()) {
    error = "missing object root.IccProfileDiagnostic";
    return false;
  }
  const IccJson& diagnostic = root["IccProfileDiagnostic"];
  if (!diagnostic.contains("BinaryEnvelope") ||
      !diagnostic["BinaryEnvelope"].is_object()) {
    error = "missing object IccProfileDiagnostic.BinaryEnvelope";
    return false;
  }
  const IccJson& binary = diagnostic["BinaryEnvelope"];

  std::string format;
  std::string encoding;
  if (!GetJsonString(binary, "Format", format, error) ||
      format != kColorBleedEnvelopeFormat) {
    if (error.empty()) {
      error = "unsupported diagnostic binary envelope format";
    }
    return false;
  }
  if (!binary.contains("Restorable") || !binary["Restorable"].is_boolean()) {
    error = "BinaryEnvelope.Restorable must be boolean";
    return false;
  }
  envelope.restorable = binary["Restorable"].get<bool>();
  if (!envelope.restorable) {
    if (binary.contains("OmissionReason") &&
        binary["OmissionReason"].is_string()) {
      envelope.omission_reason =
          binary["OmissionReason"].get<std::string>();
    }
    error = envelope.omission_reason.empty()
        ? "diagnostic binary envelope is not restorable"
        : envelope.omission_reason;
    return false;
  }
  if (!GetJsonString(binary, "Encoding", encoding, error) ||
      encoding != "base64") {
    if (error.empty()) {
      error = "unsupported diagnostic binary envelope encoding";
    }
    return false;
  }
  if (!GetJsonUnsigned(binary, "Length", envelope.length, error) ||
      !GetJsonUnsigned(binary, "HeaderDeclaredProfileLength",
                       envelope.header_declared_profile_length, error) ||
      !GetJsonUnsigned(binary, "DeclaredProfileLength",
                       envelope.declared_profile_length, error) ||
      !GetJsonUnsigned(binary, "TrailingLength", envelope.trailing_length,
                       error) ||
      !GetJsonString(binary, "SHA256", envelope.sha256, error) ||
      !GetJsonString(binary, "DeclaredProfileSHA256",
                     envelope.declared_profile_sha256, error) ||
      !GetJsonString(binary, "TrailingSHA256", envelope.trailing_sha256,
                     error) ||
      !GetJsonString(binary, "Data", envelope.data_base64, error)) {
    return false;
  }
  return true;
}

static int RestoreDiagnosticJson(const char* json_path, const char* icc_path) {
  ColorBleedBinaryEnvelope envelope;
  std::string error;
  if (!LoadJsonBinaryEnvelope(json_path, envelope, error)) {
    fprintf(stderr, "[ColorBleed] Unable to load diagnostic envelope: %s\n",
            error.c_str());
    return 1;
  }

  std::vector<uint8_t> bytes;
  if (!ColorBleedVerifyEnvelope(envelope, bytes, error)) {
    fprintf(stderr, "[ColorBleed] Diagnostic envelope verification failed: %s\n",
            error.c_str());
    return 1;
  }
  if (!ColorBleedWriteAtomic(icc_path, bytes, error)) {
    fprintf(stderr, "[ColorBleed] Diagnostic restore failed: %s\n",
            error.c_str());
    return 2;
  }

  printf("[ColorBleed] Restored %zu binary bytes (sha256=%s)\n",
         bytes.size(), envelope.sha256.c_str());
  printf("[ColorBleed] Declared profile: %llu bytes  Trailing data: %llu bytes\n",
         static_cast<unsigned long long>(envelope.declared_profile_length),
         static_cast<unsigned long long>(envelope.trailing_length));
  fflush(stdout);
  return 0;
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

  bool bNoId = false;
  bool restore_diagnostic = false;
  for (int i = 3; i < argc; i++) {
    if (!ICC_STRICMP(argv[i], "-noid")) {
      bNoId = true;
    } else if (!ICC_STRICMP(argv[i], "--restore-diagnostic")) {
      restore_diagnostic = true;
    }
  }

  char resolved_json[PATH_MAX];
  if (!realpath(argv[1], resolved_json)) {
    fprintf(stderr, "[ColorBleed] Cannot resolve input path: %s\n", argv[1]);
    return kExitNoInput;
  }
  const char* json_path = resolved_json;
  const char* icc_path = safe_dst.c_str();

  struct stat st;
  if (stat(json_path, &st) != 0) {
    fprintf(stderr, "[ColorBleed] Cannot stat input path: %s\n", json_path);
    return kExitNoInput;
  }

  printf("[ColorBleed] Sandboxed JSON->ICC %s\n",
         restore_diagnostic ? "diagnostic restoration" : "conversion");
  printf("[ColorBleed] Input:  %s\n", json_path);
  printf("[ColorBleed] Output: %s\n", icc_path);

  SandboxLimits limits;
  limits.max_mem_mb = 4096;
  limits.max_cpu_sec = 120;
  limits.max_fsize_mb = 512;
  limits.max_wall_sec = 30;

  if (st.st_size < 0 || st.st_size > kMaxJsonFileBytes) {
    fprintf(stderr, "[ColorBleed] JSON pre-flight: file exceeds 64 MB limit\n");
    limits.max_cpu_sec = 30;
    limits.max_fsize_mb = 128;
  } else {
    fprintf(stderr, "[ColorBleed] JSON pre-flight: %lld bytes\n",
            static_cast<long long>(st.st_size));
  }

  if (restore_diagnostic) {
    if (st.st_size < 0 || st.st_size > kMaxJsonFileBytes) {
      fprintf(stderr,
              "[ColorBleed] Diagnostic JSON exceeds the 64 MB restore limit\n");
      return 1;
    }

    SandboxResult restore_result = RunSandboxed([&]() -> int {
      return RestoreDiagnosticJson(json_path, icc_path);
    }, limits);
    restore_result.Report("Diagnostic JSON -> ICC bytes", json_path);
    if (restore_result.SanitizerFinding()) {
      printf("[ColorBleed] FINDING: Input triggered sanitizer report\n");
      return restore_result.exit_code;
    }
    if (restore_result.crashed) {
      printf("[ColorBleed] FINDING: Input triggered library crash\n");
      return 100 + restore_result.signal_num;
    }
    return restore_result.exit_code;
  }

  JsonPreflightSummary json_summary = PreflightJsonFile(json_path);
  ReportJsonPreflight(json_summary);
  if (json_summary.risky) {
    fprintf(stderr,
            "[ColorBleed] JSON diagnostic: risky header values detected; conversion will still be attempted under sandbox\n");
    limits.max_wall_sec = 10;
  }

  SandboxResult result = RunSandboxed([&]() -> int {
    CIccTagCreator::PushFactory(new CIccTagJsonFactory());
    CIccMpeCreator::PushFactory(new CIccMpeJsonFactory());

    CIccProfileJson profile;
    std::string reason;

    if (!profile.LoadJson(json_path, &reason)) {
      fprintf(stderr, "%s", reason.c_str());
      fprintf(stderr, "Unable to Parse '%s'\n", json_path);
      return 1;
    }

    std::string valid_report;
    icValidateStatus vs = profile.Validate(valid_report);

    int idx;
    for (idx = 0; idx < 16; idx++) {
      if (profile.m_Header.profileID.ID8[idx]) {
        break;
      }
    }

    icProfileIDSaveMethod method = bNoId ? icNeverWriteID :
      (idx < 16 ? icAlwaysWriteID : icVersionBasedID);

    if (SaveIccProfile(icc_path, &profile, method)) {
      if (vs <= icValidateWarning) {
        printf("Profile parsed and saved correctly\n");
      } else {
        printf("Profile parsed. Profile is invalid, but saved correctly\n");
        fprintf(stderr, "%s", valid_report.c_str());
      }
      printf("[ColorBleed] Review the outputs for Sensitive Information\n");
      return 0;
    }

    fprintf(stderr, "Unable to save profile as '%s'\n", icc_path);
    return 2;
  }, limits);

  result.Report("JSON -> ICC", json_path);
  WriteDiagnosticSidecar(icc_path, json_path, json_summary, result);

  if (result.SanitizerFinding()) {
    printf("[ColorBleed] FINDING: Input triggered sanitizer report\n");
    printf("[ColorBleed] Exit code: %d\n", result.exit_code);
    return result.exit_code;
  }

  if (result.crashed) {
    printf("[ColorBleed] FINDING: Input triggered library crash\n");
    printf("[ColorBleed] Exit code: %d  Signal: %s\n",
           result.exit_code, result.SignalName());
    return 100 + result.signal_num;
  }

  printf("\n");
  return result.exit_code;
}
