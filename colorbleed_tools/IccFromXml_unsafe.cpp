/*!
 *  @file IccFromXml_unsafe.cpp
 *  @brief Sandboxed Unsafe ICC Blob Writer
 *  @author David Hoyt
 *  @date 28 FEB 2026
 *  @version 6.0.1
 *
 *  Fork-isolated XML->ICC conversion using vanilla (unpatched) iccDEV.
 *  Each profile operation runs in a child process with resource limits.
 *  Library crashes are caught and reported as security findings.
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 *  @section CHANGES
 *  - 12/06/2021, h02332: Initial commit
 *  - 28/02/2026, h02332: Fork/exec sandbox isolation
 *
 */

#include <cstdio>
#include "IccTagXmlFactory.h"
#include "IccMpeXmlFactory.h"
#include "IccProfileXml.h"
#include "IccIO.h"
#include "IccUtil.h"
#include "IccProfLibVer.h"
#include "IccLibXMLVer.h"
#define COLORBLEED_SKIP_ICC_PREFLIGHT
#include "ColorBleedPreflight.h"
#include "ColorBleedBinaryEnvelope.h"
#include "ColorBleedSandbox.h"
#include <cerrno>
#include <cstring>
#include <climits>
#include <cstdlib>
#include <fcntl.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

static constexpr int kExitUsage = 64;
static constexpr int kExitNoInput = 66;

static bool IsHelpFlag(const char* arg) {
  return arg && (!strcmp(arg, "-h") || !strcmp(arg, "--help"));
}

static void PrintUsage() {
  printf("IccFromXml_unsafe built with IccProfLib Version " ICCPROFLIBVER ", IccLibXML Version " ICCLIBXMLVER "\n");
  printf("Copyright (c) 2021-2026 David H Hoyt LLC\n");
  printf("Usage: IccFromXml_unsafe xml_file saved_profile_file "
         "{-noid -v{=[relax_ng_schema_file]}|--restore-diagnostic}\n");
  printf("  --restore-diagnostic  restore and verify a ColorBleed binary envelope\n");
  printf("  Sandboxed: fork-isolated with ASan/UBSan recoverable mode\n");
  printf("\n");
}

static bool GetXmlAttribute(xmlNodePtr node,
                            const char* name,
                            std::string& value,
                            std::string& error) {
  xmlChar* attribute = xmlGetProp(node, BAD_CAST name);
  if (!attribute) {
    error = std::string("BinaryEnvelope attribute is missing: ") + name;
    return false;
  }
  value = reinterpret_cast<const char*>(attribute);
  xmlFree(attribute);
  return true;
}

static bool ParseXmlUnsigned(const std::string& text,
                             const char* name,
                             uint64_t& value,
                             std::string& error) {
  if (text.empty() || text[0] == '-') {
    error = std::string("BinaryEnvelope attribute is not unsigned: ") + name;
    return false;
  }
  for (unsigned char character : text) {
    if (character < '0' || character > '9') {
      error = std::string("BinaryEnvelope attribute is not unsigned: ") + name;
      return false;
    }
  }
  errno = 0;
  char* end = nullptr;
  unsigned long long parsed = strtoull(text.c_str(), &end, 10);
  if (errno == ERANGE || !end || *end != '\0') {
    error = std::string("BinaryEnvelope attribute is not unsigned: ") + name;
    return false;
  }
  value = static_cast<uint64_t>(parsed);
  return true;
}

static bool LoadXmlBinaryEnvelope(const char* xml_path,
                                  ColorBleedBinaryEnvelope& envelope,
                                  std::string& error) {
  xmlDocPtr document = xmlReadFile(
      xml_path, nullptr,
      XML_PARSE_NONET | XML_PARSE_NOERROR | XML_PARSE_NOWARNING |
          XML_PARSE_COMPACT);
  if (!document) {
    error = "unable to parse diagnostic XML";
    return false;
  }
  if (document->intSubset || document->extSubset) {
    xmlFreeDoc(document);
    error = "diagnostic XML must not contain a document type declaration";
    return false;
  }

  xmlNodePtr root = xmlDocGetRootElement(document);
  if (!root || root->type != XML_ELEMENT_NODE ||
      !xmlStrEqual(root->name, BAD_CAST "IccProfileDiagnostic")) {
    xmlFreeDoc(document);
    error = "missing root IccProfileDiagnostic element";
    return false;
  }

  xmlNodePtr binary = nullptr;
  for (xmlNodePtr child = root->children; child; child = child->next) {
    if (child->type == XML_ELEMENT_NODE &&
        xmlStrEqual(child->name, BAD_CAST "BinaryEnvelope")) {
      binary = child;
      break;
    }
  }
  if (!binary) {
    xmlFreeDoc(document);
    error = "missing IccProfileDiagnostic/BinaryEnvelope element";
    return false;
  }

  std::string format;
  std::string restorable;
  std::string encoding;
  std::string length;
  std::string header_declared_length;
  std::string declared_length;
  std::string trailing_length;
  if (!GetXmlAttribute(binary, "format", format, error) ||
      !GetXmlAttribute(binary, "restorable", restorable, error) ||
      !GetXmlAttribute(binary, "encoding", encoding, error) ||
      !GetXmlAttribute(binary, "length", length, error) ||
      !GetXmlAttribute(binary, "headerDeclaredProfileLength",
                       header_declared_length, error) ||
      !GetXmlAttribute(binary, "declaredProfileLength", declared_length,
                       error) ||
      !GetXmlAttribute(binary, "trailingLength", trailing_length, error)) {
    xmlFreeDoc(document);
    return false;
  }
  if (format != kColorBleedEnvelopeFormat) {
    xmlFreeDoc(document);
    error = "unsupported diagnostic binary envelope format";
    return false;
  }
  if (restorable != "true") {
    std::string omission_reason;
    if (GetXmlAttribute(binary, "omissionReason", omission_reason, error)) {
      error = omission_reason;
    } else {
      error = "diagnostic binary envelope is not restorable";
    }
    xmlFreeDoc(document);
    return false;
  }
  envelope.restorable = true;
  if (encoding != "base64") {
    xmlFreeDoc(document);
    error = "unsupported diagnostic binary envelope encoding";
    return false;
  }
  if (!ParseXmlUnsigned(length, "length", envelope.length, error) ||
      !ParseXmlUnsigned(header_declared_length,
                        "headerDeclaredProfileLength",
                        envelope.header_declared_profile_length, error) ||
      !ParseXmlUnsigned(declared_length, "declaredProfileLength",
                        envelope.declared_profile_length, error) ||
      !ParseXmlUnsigned(trailing_length, "trailingLength",
                        envelope.trailing_length, error) ||
      !GetXmlAttribute(binary, "sha256", envelope.sha256, error) ||
      !GetXmlAttribute(binary, "declaredProfileSha256",
                       envelope.declared_profile_sha256, error) ||
      !GetXmlAttribute(binary, "trailingSha256", envelope.trailing_sha256,
                       error)) {
    xmlFreeDoc(document);
    return false;
  }

  xmlChar* content = xmlNodeGetContent(binary);
  if (!content) {
    xmlFreeDoc(document);
    error = "diagnostic binary envelope has no base64 content";
    return false;
  }
  envelope.data_base64 = reinterpret_cast<const char*>(content);
  xmlFree(content);
  xmlFreeDoc(document);
  return true;
}

static int RestoreDiagnosticXml(const char* xml_path, const char* icc_path) {
  ColorBleedBinaryEnvelope envelope;
  std::string error;
  if (!LoadXmlBinaryEnvelope(xml_path, envelope, error)) {
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

/** Convert ICC XML profile to binary format in a sandboxed child process. */
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

  // Validate output path (traversal, symlinks, system directories)
  std::string safe_dst = ValidateOutputPath(argv[2]);
  if (safe_dst.empty()) {
    return kExitUsage;
  }

  // Parse optional flags before fork
  bool bNoId = false;
  bool restore_diagnostic = false;
  std::string szRelaxNGDir;
  const char* szRelaxNGFileName = "SampleIccRELAX.rng";

  for (int i=3; i<argc; i++) {
    if (!stricmp(argv[i], "-noid")) {
      bNoId = true;
    }
    else if (!stricmp(argv[i], "--restore-diagnostic")) {
      restore_diagnostic = true;
    }
    else if (!strncmp(argv[i], "-v", 2) || !strncmp(argv[i], "-V", 2)) {
      if (argv[i][2]=='=') {
        szRelaxNGDir = argv[i]+3;
      }
      else {
        std::string path = argv[0];
#ifdef WIN32
        if (path != "IccFromXml_unsafe.exe") {
          path = path.substr(0,path.find_last_of("\\"));
          path += "\\";
        }
#else
        if (path.substr(0,1) != "./"){
          path = path.substr(0,path.find_last_of("//"));
          path += "//";
        }
#endif
        path += szRelaxNGFileName;
        char resolved[PATH_MAX];
        if (!realpath(path.c_str(), resolved)) {
          resolved[0] = '\0';
        }
        int schemaFd = open(resolved, O_RDONLY);
        if (schemaFd >= 0) {
          close(schemaFd);
          szRelaxNGDir = resolved;
        }
      }
    }
  }

  // Validate input path
  char resolved_xml[PATH_MAX];
  if (!realpath(argv[1], resolved_xml)) {
    fprintf(stderr, "[ColorBleed] Cannot resolve input path: %s\n", argv[1]);
    return kExitNoInput;
  }
  const char* xml_path = resolved_xml;
  const char* icc_path = safe_dst.c_str();

  printf("[ColorBleed] Sandboxed XML->ICC %s\n",
         restore_diagnostic ? "diagnostic restoration" : "conversion");
  printf("[ColorBleed] Input:  %s\n", xml_path);
  printf("[ColorBleed] Output: %s\n", icc_path);

  if (restore_diagnostic) {
    struct stat input_stat;
    if (stat(xml_path, &input_stat) != 0 || input_stat.st_size < 0 ||
        input_stat.st_size > static_cast<off_t>(64) * 1024 * 1024) {
      fprintf(stderr,
              "[ColorBleed] Diagnostic XML exceeds the 64 MB restore limit\n");
      return 1;
    }

    SandboxLimits restore_limits;
    restore_limits.max_mem_mb = 4096;
    restore_limits.max_cpu_sec = 30;
    restore_limits.max_fsize_mb = 128;
    restore_limits.max_wall_sec = 15;
    SandboxResult restore_result = RunSandboxed([&]() -> int {
      return RestoreDiagnosticXml(xml_path, icc_path);
    }, restore_limits);
    restore_result.Report("Diagnostic XML -> ICC bytes", xml_path);
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

  // Pre-flight validation (file size, XXE detection -- no iccDEV calls)
  PreflightResult preflight = PreflightValidateXML(xml_path);
  preflight.Report(xml_path);

  SandboxLimits limits;
  limits.max_mem_mb  = 4096;
  limits.max_cpu_sec = 120;
  limits.max_fsize_mb = 512;
  limits.max_wall_sec = 30;

  if (preflight.worst == PreflightSeverity::CRITICAL) {
    limits.max_cpu_sec  = 30;
    limits.max_fsize_mb = 128;
    limits.max_wall_sec = 15;
  }

  SandboxResult result = RunSandboxed([&]() -> int {
    CIccTagCreator::PushFactory(new CIccTagXmlFactory());
    CIccMpeCreator::PushFactory(new CIccMpeXmlFactory());

    CIccProfileXml profile;
    std::string reason;

    if (!profile.LoadXml(xml_path, szRelaxNGDir.c_str(), &reason)) {
      fprintf(stderr, "%s", reason.c_str());
      fprintf(stderr, "\nUnable to Parse '%s'\n", xml_path);
      return 1;
    }

    std::string valid_report;
    icValidateStatus vs = profile.Validate(valid_report);

    int idx;
    for (idx=0; idx<16; idx++) {
      if (profile.m_Header.profileID.ID8[idx])
        break;
    }

    icProfileIDSaveMethod method = bNoId ? icNeverWriteID :
      (idx<16 ? icAlwaysWriteID : icVersionBasedID);

    if (SaveIccProfile(icc_path, &profile, method)) {
      if (vs <= icValidateWarning) {
        printf("Profile parsed and saved correctly\n");
      } else {
        printf("Profile parsed.  Profile is invalid, but saved correctly\n");
        fprintf(stderr, "%s", valid_report.c_str());
      }
      printf("[ColorBleed] Review the outputs for Sensitive Information\n");
    } else {
      fprintf(stderr, "Unable to save profile as '%s'\n", icc_path);
      return 2;
    }

    return 0;
  }, limits);

  result.Report("XML -> ICC", xml_path);

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
