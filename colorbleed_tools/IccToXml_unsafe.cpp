/*!
 *  @file IccToXml_unsafe.cpp
 *  @brief Sandboxed Unsafe ICC Blob Reader
 *  @author David Hoyt
 *  @date 28 FEB 2026
 *  @version 6.0.0
 *
 *  Fork-isolated ICC→XML conversion using vanilla (unpatched) iccDEV.
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
 *  - 10/03/2026, h02332: Diagnostic XML fallback for malformed profiles
 *
 */

#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#include <climits>
#include <cstdlib>
#include "IccTagXmlFactory.h"
#include "IccMpeXmlFactory.h"
#include "IccProfileXml.h"
#include "IccIO.h"
#include "IccProfLibVer.h"
#include "IccLibXMLVer.h"
#define COLORBLEED_SKIP_XML_PREFLIGHT
#include "ColorBleedPreflight.h"
#include "ColorBleedSandbox.h"
#include "ColorBleedDiagnosticXml.h"

// Global state for signal recovery — write partial XML on crash
static std::string* g_xml_output = nullptr;
static char         g_dst_path[PATH_MAX] = {0};

static void WritePartialOutput() {
  if (!g_xml_output || g_xml_output->empty() || g_dst_path[0] == '\0') return;

  // Append marker showing the XML was truncated by a crash
  g_xml_output->append("\n<!-- [ColorBleed] XML TRUNCATED: library crash during conversion -->\n");

  int fd = open(g_dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd >= 0) {
    FILE* f = fdopen(fd, "wb");
    if (f) {
      size_t written = fwrite(g_xml_output->c_str(), 1, g_xml_output->size(), f);
      fclose(f);
      if (written == g_xml_output->size()) {
        fprintf(stderr, "[ColorBleed] Wrote %zu bytes of partial XML to %s\n",
                g_xml_output->size(), g_dst_path);
      } else {
        fprintf(stderr, "[ColorBleed] Partial write: %zu of %zu bytes to %s\n",
                written, g_xml_output->size(), g_dst_path);
      }
    } else {
      close(fd);
    }
  }
}

int main(int argc, char* argv[])
{
  if (argc<=2) {
    printf("IccToXml_unsafe built with IccProfLib Version " ICCPROFLIBVER ", IccLibXML Version " ICCLIBXMLVER "\n");
    printf("Copyright (c) 2021-2026 David H Hoyt LLC\n");
    printf("Usage: IccToXml_unsafe src_icc_profile dest_xml_file\n");
    printf("  Sandboxed: fork-isolated with ASan/UBSan recoverable mode\n");
    printf("\n");
    return -1;
  }

  // Validate output path (traversal, symlinks, system directories)
  std::string safe_dst = ValidateOutputPath(argv[2]);
  if (safe_dst.empty()) {
    return -1;
  }

  // Validate input path
  char resolved_src[PATH_MAX];
  if (!realpath(argv[1], resolved_src)) {
    fprintf(stderr, "[ColorBleed] Cannot resolve input path: %s\n", argv[1]);
    return -1;
  }
  const char* src_path = resolved_src;
  const char* dst_path = safe_dst.c_str();

  printf("[ColorBleed] Sandboxed ICC→XML conversion\n");
  printf("[ColorBleed] Input:  %s\n", src_path);
  printf("[ColorBleed] Output: %s\n", dst_path);

  // Pre-flight validation (pure binary read, no iccDEV calls)
  PreflightResult preflight = PreflightValidateICC(src_path);
  preflight.Report(src_path);

  SandboxLimits limits;
  limits.max_mem_mb  = 4096;
  limits.max_cpu_sec = 120;
  limits.max_fsize_mb = 512;

  // Tighten resource limits for profiles with critical pre-flight warnings
  if (preflight.worst == PreflightSeverity::CRITICAL) {
    limits.max_cpu_sec  = 30;   // reduce CPU budget for suspicious profiles
    limits.max_fsize_mb = 128;  // reduce output budget
  }

  // CRITICAL pre-flight = known dangerous patterns (SBO, HBO, unterminated strings).
  // Route to diagnostic XML instead of risking ASAN errors in ToXml().
  if (preflight.worst == PreflightSeverity::CRITICAL) {
    fprintf(stderr, "[ColorBleed] CRITICAL pre-flight — routing to diagnostic XML\n");
    std::string diagXml;
    std::string reason = "Pre-flight CRITICAL:";
    for (const auto& w : preflight.warnings) {
      if (w.severity == PreflightSeverity::CRITICAL) {
        reason += " [" + std::string(w.heuristic) + "] " + std::string(w.message) + ";";
      }
    }
    if (GenerateDiagnosticXml(src_path, diagXml, reason.c_str())) {
      int dfd = open(safe_dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
      if (dfd >= 0) {
        FILE* df = fdopen(dfd, "wb");
        if (df) {
          size_t dw = fwrite(diagXml.c_str(), 1, diagXml.size(), df);
          fclose(df);
          if (dw == diagXml.size()) {
            printf("[ColorBleed] Diagnostic XML written (%zu bytes) → %s\n",
                   diagXml.size(), safe_dst.c_str());
            printf("[ColorBleed] CRITICAL pre-flight: ToXml skipped to prevent ASAN errors\n");
            return 6;
          }
        } else {
          close(dfd);
        }
      }
    }
    // If diagnostic XML failed, fall through to normal path
    fprintf(stderr, "[ColorBleed] WARNING: diagnostic XML generation failed, attempting ToXml\n");
  }

  SandboxResult result = RunSandboxed([&]() -> int {
    CIccTagCreator::PushFactory(new CIccTagXmlFactory());
    CIccMpeCreator::PushFactory(new CIccMpeXmlFactory());

    CIccProfileXml profile;
    CIccFileIO srcIO;

    if (!srcIO.Open(src_path, "r")) {
      fprintf(stderr, "Unable to open '%s'\n", src_path);
      return 1;
    }

    if (!profile.Read(&srcIO)) {
      fprintf(stderr, "Unable to read '%s' — generating diagnostic XML from raw binary\n", src_path);
      srcIO.Close();

      // Generate diagnostic XML from raw binary analysis
      std::string diagXml;
      if (GenerateDiagnosticXml(src_path, diagXml, "iccDEV CIccProfile::Read() returned false")) {
        int dfd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (dfd >= 0) {
          FILE* df = fdopen(dfd, "wb");
          if (df) {
            size_t dw = fwrite(diagXml.c_str(), 1, diagXml.size(), df);
            fclose(df);
            if (dw == diagXml.size()) {
              fprintf(stderr, "[ColorBleed] Diagnostic XML written (%zu bytes) → %s\n",
                      diagXml.size(), dst_path);
              printf("[ColorBleed] DIAGNOSTIC MODE: profile malformed, raw analysis written\n");
              return 6; // Distinct exit code: diagnostic mode
            }
          } else {
            close(dfd);
          }
        }
        fprintf(stderr, "[ColorBleed] Failed to write diagnostic XML to %s\n", dst_path);
      }
      return 2;
    }

    // Set up global state for crash recovery
    static std::string xml;
    xml.clear();
    xml.reserve(40000000);
    g_xml_output = &xml;
    snprintf(g_dst_path, sizeof(g_dst_path), "%s", dst_path);
    SetCrashRecoveryCallback(WritePartialOutput);

    if (!profile.ToXml(xml)) {
      fprintf(stderr, "Unable to convert '%s' to xml\n", src_path);
      // Still try to write whatever we got
      WritePartialOutput();
      g_xml_output = nullptr;
      return 3;
    }

    // Clean path — write full output with restricted permissions
    int fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
      fprintf(stderr, "Unable to open '%s'\n", dst_path);
      g_xml_output = nullptr;
      return 4;
    }
    FILE* f = fdopen(fd, "wb");
    if (!f) {
      close(fd);
      fprintf(stderr, "Unable to open '%s'\n", dst_path);
      g_xml_output = nullptr;
      return 4;
    }

    size_t written = fwrite(xml.c_str(), 1, xml.size(), f);
    fclose(f);
    g_xml_output = nullptr;

    if (written == xml.size()) {
      printf("XML successfully created (%zu bytes)\n", xml.size());
      printf("[ColorBleed] Sanitize the outputs of Sensitive Information\n");
    } else {
      fprintf(stderr, "Unable to write '%s'\n", dst_path);
      return 5;
    }

    return 0;
  }, limits);

  // Exit code 6 = diagnostic mode (profile malformed, raw XML written successfully)
  // This is NOT a crash — override the sandbox's generic non-zero = crashed logic
  if (result.exit_code == 6 && !result.timed_out && !result.oom_killed &&
      result.signal_num == 0) {
    printf("\n[ColorBleed] Diagnostic XML written (profile malformed, library Read failed)\n");
    printf("[ColorBleed] Output contains raw binary analysis — NOT a valid ICC XML\n");
    return 6;
  }

  result.Report("ICC → XML", src_path);

  if (result.crashed) {
    printf("[ColorBleed] FINDING: Profile triggered library crash\n");
    printf("[ColorBleed] Exit code: %d  Signal: %s\n",
           result.exit_code, result.SignalName());
    return 100 + result.signal_num;
  }

  return result.exit_code;
}
