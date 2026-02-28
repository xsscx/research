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
 *
 */

#include <cstdio>
#include <cstring>
#include "IccTagXmlFactory.h"
#include "IccMpeXmlFactory.h"
#include "IccProfileXml.h"
#include "IccIO.h"
#include "IccProfLibVer.h"
#include "IccLibXMLVer.h"
#include "ColorBleedPreflight.h"
#include "ColorBleedSandbox.h"

// Global state for signal recovery — write partial XML on crash
static std::string* g_xml_output = nullptr;
static const char*  g_dst_path   = nullptr;

static void WritePartialOutput() {
  if (!g_xml_output || g_xml_output->empty() || !g_dst_path) return;

  // Append marker showing the XML was truncated by a crash
  g_xml_output->append("\n<!-- [ColorBleed] XML TRUNCATED: library crash during conversion -->\n");

  FILE* f = fopen(g_dst_path, "wb");
  if (f) {
    fwrite(g_xml_output->c_str(), 1, g_xml_output->size(), f);
    fclose(f);
    fprintf(stderr, "[ColorBleed] Wrote %zu bytes of partial XML to %s\n",
            g_xml_output->size(), g_dst_path);
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

  // Reject output paths with traversal sequences
  if (strstr(argv[2], "..") != NULL) {
    printf("ERROR: output path must not contain '..'\n");
    return -1;
  }

  const char* src_path = argv[1];
  const char* dst_path = argv[2];

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
      fprintf(stderr, "Unable to read '%s'\n", src_path);
      return 2;
    }

    // Set up global state for crash recovery
    std::string xml;
    xml.reserve(40000000);
    g_xml_output = &xml;
    g_dst_path = dst_path;
    SetCrashRecoveryCallback(WritePartialOutput);

    if (!profile.ToXml(xml)) {
      fprintf(stderr, "Unable to convert '%s' to xml\n", src_path);
      // Still try to write whatever we got
      WritePartialOutput();
      g_xml_output = nullptr;
      return 3;
    }

    // Clean path — write full output
    FILE* f = fopen(dst_path, "wb");
    if (!f) {
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

  result.Report("ICC → XML", src_path);

  if (result.crashed) {
    printf("[ColorBleed] FINDING: Profile triggered library crash\n");
    printf("[ColorBleed] Exit code: %d  Signal: %s\n",
           result.exit_code, result.SignalName());
    return 100 + result.signal_num;
  }

  return result.exit_code;
}
