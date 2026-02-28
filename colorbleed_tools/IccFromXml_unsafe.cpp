/*!
 *  @file IccFromXml_unsafe.cpp
 *  @brief Sandboxed Unsafe ICC Blob Writer
 *  @author David Hoyt
 *  @date 28 FEB 2026
 *  @version 6.0.0
 *
 *  Fork-isolated XML→ICC conversion using vanilla (unpatched) iccDEV.
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
#include "ColorBleedPreflight.h"
#include "ColorBleedSandbox.h"
#include <cstring>
#include <climits>
#include <cstdlib>

/** Convert ICC XML profile to binary format in a sandboxed child process. */
int main(int argc, char* argv[])
{
  if (argc<=2) {
    printf("IccFromXml_unsafe built with IccProfLib Version " ICCPROFLIBVER ", IccLibXML Version " ICCLIBXMLVER "\n");
    printf("Copyright (c) 2021-2026 David H Hoyt LLC\n");
    printf("Usage: IccFromXml_unsafe xml_file saved_profile_file {-noid -v{=[relax_ng_schema_file]}}\n");
    printf("  Sandboxed: fork-isolated with ASan/UBSan recoverable mode\n");
    printf("\n");
    return -1;
  }

  // Validate output path (traversal, symlinks, system directories)
  std::string safe_dst = ValidateOutputPath(argv[2]);
  if (safe_dst.empty()) {
    return -1;
  }

  // Parse optional flags before fork
  bool bNoId = false;
  std::string szRelaxNGDir;
  const char* szRelaxNGFileName = "SampleIccRELAX.rng";

  for (int i=3; i<argc; i++) {
    if (!stricmp(argv[i], "-noid")) {
      bNoId = true;
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
        FILE *f = fopen(resolved, "r");
        if (f) {
          fclose(f);
          szRelaxNGDir = resolved;  // use resolved path to avoid TOCTOU
        }
      }
    }
  }

  const char* xml_path = argv[1];
  const char* icc_path = safe_dst.c_str();

  printf("[ColorBleed] Sandboxed XML→ICC conversion\n");
  printf("[ColorBleed] Input:  %s\n", xml_path);
  printf("[ColorBleed] Output: %s\n", icc_path);

  // Pre-flight validation (file size, XXE detection — no iccDEV calls)
  PreflightResult preflight = PreflightValidateXML(xml_path);
  preflight.Report(xml_path);

  SandboxLimits limits;
  limits.max_mem_mb  = 4096;
  limits.max_cpu_sec = 120;
  limits.max_fsize_mb = 512;

  if (preflight.worst == PreflightSeverity::CRITICAL) {
    limits.max_cpu_sec  = 30;
    limits.max_fsize_mb = 128;
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

  result.Report("XML → ICC", xml_path);

  if (result.crashed) {
    printf("[ColorBleed] FINDING: Input triggered library crash\n");
    printf("[ColorBleed] Exit code: %d  Signal: %s\n",
           result.exit_code, result.SignalName());
    return 100 + result.signal_num;
  }

  printf("\n");
  return result.exit_code;
}
