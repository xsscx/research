/*!
 *  @file IccFromXml_unsafe.cpp
 *  @brief Unsafe ICC Blob Writer
 *  @author David Hoyt
 *  @date 03 FEB 2026
 *  @version 5.0.1
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
#include <cstring>

/** Convert ICC XML profile to binary format, deliberately skipping safety checks. */
int main(int argc, char* argv[])
{
  if (argc<=2) {
    printf("IccFromXml_unsafe built with IccProfLib Version " ICCPROFLIBVER ", IccLibXML Version " ICCLIBXMLVER "\n");
    printf("Copyright (c) 2021-2026 David H Hoyt LLC\n");
    printf("Usage: IccFromXml_unsafe xml_file saved_profile_file {-noid -v{=[relax_ng_schema_file]}}\n");
    printf("\n");
    return -1;
  }

  CIccTagCreator::PushFactory(new CIccTagXmlFactory());
  CIccMpeCreator::PushFactory(new CIccMpeXmlFactory());

  CIccProfileXml profile;
  std::string reason;

  std::string szRelaxNGDir;
  bool bNoId = false;

  const char* szRelaxNGFileName = "SampleIccRELAX.rng";
  int i;
  for (i=3; i<argc; i++) {
    if (!stricmp(argv[i], "-noid")) {
      bNoId = true;
    }
    else if (!strncmp(argv[i], "-v", 2) || !strncmp(argv[i], "-V", 2)) {
      if (argv[i][2]=='=') {
        szRelaxNGDir = argv[i]+3;
      }
      else  {
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

        FILE *f = fopen(path.c_str(), "r");

        if (f) {
          fclose(f);

          szRelaxNGDir = path;
        }
      }
    }
  }

  if (!profile.LoadXml(argv[1], szRelaxNGDir.c_str(), &reason)) {
    printf("%s", reason.c_str());
#ifndef WIN32
    printf("\n");
#endif
    printf("Unable to Parse '%s'\n", argv[1]);
    return -1;
  }

  std::string valid_report;

  if (profile.Validate(valid_report)<=icValidateWarning) {
    int idx;

    for (idx=0; idx<16; idx++) {
      if (profile.m_Header.profileID.ID8[idx])
        break;
    }
    if (SaveIccProfile(argv[2], &profile, bNoId ? icNeverWriteID : (idx<16 ? icAlwaysWriteID : icVersionBasedID))) {
      printf("Profile parsed and saved correctly\n");
      printf("[ColorBleed] Review the outputs for Sensitive Information\n");
    }
    else {
      printf("Unable to save profile as '%s'\n", argv[2]);
      return -1;
    }
  }
  else {
    int idx;

    for (idx=0; idx<16; idx++) {
      if (profile.m_Header.profileID.ID8[idx])
        break;
    }
    if (SaveIccProfile(argv[2], &profile, bNoId ? icNeverWriteID : (idx<16 ? icAlwaysWriteID : icVersionBasedID))) {
      printf("Profile parsed.  Profile is invalid, but saved correctly\n");
      printf("[ColorBleed] Review the output for sensitive information\n");
    }
    else {
      printf("Unable to save profile - profile is invalid!\n");
      return -1;
    }
    printf("%s", valid_report.c_str());
  }

  printf("\n");
  return 0;
}
