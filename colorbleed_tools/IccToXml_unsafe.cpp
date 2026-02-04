/*!
 *  @file IccToXml_unsafe.cpp
 *  @brief Unsafe ICC Blob Reader
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
#include "IccProfLibVer.h"
#include "IccLibXMLVer.h"

int main(int argc, char* argv[])
{
  if (argc<=2) {
    printf("IccToXml_unsafe built with IccProfLib Version " ICCPROFLIBVER ", IccLibXML Version " ICCLIBXMLVER "\n");
    printf("Copyright (c) 2021-2026 David H Hoyt LLC\n");
    printf("Usage: IccToXml_unsafe src_icc_profile dest_xml_file\n");
    printf("\n");
    return -1;
  }
  CIccTagCreator::PushFactory(new CIccTagXmlFactory());
  CIccMpeCreator::PushFactory(new CIccMpeXmlFactory());

  CIccProfileXml profile;
  CIccFileIO srcIO, dstIO;

  if (!srcIO.Open(argv[1], "r")) {
    printf("Unable to open '%s'\n", argv[1]);
    return -1;
  }

  if (!profile.Read(&srcIO)) {
    printf("Unable to read '%s'\n", argv[1]);
    return -1;
  }

  std::string xml;
  xml.reserve(40000000);

  if (!profile.ToXml(xml)) {
    printf("Unable to convert '%s' to xml\n", argv[1]);
    return -1;
  }

  if (!dstIO.Open(argv[2], "wb")) {
    printf("unable to open '%s'\n", argv[2]);
    return -1;
  }

  if (dstIO.Write8((char*)xml.c_str(), xml.size())== xml.size()) {
    printf("XML successfully created (%zu bytes)\n", xml.size());
    printf("[ColorBleed] Sanitize the outputs of Sensitive Information\n");
  }
  else {
    printf("Unable to write '%s'\n", argv[2]);
    return -1;
  }

  dstIO.Close();

  return 0;
}
