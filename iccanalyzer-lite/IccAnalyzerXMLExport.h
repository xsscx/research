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

#ifndef _ICCANALYZERXMLEXPORT_H
#define _ICCANALYZERXMLEXPORT_H

#include <string>
#include <fstream>

/**
 * Export analysis results as XML with embedded XSLT stylesheet
 * Browser can open XML directly and render as HTML
 */
class IccAnalyzerXMLExport
{
public:
  /**
   * Export heuristics analysis to XML with embedded XSLT
   * @param filename Output XML filename
   * @param profilePath Path to analyzed ICC profile
   * @param heuristics Heuristic results (from IccAnalyzerHeuristics.h)
   * @return true on success
   */
  static bool ExportHeuristicsToXML(const char* filename,
                                     const char* profilePath,
                                     const void* heuristics);

  /**
   * Export comprehensive analysis to XML with embedded XSLT
   * @param filename Output XML filename
   * @param profilePath Path to analyzed ICC profile
   * @param analysis Comprehensive results
   * @return true on success
   */
  static bool ExportComprehensiveToXML(const char* filename,
                                        const char* profilePath,
                                        const void* analysis);

private:
  /**
   * Write embedded XSLT stylesheet
   * Transforms XML to HTML in browser
   */
  static void WriteXSLTStylesheet(std::ofstream& xml);
  
  /**
   * Escape XML special characters
   */
  static std::string XMLEscape(const std::string& text);
};

#endif // _ICCANALYZERXMLEXPORT_H
