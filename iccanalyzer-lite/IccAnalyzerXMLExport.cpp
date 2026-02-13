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

#include "IccAnalyzerCommon.h"
#include "IccAnalyzerXMLExport.h"
#include "IccAnalyzerHeuristics.h"
#include <sstream>
#include <ctime>

std::string IccAnalyzerXMLExport::XMLEscape(const std::string& text)
{
  std::string result;
  result.reserve(text.size());
  
  for (char c : text) {
    switch (c) {
      case '<':  result += "&lt;"; break;
      case '>':  result += "&gt;"; break;
      case '&':  result += "&amp;"; break;
      case '"':  result += "&quot;"; break;
      case '\'': result += "&apos;"; break;
      default:   result += c; break;
    }
  }
  
  return result;
}

/// Write embedded XSLT stylesheet for XML report rendering.
void IccAnalyzerXMLExport::WriteXSLTStylesheet(std::ofstream& xml)
{
  xml << R"XSLT(
<xsl:stylesheet version="1.0" 
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns="http://www.w3.org/1999/xhtml">
  
  <xsl:output method="html" indent="yes" encoding="UTF-8"/>
  
  <xsl:template match="/">
    <html>
      <head>
        <title>ICC Profile Analysis Report</title>
        <style>
          body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            max-width: 1200px;
            margin: 40px auto;
            padding: 0 20px;
            background: #f5f5f5;
          }
          .container {
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            padding: 30px;
          }
          h1 {
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
          }
          h2 {
            color: #34495e;
            margin-top: 30px;
            border-left: 4px solid #3498db;
            padding-left: 10px;
          }
          .meta {
            background: #ecf0f1;
            padding: 15px;
            border-radius: 4px;
            margin: 20px 0;
          }
          .meta-item {
            margin: 5px 0;
          }
          .meta-label {
            font-weight: bold;
            color: #7f8c8d;
            min-width: 120px;
            display: inline-block;
          }
          table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
          }
          th {
            background: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
          }
          td {
            padding: 10px 12px;
            border-bottom: 1px solid #ecf0f1;
          }
          tr:hover {
            background: #f8f9fa;
          }
          .status-pass {
            color: #27ae60;
            font-weight: bold;
          }
          .status-fail {
            color: #e74c3c;
            font-weight: bold;
          }
          .status-warn {
            color: #f39c12;
            font-weight: bold;
          }
          .severity-high {
            background: #e74c3c;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.85em;
          }
          .severity-medium {
            background: #f39c12;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.85em;
          }
          .severity-low {
            background: #95a5a6;
            color: white;
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 0.85em;
          }
          .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            color: #95a5a6;
            font-size: 0.9em;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🔍 ICC Profile Security Analysis Report</h1>
          
          <div class="meta">
            <div class="meta-item">
              <span class="meta-label">Profile:</span>
              <xsl:value-of select="/report/profile/filename"/>
            </div>
            <div class="meta-item">
              <span class="meta-label">Analysis Date:</span>
              <xsl:value-of select="/report/metadata/timestamp"/>
            </div>
            <div class="meta-item">
              <span class="meta-label">Analyzer Version:</span>
              <xsl:value-of select="/report/metadata/analyzer_version"/>
            </div>
          </div>
          
          <h2>📊 Security Heuristics</h2>
          <table>
            <tr>
              <th>Check</th>
              <th>Status</th>
              <th>Severity</th>
              <th>Message</th>
            </tr>
            <xsl:for-each select="/report/heuristics/check">
              <tr>
                <td><xsl:value-of select="name"/></td>
                <td>
                  <xsl:attribute name="class">
                    <xsl:choose>
                      <xsl:when test="status='PASS'">status-pass</xsl:when>
                      <xsl:when test="status='FAIL'">status-fail</xsl:when>
                      <xsl:otherwise>status-warn</xsl:otherwise>
                    </xsl:choose>
                  </xsl:attribute>
                  <xsl:value-of select="status"/>
                </td>
                <td>
                  <span>
                    <xsl:attribute name="class">
                      <xsl:choose>
                        <xsl:when test="severity='HIGH'">severity-high</xsl:when>
                        <xsl:when test="severity='MEDIUM'">severity-medium</xsl:when>
                        <xsl:otherwise>severity-low</xsl:otherwise>
                      </xsl:choose>
                    </xsl:attribute>
                    <xsl:value-of select="severity"/>
                  </span>
                </td>
                <td><xsl:value-of select="message"/></td>
              </tr>
            </xsl:for-each>
          </table>
          
          <div class="footer">
            Generated by iccAnalyzer-lite v2.9.0 | David H Hoyt LLC
          </div>
        </div>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
)XSLT";
}

bool IccAnalyzerXMLExport::ExportHeuristicsToXML(const char* filename,
                                                  const char* profilePath,
                                                  const void* heuristics)
{
  if (!filename || !profilePath || !heuristics) {
    return false;
  }
  
  const HeuristicReport* report = static_cast<const HeuristicReport*>(heuristics);
  
  std::ofstream xml(filename);
  if (!xml.is_open()) {
    return false;
  }
  
  // XML declaration
  xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  xml << "<?xml-stylesheet type=\"text/xsl\" href=\"#stylesheet\"?>\n";
  
  // Root element with embedded XSLT
  xml << "<report>\n";
  
  // Embedded stylesheet
  WriteXSLTStylesheet(xml);
  
  // Metadata
  xml << "  <metadata>\n";
  xml << "    <analyzer_version>iccAnalyzer v2.4.0</analyzer_version>\n";
  
  time_t now = time(nullptr);
  struct tm tm_buf;
  char timestamp[64];
  gmtime_r(&now, &tm_buf);
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S UTC", &tm_buf);
  xml << "    <timestamp>" << XMLEscape(timestamp) << "</timestamp>\n";
  xml << "  </metadata>\n";
  
  // Profile information
  xml << "  <profile>\n";
  xml << "    <filename>" << XMLEscape(profilePath) << "</filename>\n";
  xml << "  </profile>\n";
  
  // Heuristics results
  xml << "  <heuristics>\n";
  
  for (const auto& finding : report->findings) {
    xml << "    <check>\n";
    xml << "      <name>" << XMLEscape(finding.check_name) << "</name>\n";
    xml << "      <status>" << XMLEscape(finding.status) << "</status>\n";
    xml << "      <severity>" << XMLEscape(finding.severity) << "</severity>\n";
    xml << "      <message>" << XMLEscape(finding.message) << "</message>\n";
    xml << "    </check>\n";
  }
  
  xml << "  </heuristics>\n";
  xml << "</report>\n";
  
  xml.close();
  return true;
}

bool IccAnalyzerXMLExport::ExportComprehensiveToXML(const char* filename,
                                                     const char* profilePath,
                                                     const void* analysis)
{
  // Placeholder - similar structure to ExportHeuristicsToXML
  // Would include all comprehensive analysis data
  return false;
}
