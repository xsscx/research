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
#include "IccHeuristicsRegistry.h"
#include <sstream>
#include <ctime>
#include <cstdio>
#include <cstdlib>
#include <regex>
#include <unistd.h>
#include <sys/stat.h>
#include <vector>
#include <set>
#include <algorithm>
#include <openssl/evp.h>

// Compute SHA-256 of a file (no shell commands — safe from injection)
static std::string ComputeSHA256XML(const char *path) {
  FILE *fp = fopen(path, "rb");
  if (!fp) return "";

  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx) { fclose(fp); return ""; }

  if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(ctx); fclose(fp); return "";
  }

  unsigned char buf[8192];
  size_t n;
  while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
    EVP_DigestUpdate(ctx, buf, n);
  }
  fclose(fp);

  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hashLen = 0;
  EVP_DigestFinal_ex(ctx, hash, &hashLen);
  EVP_MD_CTX_free(ctx);

  char hex[65] = {};
  for (unsigned int i = 0; i < hashLen && i < 32; i++) {
    snprintf(hex + i * 2, 3, "%02x", hash[i]);
  }
  return std::string(hex);
}

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

/** Write embedded XSLT stylesheet for XML report rendering. */
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
        <title>ICC Profile Security Report</title>
        <style>
          * { box-sizing: border-box; }
          body { 
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
            background: #0d1117;
            color: #c9d1d9;
          }
          .container {
            background: #161b22;
            border-radius: 8px;
            border: 1px solid #30363d;
            padding: 30px;
          }
          h1 {
            color: #58a6ff;
            border-bottom: 2px solid #1f6feb;
            padding-bottom: 12px;
            font-size: 1.4em;
          }
          h2 {
            color: #79c0ff;
            margin-top: 30px;
            border-left: 3px solid #1f6feb;
            padding-left: 12px;
            font-size: 1.1em;
          }
          .banner {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 16px 20px;
            margin: 16px 0;
            font-family: monospace;
            font-size: 0.9em;
          }
          .banner-row {
            margin: 4px 0;
          }
          .banner-label {
            color: #8b949e;
            display: inline-block;
            min-width: 100px;
          }
          .banner-value { color: #c9d1d9; }
          .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 12px;
            margin: 16px 0;
          }
          .summary-card {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 6px;
            padding: 12px;
            text-align: center;
          }
          .summary-count {
            font-size: 1.8em;
            font-weight: bold;
          }
          .summary-label { color: #8b949e; font-size: 0.85em; }
          table {
            width: 100%;
            border-collapse: collapse;
            margin: 16px 0;
            font-size: 0.88em;
          }
          th {
            background: #21262d;
            color: #c9d1d9;
            padding: 10px 12px;
            text-align: left;
            font-weight: 600;
            border-bottom: 2px solid #30363d;
          }
          td {
            padding: 8px 12px;
            border-bottom: 1px solid #21262d;
            vertical-align: top;
          }
          tr:hover { background: #1c2128; }
          .status-pass { color: #3fb950; }
          .status-fail { color: #f85149; font-weight: bold; }
          .status-warn { color: #d29922; font-weight: bold; }
          .sev-badge {
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
            white-space: nowrap;
          }
          .severity-critical { background: #da3633; color: white; }
          .severity-high { background: #f85149; color: white; }
          .severity-medium { background: #d29922; color: #0d1117; }
          .severity-low { background: #388bfd; color: white; }
          .severity-info { background: #30363d; color: #8b949e; }
          .cwe-tag {
            background: #21262d;
            color: #79c0ff;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.8em;
            margin-right: 4px;
          }
          .cve-tag {
            background: #1c2128;
            color: #f0883e;
            padding: 2px 6px;
            border-radius: 4px;
            font-size: 0.8em;
            margin-right: 4px;
          }
          .detail-text {
            color: #8b949e;
            font-size: 0.85em;
            max-width: 500px;
            word-break: break-word;
          }
          .footer {
            margin-top: 30px;
            padding-top: 16px;
            border-top: 1px solid #30363d;
            text-align: center;
            color: #484f58;
            font-size: 0.85em;
          }
          .section-count {
            color: #8b949e;
            font-size: 0.9em;
            margin-left: 8px;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>&#x1f6e1; ICC Profile Security Report</h1>
          
          <div class="banner">
            <div class="banner-row">
              <span class="banner-label">Tool:</span>
              <span class="banner-value"><xsl:value-of select="/report/metadata/analyzer_version"/></span>
            </div>
            <div class="banner-row">
              <span class="banner-label">Date:</span>
              <span class="banner-value"><xsl:value-of select="/report/metadata/timestamp"/></span>
            </div>
            <div class="banner-row">
              <span class="banner-label">File:</span>
              <span class="banner-value"><xsl:value-of select="/report/profile/filename"/></span>
            </div>
            <xsl:if test="/report/profile/sha256">
              <div class="banner-row">
                <span class="banner-label">SHA-256:</span>
                <span class="banner-value" style="font-family:monospace;font-size:0.85em">
                  <xsl:value-of select="/report/profile/sha256"/>
                </span>
              </div>
            </xsl:if>
            <xsl:if test="/report/profile/filesize">
              <div class="banner-row">
                <span class="banner-label">Size:</span>
                <span class="banner-value"><xsl:value-of select="/report/profile/filesize"/> bytes</span>
              </div>
            </xsl:if>
          </div>

          <h2>Executive Summary</h2>
          <div class="summary-grid">
            <div class="summary-card">
              <div class="summary-count" style="color:#3fb950">
                <xsl:value-of select="/report/heuristics/summary/@passed"/>
              </div>
              <div class="summary-label">PASSED</div>
            </div>
            <div class="summary-card">
              <div class="summary-count" style="color:#f85149">
                <xsl:value-of select="/report/heuristics/summary/@findings"/>
              </div>
              <div class="summary-label">FINDINGS</div>
            </div>
            <div class="summary-card">
              <div class="summary-count" style="color:#d29922">
                <xsl:value-of select="/report/heuristics/summary/@total"/>
              </div>
              <div class="summary-label">TOTAL CHECKS</div>
            </div>
          </div>
          
          <xsl:if test="/report/heuristics/check[status!='PASS']">
            <h2>&#x26a0; Findings <span class="section-count">(<xsl:value-of select="count(/report/heuristics/check[status!='PASS'])"/>)</span></h2>
            <table>
              <tr>
                <th style="width:50px">ID</th>
                <th>Check</th>
                <th style="width:80px">Severity</th>
                <th style="width:90px">CWE</th>
                <th>Detail</th>
                <th style="width:100px">CVEs</th>
              </tr>
              <xsl:for-each select="/report/heuristics/check[status!='PASS']">
                <xsl:sort select="
                  (number(severity='CRITICAL') * 1) +
                  (number(severity='HIGH') * 2) +
                  (number(severity='MEDIUM') * 3) +
                  (number(severity='LOW') * 4) +
                  (number(severity='INFO') * 5)
                " data-type="number"/>
                <tr>
                  <td style="color:#79c0ff">H<xsl:value-of select="id"/></td>
                  <td><xsl:value-of select="name"/></td>
                  <td>
                    <span class="sev-badge">
                      <xsl:attribute name="class">sev-badge <xsl:choose>
                        <xsl:when test="severity='CRITICAL'">severity-critical</xsl:when>
                        <xsl:when test="severity='HIGH'">severity-high</xsl:when>
                        <xsl:when test="severity='MEDIUM'">severity-medium</xsl:when>
                        <xsl:when test="severity='LOW'">severity-low</xsl:when>
                        <xsl:otherwise>severity-info</xsl:otherwise>
                      </xsl:choose></xsl:attribute>
                      <xsl:value-of select="severity"/>
                    </span>
                  </td>
                  <td><xsl:if test="cwe"><span class="cwe-tag"><xsl:value-of select="cwe"/></span></xsl:if></td>
                  <td class="detail-text"><xsl:value-of select="message"/></td>
                  <td><xsl:if test="cveRefs"><span class="cve-tag"><xsl:value-of select="cveRefs"/></span></xsl:if></td>
                </tr>
              </xsl:for-each>
            </table>
          </xsl:if>

          <h2>All Checks <span class="section-count">(<xsl:value-of select="count(/report/heuristics/check)"/>)</span></h2>
          <table>
            <tr>
              <th style="width:50px">ID</th>
              <th>Check</th>
              <th style="width:60px">Status</th>
              <th style="width:80px">Severity</th>
              <th style="width:90px">CWE</th>
              <th>Detail</th>
            </tr>
            <xsl:for-each select="/report/heuristics/check">
              <tr>
                <td style="color:#79c0ff">H<xsl:value-of select="id"/></td>
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
                  <span class="sev-badge">
                    <xsl:attribute name="class">sev-badge <xsl:choose>
                      <xsl:when test="severity='CRITICAL'">severity-critical</xsl:when>
                      <xsl:when test="severity='HIGH'">severity-high</xsl:when>
                      <xsl:when test="severity='MEDIUM'">severity-medium</xsl:when>
                      <xsl:when test="severity='LOW'">severity-low</xsl:when>
                      <xsl:otherwise>severity-info</xsl:otherwise>
                    </xsl:choose></xsl:attribute>
                    <xsl:value-of select="severity"/>
                  </span>
                </td>
                <td><xsl:if test="cwe"><span class="cwe-tag"><xsl:value-of select="cwe"/></span></xsl:if></td>
                <td class="detail-text"><xsl:value-of select="message"/></td>
              </tr>
            </xsl:for-each>
          </table>
          
          <div class="footer">
            Generated by )" ICCANALYZER_VERSION_FULL R"( &#x2022; ICC.1-2022-05, ICC.2-2023 &#x2022; David H Hoyt LLC
          </div>
        </div>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
)XSLT";
}

/** Derive companion .xsl path from an XML filename. */
static std::string DeriveXSLPath(const char* xmlFilename)
{
  std::string path(xmlFilename);
  auto dot = path.rfind('.');
  if (dot != std::string::npos)
    return path.substr(0, dot) + ".xsl";
  return path + ".xsl";
}

/** Write companion .xsl file so browsers can render the XML as HTML. */
static bool WriteCompanionXSL(const char* xmlFilename)
{
  std::string xslPath = DeriveXSLPath(xmlFilename);
  std::ofstream xsl(xslPath);
  if (!xsl.is_open()) return false;

  xsl << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  IccAnalyzerXMLExport::WriteXSLTStylesheet(xsl);
  xsl.close();
  return true;
}

/** Write standard XML header with PI, metadata, and profile elements. */
static void WriteXMLHeader(std::ofstream& xml, const char* xslBasename,
                            const char* profilePath)
{
  xml << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  xml << "<?xml-stylesheet type=\"text/xsl\" href=\""
      << IccAnalyzerXMLExport::XMLEscape(xslBasename) << "\"?>\n";
  xml << "<report>\n";

  xml << "  <metadata>\n";
  xml << "    <analyzer_version>" ICCANALYZER_VERSION_FULL "</analyzer_version>\n";
  xml << "    <build>ASAN+UBSAN+Coverage</build>\n";

  time_t now = time(nullptr);
  struct tm tm_buf;
  char timestamp[64];
  gmtime_r(&now, &tm_buf);
  strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S UTC", &tm_buf);
  xml << "    <timestamp>" << IccAnalyzerXMLExport::XMLEscape(timestamp)
      << "</timestamp>\n";
  xml << "  </metadata>\n";

  xml << "  <profile>\n";
  xml << "    <filename>" << IccAnalyzerXMLExport::XMLEscape(profilePath)
      << "</filename>\n";

  // Add SHA-256 and file size
  struct stat st;
  if (stat(profilePath, &st) == 0) {
    xml << "    <filesize>" << st.st_size << "</filesize>\n";
  }
  std::string sha = ComputeSHA256XML(profilePath);
  if (sha.size() == 64) {
    xml << "    <sha256>" << sha << "</sha256>\n";
  }

  xml << "  </profile>\n";
}

/** Extract basename of the companion .xsl from an XML filepath. */
static std::string XSLBasename(const char* xmlFilename)
{
  std::string xslPath = DeriveXSLPath(xmlFilename);
  auto slash = xslPath.rfind('/');
  return (slash != std::string::npos) ? xslPath.substr(slash + 1) : xslPath;
}

/** Write heuristic findings to an XML stream (legacy stub path). */
static void WriteFindings(std::ofstream& xml, const HeuristicReport* report)
{
  xml << "  <heuristics>\n";
  xml << "    <summary total=\"" << report->totalChecks
      << "\" passed=\"" << report->passedChecks
      << "\" failed=\"" << report->failedChecks
      << "\" warnings=\"" << report->warningChecks
      << "\" findings=\"" << (report->failedChecks + report->warningChecks)
      << "\"/>\n";

  for (const auto& f : report->findings) {
    xml << "    <check>\n";
    xml << "      <name>" << IccAnalyzerXMLExport::XMLEscape(f.check_name)
        << "</name>\n";
    xml << "      <status>" << IccAnalyzerXMLExport::XMLEscape(f.status)
        << "</status>\n";
    xml << "      <severity>" << IccAnalyzerXMLExport::XMLEscape(f.severity)
        << "</severity>\n";
    xml << "      <message>" << IccAnalyzerXMLExport::XMLEscape(f.message)
        << "</message>\n";
    xml << "    </check>\n";
  }
  xml << "  </heuristics>\n";
}

// --- Captured-output XML export (per-heuristic, same as --json/--report) ---

extern int HeuristicAnalyze(const char* profilePath, const char* fingerprint_db);

struct XMLFinding {
  int id;
  std::string name;
  std::string status;   // PASS, WARN, CRITICAL
  std::string detail;
  HeuristicSeverity severity;
  const char *cwe;
  const char *specRef;
  const char *cveRefs;
};

int IccAnalyzerXMLExport::RunWithXMLOutput(const char *profilePath,
                                            const char *xmlFilename,
                                            const char *fingerprint_db)
{
  if (!profilePath || !xmlFilename) return 2;
  if (strstr(xmlFilename, "..") || strlen(xmlFilename) > 4096) return 2;

  // Capture stdout via pipe (same pattern as --json/--report)
  int pipefd[2];
  if (pipe(pipefd) != 0) {
    fprintf(stderr, "[ERR] pipe() failed for XML capture\n");
    return 2;
  }

  int savedStdout = dup(STDOUT_FILENO);
  dup2(pipefd[1], STDOUT_FILENO);
  close(pipefd[1]);

  int exitCode = HeuristicAnalyze(profilePath, fingerprint_db);

  fflush(stdout);
  dup2(savedStdout, STDOUT_FILENO);
  close(savedStdout);

  // Read captured output
  std::string captured;
  {
    char buf[4096];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0)
      captured.append(buf, n);
    close(pipefd[0]);
  }

  // Parse [H##] markers from captured output
  std::regex hRegex(R"(\[H(\d+)\]\s+(.+))");
  std::regex warnRegex(R"(\[WARN\])");
  std::regex critRegex(R"(\[CRIT)");
  std::regex okRegex(R"(\[OK\])");

  std::vector<XMLFinding> findings;
  int okCount = 0, warnCount = 0, critCount = 0;
  std::istringstream stream(captured);
  std::string line;

  int currentH = -1;
  std::string currentTitle;
  std::string currentDetail;
  std::string currentStatus = "PASS";

  auto flushFinding = [&]() {
    if (currentH > 0) {
      const HeuristicEntry *entry = LookupHeuristic(currentH);
      XMLFinding f;
      f.id = currentH;
      f.name = entry ? entry->name : currentTitle;
      f.status = currentStatus;
      f.detail = currentDetail;
      f.severity = entry ? entry->severity : HeuristicSeverity::INFO;
      f.cwe = entry ? entry->primaryCWE : nullptr;
      f.specRef = entry ? entry->specRef : nullptr;
      f.cveRefs = entry ? entry->cveRefs : nullptr;

      if (currentStatus == "PASS") okCount++;
      else if (currentStatus == "WARN") warnCount++;
      else if (currentStatus == "CRITICAL") critCount++;

      findings.push_back(f);
    }
  };

  while (std::getline(stream, line)) {
    std::smatch m;
    if (std::regex_search(line, m, hRegex)) {
      flushFinding();
      currentH = std::stoi(m[1].str());
      currentTitle = m[2].str();
      currentDetail.clear();
      currentStatus = "PASS";
    } else if (currentH > 0) {
      if (line.find("HEURISTIC SUMMARY") != std::string::npos ||
          line.find("PHASE 2:") != std::string::npos ||
          line.find("PHASE 3:") != std::string::npos ||
          line.find("========") != std::string::npos) {
        flushFinding();
        currentH = -1;
        continue;
      }
      if (std::regex_search(line, critRegex)) currentStatus = "CRITICAL";
      else if (std::regex_search(line, warnRegex) && currentStatus != "CRITICAL")
        currentStatus = "WARN";
      // Extract first meaningful detail line
      if (!line.empty() && currentDetail.empty()) {
        // Trim leading whitespace
        size_t start = line.find_first_not_of(" \t");
        if (start != std::string::npos)
          currentDetail = line.substr(start);
      }
    }
  }
  flushFinding();

  // Write XML
  std::ofstream xml(xmlFilename);
  if (!xml.is_open()) {
    fprintf(stderr, "[ERR] Cannot write XML to: %s\n", xmlFilename);
    return 2;
  }

  WriteXMLHeader(xml, XSLBasename(xmlFilename).c_str(), profilePath);

  xml << "  <heuristics>\n";
  xml << "    <summary total=\"" << (int)findings.size()
      << "\" passed=\"" << okCount
      << "\" findings=\"" << (warnCount + critCount)
      << "\" warnings=\"" << warnCount
      << "\" critical=\"" << critCount << "\"/>\n";

  for (const auto& f : findings) {
    xml << "    <check>\n";
    xml << "      <id>" << f.id << "</id>\n";
    xml << "      <name>" << XMLEscape(f.name) << "</name>\n";
    xml << "      <status>" << XMLEscape(f.status) << "</status>\n";
    xml << "      <severity>" << XMLEscape(SeverityToString(f.severity))
        << "</severity>\n";
    if (f.cwe)
      xml << "      <cwe>" << XMLEscape(f.cwe) << "</cwe>\n";
    if (f.specRef)
      xml << "      <specRef>" << XMLEscape(f.specRef) << "</specRef>\n";
    if (f.cveRefs)
      xml << "      <cveRefs>" << XMLEscape(f.cveRefs) << "</cveRefs>\n";
    if (!f.detail.empty())
      xml << "      <message>" << XMLEscape(f.detail) << "</message>\n";
    xml << "    </check>\n";
  }

  xml << "  </heuristics>\n";
  xml << "</report>\n";
  xml.close();

  WriteCompanionXSL(xmlFilename);

  fprintf(stderr, "\n[OK] XML report written to: %s (%d heuristics, %d findings)\n",
          xmlFilename, (int)findings.size(), warnCount + critCount);
  fprintf(stderr, "[OK] XSLT stylesheet written alongside XML\n");
  fprintf(stderr, "[OK] Open the XML file in a browser to view the styled report\n");

  return exitCode;
}

bool IccAnalyzerXMLExport::ExportHeuristicsToXML(const char* filename,
                                                  const char* profilePath,
                                                  const void* heuristics)
{
  if (!filename || !profilePath || !heuristics)
    return false;
  if (strstr(filename, "..") || strlen(filename) > 4096)
    return false;

  const auto* report = static_cast<const HeuristicReport*>(heuristics);

  std::ofstream xml(filename);
  if (!xml.is_open())
    return false;

  WriteXMLHeader(xml, XSLBasename(filename).c_str(), profilePath);
  WriteFindings(xml, report);
  xml << "</report>\n";
  xml.close();

  WriteCompanionXSL(filename);
  return true;
}

bool IccAnalyzerXMLExport::ExportComprehensiveToXML(const char* filename,
                                                     const char* profilePath,
                                                     const void* analysis)
{
  if (!filename || !profilePath || !analysis)
    return false;
  if (strstr(filename, "..") || strlen(filename) > 4096)
    return false;

  const auto* report = static_cast<const HeuristicReport*>(analysis);

  std::ofstream xml(filename);
  if (!xml.is_open())
    return false;

  WriteXMLHeader(xml, XSLBasename(filename).c_str(), profilePath);
  WriteFindings(xml, report);
  xml << "</report>\n";
  xml.close();

  WriteCompanionXSL(filename);
  return true;
}
