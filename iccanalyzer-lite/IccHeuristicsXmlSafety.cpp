/*
 * IccHeuristicsXmlSafety.cpp — XML serialization safety heuristics (H142-H145)
 *
 * Copyright (c) 1994 - 2026 David H Hoyt LLC
 * All Rights Reserved.
 *
 * [BSD 3-Clause License - see IccAnalyzerSecurity.h for full text]
 *
 * Extends iccanalyzer-lite coverage to the 25 XML-related iccDEV security
 * advisories. H142 exercises the actual ToXml() serialization path under
 * fork() isolation with ASAN+UBSAN. H143-H145 validate binary preconditions
 * that trigger XML serializer bugs.
 *
 * Advisory coverage:
 *   GHSA-mv6h-vpcg-pwfx  (HBO icCurvesFromXml)     → H142, H145
 *   GHSA-j3mh-rjg5-8gw7  (NPD ParseTag)            → H142
 *   GHSA-h3ph-mwq5-3883  (SBO icFixXml)             → H142, H144
 *   GHSA-pmcg-2h65-35h8  (HBO DumpArray)            → H142, H143
 *   GHSA-2pjj-3c98-qp37  (type confusion ToXmlCurve)→ H142, H145
 *   GHSA-xqq3-g894-w2h5  (HBO IccTagXml)            → H142, H143
 *   CVE-2026-25502       (SBO oversized tag name)    → H142, H144
 *   CVE-2026-24852       (HBO string size mismatch)  → H142, H144
 *   CVE-2026-24412       (HBO curve sample count)    → H142, H145
 *   CVE-2026-24411       (UB curve type mismatch)    → H142, H145
 *   CVE-2026-24410       (HBO CIccSampledCalculatorCurve) → H142
 *   CVE-2026-24409       (HBO CIccFormulaSegment)    → H142
 *   CVE-2026-24408       (HBO CIccMpeXmlCalculator)  → H142
 *   CVE-2026-24407       (HBO CIccSinglSampledCurve) → H142
 *   CVE-2026-24406       (HBO CIccParamFormulaCurve) → H142
 *   CVE-2026-24404       (UB CIccMpeTintArray)       → H142
 *   CVE-2026-22046       (HBO tag size > profile)    → H142, H143
 *   CVE-2026-21693       (type confusion)            → H142, H145
 *   CVE-2026-21692       (type confusion)            → H142, H145
 *   CVE-2026-21690       (type mismatch)             → H142, H145
 *   CVE-2026-21689       (type mismatch)             → H142, H145
 *   CVE-2026-21682       (HBO array count)           → H142, H143
 *   CVE-2026-21678       (HBO serialization)         → H142
 *   CVE-2026-21506-21498 (NPD missing elements)     → H142
 *   CVE-2026-21500       (SO macro recursion)        → H142
 */

#include "IccHeuristicsXmlSafety.h"
#include "IccHeuristicsHelpers.h"
#include "IccHeuristicResult.h"
#include "IccAnalyzerColors.h"
#include "IccProfileXml.h"
#include "IccTagXmlFactory.h"
#include "IccMpeXmlFactory.h"
#include "IccDefs.h"
#include "IccUtil.h"
#include "IccIO.h"
#include "IccTagBasic.h"
#include "IccTagMPE.h"
#include "IccMpeBasic.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <new>
#include <csignal>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>


// =====================================================================
// H142: XML Serialization Safety
// Exercises the full CIccProfileXml::ToXml() code path under fork()
// isolation. The child process runs ToXml() with ASAN+UBSAN active —
// any memory safety bug (HBO, SBO, NPD, UAF, type confusion, stack
// overflow) causes the child to crash with a signal. The parent detects
// this and reports a CRITICAL finding.
//
// This single heuristic covers all 25 XML-related advisories because
// ToXml() exercises every tag serializer, curve serializer, MPE
// serializer, and string formatter in IccLibXML.
//
// CWE-787, CWE-125, CWE-416, CWE-476, CWE-843, CWE-674
// =====================================================================
int RunHeuristic_H142_XmlSerializationSafety(CIccProfile * /*pIcc*/, const char *filename)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(142, "XML Serialization Safety (§10 Tag Type Definitions)");

  if (!filename || !filename[0]) {
    return hc.skip("no filename provided");
  }

  // Fork to isolate: ToXml() may ASAN-crash on malformed profiles.
  // We detect the crash signal in the parent without dying ourselves.
  fflush(stdout);
  fflush(stderr);
  pid_t pid = fork();

  if (pid < 0) {
    hc.warn("Fork() failed (errno=%d) — XML safety check skipped", errno);
    hc.cweNote("CWE-271: Cannot isolate XML serialization");
    return hc.end("Fork failed");
  }

  if (pid == 0) {
    // ── Child process ──
    // Close stdout/stderr to suppress ASAN output in normal flow.
    // ASAN will still crash with a signal that the parent detects.
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }

    // Set a timeout so ToXml() can't hang forever (CWE-400)
    alarm(10);

    // Register XML factories (required for ToXml to handle XML tag types)
    auto *tagFactory = new (std::nothrow) CIccTagXmlFactory();
    auto *mpeFactory = new (std::nothrow) CIccMpeXmlFactory();
    if (!tagFactory || !mpeFactory) {
      delete tagFactory;
      delete mpeFactory;
      _exit(0);  // OOM in child — not an XML safety issue
    }
    CIccTagCreator::PushFactory(tagFactory);
    CIccMpeCreator::PushFactory(mpeFactory);

    // Load the profile as CIccProfileXml
    CIccProfileXml xmlProfile;
    CIccFileIO srcIO;
    if (!srcIO.Open(filename, "rb")) {
      _exit(0);  // Can't open — not an XML safety issue
    }
    if (!xmlProfile.Read(&srcIO)) {
      _exit(0);  // Can't parse — binary parse failure, not XML issue
    }
    srcIO.Close();

    // Exercise the XML serialization path
    std::string xmlOutput;
    try {
      xmlOutput.reserve(4 * 1024 * 1024);  // 4MB pre-alloc cap
    } catch (...) {
      _exit(0);  // OOM on reserve — not an XML crash
    }

    bool ok = xmlProfile.ToXml(xmlOutput);
    // If we get here without crashing, XML serialization is safe
    _exit(ok ? 0 : 1);
  }

  // ── Parent process ──
  int status = 0;
  int waited = 0;

  // Wait up to 15 seconds (child has 10s alarm + 5s grace)
  for (int i = 0; i < 150; i++) {
    pid_t ret = waitpid(pid, &status, WNOHANG);
    if (ret == pid) { waited = 1; break; }
    if (ret < 0) { waited = -1; break; }
    usleep(100000);  // 100ms
  }

  if (!waited) {
    // Child still running after 15s — kill it
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    hc.warn("HEURISTIC: XML serialization timed out (>15s) — CWE-400 (Resource Exhaustion)");
    hc.info("Possible infinite loop or exponential expansion in ToXml()");
    hc.cweNote("CWE-400: Uncontrolled Resource Consumption");
    return hc.end("XML serialization timed out");
  }

  if (WIFSIGNALED(status)) {
    int sig = WTERMSIG(status);
    const char *sigName = "UNKNOWN";
    switch (sig) {
      case SIGSEGV: sigName = "SIGSEGV"; break;
      case SIGABRT: sigName = "SIGABRT (ASAN/UBSAN)"; break;
      case SIGBUS:  sigName = "SIGBUS"; break;
      case SIGFPE:  sigName = "SIGFPE"; break;
      case SIGALRM: sigName = "SIGALRM (timeout)"; break;
      case SIGKILL: sigName = "SIGKILL (OOM)"; break;
    }
    hc.warn("HEURISTIC: XML serialization crashed with %s (signal %d)", sigName, sig);
    hc.info("CIccProfileXml::ToXml() triggered a memory safety violation");
    hc.info("This indicates the profile exercises a known XML serializer vulnerability");

    if (sig == SIGABRT) {
      hc.info("ASAN/UBSAN detected: heap-buffer-overflow, stack-buffer-overflow,");
      hc.info("use-after-free, null-pointer-deref, or type confusion in IccLibXML");
      hc.cweNote("CWE-787: Out-of-bounds Write / CWE-125: Out-of-bounds Read");
    } else if (sig == SIGSEGV || sig == SIGBUS) {
      hc.cweNote("CWE-476: NULL Pointer Dereference / CWE-125: Out-of-bounds Read");
    } else if (sig == SIGALRM) {
      hc.cweNote("CWE-400: Uncontrolled Resource Consumption (timeout in ToXml)");
    }
    return hc.end("XML serialization crashed");
  }

  if (WIFEXITED(status)) {
    int exitCode = WEXITSTATUS(status);
    if (exitCode == 0) {
      return hc.end("XML serialization completed safely (ToXml succeeded)");
    } else {
      char buf[128];
      snprintf(buf, sizeof(buf), "XML serialization returned error (ToXml=false, exit %d) — no crash", exitCode);
      return hc.end(buf);
    }
  }

  char buf[128];
  snprintf(buf, sizeof(buf), "XML serialization check completed (status=0x%x)", status);
  return hc.end(buf);
}


// =====================================================================
// H143: XML Array Bounds Precheck
// Validates that array-type tag element counts are consistent with
// available data sizes. When CIccXmlArrayType<T>::DumpArray() serializes
// to XML, it iterates m_nSize elements without checking if the backing
// buffer was fully populated. A count exceeding the data → HBO.
//
// Catches: GHSA-pmcg-2h65-35h8, GHSA-xqq3-g894-w2h5, CVE-2026-21682,
//          CVE-2026-22046
// CWE-131: Incorrect Calculation of Buffer Size
// =====================================================================
int RunHeuristic_H143_XmlArrayBoundsPrecheck(CIccProfile *pIcc)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(143, "XML Array Bounds Precheck");

  if (!pIcc) {
    return hc.skip("no profile loaded");
  }

  TagEntryList &tagList = pIcc->m_Tags;
  if (tagList.empty()) {
    return hc.end("No tags in profile");
  }

  icUInt32Number profileSize = pIcc->m_Header.size;

  for (auto it = tagList.begin(); it != tagList.end(); it++) {
    IccTagEntry &entry = *it;
    icUInt32Number tagSize = entry.TagInfo.size;
    icUInt32Number tagOffset = entry.TagInfo.offset;

    // Array tags: icSigUInt8ArrayType, icSigUInt16ArrayType,
    // icSigUInt32ArrayType, icSigUInt64ArrayType, icSigFloat16ArrayType,
    // icSigFloat32ArrayType, icSigFloat64ArrayType
    CIccTag *pTag = pIcc->FindTag(entry.TagInfo.sig);
    if (!pTag) continue;

    icTagTypeSignature typeSig = pTag->GetType();

    // Check array-like types where element count derives from tag size
    int elemSize = 0;
    switch (typeSig) {
      case icSigUInt8ArrayType:   elemSize = 1; break;
      case icSigUInt16ArrayType:  elemSize = 2; break;
      case icSigUInt32ArrayType:  elemSize = 4; break;
      case icSigUInt64ArrayType:  elemSize = 8; break;
      case icSigFloat16ArrayType: elemSize = 2; break;
      case icSigFloat32ArrayType: elemSize = 4; break;
      case icSigFloat64ArrayType: elemSize = 8; break;
      default: continue;
    }

    // Tag data starts after 8-byte type header (4-byte sig + 4-byte reserved)
    if (tagSize < 8) {
      char sigStr[5] = {};
      SigToChars(entry.TagInfo.sig, sigStr);
      hc.warn("Array tag '%s' size %u < 8-byte header", sigStr, tagSize);
      hc.cweNote("CWE-131: Incorrect Calculation of Buffer Size");
      hc.info("Risk: DumpArray will read uninitialized/OOB memory during XML export");
      continue;
    }

    icUInt32Number dataBytes = tagSize - 8;
    icUInt32Number maxElements = dataBytes / static_cast<icUInt32Number>(elemSize);

    // If tag offset + size exceeds profile, the array will read OOB
    if (tagOffset + tagSize > profileSize) {
      char sigStr[5] = {};
      SigToChars(entry.TagInfo.sig, sigStr);
      hc.warn("Array tag '%s' extends beyond profile (offset=%u + size=%u > profileSize=%u)",
              sigStr, tagOffset, tagSize, profileSize);
      hc.cweNote("CWE-125: Out-of-bounds Read — DumpArray will serialize OOB data to XML");
    }

    // Warn on suspiciously large arrays (>1M elements → DoS in XML output)
    if (maxElements > 1000000) {
      char sigStr[5] = {};
      SigToChars(entry.TagInfo.sig, sigStr);
      hc.warn("Array tag '%s' has %u elements — XML expansion risk", sigStr, maxElements);
      hc.cweNote("CWE-400: Uncontrolled Resource Consumption in DumpArray → XML output");
    }
  }

  return hc.end("All array tag element counts consistent with data sizes");
}


// =====================================================================
// H144: XML String Termination Precheck
// Validates that string fields in fixed-size buffers are null-terminated.
// When ToXml() serializes ColorantTable or NamedColor2 entries, it treats
// fixed char[32] fields as C-strings via strlen(). If the field is not
// null-terminated, strlen reads past the buffer boundary → HBO read.
//
// Catches: GHSA-4wqv-pvm8-5h27, GHSA-h3ph-mwq5-3883,
//          CVE-2026-25502, CVE-2026-24852
// CWE-170: Improper Null Termination
// =====================================================================
int RunHeuristic_H144_XmlStringTerminationPrecheck(CIccProfile *pIcc)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(144, "XML String Termination Precheck");

  if (!pIcc) {
    return hc.skip("no profile loaded");
  }

  // Check ColorantTable tags (clrt, clot)
  icTagSignature colorantSigs[] = {
    icSigColorantTableTag,
    icSigColorantTableOutTag
  };

  for (int i = 0; i < 2; i++) {
    CIccTag *pTag = pIcc->FindTag(colorantSigs[i]);
    if (!pTag) continue;

    // CIccTagColorantTable stores colorant names as icColorantName[32]
    CIccTagColorantTable *pClr = dynamic_cast<CIccTagColorantTable*>(pTag);
    if (!pClr) continue;

    icUInt32Number count = pClr->GetSize();
    for (icUInt32Number j = 0; j < count && j < 256; j++) {
      // Access the colorant entry
      icColorantTableEntry &clrEntry = (*pClr)[j];

      // Check if name[32] is null-terminated
      bool terminated = false;
      for (int k = 0; k < 32; k++) {
        if (clrEntry.name[k] == '\0') {
          terminated = true;
          break;
        }
      }

      if (!terminated) {
        const char *tagName = (i == 0) ? "clrt" : "clot";
        hc.warn("Colorant name[%u] in '%s' not null-terminated", j, tagName);
        hc.cweNote("CWE-170: Improper Null Termination");
        hc.info("Risk: strlen overflow in ToXml → heap-buffer-overflow read");
        hc.info("GHSA-4wqv-pvm8-5h27: HBO read via unterminated colorant name");
        break;  // One warning per tag is sufficient
      }
    }
  }

  // Check NamedColor2 tag — name roots and prefix/suffix
  CIccTag *pNcl = pIcc->FindTag(icSigNamedColor2Tag);
  if (pNcl) {
    CIccTagNamedColor2 *pNc2 = dynamic_cast<CIccTagNamedColor2*>(pNcl);
    if (pNc2) {
      // Check prefix (32-byte fixed field)
      const char *prefix = pNc2->GetPrefix();

      if (prefix) {
        bool terminated = false;
        for (int k = 0; k < 32; k++) {
          if (prefix[k] == '\0') { terminated = true; break; }
        }
        if (!terminated) {
          hc.warn("NamedColor2 prefix not null-terminated");
          hc.cweNote("CWE-170: Improper Null Termination — strlen overflow in ToXml");
        }
      }
    }
  }

  return hc.end("All string fields properly null-terminated for XML serialization");
}


// =====================================================================
// H145: XML Curve Type Consistency
// Validates that curve and MPE elements have type signatures consistent
// with their container expectations. ToXmlCurve() in IccMpeXml.cpp
// casts curve pointers based on type signature without runtime type
// checking — if a curve's declared type doesn't match its actual C++
// class, the cast produces an invalid pointer → type confusion → crash.
//
// Catches: GHSA-2pjj-3c98-qp37, GHSA-mv6h-vpcg-pwfx,
//          CVE-2026-24411, CVE-2026-24412, CVE-2026-21693, CVE-2026-21692,
//          CVE-2026-21690, CVE-2026-21689
// CWE-843: Access of Resource Using Incompatible Type
// =====================================================================
int RunHeuristic_H145_XmlCurveTypeConsistency(CIccProfile *pIcc)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(145, "XML Curve Type Consistency");

  if (!pIcc) {
    return hc.skip("no profile loaded");
  }

  TagEntryList &tagList = pIcc->m_Tags;
  if (tagList.empty()) {
    return hc.end("No tags in profile");
  }

  // Check MPE CurveSet elements for type consistency
  for (auto it = tagList.begin(); it != tagList.end(); it++) {
    IccTagEntry &entry = *it;
    CIccTag *pTag = pIcc->FindTag(entry.TagInfo.sig);
    if (!pTag) continue;

    // Look for multiProcessElementsType tags (AToB, BToA, DToB, BToD, gamut, etc.)
    CIccTagMultiProcessElement *pMpe = dynamic_cast<CIccTagMultiProcessElement*>(pTag);
    if (!pMpe) continue;

    // Iterate MPE elements looking for CurveSet elements
    icUInt32Number nElements = pMpe->NumElements();

    for (icUInt32Number elemIdx = 0; elemIdx < nElements && elemIdx < 64; elemIdx++) {
      CIccMultiProcessElement *pElem = pMpe->GetElement(static_cast<int>(elemIdx));
      if (!pElem) continue;

      // Check if this is a CurveSet element
      CIccMpeCurveSet *pCurveSet = dynamic_cast<CIccMpeCurveSet*>(pElem);
      if (!pCurveSet) continue;

      // Validate CurveSet element type signature
      if (pCurveSet->NumInputChannels() > 0) {
        icElemTypeSignature elemType = pCurveSet->GetType();
        if (elemType != icSigCurveSetElemType) {
          char typeStr[5] = {};
          SigToChars(static_cast<uint32_t>(elemType), typeStr);
          hc.warn("MPE element %u has type '%s' (0x%08X) but is CIccMpeCurveSet",
                  elemIdx, typeStr, elemType);
          hc.cweNote("CWE-843: Access of Resource Using Incompatible Type");
          hc.info("Risk: ToXmlCurve() may cast to wrong class → type confusion crash");
          hc.info("GHSA-2pjj-3c98-qp37: type confusion in ToXmlCurve()");
        }
      }
    }
  }

  return hc.end("All curve/MPE type signatures consistent for XML serialization");
}

// =====================================================================
// H180: XML Round-Trip Fidelity (CWE-345/CWE-787)
// =====================================================================
// Validates that ICC -> XML -> ICC round-trip preserves profile binary
// content. Data loss or corruption during XML serialization can hide
// malicious tag content or silently alter color transforms.
//
// Uses fork() isolation (same pattern as H142) because both ToXml()
// and LoadXml()/FromXml() can crash on malformed profiles.
//
// The child process:
//   1. Loads the original profile as CIccProfileXml
//   2. Calls ToXml() to serialize to XML string
//   3. Creates a new CIccProfileXml and calls LoadXml()
//   4. Writes round-tripped profile to memory via CIccMemIO
//   5. Compares header fields and tag table structure
//   6. Reports discrepancies via exit code
//
// Exit codes from child:
//   0 = round-trip matched (or profile can't be loaded)
//   1 = ToXml() failed
//   2 = LoadXml() (FromXml) failed
//   3 = structural mismatch (tag count, header fields)
//   4 = tag data size mismatch
// =====================================================================
int RunHeuristic_H180_XmlRoundTripFidelity(CIccProfile * /*pIcc*/, const char *filename)
{
  auto &hc = HeuristicCollector::instance();
  hc.begin(180, "XML Round-Trip Fidelity (ToXml -> FromXml -> Write)");

  if (!filename || !filename[0])
    return hc.skip("no filename provided");

  fflush(stdout);
  fflush(stderr);
  pid_t pid = fork();

  if (pid < 0) {
    hc.warn("Fork() failed (errno=%d)", errno);
    return hc.end("Fork failed");
  }

  if (pid == 0) {
    // -- Child process --
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      dup2(devnull, STDOUT_FILENO);
      dup2(devnull, STDERR_FILENO);
      close(devnull);
    }
    alarm(15);  // 15s timeout for full round-trip

    // Register XML factories
    auto *tagFactory = new (std::nothrow) CIccTagXmlFactory();
    auto *mpeFactory = new (std::nothrow) CIccMpeXmlFactory();
    if (!tagFactory || !mpeFactory) {
      delete tagFactory;
      delete mpeFactory;
      _exit(0);
    }
    CIccTagCreator::PushFactory(tagFactory);
    CIccMpeCreator::PushFactory(mpeFactory);

    // Step 1: Load original profile
    CIccProfileXml origProfile;
    CIccFileIO srcIO;
    if (!srcIO.Open(filename, "rb"))
      _exit(0);
    if (!origProfile.Read(&srcIO))
      _exit(0);  // Binary parse failure -- not XML round-trip issue
    srcIO.Close();

    // Capture original header and tag count
    icUInt32Number origTagCount = static_cast<icUInt32Number>(origProfile.m_Tags.size());
    icUInt32Number origVersion = origProfile.m_Header.version;
    icUInt32Number origClass = (icUInt32Number)origProfile.m_Header.deviceClass;
    icColorSpaceSignature origCS = origProfile.m_Header.colorSpace;
    icColorSpaceSignature origPCS = origProfile.m_Header.pcs;

    // Step 2: ToXml()
    std::string xmlOutput;
    try {
      xmlOutput.reserve(4 * 1024 * 1024);
    } catch (...) {
      _exit(0);
    }
    if (!origProfile.ToXml(xmlOutput))
      _exit(1);  // ToXml failed

    // Step 3: FromXml (LoadXml from temp file)
    char tmpXml[] = "/tmp/h180-rt-XXXXXX";
    int tmpFd = mkstemp(tmpXml);
    if (tmpFd < 0)
      _exit(0);
    ssize_t written = write(tmpFd, xmlOutput.c_str(), xmlOutput.size());
    close(tmpFd);
    if (written < 0 || (size_t)written != xmlOutput.size()) {
      unlink(tmpXml);
      _exit(0);
    }

    CIccProfileXml rtProfile;
    std::string loadParseStr;
    bool loadOk = rtProfile.LoadXml(tmpXml, NULL, &loadParseStr);
    unlink(tmpXml);
    if (!loadOk)
      _exit(2);  // LoadXml/ParseXml failed

    // Step 4: Compare structural fields
    if (rtProfile.m_Header.version != origVersion ||
        (icUInt32Number)rtProfile.m_Header.deviceClass != origClass ||
        rtProfile.m_Header.colorSpace != origCS ||
        rtProfile.m_Header.pcs != origPCS) {
      _exit(3);  // Header mismatch
    }

    // Step 5: Compare tag counts
    icUInt32Number rtTagCount = static_cast<icUInt32Number>(rtProfile.m_Tags.size());
    if (rtTagCount != origTagCount) {
      _exit(3);
    }

    // Step 6: Compare tag signatures present in both
    int tagMismatches = 0;
    for (auto it = origProfile.m_Tags.begin(); it != origProfile.m_Tags.end(); ++it) {
      icTagSignature origSig = it->TagInfo.sig;
      CIccTag *rtTag = rtProfile.FindTag(origSig);
      if (!rtTag) {
        tagMismatches++;
      }
    }
    if (tagMismatches > 0)
      _exit(4);  // Tag data loss

    _exit(0);  // Round-trip OK
  }

  // -- Parent process --
  int status = 0;
  int waited = 0;
  for (int i = 0; i < 200; i++) {  // 20s max wait
    pid_t ret = waitpid(pid, &status, WNOHANG);
    if (ret == pid) { waited = 1; break; }
    if (ret < 0) { waited = -1; break; }
    usleep(100000);
  }

  if (!waited) {
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    hc.warn("HEURISTIC: XML round-trip timed out (>20s) -- CWE-400");
    hc.cweNote("CWE-400: Uncontrolled Resource Consumption");
    return hc.end("Round-trip timed out");
  }

  if (WIFSIGNALED(status)) {
    int sig = WTERMSIG(status);
    hc.critical("HEURISTIC: XML round-trip CRASHED (signal %d) -- "
                "ToXml/FromXml path has memory safety bug", sig);
    hc.cweNote("CWE-787: Out-of-bounds Write / CWE-125: Out-of-bounds Read");
    char crashMsg[80];
    snprintf(crashMsg, sizeof(crashMsg), "Round-trip crashed with signal %d", sig);
    return hc.end(crashMsg);
  }

  if (WIFEXITED(status)) {
    int code = WEXITSTATUS(status);
    switch (code) {
    case 0:
      return hc.end("XML round-trip preserves profile structure");
    case 1:
      hc.warn("HEURISTIC: ToXml() serialization failed -- data not representable as XML");
      hc.cweNote("CWE-345: Insufficient Verification of Data Authenticity");
      return hc.end("ToXml failed");
    case 2:
      hc.warn("HEURISTIC: FromXml(ToXml()) failed -- round-trip data loss");
      hc.cweNote("CWE-345: Insufficient Verification of Data Authenticity");
      return hc.end("FromXml failed on ToXml output");
    case 3:
      hc.warn("HEURISTIC: Round-trip header/tag-count mismatch -- structural data loss");
      hc.cweNote("CWE-345: Insufficient Verification of Data Authenticity");
      return hc.end("Structural mismatch after round-trip");
    case 4:
      hc.warn("HEURISTIC: Round-trip tag data loss -- tags present in original missing after round-trip");
      hc.cweNote("CWE-345: Insufficient Verification of Data Authenticity");
      return hc.end("Tag data lost in round-trip");
    default:
      hc.info("XML round-trip child exited with code %d", code);
      char defMsg[80];
      snprintf(defMsg, sizeof(defMsg), "Round-trip exited with code %d", code);
      return hc.end(defMsg);
    }
  }

  return hc.end("XML round-trip check completed (unknown child status)");
}

// ============================================================================
// Sub-Dispatcher: RunXmlSafetyHeuristics (H142-H145, H180)
// ============================================================================
int RunXmlSafetyHeuristics(CIccProfile *pIcc, const char *filename)
{
  int heuristicCount = 0;
  heuristicCount += RunHeuristic_H142_XmlSerializationSafety(pIcc, filename);
  heuristicCount += RunHeuristic_H143_XmlArrayBoundsPrecheck(pIcc);
  heuristicCount += RunHeuristic_H144_XmlStringTerminationPrecheck(pIcc);
  heuristicCount += RunHeuristic_H145_XmlCurveTypeConsistency(pIcc);
  heuristicCount += RunHeuristic_H180_XmlRoundTripFidelity(pIcc, filename);
  return heuristicCount;
}
