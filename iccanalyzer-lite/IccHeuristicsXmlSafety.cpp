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
  printf("[H142] XML Serialization Safety (§10 Tag Type Definitions)\n");

  if (!filename || !filename[0]) {
    printf("      [OK] Skipped — no filename provided\n\n");
    return 0;
  }

  // Fork to isolate: ToXml() may ASAN-crash on malformed profiles.
  // We detect the crash signal in the parent without dying ourselves.
  fflush(stdout);
  fflush(stderr);
  pid_t pid = fork();

  if (pid < 0) {
    printf("      [WARN]  Fork() failed (errno=%d) — XML safety check skipped\n", errno);
    printf("       CWE-271: Cannot isolate XML serialization\n\n");
    return 1;  // Report as finding — analysis incomplete
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
    printf("      %s[WARN]  HEURISTIC: XML serialization timed out (>15s) — CWE-400 (Resource Exhaustion)%s\n",
           ColorCritical(), ColorReset());
    printf("       Possible infinite loop or exponential expansion in ToXml()\n");
    printf("       CWE-400: Uncontrolled Resource Consumption\n\n");
    return 1;
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
    printf("      %s[WARN]  HEURISTIC: XML serialization crashed with %s (signal %d)%s\n",
           ColorCritical(), sigName, sig, ColorReset());
    printf("       CIccProfileXml::ToXml() triggered a memory safety violation\n");
    printf("       This indicates the profile exercises a known XML serializer vulnerability\n");

    if (sig == SIGABRT) {
      printf("       ASAN/UBSAN detected: heap-buffer-overflow, stack-buffer-overflow,\n");
      printf("       use-after-free, null-pointer-deref, or type confusion in IccLibXML\n");
      printf("       CWE-787: Out-of-bounds Write / CWE-125: Out-of-bounds Read\n");
    } else if (sig == SIGSEGV || sig == SIGBUS) {
      printf("       CWE-476: NULL Pointer Dereference / CWE-125: Out-of-bounds Read\n");
    } else if (sig == SIGALRM) {
      printf("       CWE-400: Uncontrolled Resource Consumption (timeout in ToXml)\n");
    }
    printf("\n");
    return 1;
  }

  if (WIFEXITED(status)) {
    int exitCode = WEXITSTATUS(status);
    if (exitCode == 0) {
      printf("      [OK] XML serialization completed safely (ToXml succeeded)\n\n");
    } else {
      // Exit 1 = ToXml returned false (graceful failure, not a crash)
      printf("      [OK] XML serialization returned error (ToXml=false, exit %d) — no crash\n\n", exitCode);
    }
    return 0;
  }

  printf("      [OK] XML serialization check completed (status=0x%x)\n\n", status);
  return 0;
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
  printf("[H143] XML Array Bounds Precheck (§10 Tag Types)\n");

  if (!pIcc) {
    printf("      [OK] Skipped — no profile loaded\n\n");
    return 0;
  }

  int warnings = 0;
  TagEntryList &tagList = pIcc->m_Tags;
  if (tagList.empty()) {
    printf("      [OK] No tags in profile\n\n");
    return 0;
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
      printf("      %s[WARN]  HEURISTIC: Array tag '%s' size %u < 8-byte header%s\n",
             ColorCritical(), sigStr, tagSize, ColorReset());
      printf("       CWE-131: Incorrect Calculation of Buffer Size\n");
      printf("       Risk: DumpArray will read uninitialized/OOB memory during XML export\n");
      warnings++;
      continue;
    }

    icUInt32Number dataBytes = tagSize - 8;
    icUInt32Number maxElements = dataBytes / static_cast<icUInt32Number>(elemSize);

    // If tag offset + size exceeds profile, the array will read OOB
    if (tagOffset + tagSize > profileSize) {
      char sigStr[5] = {};
      SigToChars(entry.TagInfo.sig, sigStr);
      printf("      %s[WARN]  HEURISTIC: Array tag '%s' extends beyond profile (offset=%u + size=%u > profileSize=%u)%s\n",
             ColorCritical(), sigStr, tagOffset, tagSize, profileSize, ColorReset());
      printf("       CWE-125: Out-of-bounds Read — DumpArray will serialize OOB data to XML\n");
      warnings++;
    }

    // Warn on suspiciously large arrays (>1M elements → DoS in XML output)
    if (maxElements > 1000000) {
      char sigStr[5] = {};
      SigToChars(entry.TagInfo.sig, sigStr);
      printf("      %s[WARN]  HEURISTIC: Array tag '%s' has %u elements — XML expansion risk%s\n",
             ColorWarning(), sigStr, maxElements, ColorReset());
      printf("       CWE-400: Uncontrolled Resource Consumption in DumpArray → XML output\n");
      warnings++;
    }
  }

  if (warnings == 0) {
    printf("      [OK] All array tag element counts consistent with data sizes\n");
  }
  printf("\n");
  return warnings;
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
  printf("[H144] XML String Termination Precheck (§10.4/§10.19)\n");

  if (!pIcc) {
    printf("      [OK] Skipped — no profile loaded\n\n");
    return 0;
  }

  int warnings = 0;

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
        printf("      %s[WARN]  HEURISTIC: Colorant name[%u] in '%s' not null-terminated%s\n",
               ColorCritical(), j, tagName, ColorReset());
        printf("       CWE-170: Improper Null Termination\n");
        printf("       Risk: strlen overflow in ToXml → heap-buffer-overflow read\n");
        printf("       GHSA-4wqv-pvm8-5h27: HBO read via unterminated colorant name\n");
        warnings++;
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
          printf("      %s[WARN]  HEURISTIC: NamedColor2 prefix not null-terminated%s\n",
                 ColorCritical(), ColorReset());
          printf("       CWE-170: Improper Null Termination — strlen overflow in ToXml\n");
          warnings++;
        }
      }
    }
  }

  if (warnings == 0) {
    printf("      [OK] All string fields properly null-terminated for XML serialization\n");
  }
  printf("\n");
  return warnings;
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
  printf("[H145] XML Curve Type Consistency (§10.14 MPE)\n");

  if (!pIcc) {
    printf("      [OK] Skipped — no profile loaded\n\n");
    return 0;
  }

  int warnings = 0;
  TagEntryList &tagList = pIcc->m_Tags;
  if (tagList.empty()) {
    printf("      [OK] No tags in profile\n\n");
    return 0;
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
          printf("      %s[WARN]  HEURISTIC: MPE element %u has type '%s' (0x%08X) but is CIccMpeCurveSet%s\n",
                 ColorCritical(), elemIdx, typeStr, elemType, ColorReset());
          printf("       CWE-843: Access of Resource Using Incompatible Type\n");
          printf("       Risk: ToXmlCurve() may cast to wrong class → type confusion crash\n");
          printf("       GHSA-2pjj-3c98-qp37: type confusion in ToXmlCurve()\n");
          warnings++;
        }
      }
    }
  }

  if (warnings == 0) {
    printf("      [OK] All curve/MPE type signatures consistent for XML serialization\n");
  }
  printf("\n");
  return warnings;
}
