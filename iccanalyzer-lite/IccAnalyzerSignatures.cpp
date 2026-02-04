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
#include "IccAnalyzerSignatures.h"

// Convert 4-byte signature to ASCII string (FourCC format)
void SignatureToFourCC(icUInt32Number sig, char *fourcc)
{
  fourcc[0] = (sig >> 24) & 0xFF;
  fourcc[1] = (sig >> 16) & 0xFF;
  fourcc[2] = (sig >> 8) & 0xFF;
  fourcc[3] = sig & 0xFF;
  fourcc[4] = '\0';
  
  // Replace non-printable characters with '.'
  for (int i = 0; i < 4; i++) {
    if (fourcc[i] < 32 || fourcc[i] > 126) {
      fourcc[i] = '.';
    }
  }
}

// Check if signature contains non-printable characters
bool HasNonPrintableSignature(icUInt32Number sig)
{
  for (int i = 0; i < 4; i++) {
    unsigned char c = (sig >> (24 - i*8)) & 0xFF;
    if (c < 32 || c > 126) {
      return true;
    }
  }
  return false;
}

int AnalyzeSignatures(CIccProfile *pIcc)
{
  printf("\n=== Signature Analysis ===\n\n");
  
  CIccInfo info;
  int issueCount = 0;
  
  // Analyze header signatures
  printf("Header Signatures:\n");
  printf("  Device Class:    0x%08X  '%s'  %s\n",
         pIcc->m_Header.deviceClass,
         "",
         info.GetProfileClassSigName((icProfileClassSignature)pIcc->m_Header.deviceClass));
  
  char fourcc[5];
  SignatureToFourCC(pIcc->m_Header.colorSpace, fourcc);
  printf("  Color Space:     0x%08X  '%s'  %s",
         pIcc->m_Header.colorSpace,
         fourcc,
         info.GetColorSpaceSigName((icColorSpaceSignature)pIcc->m_Header.colorSpace));
  if (HasNonPrintableSignature(pIcc->m_Header.colorSpace)) {
    printf(" [WARN] non-printable");
    issueCount++;
  }
  printf("\n");
  
  SignatureToFourCC(pIcc->m_Header.pcs, fourcc);
  printf("  PCS:             0x%08X  '%s'  %s",
         pIcc->m_Header.pcs,
         fourcc,
         info.GetColorSpaceSigName((icColorSpaceSignature)pIcc->m_Header.pcs));
  if (HasNonPrintableSignature(pIcc->m_Header.pcs)) {
    printf(" [WARN] non-printable");
    issueCount++;
  }
  printf("\n");
  
  SignatureToFourCC(pIcc->m_Header.manufacturer, fourcc);
  printf("  Manufacturer:    0x%08X  '%s'\n", pIcc->m_Header.manufacturer, fourcc);
  
  SignatureToFourCC(pIcc->m_Header.model, fourcc);
  printf("  Model:           0x%08X  '%s'\n", pIcc->m_Header.model, fourcc);
  
  printf("\nTag Signatures:\n");
  printf("%-4s %-12s %-10s %-12s %s\n", "Idx", "Tag", "FourCC", "Type", "Issues");
  printf("%-4s %-12s %-10s %-12s %s\n", "---", "------------", "----------", "------------", "------");
  
  int idx = 0;
  TagEntryList::iterator i;
  for (i = pIcc->m_Tags.begin(); i != pIcc->m_Tags.end(); i++, idx++) {
    IccTagEntry *entry = &(*i);
    CIccTag *pTag = pIcc->FindTag(entry->TagInfo.sig);
    
    SignatureToFourCC(entry->TagInfo.sig, fourcc);
    char typeFourCC[5] = "";
    if (pTag) {
      SignatureToFourCC(pTag->GetType(), typeFourCC);
    }
    
    printf("%-4d %-12s '%-8s'  %-12s",
           idx,
           info.GetTagSigName(entry->TagInfo.sig),
           fourcc,
           pTag ? info.GetTagTypeSigName(pTag->GetType()) : "N/A");
    
    // Check for issues
    bool hasIssues = false;
    if (HasNonPrintableSignature(entry->TagInfo.sig)) {
      printf(" non-printable");
      hasIssues = true;
      issueCount++;
    }
    if (pTag && HasNonPrintableSignature(pTag->GetType())) {
      if (hasIssues) printf(",");
      printf(" bad-type");
      hasIssues = true;
      issueCount++;
    }
    
    printf("\n");
  }
  
  printf("\nSummary: %d signature issue(s) detected\n", issueCount);
  return issueCount;
}
